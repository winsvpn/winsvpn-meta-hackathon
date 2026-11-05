package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
)

// validateStrictJSON rejects the normal encoding/json ambiguities before typed
// decoding: duplicate names, case-insensitive aliases, unknown names, absent
// required fields, nulls, and the wrong JSON kind at any nested level.
func validateStrictJSON(content []byte, target any) error {
	targetType := reflect.TypeOf(target)
	if targetType.Kind() != reflect.Struct {
		panic("strict JSON target must be a struct")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := validateJSONValue(decoder, targetType, "root"); err != nil {
		return err
	}
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("JSON is followed by trailing content")
	}
	return err
}

func validateJSONValue(
	decoder *json.Decoder,
	expected reflect.Type,
	path string,
) error {
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	switch expected.Kind() {
	case reflect.Struct:
		return validateJSONObject(decoder, expected, path)
	case reflect.Slice, reflect.Array:
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '[' {
			return fmt.Errorf("%s is not an array", path)
		}
		for index := 0; decoder.More(); index++ {
			if err := validateJSONValue(
				decoder,
				expected.Elem(),
				fmt.Sprintf("%s[%d]", path, index),
			); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if token == nil {
			return fmt.Errorf("%s is null", path)
		}
		if _, composite := token.(json.Delim); composite {
			return fmt.Errorf("%s is not a scalar", path)
		}
		return nil
	}
}

func validateJSONObject(
	decoder *json.Decoder,
	expected reflect.Type,
	path string,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return fmt.Errorf("%s is not an object", path)
	}
	fields := exactJSONFields(expected)
	seen := make(map[string]struct{}, len(fields))
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("%s has a non-string member name", path)
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("%s repeats member %q", path, name)
		}
		fieldType, declared := fields[name]
		if !declared {
			return fmt.Errorf("%s has unknown member %q", path, name)
		}
		seen[name] = struct{}{}
		if err := validateJSONValue(
			decoder,
			fieldType,
			path+"."+name,
		); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for name := range fields {
		if _, present := seen[name]; !present {
			return fmt.Errorf("%s is missing member %q", path, name)
		}
	}
	return nil
}

func exactJSONFields(target reflect.Type) map[string]reflect.Type {
	fields := make(map[string]reflect.Type, target.NumField())
	for index := 0; index < target.NumField(); index++ {
		field := target.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name := field.Tag.Get("json")
		if comma := bytes.IndexByte([]byte(name), ','); comma >= 0 {
			name = name[:comma]
		}
		if name == "" {
			name = field.Name
		}
		if name == "-" {
			continue
		}
		if _, duplicate := fields[name]; duplicate {
			panic("duplicate JSON field declaration " + name)
		}
		fields[name] = field.Type
	}
	return fields
}

func decodeCanonicalJSON(content []byte, destination any) error {
	target := reflect.TypeOf(destination)
	if target.Kind() != reflect.Pointer || target.Elem().Kind() != reflect.Struct {
		panic("canonical JSON destination must point to a struct")
	}
	if err := validateStrictJSON(
		content,
		reflect.New(target.Elem()).Elem().Interface(),
	); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON is followed by trailing content")
		}
		return err
	}
	canonical, err := json.Marshal(destination)
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(content, canonical) {
		return errors.New("JSON is not canonical compact bytes plus one line feed")
	}
	return nil
}
