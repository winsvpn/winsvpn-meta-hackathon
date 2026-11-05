package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// decodeExactJSONObject rejects duplicate members at every nesting level and
// requires the top-level object to contain exactly the named members. Go's
// json.Unmarshal otherwise accepts duplicate keys with last-value-wins
// semantics and silently leaves omitted scalar fields at their zero values.
func decodeExactJSONObject(
	raw []byte, required []string, destination any,
) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := rejectDuplicateJSONValue(decoder); err != nil {
		return err
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON value begins with %v", token)
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return fmt.Errorf("decode JSON object members: %w", err)
	}
	if members == nil {
		return errors.New("top-level JSON value is not an object")
	}
	requiredSet := make(map[string]struct{}, len(required))
	for _, name := range required {
		requiredSet[name] = struct{}{}
		if _, ok := members[name]; !ok {
			return fmt.Errorf("required JSON member %q is absent", name)
		}
	}
	for name := range members {
		if _, ok := requiredSet[name]; !ok {
			return fmt.Errorf("unknown JSON member %q", name)
		}
	}

	strict := json.NewDecoder(bytes.NewReader(raw))
	strict.DisallowUnknownFields()
	if err := strict.Decode(destination); err != nil {
		return fmt.Errorf("decode exact JSON object: %w", err)
	}
	var generic any
	presenceDecoder := json.NewDecoder(bytes.NewReader(raw))
	presenceDecoder.UseNumber()
	if err := presenceDecoder.Decode(&generic); err != nil {
		return fmt.Errorf("decode JSON for presence validation: %w", err)
	}
	if err := requireJSONPresence(generic, reflect.TypeOf(destination)); err != nil {
		return err
	}
	if err := strict.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON object carries trailing data")
	}
	return nil
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})

func requireJSONPresence(value any, destination reflect.Type) error {
	for destination.Kind() == reflect.Pointer {
		destination = destination.Elem()
	}
	if destination == rawMessageType {
		return nil
	}
	switch destination.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("JSON value for %s is not an object", destination)
		}
		for index := 0; index < destination.NumField(); index++ {
			field := destination.Field(index)
			if field.PkgPath != "" {
				continue
			}
			tag := strings.Split(field.Tag.Get("json"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = field.Name
			}
			child, exists := object[tag]
			if !exists {
				return fmt.Errorf("required JSON member %q is absent", tag)
			}
			if err := requireJSONPresence(child, field.Type); err != nil {
				return fmt.Errorf("member %q: %w", tag, err)
			}
		}
	case reflect.Slice, reflect.Array:
		if destination.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("JSON value for %s is not an array", destination)
		}
		for index, child := range array {
			if err := requireJSONPresence(child, destination.Elem()); err != nil {
				return fmt.Errorf("array element %d: %w", index, err)
			}
		}
	}
	return nil
}

func rejectDuplicateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode JSON token: %w", err)
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("decode JSON object key: %w", err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON member %q", key)
			}
			seen[key] = struct{}{}
			if err := rejectDuplicateJSONValue(decoder); err != nil {
				return fmt.Errorf("member %q: %w", key, err)
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := rejectDuplicateJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array is not terminated")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delimiter)
	}
	return nil
}
