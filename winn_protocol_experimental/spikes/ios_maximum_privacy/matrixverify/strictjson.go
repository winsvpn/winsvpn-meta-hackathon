package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

type jsonShape struct {
	name    string
	members map[string]jsonMember
}

type jsonMember struct {
	required bool
	object   *jsonShape
	element  *jsonShape
}

func newJSONShape(name string) *jsonShape {
	return &jsonShape{name: name, members: make(map[string]jsonMember)}
}

func (shape *jsonShape) declare(name string, member jsonMember) *jsonShape {
	if _, exists := shape.members[name]; exists {
		panic("duplicate member declaration " + shape.name + "." + name)
	}
	shape.members[name] = member
	return shape
}

func (shape *jsonShape) required(names ...string) *jsonShape {
	for _, name := range names {
		shape.declare(name, jsonMember{required: true})
	}
	return shape
}

func (shape *jsonShape) optional(names ...string) *jsonShape {
	for _, name := range names {
		shape.declare(name, jsonMember{})
	}
	return shape
}

func (shape *jsonShape) requiredObject(name string, nested *jsonShape) *jsonShape {
	return shape.declare(name, jsonMember{required: true, object: nested})
}

func (shape *jsonShape) optionalObject(name string, nested *jsonShape) *jsonShape {
	return shape.declare(name, jsonMember{object: nested})
}

func (shape *jsonShape) requiredArray(name string, element *jsonShape) *jsonShape {
	return shape.declare(name, jsonMember{required: true, element: element})
}

func validateStrictJSON(content []byte, shape *jsonShape) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := validateJSONObject(decoder, shape, shape.name); err != nil {
		return err
	}
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return fmt.Errorf("%s is followed by trailing JSON", shape.name)
	}
	return err
}

func validateJSONObject(
	decoder *json.Decoder,
	shape *jsonShape,
	path string,
) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '{' {
		return fmt.Errorf("%s is not a JSON object", path)
	}
	seen := make(map[string]struct{}, len(shape.members))
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("%s has a non-string member name", path)
		}
		if _, repeated := seen[name]; repeated {
			return fmt.Errorf("%s repeats member %q", path, name)
		}
		seen[name] = struct{}{}
		member, declared := shape.members[name]
		if !declared {
			return fmt.Errorf("%s: %s", path, undeclaredMemberReason(shape, name))
		}
		if err := validateJSONMember(decoder, member, path+"."+name); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	for _, name := range sortedRequiredMembers(shape) {
		if _, present := seen[name]; !present {
			return fmt.Errorf("%s is missing required member %q", path, name)
		}
	}
	return nil
}

func validateJSONMember(
	decoder *json.Decoder,
	member jsonMember,
	path string,
) error {
	switch {
	case member.object != nil:
		return validateJSONObject(decoder, member.object, path)
	case member.element != nil:
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
			return fmt.Errorf("%s is not a JSON array", path)
		}
		for index := 0; decoder.More(); index++ {
			if err := validateJSONObject(
				decoder,
				member.element,
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
		if _, composite := token.(json.Delim); composite {
			return fmt.Errorf("%s must be a scalar", path)
		}
		if token == nil {
			return fmt.Errorf("%s is null", path)
		}
		return nil
	}
}

func undeclaredMemberReason(shape *jsonShape, name string) string {
	for declared := range shape.members {
		if declared != name && strings.EqualFold(declared, name) {
			return fmt.Sprintf(
				"member %q is a case variant of declared member %q",
				name,
				declared,
			)
		}
	}
	return fmt.Sprintf("member %q is not declared", name)
}

func sortedRequiredMembers(shape *jsonShape) []string {
	names := make([]string, 0, len(shape.members))
	for name, member := range shape.members {
		if member.required {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
