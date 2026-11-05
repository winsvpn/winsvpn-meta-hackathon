package main

import (
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

func parseDirectStart(line string) (string, error) {
	if len(line) == 0 || len(line) > 64<<10 {
		return "", errors.New("direct start size invalid")
	}
	dec := json.NewDecoder(strings.NewReader(line))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return "", errors.New("direct start must be an object")
	}
	if !dec.More() {
		return "", errors.New("direct profile required")
	}
	key, err := dec.Token()
	if err != nil || key != "profile" {
		return "", errors.New("direct start accepts only profile")
	}
	var path string
	if err := dec.Decode(&path); err != nil {
		return "", err
	}
	if dec.More() {
		return "", errors.New("direct start has extra or duplicate fields")
	}
	if token, err = dec.Token(); err != nil || token != json.Delim('}') {
		return "", errors.New("direct start object incomplete")
	}
	if dec.Decode(new(any)) != io.EOF {
		return "", errors.New("direct start trailing input")
	}
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("direct profile requires an absolute local path")
	}
	// Windows device and network namespaces are not local profile files.
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) {
		return "", errors.New("direct profile cannot use a device or network namespace")
	}
	return path, nil
}
