//go:build unix

package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
)

const maximumExtendedAttributeList = 1 << 20

// quarantineExtendedAttributes are refused wherever the Unix descriptor
// backend can report them. macOS attaches com.apple.quarantine to anything
// that arrived from a browser or an archive.
var quarantineExtendedAttributes = []string{
	"com.apple.quarantine",
	"user.winn.quarantine",
}

func listDescriptorXattrs(
	file *os.File,
	list func(int, []byte) (int, error),
) ([]string, error) {
	if file == nil {
		return nil, fmt.Errorf("list descriptor xattrs: nil file")
	}
	// #nosec G115 -- os.File owns a live Unix kernel descriptor represented
	// by int; Fd widens that descriptor to uintptr.
	size, err := list(int(file.Fd()), nil)
	if err != nil {
		if isExtendedAttributeUnsupported(err) {
			return nil, fmt.Errorf(
				"descriptor extended-attribute listing is unsupported: %w", err,
			)
		}
		return nil, fmt.Errorf("flistxattr %s: %w", file.Name(), err)
	}
	if size < 0 || size > maximumExtendedAttributeList {
		return nil, fmt.Errorf(
			"extended-attribute list for %s has invalid size %d",
			file.Name(), size,
		)
	}
	if size == 0 {
		return []string{}, nil
	}
	buffer := make([]byte, size)
	// #nosec G115 -- os.File owns a live Unix kernel descriptor represented
	// by int; Fd widens that descriptor to uintptr.
	read, err := list(int(file.Fd()), buffer)
	if err != nil {
		return nil, fmt.Errorf("flistxattr %s: %w", file.Name(), err)
	}
	if read < 0 || read > len(buffer) {
		return nil, fmt.Errorf(
			"extended-attribute list for %s changed size from %d to %d",
			file.Name(), size, read,
		)
	}
	buffer = buffer[:read]
	parts := bytes.Split(buffer, []byte{0})
	names := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		name := string(part)
		if strings.ContainsRune(name, 0) {
			return nil, fmt.Errorf("invalid NUL in extended-attribute name")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for index := 1; index < len(names); index++ {
		if names[index] == names[index-1] {
			return nil, fmt.Errorf(
				"duplicate extended-attribute name %q on %s",
				names[index], file.Name(),
			)
		}
	}
	return names, nil
}

func checkDescriptorQuarantine(
	file *os.File, display string,
) ([]string, error) {
	names, err := listExtendedAttributesDescriptor(file)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot inspect extended attributes of %s: %w", display, err,
		)
	}
	present := make(map[string]bool, len(names))
	for _, name := range names {
		present[name] = true
	}
	for _, attribute := range quarantineExtendedAttributes {
		if !present[attribute] {
			continue
		}
		stillPresent, err := hasExtendedAttributeDescriptor(file, attribute)
		if err != nil {
			return nil, fmt.Errorf(
				"cannot verify extended attribute %s on %s: %w",
				attribute, display, err,
			)
		}
		if !stillPresent {
			return nil, fmt.Errorf(
				"extended attributes of %s changed during inspection", display,
			)
		}
		return nil, fmt.Errorf(
			"%w: %s carries the %s extended attribute",
			errQuarantined, display, attribute,
		)
	}
	return names, nil
}

func verifyDescriptorQuarantineState(
	file *os.File, display string, before []string,
) error {
	after, err := checkDescriptorQuarantine(file, display)
	if err != nil {
		return err
	}
	if strings.Join(before, "\x00") != strings.Join(after, "\x00") {
		return fmt.Errorf(
			"extended attributes of %s changed during snapshot inspection",
			display,
		)
	}
	return nil
}
