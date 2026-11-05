package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	forkReference  = "pkg:generic/quic-go/masque-go@v0.4.0-winn.1"
	upstreamCommit = "03179c5407a332f0509fa8e165244e6410ac165a"
)

func main() {
	bomPath := flag.String("bom", "", "CycloneDX JSON BOM to augment in place")
	sourceRoot := flag.String("source-root", ".", "Winn protocol module root")
	flag.Parse()
	if *bomPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: winn-sbom-augment -bom PATH [-source-root PATH]")
		os.Exit(64)
	}
	if err := augmentFile(*bomPath, *sourceRoot); err != nil {
		fmt.Fprintf(os.Stderr, "augment Winn SBOM: %v\n", err)
		os.Exit(1)
	}
}

func augmentFile(bomPath, sourceRoot string) error {
	bomRoot, err := os.OpenRoot(filepath.Dir(bomPath))
	if err != nil {
		return err
	}
	defer func() { _ = bomRoot.Close() }()
	bomName := filepath.Base(bomPath)
	info, err := bomRoot.Lstat(bomName)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("BOM input must be a regular non-symlink file")
	}
	input, err := bomRoot.ReadFile(bomName)
	if err != nil {
		return err
	}
	output, err := augmentBOM(input, sourceRoot)
	if err != nil {
		return err
	}
	temporary, temporaryName, err := createRootedTemporary(
		bomRoot,
		info.Mode().Perm(),
	)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = bomRoot.Remove(temporaryName)
		}
	}()
	if _, err := temporary.Write(output); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := bomRoot.Rename(temporaryName, bomName); err != nil {
		return err
	}
	removeTemporary = false
	return nil
}

func createRootedTemporary(root *os.Root, mode os.FileMode) (*os.File, string, error) {
	for range 16 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".winn-sbom-augment-" + hex.EncodeToString(random[:]) + ".json"
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate a unique SBOM temporary file")
}

func augmentBOM(input []byte, sourceRoot string) ([]byte, error) {
	var bom map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(input)))
	decoder.UseNumber()
	if err := decoder.Decode(&bom); err != nil {
		return nil, fmt.Errorf("decode CycloneDX JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if bom["bomFormat"] != "CycloneDX" || bom["specVersion"] != "1.6" {
		return nil, errors.New("expected a CycloneDX 1.6 JSON BOM")
	}

	sourceDigest, sourceFiles, err := forkSourceDigest(sourceRoot)
	if err != nil {
		return nil, err
	}
	components, err := objectArray(bom, "components")
	if err != nil {
		return nil, err
	}
	for _, component := range components {
		if component["bom-ref"] == forkReference ||
			component["name"] == "github.com/quic-go/masque-go" {
			return nil, errors.New("MASQUE fork is already represented in BOM")
		}
	}
	dependencyReferences := make([]string, 0, 3)
	for _, moduleName := range []string{
		"github.com/dunglas/httpsfv",
		"github.com/quic-go/quic-go",
		"github.com/yosida95/uritemplate/v3",
	} {
		reference, found := componentReference(components, moduleName)
		if !found {
			return nil, fmt.Errorf("required fork dependency is absent from BOM: %s", moduleName)
		}
		if reference == "" {
			return nil, fmt.Errorf("required fork dependency has empty bom-ref: %s", moduleName)
		}
		dependencyReferences = append(dependencyReferences, reference)
	}
	slices.Sort(dependencyReferences)

	forkComponent := map[string]any{
		"bom-ref": forkReference,
		"type":    "library",
		"group":   "github.com/quic-go",
		"name":    "masque-go",
		"version": "v0.4.0-winn.1",
		"scope":   "required",
		"purl":    forkReference,
		"licenses": []any{
			map[string]any{"license": map[string]any{"id": "MIT"}},
		},
		"externalReferences": []any{
			map[string]any{
				"type": "vcs",
				"url":  "https://github.com/quic-go/masque-go/tree/" + upstreamCommit,
			},
		},
		"properties": []any{
			map[string]any{"name": "winsvpn:embedded-fork", "value": "true"},
			map[string]any{"name": "winsvpn:upstream-module", "value": "github.com/quic-go/masque-go"},
			map[string]any{"name": "winsvpn:upstream-version", "value": "v0.4.0"},
			map[string]any{"name": "winsvpn:upstream-commit", "value": upstreamCommit},
			map[string]any{"name": "winsvpn:source-manifest-sha256", "value": sourceDigest},
			map[string]any{"name": "winsvpn:source-file-count", "value": strconv.Itoa(sourceFiles)},
		},
	}
	components = append(components, forkComponent)
	slices.SortFunc(components, func(left, right map[string]any) int {
		return strings.Compare(stringValue(left["bom-ref"]), stringValue(right["bom-ref"]))
	})
	bom["components"] = mapsToAny(components)

	dependencies, err := objectArray(bom, "dependencies")
	if err != nil {
		return nil, err
	}
	rootReference, err := rootComponentReference(bom)
	if err != nil {
		return nil, err
	}
	rootFound := false
	for _, dependency := range dependencies {
		if dependency["ref"] != rootReference {
			continue
		}
		rootFound = true
		dependsOn, err := stringArray(dependency, "dependsOn")
		if err != nil {
			return nil, err
		}
		if !slices.Contains(dependsOn, forkReference) {
			dependsOn = append(dependsOn, forkReference)
		}
		slices.Sort(dependsOn)
		dependency["dependsOn"] = stringsToAny(dependsOn)
	}
	if !rootFound {
		return nil, errors.New("root component dependency entry is absent")
	}
	dependencies = append(dependencies, map[string]any{
		"ref":       forkReference,
		"dependsOn": stringsToAny(dependencyReferences),
	})
	slices.SortFunc(dependencies, func(left, right map[string]any) int {
		return strings.Compare(stringValue(left["ref"]), stringValue(right["ref"]))
	})
	bom["dependencies"] = mapsToAny(dependencies)

	output, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode augmented CycloneDX JSON: %w", err)
	}
	return append(output, '\n'), nil
}

func forkSourceDigest(sourceRoot string) (string, int, error) {
	forkRoot, err := os.OpenRoot(filepath.Join(sourceRoot, "internal", "masque"))
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = forkRoot.Close() }()
	forkDirectory, err := forkRoot.Open(".")
	if err != nil {
		return "", 0, err
	}
	entries, readDirectoryErr := forkDirectory.ReadDir(-1)
	closeDirectoryErr := forkDirectory.Close()
	if readDirectoryErr != nil || closeDirectoryErr != nil {
		return "", 0, errors.Join(readDirectoryErr, closeDirectoryErr)
	}
	slices.SortFunc(entries, func(left, right os.DirEntry) int {
		return strings.Compare(left.Name(), right.Name())
	})
	hasher := sha256.New()
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			// testdata is the one directory that cannot hide shipped source
			// from this digest: the Go toolchain excludes testdata from every
			// build, and Go requires a fuzz seed corpus to live at
			// testdata/fuzz/<FuzzTarget>/, so there is nowhere else to put it.
			// Hashing it would also make the release SBOM non-reproducible,
			// because the fuzz targets this gate runs append new corpus entries
			// whenever they find one. Every other directory still fails closed:
			// this digest is flat, so source inside one would escape unrecorded.
			if entry.Name() == "testdata" {
				continue
			}
			return "", 0, fmt.Errorf("unexpected directory in MASQUE fork: %s", entry.Name())
		}
		// AppleDouble sidecars (._file). filepath.Ext("._conn.go") is ".go",
		// so the whitelist below would hash Finder metadata as fork source
		// and make the release SBOM digest Darwin-only. Skip, like testdata.
		if strings.HasPrefix(entry.Name(), "._") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return "", 0, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", 0, fmt.Errorf("MASQUE fork input is not a regular file: %s", entry.Name())
		}
		if filepath.Ext(entry.Name()) != ".go" &&
			entry.Name() != "LICENSE" &&
			entry.Name() != "UPSTREAM.md" &&
			entry.Name() != "UPSTREAM_README.md" {
			continue
		}
		file, err := forkRoot.Open(entry.Name())
		if err != nil {
			return "", 0, err
		}
		fileHasher := sha256.New()
		_, copyErr := io.Copy(fileHasher, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return "", 0, errors.Join(copyErr, closeErr)
		}
		fmt.Fprintf(
			hasher,
			"%s  internal/masque/%s\n",
			hex.EncodeToString(fileHasher.Sum(nil)),
			entry.Name(),
		)
		count++
	}
	if count == 0 {
		return "", 0, errors.New("MASQUE fork source set is empty")
	}
	return hex.EncodeToString(hasher.Sum(nil)), count, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("CycloneDX JSON has trailing content")
		}
		return fmt.Errorf("decode trailing CycloneDX content: %w", err)
	}
	return nil
}

func objectArray(object map[string]any, key string) ([]map[string]any, error) {
	values, ok := object[key].([]any)
	if !ok {
		return nil, fmt.Errorf("CycloneDX field %q is not an array", key)
	}
	result := make([]map[string]any, 0, len(values))
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("CycloneDX field %q contains a non-object", key)
		}
		result = append(result, item)
	}
	return result, nil
}

func stringArray(object map[string]any, key string) ([]string, error) {
	value, found := object[key]
	if !found {
		return nil, nil
	}
	values, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("CycloneDX field %q is not an array", key)
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("CycloneDX field %q contains a non-string", key)
		}
		result = append(result, text)
	}
	return result, nil
}

func rootComponentReference(bom map[string]any) (string, error) {
	metadata, ok := bom["metadata"].(map[string]any)
	if !ok {
		return "", errors.New("CycloneDX metadata is absent")
	}
	component, ok := metadata["component"].(map[string]any)
	if !ok {
		return "", errors.New("CycloneDX root component is absent")
	}
	reference := stringValue(component["bom-ref"])
	if reference == "" {
		return "", errors.New("CycloneDX root component reference is absent")
	}
	return reference, nil
}

func componentReference(components []map[string]any, name string) (string, bool) {
	for _, component := range components {
		if component["name"] == name {
			return stringValue(component["bom-ref"]), true
		}
	}
	return "", false
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func mapsToAny(values []map[string]any) []any {
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result
}

func stringsToAny(values []string) []any {
	result := make([]any, len(values))
	for index := range values {
		result[index] = values[index]
	}
	return result
}
