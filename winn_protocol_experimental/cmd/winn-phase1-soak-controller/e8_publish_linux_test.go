//go:build linux && winn_incomplete_e8

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testEncodedE8Receipt(t *testing.T) (e8Receipt, []byte) {
	t.Helper()
	value, encoded, err := encodeE8Receipt(e8PositiveVector(t))
	if err != nil {
		t.Fatal(err)
	}
	return value, encoded
}

func TestPublishE8ReceiptFailureBoundaries(t *testing.T) {
	value, encoded := testEncodedE8Receipt(t)
	for name, inject := range map[string]func() func(){
		"write": func() func() {
			old := writeE8ReceiptOperation
			writeE8ReceiptOperation = func(io.Writer, []byte) error {
				return io.ErrShortWrite
			}
			return func() { writeE8ReceiptOperation = old }
		},
		"sync": func() func() {
			old := syncE8ReceiptOperation
			syncE8ReceiptOperation = func(*os.File) error {
				return errors.New("injected sync refusal")
			}
			return func() { syncE8ReceiptOperation = old }
		},
		"close": func() func() {
			old := closeE8ReceiptOperation
			closeE8ReceiptOperation = func(file *os.File) error {
				return errors.Join(file.Close(), errors.New("injected close refusal"))
			}
			return func() { closeE8ReceiptOperation = old }
		},
		"rename": func() func() {
			old := renameE8ReceiptOperation
			renameE8ReceiptOperation = func(*secureDirectory) error {
				return errors.New("injected rename refusal")
			}
			return func() { renameE8ReceiptOperation = old }
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := privateTestDirectory(t)
			directory, err := openAdmittedPrivateDirectory(root)
			if err != nil {
				t.Fatal(err)
			}
			defer directory.Close()
			restore := inject()
			defer restore()
			if err := publishE8Receipt(directory, encoded, value); err == nil {
				t.Fatal("injected E8 publication failure was accepted")
			}
			entries, err := os.ReadDir(root)
			if name == "rename" {
				if err != nil || len(entries) != 1 ||
					entries[0].Name() != "."+e8ReceiptFile+".pending" {
					t.Fatalf("E8 rename recovery artifact missing: %v %v", err, entries)
				}
			} else if err != nil || len(entries) != 0 {
				t.Fatalf("E8 pre-rename failure left artifacts: %v %v", err, entries)
			}
		})
	}

	t.Run("no-replace", func(t *testing.T) {
		root := privateTestDirectory(t)
		finalPath := filepath.Join(root, e8ReceiptFile)
		if err := os.WriteFile(finalPath, []byte("existing"), 0o400); err != nil {
			t.Fatal(err)
		}
		directory, err := openAdmittedPrivateDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		if err := publishE8Receipt(directory, encoded, value); err == nil {
			t.Fatal("E8 publication replaced an existing receipt")
		}
		data, err := os.ReadFile(finalPath)
		if err != nil || string(data) != "existing" {
			t.Fatal("existing E8 receipt changed")
		}
	})

	t.Run("directory-sync-indeterminate", func(t *testing.T) {
		root := privateTestDirectory(t)
		directory, err := openAdmittedPrivateDirectory(root)
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		old := syncE8DirectoryOperation
		syncE8DirectoryOperation = func(*secureDirectory) error {
			return errors.New("injected directory sync refusal")
		}
		defer func() { syncE8DirectoryOperation = old }()
		err = publishE8Receipt(directory, encoded, value)
		var publication *e8PublicationError
		if !errors.As(err, &publication) ||
			publication.Stage != "parent-directory-fsync" ||
			!publication.FinalReceiptMayExist || publication.DirectorySynced {
			t.Fatalf("E8 sync failure was not indeterminate: %v", err)
		}
		if _, err := os.Stat(filepath.Join(root, e8ReceiptFile)); err != nil {
			t.Fatalf("E8 renamed receipt missing: %v", err)
		}
	})
}

func TestE8ReceiptRejectsSelfConsistentButFalseOperationEvidence(t *testing.T) {
	value, _ := testEncodedE8Receipt(t)
	mutant := value
	mutant.Nodes[0].Terminal.OperationOutput = e8VectorHex("00")
	mutant = e8SealVector(t, mutant)
	if err := validateE8Receipt(mutant); err == nil {
		t.Fatal("E8 accepted recomputed frame digest over false operation evidence")
	}
}

func TestPublishE8ReceiptConcurrentNoReplaceRace(t *testing.T) {
	value, encoded := testEncodedE8Receipt(t)
	root := privateTestDirectory(t)
	first, err := openAdmittedPrivateDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openAdmittedPrivateDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	start := make(chan struct{})
	results := make(chan error, 2)
	var wait sync.WaitGroup
	for _, directory := range []*secureDirectory{first, second} {
		wait.Add(1)
		go func(directory *secureDirectory) {
			defer wait.Done()
			<-start
			results <- publishE8Receipt(directory, encoded, value)
		}(directory)
	}
	close(start)
	wait.Wait()
	close(results)
	successes := 0
	for result := range results {
		if result == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("publication race produced no durable winner")
	}
	data, err := os.ReadFile(filepath.Join(root, e8ReceiptFile))
	if err != nil || string(data) != string(encoded) {
		t.Fatalf("publication race changed final bytes: %v", err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 1 ||
		entries[0].Name() != e8ReceiptFile {
		t.Fatalf("publication race left an ambiguous census: %v %v", entries, err)
	}
}
