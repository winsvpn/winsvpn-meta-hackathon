// Decompression bounds for producer archives.
//
// Each test drives the SAME parser production uses, through a tiny proportional
// limit, and asserts the specific bound it claims to test.
//
// Two failures are avoided at once. Asserting the arithmetic of a constant
// proves nothing about whether the parser consults it, so real input is fed
// through the real reader. And expanding eight gigabytes on every suite run to
// prove a limiter works produces a half-minute test that people begin skipping
// — at which point the bound is untested again, quietly.
package producersnapshot

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tinyArchiveLimits are proportional to the production bounds, three orders of
// magnitude smaller. Identical code path, millisecond runtime.
func tinyArchiveLimits() archiveLimits {
	return archiveLimits{
		compressedBytes: 64 << 10,
		totalBytes:      10 << 10,
		memberBytes:     4 << 10,
		members:         8,
	}
}

// gzipTar writes members through archive/tar, which is what a well-formed
// producer emits.
func gzipTar(t *testing.T, path string, build func(*tar.Writer)) {
	t.Helper()
	var buffer bytes.Buffer
	compressor, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(compressor)
	build(writer)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func tarMember(t *testing.T, writer *tar.Writer, name string, size int64) {
	t.Helper()
	if err := writer.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: name, Mode: 0o600,
		Size: size, Format: tar.FormatPAX,
	}); err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 4096)
	for remaining := size; remaining > 0; {
		chunk := int64(len(block))
		if remaining < chunk {
			chunk = remaining
		}
		if _, err := writer.Write(block[:chunk]); err != nil {
			t.Fatal(err)
		}
		remaining -= chunk
	}
}

func readTiny(t *testing.T, path string) error {
	t.Helper()
	_, err := verifyPendingArchiveWithLimits(
		path, "evidence", map[string]string{}, map[string]struct{}{},
		tinyArchiveLimits(),
	)
	return err
}

// TestArchiveAggregateExpansionLimit proves the aggregate bound fires, and
// fires as the aggregate bound rather than as a generic parse failure.
func TestArchiveAggregateExpansionLimit(t *testing.T) {
	limits := tinyArchiveLimits()
	path := filepath.Join(t.TempDir(), "bomb.tar.gz")
	// Four members of 3 KiB declare 12 KiB, past the 10 KiB aggregate bound,
	// while each stays under the 4 KiB member bound and the count stays under
	// the member limit — so only the aggregate bound can reject this.
	gzipTar(t, path, func(writer *tar.Writer) {
		for index := 0; index < 4; index++ {
			tarMember(t, writer,
				fmt.Sprintf("evidence/m%d.bin", index), 3<<10)
		}
	})
	err := readTiny(t, path)
	if err == nil {
		t.Fatal("an archive past the aggregate expansion bound was accepted")
	}
	if !errors.Is(err, errArchiveExpansionLimit) {
		t.Fatalf(
			"the aggregate bound reported %v; it must report the expansion "+
				"limit specifically, not a generic malformed-archive error "+
				"that is indistinguishable from corruption", err,
		)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("%d", limits.totalBytes)) {
		t.Fatalf("the refusal does not name the limit it enforced: %v", err)
	}
}

// TestArchiveAggregateLimitWhenTheHeaderUnderstates covers the same bound
// reached from a different place in the parse: a header that declares one byte
// and then streams past the budget. The declared-size check cannot see this, so
// exhaustion surfaces inside a member copy — and must still be reported as the
// aggregate limit.
func TestArchiveAggregateLimitWhenTheHeaderUnderstates(t *testing.T) {
	limits := tinyArchiveLimits()
	path := filepath.Join(t.TempDir(), "understated.tar.gz")
	var buffer bytes.Buffer
	compressor, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	// Written by hand: archive/tar refuses to overrun a declared size, which is
	// exactly what a hostile producer would do.
	header := make([]byte, 512)
	copy(header, "evidence/liar.bin")
	copy(header[100:], "0000600\x00")
	copy(header[124:], "00000000001\x00")
	header[156] = '0'
	copy(header[257:], "ustar\x0000")
	for index := 148; index < 156; index++ {
		header[index] = ' '
	}
	checksum := 0
	for _, b := range header {
		checksum += int(b)
	}
	copy(header[148:], fmt.Appendf(nil, "%06o\x00 ", checksum))
	if _, err := compressor.Write(header); err != nil {
		t.Fatal(err)
	}
	if _, err := compressor.Write(
		make([]byte, limits.totalBytes+(4<<10)),
	); err != nil {
		t.Fatal(err)
	}
	if err := compressor.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	err = readTiny(t, path)
	if err == nil {
		t.Fatal("an understated bomb was fully expanded and accepted")
	}
	if !errors.Is(err, errArchiveExpansionLimit) {
		t.Fatalf(
			"exhaustion inside a member copy reported %v; every place the "+
				"budget can run out must report the aggregate limit", err,
		)
	}
}

// TestArchivePerMemberSizeLimit proves the per-member bound, and that it is the
// one firing: the archive holds a single member, so no aggregate or count bound
// can be responsible.
func TestArchivePerMemberSizeLimit(t *testing.T) {
	limits := tinyArchiveLimits()
	path := filepath.Join(t.TempDir(), "big-member.tar.gz")
	gzipTar(t, path, func(writer *tar.Writer) {
		// One byte past the member bound, and under the aggregate bound, so
		// only the member bound can reject it.
		tarMember(t, writer, "evidence/one.bin", limits.memberBytes+1)
	})
	err := readTiny(t, path)
	if err == nil {
		t.Fatal("a member past the per-member bound was accepted")
	}
	if !strings.Contains(err.Error(), "member limit") {
		t.Fatalf("the per-member bound was not what rejected this: %v", err)
	}
	if errors.Is(err, errArchiveExpansionLimit) {
		t.Fatalf("the aggregate bound fired instead of the member bound: %v", err)
	}

	// Exactly at the bound is accepted, so the boundary is a boundary.
	exact := filepath.Join(t.TempDir(), "exact-member.tar.gz")
	gzipTar(t, exact, func(writer *tar.Writer) {
		tarMember(t, writer, "evidence/one.bin", limits.memberBytes)
	})
	if err := readTiny(t, exact); err != nil &&
		strings.Contains(err.Error(), "member limit") {
		t.Fatalf("a member exactly at the bound was refused: %v", err)
	}
}

// TestArchiveCompressedSizeLimit proves the on-disk bound, which is consulted
// before a single byte is decompressed.
func TestArchiveCompressedSizeLimit(t *testing.T) {
	limits := tinyArchiveLimits()
	path := filepath.Join(t.TempDir(), "oversized.tar.gz")
	if err := os.WriteFile(
		path, make([]byte, limits.compressedBytes+1), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	err := readTiny(t, path)
	if err == nil {
		t.Fatal("an oversized archive file was read")
	}
	if !strings.Contains(err.Error(), "compressed limit") {
		t.Fatalf("the compressed-size bound was not what rejected this: %v", err)
	}
}

// TestArchiveMemberCountLimit proves the count bound with members small enough
// that neither size bound can be responsible.
func TestArchiveMemberCountLimit(t *testing.T) {
	limits := tinyArchiveLimits()
	path := filepath.Join(t.TempDir(), "many.tar.gz")
	gzipTar(t, path, func(writer *tar.Writer) {
		for index := 0; index <= limits.members; index++ {
			tarMember(t, writer, fmt.Sprintf("evidence/m%d", index), 0)
		}
	})
	err := readTiny(t, path)
	if err == nil {
		t.Fatal("an archive past the member-count bound was accepted")
	}
	if !strings.Contains(err.Error(), "member limit") ||
		!strings.Contains(err.Error(), "members") {
		t.Fatalf("the member-count bound was not what rejected this: %v", err)
	}
	if errors.Is(err, errArchiveExpansionLimit) {
		t.Fatalf("the aggregate bound fired instead of the count bound: %v", err)
	}

	// Exactly at the bound is accepted, so the boundary is a boundary and not
	// an off-by-one. This replaces an earlier test that built two hundred
	// thousand members to assert the same thing in two and a half seconds.
	exact := filepath.Join(t.TempDir(), "exact-count.tar.gz")
	gzipTar(t, exact, func(writer *tar.Writer) {
		if err := writer.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir, Name: "evidence/", Mode: 0o700,
			Format: tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		// The directory entry counts towards the total.
		for index := 0; index < limits.members-1; index++ {
			tarMember(t, writer, fmt.Sprintf("evidence/m%d", index), 0)
		}
	})
	if err := readTiny(t, exact); err != nil &&
		strings.Contains(err.Error(), "member limit") {
		t.Fatalf("an archive exactly at the member bound was refused: %v", err)
	}
}

// TestProductionArchiveLimitsAreTheRealConstants pins the injected limits to
// the values production actually uses, so the tiny limits cannot drift into
// testing a parser nobody runs.
func TestProductionArchiveLimitsAreTheRealConstants(t *testing.T) {
	limits := productionArchiveLimits()
	if limits.compressedBytes != maximumCompressedArchive ||
		limits.totalBytes != maximumArchiveTotalBytes ||
		limits.memberBytes != maximumArchiveMemberSize ||
		limits.members != maximumArchiveMembers {
		t.Fatalf("production limits diverged from the constants: %+v", limits)
	}
}
