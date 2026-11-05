package duplex

import (
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// referenceHeader is the normative C++ implementation of this wire format. It
// is READ, never modified: windows/ belongs to another lane.
const referenceHeader = "windows/runner/winn_frame.h"

// TestConformsToTheCppReferenceEncoder compiles the normative header and
// compares its bytes against this package's, vector by vector.
//
// The coordinator's arbitration was explicit: "match its bytes exactly, and
// treat any disagreement between your Go encoder and that header as your bug".
// A comment claiming they agree would decay the first time either side is
// touched, so the claim is executed instead. It skips rather than fails when
// there is no C++ compiler or no checkout of the header, because absence of the
// other lane's file is not evidence that this encoder is wrong.
func TestConformsToTheCppReferenceEncoder(t *testing.T) {
	root := repositoryRoot(t)
	header := filepath.Join(root, referenceHeader)
	if _, err := os.Stat(header); err != nil {
		t.Skipf("normative header not present at %s: %v", header, err)
	}
	compiler := ""
	for _, candidate := range []string{"clang++", "g++", "c++"} {
		if path, err := exec.LookPath(candidate); err == nil {
			compiler = path
			break
		}
	}
	if compiler == "" {
		t.Skip("no C++ compiler on PATH; cross-language conformance unchecked")
	}

	vectors := []struct {
		name    string
		opcode  Opcode
		cppName string
		payload string
	}{
		{"inbound", OpInbound, "Opcode::kInbound", "AB"},
		{"close", OpClose, "Opcode::kClose", ""},
		{"close-ack", OpCloseAck, "Opcode::kCloseAck", ""},
		{"error", OpError, "Opcode::kError", "x"},
		{"create", OpCreate, "Opcode::kCreate", "{}"},
		{"status-response", OpStatusResponse, "Opcode::kStatusResponse", "{}"},
		{"outbound", OpOutbound, "Opcode::kOutbound", "packet-bytes"},
		{"status-request", OpStatusRequest, "Opcode::kStatusRequest", ""},
		{"create-ack", OpCreateAck, "Opcode::kCreateAck", `{"up":true}`},
	}

	var program strings.Builder
	program.WriteString(`#include "winn_frame.h"
#include <cstdio>
#include <string>
#include <vector>
using namespace winsvpn::winn;
static void dump(Opcode op, const std::string& payload) {
  std::vector<uint8_t> out;
  if (!EncodeFrame(op, payload, &out)) { printf("ENCODE-REFUSED\n"); return; }
  for (uint8_t b : out) printf("%02x", b);
  printf("\n");
}
int main() {
  printf("%u %u %zu %u\n", kFrameMagic, (unsigned)kFrameVersion,
         kFrameHeaderBytes, kMaxFramePayloadBytes);
`)
	for _, vector := range vectors {
		program.WriteString("  dump(" + vector.cppName + ", std::string(" +
			strconv.Quote(vector.payload) + ", " +
			strconv.Itoa(len(vector.payload)) + "));\n")
	}
	program.WriteString("  return 0;\n}\n")

	workspace := t.TempDir()
	source := filepath.Join(workspace, "conformance.cc")
	if err := os.WriteFile(source, []byte(program.String()), 0o600); err != nil {
		t.Fatalf("write conformance program: %v", err)
	}
	binary := filepath.Join(workspace, "conformance")
	compile := exec.Command(compiler, "-std=c++17",
		"-I", filepath.Join(root, "windows", "runner"), "-o", binary, source)
	if combined, err := compile.CombinedOutput(); err != nil {
		t.Skipf("could not compile against the normative header: %v\n%s",
			err, combined)
	}
	output, err := exec.Command(binary).Output()
	if err != nil {
		t.Fatalf("run conformance program: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != len(vectors)+1 {
		t.Fatalf("expected %d lines from the reference, got %d:\n%s",
			len(vectors)+1, len(lines), output)
	}

	constants := strings.Fields(lines[0])
	if len(constants) != 4 {
		t.Fatalf("constants line = %q", lines[0])
	}
	expectedConstants := []string{
		strconv.FormatUint(uint64(Magic), 10),
		strconv.FormatUint(uint64(Version), 10),
		strconv.Itoa(HeaderSize),
		strconv.Itoa(MaxPayload),
	}
	names := []string{"magic", "version", "header size", "max payload"}
	for index, want := range expectedConstants {
		if constants[index] != want {
			t.Errorf("%s: reference has %s, this package has %s",
				names[index], constants[index], want)
		}
	}

	for index, vector := range vectors {
		reference := lines[index+1]
		mine, err := encodeToHex(vector.opcode, []byte(vector.payload))
		if err != nil {
			t.Fatalf("%s: encode: %v", vector.name, err)
		}
		if mine != reference {
			t.Errorf("%s frame disagrees with the normative header:\n"+
				"  reference (winn_frame.h): %s\n"+
				"  this package:             %s",
				vector.name, reference, mine)
		}
	}
}

func encodeToHex(opcode Opcode, payload []byte) (string, error) {
	var sink hexSink
	if err := NewWriter(&sink).Write(opcode, payload); err != nil {
		return "", err
	}
	return hex.EncodeToString(sink.bytes), nil
}

type hexSink struct{ bytes []byte }

func (s *hexSink) Write(chunk []byte) (int, error) {
	s.bytes = append(s.bytes, chunk...)
	return len(chunk), nil
}

// repositoryRoot walks up from the module to the repository that contains
// windows/runner. The module lives one level down, but a caller may have the
// module checked out on its own, which the Stat above then reports as a skip.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	// datapath/duplex -> datapath -> module -> repository
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	return root
}
