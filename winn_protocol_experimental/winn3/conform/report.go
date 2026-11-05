package conform

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// HostReport is what a NON-GO host emits about itself.
//
// ===========================================================================
// WHY THE HOSTS REPORT RATHER THAN ASSERT
// ===========================================================================
//
// Kotlin and Swift cannot import this package, so the obvious design is to
// hand each of them the vector file and let it assert. That was rejected:
// three independent assertion implementations means three chances to write a
// comparison that passes when it should not, and the one that would have
// caught defect 1 is the one nobody would have written carefully.
//
// So each host does the ONE thing only it can do — run its own real derivation
// code — and emits the answer. The comparison happens here, once, in the same
// function the Go hosts use, with the same failure message naming both values
// and the field consequence. A host harness that emits a wrong number cannot
// hide it by comparing it wrongly.
//
// It also means a host harness is trivial to write and hard to get wrong: it
// prints JSON. That matters, because the harness for a platform is written by
// whoever owns that platform, usually once.
type HostReport struct {
	// Host names the code path precisely enough to open the file.
	Host string `json:"host"`

	// Language is "kotlin", "swift", "c++" or "go". Reported so the summary
	// table can say which platforms were actually covered on this run rather
	// than which ones were intended to be.
	Language string `json:"language"`

	// The admission-tag inputs, hex. Empty is only legitimate when the field
	// is named in NotDerived. An empty string with no such entry is a FAILURE,
	// not a skip — a harness that forgot to fill the field looks identical in
	// JSON to a host that genuinely does not derive it, and only the latter is
	// fine. See NotDerived.
	GatewayIDHex    string `json:"gateway_id_hex"`
	AdmissionKeyHex string `json:"admission_key_hex"`
	TagSize         int    `json:"tag_size"`

	// The resolved sizing for the reference operator configuration.
	PathMTU        int      `json:"path_mtu"`
	CarrierClasses []string `json:"carrier_classes"`
	MessageSize    int      `json:"message_size"`
	InnerMTU       int      `json:"inner_mtu"`
	InnerIPv6      bool     `json:"inner_ipv6"`

	// TransportObservedBothWays is the host's report of whether its engine
	// publishes transport counters for BOTH directions — RxPackets (inbound
	// deliveries) and TxPackets (outbound sends).
	//
	// The promotion predicate gates on RxPackets alone, but a status document
	// that carries RxPackets and not TxPackets leaves a host unable to tell
	// "the tunnel proved the chain inbound and the data came back out" from
	// "inbound only, data never left" — and the latter is the silent half of a
	// carrier-class leak. A host that omits TxPackets without declaring it
	// not_derived is treated as a failure: the field exists, and absence is a
	// defect.
	TransportObservedBothWays bool `json:"transport_observed_both_ways"`

	// Floors is the host's answer for EVERY row of the matrix, not just the
	// reference row. A host that agrees at 1500 and disagrees at 1280 has the
	// same defect; it just has not met the path that shows it yet.
	Floors []FloorRow `json:"floors"`

	// Overheads is the host's answer for every class over both families.
	Overheads []OverheadRow `json:"overheads"`

	// NotDerived names, explicitly, every value above this host does not
	// compute — so that "0" is never read as "agrees with zero".
	//
	// An empty string in a field with no entry here is a FAILURE, not a skip.
	// That distinction is the reason this field exists: a harness that forgot
	// to fill something in and a host that genuinely does not derive it look
	// identical in JSON, and only one of them is fine.
	//
	// Declaring a field not_derived and then reporting a value for it is also
	// a FAILURE. The declaration is an escape for a host that does not compute
	// the field, not cover for a value. Scalar fields go through check();
	// floors and overheads apply the same rule to a non-empty slice.
	NotDerived []string `json:"not_derived"`
}

// notDerived reports whether the host declared this field out of scope.
func (r HostReport) notDerived(field string) bool {
	for _, f := range r.NotDerived {
		if f == field {
			return true
		}
	}
	return false
}

// ParseHostReport decodes a host harness's output.
//
// Unknown fields are refused. A harness that emits a misspelled key would
// otherwise report a value nobody compared, which is the same silent-success
// failure this whole suite exists to remove.
//
// Trailing JSON after the object is refused for the same reason: a decoder
// that stops after the first value would compare only the first object and
// silently ignore a second, which is a host the suite never looked at.
func ParseHostReport(raw []byte) (HostReport, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var r HostReport
	if err := dec.Decode(&r); err != nil {
		return HostReport{}, fmt.Errorf("decode host report: %w", err)
	}
	if strings.TrimSpace(r.Host) == "" {
		return HostReport{}, fmt.Errorf("host report names no host")
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return HostReport{}, fmt.Errorf("host report has trailing JSON after the object")
		}
		return HostReport{}, fmt.Errorf("host report has trailing JSON after the object: %w", err)
	}
	return r, nil
}

// VerifyReport compares one host's report against the reference vectors.
//
// Returns every disagreement, in a stable order, with both values rendered.
func VerifyReport(v Vectors, r HostReport) []Mismatch {
	var out []Mismatch
	add := func(field, want, got string) {
		if want != got {
			out = append(out, Mismatch{Field: field, A: want, B: got})
		}
	}
	check := func(field, want, got string) {
		if r.notDerived(field) {
			if got != "" && got != "0" && got != "false" {
				out = append(out, Mismatch{
					Field: field + " (declared not_derived)",
					A:     "<nothing, because the host declared it not derived>",
					B:     got,
				})
			}
			return
		}
		add(field, want, got)
	}

	check("gateway_id_hex", v.Admission.GatewayIDHex, r.GatewayIDHex)
	check("admission_key_hex", v.Admission.AdmissionKeyHex, r.AdmissionKeyHex)
	check("tag_size", fmt.Sprint(v.Admission.TagSize), fmt.Sprint(r.TagSize))

	// The reference row. A matrix that does not contain the operator's plan
	// used to compare against a zero FloorRow, so a host that also reported
	// zeros would agree. That is fail-open of the suite itself.
	ref, ok := referenceRow(v)
	if !ok {
		out = append(out, Mismatch{
			Field: "reference plan floor",
			A: fmt.Sprintf("a matrix row for plan %s at path_mtu %d",
				strings.Join(v.Operator.CarrierClasses, "+"), v.Operator.PathMTU),
			B: "<the matrix has no row for this operator>",
		})
	}
	check("path_mtu", fmt.Sprint(v.Operator.PathMTU), fmt.Sprint(r.PathMTU))
	check("carrier_classes", strings.Join(v.Operator.CarrierClasses, "+"),
		strings.Join(r.CarrierClasses, "+"))
	check("message_size", fmt.Sprint(ref.MessageSize), fmt.Sprint(r.MessageSize))
	check("inner_mtu", fmt.Sprint(ref.InnerMTU), fmt.Sprint(r.InnerMTU))
	check("inner_ipv6", fmt.Sprint(ref.InnerIPv6), fmt.Sprint(r.InnerIPv6))

	// Transport observed BOTH ways. The promotion predicate gates on RxPackets
	// (inbound), so the status document must also carry TxPackets (outbound) —
	// a host that reports RxPackets>0 but no TxPackets cannot distinguish "data
	// went in and came back" from "data went in and vanished". A host that omits
	// the field without declaring it not_derived is a field a host forgot, not
	// one a host chose; DisallowUnknownFields in ParseHostReport already refuses
	// a misspelled key, and this check closes the half where the key is correct
	// but the value is silently absent.
	//
	// It goes through check() for the same reason every other field does: the
	// "without declaring it not_derived" half of that contract is only real if
	// declaring it not_derived is possible. Routed here, all four cases behave
	// the way the field comment says they should — a host that reports true
	// agrees; a host that neither reports true nor declares the field fails, so
	// the gate keeps its teeth against a harness that simply forgot; a host that
	// declares it not_derived is excused, which is the escape the contract
	// promises a host whose engine genuinely publishes no such pair; and a host
	// that declares it not_derived and then reports true anyway is flagged, so
	// the declaration cannot be used as cover for a value.
	//
	// 2026-08-12: this was an unconditional `if !r.TransportObservedBothWays`,
	// which made this the only field in HostReport with no way to express "not
	// derived" and rejected every host including one deriving the reference
	// exactly. See D18_CONFORM_AND_DATAPATH_GATES_20260812_d18_conform_report_fix.md.
	check("transport_observed_both_ways", "true",
		fmt.Sprint(r.TransportObservedBothWays))

	out = append(out, compareFloors(v, r)...)
	out = append(out, compareOverheads(v, r)...)
	return out
}

func referenceRow(v Vectors) (FloorRow, bool) {
	key := strings.Join(v.Operator.CarrierClasses, "+")
	for _, row := range v.Floors {
		if strings.Join(row.Classes, "+") == key && row.PathMTU == v.Operator.PathMTU {
			return row, true
		}
	}
	return FloorRow{}, false
}

// compareFloors walks the whole matrix.
//
// A row the host did not report is a MISMATCH, not a skip. A harness that
// silently drops the rows it finds inconvenient is a harness that will drop
// exactly the row where its host is wrong — the clamped one, most likely,
// because that is the branch nobody copies.
//
// Declaring floors not_derived while also sending rows is the same failure
// check() already flags for scalars: the declaration is an escape, not cover.
func compareFloors(v Vectors, r HostReport) []Mismatch {
	if r.notDerived("floors") {
		if len(r.Floors) > 0 {
			return []Mismatch{{
				Field: "floors (declared not_derived)",
				A:     "<nothing, because the host declared it not derived>",
				B:     fmt.Sprintf("%d row(s)", len(r.Floors)),
			}}
		}
		return nil
	}
	got := map[string]FloorRow{}
	for _, row := range r.Floors {
		got[floorKey(row)] = row
	}
	var out []Mismatch
	for _, want := range v.Floors {
		k := floorKey(want)
		have, ok := got[k]
		if !ok {
			out = append(out, Mismatch{
				Field: "plan floor " + k,
				A:     fmt.Sprintf("message_size=%d inner_mtu=%d", want.MessageSize, want.InnerMTU),
				B:     "<the host reported no row for this plan and path MTU>",
			})
			continue
		}
		if have.MessageSize != want.MessageSize || have.InnerMTU != want.InnerMTU ||
			have.InnerIPv6 != want.InnerIPv6 {
			out = append(out, Mismatch{
				Field: "plan floor " + k,
				A: fmt.Sprintf("message_size=%d inner_mtu=%d inner_ipv6=%t",
					want.MessageSize, want.InnerMTU, want.InnerIPv6),
				B: fmt.Sprintf("message_size=%d inner_mtu=%d inner_ipv6=%t",
					have.MessageSize, have.InnerMTU, have.InnerIPv6),
			})
		}
		delete(got, k)
	}
	extra := make([]string, 0, len(got))
	for k := range got {
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, Mismatch{
			Field: "plan floor " + k,
			A:     "<not in the conformance matrix>",
			B:     "<the host reported a row the suite does not know about>",
		})
	}
	return out
}

func floorKey(r FloorRow) string {
	return fmt.Sprintf("[%s]@%d", strings.Join(r.Classes, ","), r.PathMTU)
}

func compareOverheads(v Vectors, r HostReport) []Mismatch {
	if r.notDerived("overheads") {
		if len(r.Overheads) > 0 {
			return []Mismatch{{
				Field: "overheads (declared not_derived)",
				A:     "<nothing, because the host declared it not derived>",
				B:     fmt.Sprintf("%d row(s)", len(r.Overheads)),
			}}
		}
		return nil
	}
	got := map[string]int{}
	for _, row := range r.Overheads {
		got[overheadKey(row)] = row.Overhead
	}
	var out []Mismatch
	for _, want := range v.Overheads {
		k := overheadKey(want)
		have, ok := got[k]
		if !ok {
			out = append(out, Mismatch{
				Field: "carrier overhead " + k,
				A:     fmt.Sprint(want.Overhead),
				B:     "<the host reported no overhead for this class and family>",
			})
			continue
		}
		if have != want.Overhead {
			out = append(out, Mismatch{
				Field: "carrier overhead " + k,
				A:     fmt.Sprint(want.Overhead),
				B:     fmt.Sprint(have),
			})
		}
		delete(got, k)
	}
	extra := make([]string, 0, len(got))
	for k := range got {
		extra = append(extra, k)
	}
	sort.Strings(extra)
	for _, k := range extra {
		out = append(out, Mismatch{
			Field: "carrier overhead " + k,
			A:     "<not in the conformance matrix>",
			B:     "<the host reported a row the suite does not know about>",
		})
	}
	return out
}

func overheadKey(r OverheadRow) string {
	family := "v6"
	if r.IPv4 {
		family = "v4"
	}
	return r.Class + "/" + family
}

// ExplainReport renders a host's failures the way Explain renders two Go
// hosts', including the consequence.
func ExplainReport(v Vectors, r HostReport, ms []Mismatch) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "\nwinn/3 CONFORMANCE FAILURE: %s (%s) disagrees with the reference in %d place(s)\n",
		r.Host, r.Language, len(ms))
	fmt.Fprintf(&sb, "  operator configuration: gateway_id=%q path_mtu=%d carrier_classes=%v\n",
		v.Operator.GatewayID, v.Operator.PathMTU, v.Operator.CarrierClasses)
	for _, m := range ms {
		fmt.Fprintf(&sb, "    %s\n", m.Field)
		fmt.Fprintf(&sb, "        reference = %s\n", m.A)
		fmt.Fprintf(&sb, "        %-9s = %s\n", "host", m.B)
		if hint := hintFor(v, m); hint != "" {
			fmt.Fprintf(&sb, "        %s\n", hint)
		}
	}
	sb.WriteString(consequence(ms))
	return sb.String()
}

// hintFor recognises the two mistakes this suite exists for and says so.
//
// A conformance failure that makes the reader work out WHICH mistake they made
// has moved the cost rather than removed it. When the observed value is exactly
// the base64-decoded gateway id, or exactly the hex-decoded admission secret,
// the suite says so in one line.
func hintFor(v Vectors, m Mismatch) string {
	switch {
	case strings.HasPrefix(m.Field, "gateway_id") && m.B == v.Admission.GatewayIDBase64Decoded:
		return "^ this is EXACTLY the base64-DECODED gateway id. This host decodes a field " +
			"every other host takes verbatim — defect 1, 2026-08-09. The decode belongs at the " +
			"signed-descriptor boundary, not at the host-to-engine interface."
	case strings.HasPrefix(m.Field, "admission_key") && m.B == v.Admission.AdmissionIfHexDecoded:
		return "^ this is EXACTLY the hex-DECODED admission secret. keygen writes hex TEXT and " +
			"every consumer keys with the file's bytes; the secret is opaque and is never decoded."
	case strings.HasPrefix(m.Field, "inner_mtu") || strings.HasPrefix(m.Field, "plan floor"):
		for _, row := range v.Floors {
			if strings.Contains(m.B, fmt.Sprint(row.DialledUDPv4InnerMTU)) &&
				row.DialledUDPv4InnerMTU != row.InnerMTU {
				return fmt.Sprintf(
					"^ this is EXACTLY InnerMTUForPath(%d, 28) — the DIALLED UDP-over-IPv4 "+
						"carrier, not the plan floor. That is defect 2: %d bytes too wide, and "+
						"it black-holes every full-size flow at the first migration while the "+
						"tunnel reads up at both ends.",
					row.PathMTU, row.Gap)
			}
		}
	}
	return ""
}

// DecodeHex is a small convenience for harness authors reading the vectors.
func DecodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }
