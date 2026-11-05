package costledger

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestProjectSeparatesProvidersAndCurrencies(t *testing.T) {
	observed := time.Date(2026, 7, 24, 1, 0, 0, 0, time.UTC)
	snapshot := Snapshot{
		Format:     FormatV1,
		ObservedAt: observed,
		Accounts: []Account{
			{
				Provider:              "upcloud",
				Currency:              "EUR",
				AvailableCreditMicros: 233_630_000,
				Source:                "authenticated console",
			},
			{
				Provider:              "vultr",
				Currency:              "USD",
				AvailableCreditMicros: 255_000_000,
				Source:                "authenticated console",
			},
		},
		Resources: []Resource{
			{
				Provider: "upcloud", ResourceID: "exit-chi",
				Role: "exit", Phase: "phase1", Region: "us-chi1",
				Currency: "EUR", RateMicros: 52_000_000,
				BillingPeriodSeconds: 30 * 24 * 60 * 60, Quantity: 1,
			},
			{
				Provider: "vultr", ResourceID: "control-atl",
				Role: "controller", Phase: "phase1", Region: "atl",
				Currency: "USD", RateMicros: 5_000_000,
				BillingPeriodSeconds: 30 * 24 * 60 * 60, Quantity: 1,
			},
		},
	}
	report, err := Project(snapshot, observed.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Scopes) != 2 {
		t.Fatalf("got %d scopes", len(report.Scopes))
	}
	if report.Scopes[0].Provider != "upcloud" ||
		report.Scopes[0].Cost30DaysMicros != 52_000_000 {
		t.Fatalf("unexpected UpCloud projection: %+v", report.Scopes[0])
	}
	if report.Scopes[1].Provider != "vultr" ||
		report.Scopes[1].Cost30DaysMicros != 5_000_000 {
		t.Fatalf("unexpected Vultr projection: %+v", report.Scopes[1])
	}
}

func TestProjectionRoundsUp(t *testing.T) {
	resource := Resource{
		Provider: "vultr", ResourceID: "one",
		Role: "entry", Phase: "phase1", Region: "ewr",
		Currency: "USD", RateMicros: 1,
		BillingPeriodSeconds: 3600, Quantity: 1,
	}
	got, err := projectResources([]Resource{resource}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("projection = %d, want conservative ceil 1", got)
	}
}

func TestMulDivHandlesWideProductsWithoutRecursionOrWrap(t *testing.T) {
	if got := mulDivCeil(
		math.MaxUint64,
		math.MaxUint64,
		math.MaxUint64,
	); got != math.MaxUint64 {
		t.Fatalf("wide ceil = %d", got)
	}
	if got := mulDivFloor(
		math.MaxUint64,
		math.MaxUint64,
		math.MaxUint64,
	); got != math.MaxUint64 {
		t.Fatalf("wide floor = %d", got)
	}
	if got := mulDivCeil(math.MaxUint64, 2, math.MaxUint64); got != 2 {
		t.Fatalf("exact wide ceil = %d", got)
	}
}

func TestDecodeRejectsUnknownAndMissingScope(t *testing.T) {
	_, err := Decode(strings.NewReader(`{
	  "format":"winn-cloud-cost/v1",
	  "observed_at":"2026-07-24T01:00:00Z",
	  "accounts":[{"provider":"vultr","currency":"USD",
	    "available_credit_micros":1,"current_charges_micros":0,
	    "source":"console","unknown":true}],
	  "resources":[]
	}`))
	if err == nil {
		t.Fatal("unknown field was accepted")
	}

	snapshot := validSnapshot()
	snapshot.Resources = []Resource{{
		Provider: "upcloud", ResourceID: "exit",
		Role: "exit", Phase: "phase1", Region: "chi",
		Currency: "EUR", RateMicros: 1,
		BillingPeriodSeconds: 3600, Quantity: 1,
	}}
	if err := snapshot.Validate(); err == nil {
		t.Fatal("resource without account scope was accepted")
	}
}

func TestUsageCountersRequireWindow(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Connections = 1
	if err := snapshot.Validate(); err == nil {
		t.Fatal("usage without window was accepted")
	}
	snapshot.WindowSeconds = 60
	if err := snapshot.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowSecondsRejectsValuesThatWouldOverflowDuration(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Connections = 1
	// 18,446,744,074 seconds, converted to nanoseconds and reduced modulo
	// 2^64, wraps around to a POSITIVE Duration of 290.448384ms instead of
	// the enormous (or negative) value the raw arithmetic implies. Because
	// it lands positive, the `horizon < 0` guard in projectResources never
	// fires: before the upper bound below was added, this value silently
	// produced a bogus near-zero-second cost window instead of an error.
	snapshot.WindowSeconds = 18_446_744_074
	if err := snapshot.Validate(); err == nil {
		t.Fatal("excessive measurement window was accepted")
	}

	snapshot.WindowSeconds = uint64(maxBillingPeriod / time.Second)
	if err := snapshot.Validate(); err != nil {
		t.Fatalf("boundary measurement window was rejected: %v", err)
	}

	snapshot.WindowSeconds++
	if err := snapshot.Validate(); err == nil {
		t.Fatal("measurement window one second over the limit was accepted")
	}
}

func validSnapshot() Snapshot {
	return Snapshot{
		Format:     FormatV1,
		ObservedAt: time.Date(2026, 7, 24, 1, 0, 0, 0, time.UTC),
		Accounts: []Account{{
			Provider: "vultr", Currency: "USD",
			AvailableCreditMicros: 1, Source: "console",
		}},
		Resources: []Resource{},
	}
}

func TestProjectErrorsWhenSingleResourceCostOverflows(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.Resources = []Resource{{
		Provider: "vultr", ResourceID: "one",
		Role: "entry", Phase: "phase1", Region: "ewr",
		Currency: "USD", RateMicros: 1_000_000_000_000_000,
		BillingPeriodSeconds: 1, Quantity: 1024,
	}}
	report, err := Project(snapshot, snapshot.ObservedAt.Add(time.Minute))
	if err == nil {
		t.Fatalf("overflowing projection succeeded: %+v", report)
	}
	if !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("error = %v, want overflows", err)
	}
}

func TestProjectErrorsWhenTransferredTBUnitCostOverflows(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.WindowSeconds = 60
	snapshot.EgressBytes = 1
	// Rate is high enough that windowCost * 1e12 overflows uint64, but low
	// enough that the 24h/30d horizon products still fit. 1e15 fails closed
	// earlier in Cost30DaysMicros and never reaches the TB unit-cost path.
	snapshot.Resources = []Resource{{
		Provider: "vultr", ResourceID: "one",
		Role: "entry", Phase: "phase1", Region: "ewr",
		Currency: "USD", RateMicros: 20_000_000,
		BillingPeriodSeconds: 60, Quantity: 1,
	}}
	report, err := Project(snapshot, snapshot.ObservedAt.Add(time.Minute))
	if err == nil {
		t.Fatalf("unit-cost overflow succeeded: %+v", report)
	}
	if !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("error = %v, want overflows", err)
	}
}

func TestProjectErrorsWhenConnectionsUnitCostOverflows(t *testing.T) {
	snapshot := validSnapshot()
	snapshot.WindowSeconds = 30 * 24 * 60 * 60
	snapshot.Connections = 1
	snapshot.Resources = []Resource{{
		Provider: "vultr", ResourceID: "one",
		Role: "entry", Phase: "phase1", Region: "ewr",
		Currency: "USD", RateMicros: 1_000_000_000_000_000,
		BillingPeriodSeconds: 30 * 24 * 60 * 60, Quantity: 2,
	}}
	report, err := Project(snapshot, snapshot.ObservedAt.Add(time.Minute))
	if err == nil {
		t.Fatalf("unit-cost overflow succeeded: %+v", report)
	}
	if !strings.Contains(err.Error(), "overflows") {
		t.Fatalf("error = %v, want overflows", err)
	}
}

func TestDecodeAcceptsRFC3339ZeroOffset(t *testing.T) {
	for _, stamp := range []string{
		"2026-07-24T01:00:00Z",
		"2026-07-24T01:00:00+00:00",
		"2026-07-24T01:00:00-00:00",
	} {
		body := fmt.Sprintf(`{
		  "format":"winn-cloud-cost/v1",
		  "observed_at":%q,
		  "accounts":[{"provider":"vultr","currency":"USD",
		    "available_credit_micros":1,"current_charges_micros":0,
		    "source":"console"}],
		  "resources":[]
		}`, stamp)
		if _, err := Decode(strings.NewReader(body)); err != nil {
			t.Fatalf("observed_at %s: %v", stamp, err)
		}
	}
}

func TestDecodeRejectsNonZeroNumericOffset(t *testing.T) {
	body := `{
	  "format":"winn-cloud-cost/v1",
	  "observed_at":"2026-07-24T01:00:00+01:00",
	  "accounts":[{"provider":"vultr","currency":"USD",
	    "available_credit_micros":1,"current_charges_micros":0,
	    "source":"console"}],
	  "resources":[]
	}`
	if _, err := Decode(strings.NewReader(body)); err == nil {
		t.Fatal("+01:00 observed_at was accepted")
	}
}

func TestEncodeRoundTripViaDecodeBytes(t *testing.T) {
	snapshot := validSnapshot()
	data, err := Encode(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Fatalf("encode framing: len=%d", len(data))
	}
	got, err := DecodeBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Format != snapshot.Format || !got.ObservedAt.Equal(snapshot.ObservedAt) {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if _, err := DecodeBytes(nil); err == nil {
		t.Fatal("DecodeBytes(nil) succeeded")
	}
}

func TestProjectAcceptsGeneratedAtWithZeroOffset(t *testing.T) {
	snapshot := validSnapshot()
	generated := time.Date(2026, 7, 24, 1, 1, 0, 0, time.FixedZone("lab", 0))
	if _, err := Project(snapshot, generated); err != nil {
		t.Fatal(err)
	}
	nonzero := time.Date(2026, 7, 24, 1, 1, 0, 0, time.FixedZone("lab", 3600))
	if _, err := Project(snapshot, nonzero); err == nil {
		t.Fatal("generatedAt +01:00 was accepted")
	}
}
