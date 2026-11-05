package phase1anchor

import (
	"strings"
	"testing"
)

func testSlotConfig(oneHost, twoHost string) SlotConfig {
	digest := strings.Repeat("ab", 32)
	return SlotConfig{
		Schema:           SlotConfigSchema,
		KnownHostsDigest: digest,
		ProviderOneID:    "provider-one",
		ProviderOneHost:  oneHost,
		ProviderOneKeyID: digest,
		ProviderOnePrior: ZeroDigest,
		ProviderTwoID:    "provider-two",
		ProviderTwoHost:  twoHost,
		ProviderTwoKeyID: strings.Repeat("cd", 32),
		ProviderTwoPrior: ZeroDigest,
	}
}

func verifierWant(config SlotConfig) SlotConfigExpectation {
	return SlotConfigExpectation{
		ProviderOneID:    config.ProviderOneID,
		ProviderTwoID:    config.ProviderTwoID,
		ProviderOneKeyID: config.ProviderOneKeyID,
		ProviderTwoKeyID: config.ProviderTwoKeyID,
		PreviousOne:      config.ProviderOnePrior,
		PreviousTwo:      config.ProviderTwoPrior,
		KnownHostsDigest: config.KnownHostsDigest,
	}
}

func TestSlotConfigVerifyAcceptsIndependentLiteralIPs(t *testing.T) {
	config := testSlotConfig("203.0.113.10", "203.0.113.20")
	if err := config.Verify(verifierWant(config)); err != nil {
		t.Fatal(err)
	}
	config = testSlotConfig("2001:db8::1", "2001:db8::2")
	if err := config.Verify(verifierWant(config)); err != nil {
		t.Fatal(err)
	}
}

func TestSlotConfigVerifyRejectsIdenticalHostStrings(t *testing.T) {
	config := testSlotConfig("203.0.113.10", "203.0.113.10")
	err := config.Verify(verifierWant(config))
	if err == nil || !strings.Contains(err.Error(), "same host") {
		t.Fatalf("identical hosts error=%v", err)
	}
}

func TestSlotConfigVerifyRejectsIPv4MappedAlias(t *testing.T) {
	// The pin CLI already refuses this pair. Verify used to compare strings
	// and accept it, so an auditor reading sealed evidence was weaker than
	// the producer.
	config := testSlotConfig("127.0.0.1", "::ffff:127.0.0.1")
	err := config.Verify(verifierWant(config))
	if err == nil || !strings.Contains(err.Error(), "same host") {
		t.Fatalf("IPv4-mapped alias error=%v", err)
	}
	config = testSlotConfig("127.0.0.1", "::FFFF:127.0.0.1")
	err = config.Verify(verifierWant(config))
	if err == nil || !strings.Contains(err.Error(), "same host") {
		t.Fatalf("uppercase IPv4-mapped alias error=%v", err)
	}
}

func TestSlotConfigVerifyRejectsIPv6CompressedAndExpandedForms(t *testing.T) {
	config := testSlotConfig("2001:db8::1", "2001:db8:0:0:0:0:0:1")
	err := config.Verify(verifierWant(config))
	if err == nil || !strings.Contains(err.Error(), "same host") {
		t.Fatalf("IPv6 compressed/expanded alias error=%v", err)
	}
}

func TestSlotConfigVerifyRejectsMissingAndNonAddressHosts(t *testing.T) {
	config := testSlotConfig("203.0.113.10", "")
	err := config.Verify(verifierWant(config))
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("empty second host error=%v", err)
	}
	config = testSlotConfig("provider-one.example", "provider-two.example")
	err = config.Verify(verifierWant(config))
	if err == nil || !strings.Contains(err.Error(), "not an IP address") {
		t.Fatalf("hostname pair error=%v", err)
	}
}

func TestSlotConfigVerifyWantHostIsExactString(t *testing.T) {
	config := testSlotConfig("203.0.113.10", "203.0.113.20")
	want := verifierWant(config)
	want.ProviderOneHost = "203.0.113.10"
	want.ProviderTwoHost = "203.0.113.20"
	if err := config.Verify(want); err != nil {
		t.Fatal(err)
	}
	want.ProviderTwoHost = "203.0.113.21"
	err := config.Verify(want)
	if err == nil || !strings.Contains(err.Error(), "this run uses") {
		t.Fatalf("want-host mismatch error=%v", err)
	}
}

func TestProviderHostsAreDistinct(t *testing.T) {
	if !ProviderHostsAreDistinct("203.0.113.10", "203.0.113.20") {
		t.Fatal("two IPv4 addresses treated as one machine")
	}
	if ProviderHostsAreDistinct("127.0.0.1", "::ffff:127.0.0.1") {
		t.Fatal("IPv4-mapped address treated as a second provider")
	}
	if ProviderHostsAreDistinct("127.0.0.1", "127.0.0.1") {
		t.Fatal("identical IPv4 strings treated as distinct")
	}
	if ProviderHostsAreDistinct("", "127.0.0.1") {
		t.Fatal("empty host accepted as distinct")
	}
	if ProviderHostsAreDistinct("not-an-ip", "127.0.0.1") {
		t.Fatal("unparseable host accepted as distinct")
	}
}

func TestRequireCanonicalSlotConfigRejectsWhitespace(t *testing.T) {
	config := testSlotConfig("203.0.113.10", "203.0.113.20")
	sealed, err := config.SealedBytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := RequireCanonicalSlotConfig(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got != config {
		t.Fatalf("canonical round-trip changed the record: %#v", got)
	}
	padded := append([]byte(" "), sealed...)
	if _, err := RequireCanonicalSlotConfig(padded); err == nil {
		t.Fatal("leading whitespace was accepted as canonical")
	}
	if _, err := RequireCanonicalSlotConfig([]byte("{}")); err == nil {
		t.Fatal("empty object was accepted as a canonical slot config")
	}
}
