package main

import (
	"encoding/base64"
	"net/netip"
	"testing"
)

func TestResolveFreeMbpsEnvMapping(t *testing.T) {
	for _, tc := range []struct {
		flag int
		env  string
		want int
	}{
		{100, "", 100},
		{100, "50", 50},
		{100, "0", 0},
		{0, "", 0},
		{0, "100", 0},
		{7, "100000", 7},
		{7, "0", 7},
	} {
		got, err := resolveFreeMbps(tc.flag, tc.env)
		if err != nil || got != tc.want {
			t.Fatalf("resolveFreeMbps(%d, %q) = %d, %v; want %d, nil", tc.flag, tc.env, got, err, tc.want)
		}
	}
	for _, env := range []string{"abc", "-1", "100001", "1.5", "007", "+5", " 5", "5 "} {
		for _, flagValue := range []int{0, 7, 100} {
			if _, err := resolveFreeMbps(flagValue, env); err == nil {
				t.Fatalf("env %q was accepted with flag %d", env, flagValue)
			}
		}
	}
}

func TestPeerRegistryVersionOneWithoutTierIsAllPremium(t *testing.T) {
	_, encoded := registryKey(0xA1)
	// A document of today's shape: no tier anywhere. Under an armed cap the
	// binding answers with no budget.
	body := `{"version":1,"peers":[{"static_public":"` + encoded + `","inner_v4":"10.10.0.2","not_after":4102444800}]}`
	r, err := newPeerRegistryWithRate(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24"), 100)
	if err != nil {
		t.Fatalf("version 1 document refused: %v", err)
	}
	raw, _ := base64.StdEncoding.Strict().DecodeString(encoded)
	binding, ok := r.policyForPeer(raw)
	if !ok || binding.bandwidth != nil {
		t.Fatal("version 1 binding did not answer premium")
	}
}

func TestPeerRegistryVersionOneTierWordsArmTheCapOnlyForFree(t *testing.T) {
	freeKey, freeEncoded := registryKey(0xA5)
	premiumKey, premiumEncoded := registryKey(0xA6)
	body := `{"version":1,"peers":[` +
		`{"tier":"free","static_public":"` + freeEncoded + `","inner_v4":"10.10.0.2","not_after":4102444800},` +
		`{"tier":"premium","static_public":"` + premiumEncoded + `","inner_v4":"10.10.0.3","not_after":4102444800}]}`
	r, err := newPeerRegistryWithRate(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24"), 100)
	if err != nil {
		t.Fatalf("tiered version 1 document refused: %v", err)
	}
	if binding, ok := r.policyForPeer(freeKey); !ok || binding.bandwidth == nil {
		t.Fatal("tier free did not arm the cap")
	}
	if binding, ok := r.policyForPeer(premiumKey); !ok || binding.bandwidth != nil {
		t.Fatal("tier premium acquired a limiter")
	}
}

func TestPeerRegistryRefusesAnyOtherVersion(t *testing.T) {
	_, encoded := registryKey(0xA2)
	for _, version := range []string{"0", "2", "3"} {
		body := `{"version":` + version + `,"peers":[{"static_public":"` + encoded + `","inner_v4":"10.10.0.2","not_after":4102444800}]}`
		if _, err := newPeerRegistry(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24")); err == nil {
			t.Fatalf("accepted registry version %s", version)
		}
	}
}

func TestPeerRegistryRefusesANullTier(t *testing.T) {
	_, encoded := registryKey(0xA4)
	body := `{"version":1,"peers":[{"tier":null,"static_public":"` + encoded + `","inner_v4":"10.10.0.2","not_after":4102444800}]}`
	_, err := newPeerRegistry(writeRegistry(t, body), netip.MustParsePrefix("10.10.0.0/24"))
	if err == nil {
		t.Fatal("accepted a null tier")
	}
}

func TestValidateOperatorRefusesAnOutOfRangeFreeRate(t *testing.T) {
	if err := validateOperatorValues(serveOptions{freeMbps: -1}); err == nil {
		t.Fatal("negative free rate accepted")
	}
	if err := validateOperatorValues(serveOptions{freeMbps: 100001}); err == nil {
		t.Fatal("free rate above 100000 accepted")
	}
}
