package main

import (
	"strings"
	"testing"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

func TestValidateProbeFlagsRefusesCountThatWrapsICMPSeq(t *testing.T) {
	o := validICMP()
	o.count = icmpSeqMax + 1
	_, err := validateProbeFlags(o)
	if err == nil {
		t.Fatal("-count 65536 was accepted; uint16 seq would wrap")
	}
	msg := err.Error()
	for _, w := range []string{"-count", "65535", "uint16"} {
		if !strings.Contains(msg, w) {
			t.Errorf("refusal %q does not name %q", msg, w)
		}
	}
}

func TestValidateProbeFlagsAcceptsCountAtICMPSeqMax(t *testing.T) {
	o := validICMP()
	o.count = icmpSeqMax
	if _, err := validateProbeFlags(o); err != nil {
		t.Fatalf("-count %d (seq 1..65535) was refused: %v", icmpSeqMax, err)
	}
}

func TestValidateProbeFlagsRefusesCountThatWrapsDNSSrcPort(t *testing.T) {
	o := validDNS()
	span := int(^uint16(0)) - dnsUDPSrcPortBase + 1
	o.count = span + 1
	_, err := validateProbeFlags(o)
	if err == nil {
		t.Fatalf("-count %d was accepted; DNS source port base %d would wrap", o.count, dnsUDPSrcPortBase)
	}
	msg := err.Error()
	for _, w := range []string{"-count", "source port", "40000"} {
		if !strings.Contains(msg, w) {
			t.Errorf("refusal %q does not name %q", msg, w)
		}
	}
}

func TestValidateProbeFlagsAcceptsCountAtDNSSrcPortSpan(t *testing.T) {
	o := validDNS()
	o.count = int(^uint16(0)) - dnsUDPSrcPortBase + 1
	if _, err := validateProbeFlags(o); err != nil {
		t.Fatalf("-count %d (ports %d..65535) was refused: %v", o.count, dnsUDPSrcPortBase, err)
	}
}

func TestDefaultUDPSizingIsRecorded(t *testing.T) {
	sz, err := driver.NewSizing(carrier.DefaultPathMTU, carrier.ClassUDP)
	if err != nil {
		t.Fatal(err)
	}
	if sz.PathMTU != carrier.DefaultPathMTU {
		t.Fatalf("PathMTU %d, want carrier.DefaultPathMTU %d", sz.PathMTU, carrier.DefaultPathMTU)
	}
	t.Logf("MEASURED default udp sizing PathMTU=%d MessageSize=%d InnerMTU=%d InnerIPv6=%v MinPathMTUForInnerIPv6=%d DefaultPathMTU_const=%d",
		sz.PathMTU, sz.MessageSize, sz.InnerMTU, sz.InnerIPv6, sz.MinPathMTUForInnerIPv6, carrier.DefaultPathMTU)
}
