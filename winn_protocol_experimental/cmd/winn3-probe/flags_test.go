package main

import (
	"errors"
	"flag"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"winsvpn.local/winnprotocol/winn3/carrier"
	"winsvpn.local/winnprotocol/winn3/driver"
)

// validICMP is a combination that must be accepted. Tests that a refusal
// fires on a one-field spoil of this config; if a case starts failing because
// the baseline itself is now illegal, the spoil is not what broke.
func validICMP() probeOptions {
	return probeOptions{
		gw:        "127.0.0.1:51833",
		dir:       "/unused-by-validateProbeFlags",
		gatewayID: "winsgw01",
		inner:     "10.64.0.2",
		target:    defaultProbeTarget,
		pathMTU:   carrier.DefaultPathMTU,
		count:     4,
		interval:  time.Second,
		budget:    45 * time.Second,
	}
}

func validDNS() probeOptions {
	o := validICMP()
	o.dnsName = "example.com"
	o.dnsServer = "10.64.0.1"
	return o
}

func TestProbeFlagDefaults(t *testing.T) {
	fs := flag.NewFlagSet("winn3-probe", flag.ContinueOnError)
	o := defineProbeFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if o.gw != "" || o.dir != "" || o.gatewayID != "" || o.inner != "" {
		t.Fatalf("required flags must default empty, got gw=%q dir=%q gateway-id=%q inner=%q",
			o.gw, o.dir, o.gatewayID, o.inner)
	}
	if o.target != defaultProbeTarget {
		t.Fatalf("-target default %q, want %q", o.target, defaultProbeTarget)
	}
	if o.pathMTU != carrier.DefaultPathMTU {
		t.Fatalf("-path-mtu default %d, want carrier.DefaultPathMTU %d (a drift here is a silent handshake mismatch with winn3-gateway)",
			o.pathMTU, carrier.DefaultPathMTU)
	}
	if o.count != 4 {
		t.Fatalf("-count default %d, want 4", o.count)
	}
	if o.interval != time.Second {
		t.Fatalf("-interval default %s, want 1s", o.interval)
	}
	if o.budget != 45*time.Second {
		t.Fatalf("-budget default %s, want 45s", o.budget)
	}
	if o.dnsName != "" || o.dnsServer != "" {
		t.Fatalf("-dns/-dns-server must default empty, got %q %q", o.dnsName, o.dnsServer)
	}
	if o.canary {
		t.Fatal("-canary must default false")
	}
	if o.reflectTo != "" {
		t.Fatalf("-reflect-to must default empty, got %q", o.reflectTo)
	}
	if o.rekeyAfter != 0 {
		t.Fatalf("-rekey-after must default 0, got %d", o.rekeyAfter)
	}
	if handshakeWait != 40*time.Second {
		t.Fatalf("handshakeWait %s, want 40s (the undocumented wait that is not -budget)", handshakeWait)
	}
}

func validCanary() probeOptions {
	o := validICMP()
	o.canary = true
	o.reflectTo = "10.64.0.1"
	return o
}

func TestValidateProbeFlagsAcceptsBaseline(t *testing.T) {
	if _, err := validateProbeFlags(validICMP()); err != nil {
		t.Fatalf("valid ICMP config refused: %v", err)
	}
	if _, err := validateProbeFlags(validDNS()); err != nil {
		t.Fatalf("valid DNS config refused: %v", err)
	}
	parsed, err := validateProbeFlags(validCanary())
	if err != nil {
		t.Fatalf("valid canary config refused: %v", err)
	}
	if !parsed.canary {
		t.Fatal("canary parsed as false")
	}
	if parsed.rekeyAfter != canaryRekeyAfterDefault {
		t.Fatalf("canary rekey-after %d, want default %d", parsed.rekeyAfter, canaryRekeyAfterDefault)
	}
	if parsed.reflectAddr.String() != "10.64.0.1" {
		t.Fatalf("reflectAddr %s, want 10.64.0.1", parsed.reflectAddr)
	}
	if parsed.dstAddr.String() != "10.64.0.1" {
		t.Fatalf("canary dstAddr %s, want the reflector", parsed.dstAddr)
	}
}

func TestValidateProbeFlagsRefusals(t *testing.T) {
	type tc struct {
		name    string
		spoil   func(*probeOptions)
		want    []string
		dnsBase bool
	}
	cases := []tc{
		{
			name:  "missing gw",
			spoil: func(o *probeOptions) { o.gw = "" },
			want:  []string{"-gw", "-dir", "-gateway-id", "-inner", "required", "-gw is empty"},
		},
		{
			name:  "missing dir",
			spoil: func(o *probeOptions) { o.dir = "" },
			want:  []string{"-gw", "-dir", "-gateway-id", "-inner", "required", "-dir is empty"},
		},
		{
			name:  "missing gateway-id",
			spoil: func(o *probeOptions) { o.gatewayID = "" },
			want:  []string{"-gw", "-dir", "-gateway-id", "-inner", "required", "-gateway-id is empty"},
		},
		{
			name:  "missing inner",
			spoil: func(o *probeOptions) { o.inner = "" },
			want:  []string{"-gw", "-dir", "-gateway-id", "-inner", "required", "-inner is empty"},
		},
		{
			name:  "inner equals target is a tun martian then a false -forward blame",
			spoil: func(o *probeOptions) { o.target = o.inner },
			want:  []string{"-target", "-inner", "-forward", "martian"},
		},
		{
			name:  "target reserved leading zero",
			spoil: func(o *probeOptions) { o.target = "0.0.0.1" },
			want:  []string{"-target", "reserved leading zero"},
		},
		{
			name:    "dns-server IPv4-mapped IPv6",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "::ffff:10.64.0.1" },
			want:    []string{"-dns-server", "IPv4"},
		},
		{
			name:    "dns-server multicast",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "224.0.0.1" },
			want:    []string{"-dns-server", "multicast"},
		},
		{
			name:    "dns-server unspecified",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "0.0.0.0" },
			want:    []string{"-dns-server", "unspecified"},
		},
		{
			name:    "dns-server link-local",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "169.254.1.1" },
			want:    []string{"-dns-server", "link-local"},
		},
		{
			name:    "dns-server reserved high",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "240.0.0.1" },
			want:    []string{"-dns-server", "reserved high"},
		},
		{
			name:    "dns label longer than 63",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsName = strings.Repeat("a", 64) + ".example" },
			want:    []string{"-dns", "invalid DNS label"},
		},
		{
			name:  "gw IPv6 host",
			spoil: func(o *probeOptions) { o.gw = "[::1]:51833" },
			want:  []string{"-gw"},
		},
		{
			name:  "path-mtu 1 below IPv4 inner floor",
			spoil: func(o *probeOptions) { o.pathMTU = 1 },
			want:  []string{"-path-mtu"},
		},
		{
			name:  "gateway-id trailing space",
			spoil: func(o *probeOptions) { o.gatewayID = "winsgw01 " },
			want:  []string{"-gateway-id", "whitespace", "silence"},
		},
		{
			name:  "gateway-id leading tab",
			spoil: func(o *probeOptions) { o.gatewayID = "\twinsgw01" },
			want:  []string{"-gateway-id", "whitespace"},
		},
		{
			name:  "gateway-id only spaces",
			spoil: func(o *probeOptions) { o.gatewayID = "   " },
			want:  []string{"-gateway-id", "whitespace", "non-empty"},
		},
		{
			name:  "gateway-id too long",
			spoil: func(o *probeOptions) { o.gatewayID = strings.Repeat("a", 256) },
			want:  []string{"-gateway-id", "255"},
		},
		{
			name:  "inner not an address",
			spoil: func(o *probeOptions) { o.inner = "not-an-ip" },
			want:  []string{"-inner"},
		},
		{
			name:  "inner IPv6",
			spoil: func(o *probeOptions) { o.inner = "fd00::2" },
			want:  []string{"-inner", "IPv4"},
		},
		{
			name:  "inner loopback",
			spoil: func(o *probeOptions) { o.inner = "127.0.0.1" },
			want:  []string{"-inner", "loopback"},
		},
		{
			name:  "inner unspecified",
			spoil: func(o *probeOptions) { o.inner = "0.0.0.0" },
			want:  []string{"-inner", "unspecified"},
		},
		{
			name:  "inner multicast",
			spoil: func(o *probeOptions) { o.inner = "224.0.0.1" },
			want:  []string{"-inner", "multicast"},
		},
		{
			name:  "inner link-local",
			spoil: func(o *probeOptions) { o.inner = "169.254.1.1" },
			want:  []string{"-inner", "link-local"},
		},
		{
			name:  "inner reserved high",
			spoil: func(o *probeOptions) { o.inner = "240.0.0.1" },
			want:  []string{"-inner", "reserved high"},
		},
		{
			name:  "inner reserved leading zero",
			spoil: func(o *probeOptions) { o.inner = "0.0.0.1" },
			want:  []string{"-inner", "reserved leading zero"},
		},
		{
			name:  "inner IPv4-mapped IPv6",
			spoil: func(o *probeOptions) { o.inner = "::ffff:10.64.0.2" },
			want:  []string{"-inner", "IPv4"},
		},
		{
			name:  "target not an address",
			spoil: func(o *probeOptions) { o.target = "nope" },
			want:  []string{"-target"},
		},
		{
			name:  "target IPv6 would have panicked As4",
			spoil: func(o *probeOptions) { o.target = "2001:db8::1" },
			want:  []string{"-target", "IPv4"},
		},
		{
			name:  "target loopback is a false-green internet proof",
			spoil: func(o *probeOptions) { o.target = "127.0.0.1" },
			want:  []string{"-target", "loopback", "internet transit"},
		},
		{
			name:  "target unspecified",
			spoil: func(o *probeOptions) { o.target = "0.0.0.0" },
			want:  []string{"-target", "unspecified"},
		},
		{
			name:  "target multicast",
			spoil: func(o *probeOptions) { o.target = "224.0.0.1" },
			want:  []string{"-target", "multicast"},
		},
		{
			name:  "target link-local",
			spoil: func(o *probeOptions) { o.target = "169.254.1.1" },
			want:  []string{"-target", "link-local"},
		},
		{
			name:  "target reserved high",
			spoil: func(o *probeOptions) { o.target = "255.255.255.255" },
			want:  []string{"-target", "reserved high"},
		},
		{
			name:    "dns without dns-server",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "" },
			want:    []string{"-dns", "-dns-server"},
		},
		{
			name:  "dns-server without dns (inert flag)",
			spoil: func(o *probeOptions) { o.dnsServer = "10.64.0.1" },
			want:  []string{"-dns-server", "-dns", "ignored"},
		},
		{
			name:    "dns with non-default target (inert flag)",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.target = "8.8.8.8" },
			want:    []string{"-target", "-dns", "ignored"},
		},
		{
			name:    "dns-server IPv6",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "fd00::1" },
			want:    []string{"-dns-server", "IPv4"},
		},
		{
			name:    "dns-server not an address",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "nope" },
			want:    []string{"-dns-server"},
		},
		{
			name:    "dns-server loopback",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsServer = "127.0.0.1" },
			want:    []string{"-dns-server", "loopback"},
		},
		{
			name:    "inner equals dns-server",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.inner = "10.64.0.1" },
			want:    []string{"-inner", "-dns-server"},
		},
		{
			name:    "dns empty label",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.dnsName = "foo..bar" },
			want:    []string{"-dns", "invalid DNS label"},
		},
		{
			name:  "gw missing port",
			spoil: func(o *probeOptions) { o.gw = "127.0.0.1" },
			want:  []string{"-gw"},
		},
		{
			name:  "gw port zero",
			spoil: func(o *probeOptions) { o.gw = "127.0.0.1:0" },
			want:  []string{"-gw", "port is 0"},
		},
		{
			name:  "gw empty host",
			spoil: func(o *probeOptions) { o.gw = ":51833" },
			want:  []string{"-gw", "no usable IPv4 host"},
		},
		{
			name:  "gw unspecified",
			spoil: func(o *probeOptions) { o.gw = "0.0.0.0:51833" },
			want:  []string{"-gw", "no usable IPv4 host"},
		},
		{
			name:  "budget negative",
			spoil: func(o *probeOptions) { o.budget = -time.Second },
			want:  []string{"-budget"},
		},
		{
			name:  "count zero used to report no reply",
			spoil: func(o *probeOptions) { o.count = 0 },
			want:  []string{"-count"},
		},
		{
			name:  "count negative",
			spoil: func(o *probeOptions) { o.count = -1 },
			want:  []string{"-count"},
		},
		{
			name:  "interval negative",
			spoil: func(o *probeOptions) { o.interval = -time.Second },
			want:  []string{"-interval"},
		},
		{
			name:  "budget zero",
			spoil: func(o *probeOptions) { o.budget = 0 },
			want:  []string{"-budget"},
		},
		{
			name:  "path-mtu zero",
			spoil: func(o *probeOptions) { o.pathMTU = 0 },
			want:  []string{"-path-mtu"},
		},
		{
			name:  "path-mtu negative",
			spoil: func(o *probeOptions) { o.pathMTU = -1 },
			want:  []string{"-path-mtu"},
		},
		{
			name:  "canary without reflect-to",
			spoil: func(o *probeOptions) { o.canary = true },
			want:  []string{"-canary", "-reflect-to"},
		},
		{
			name:  "reflect-to without canary is inert",
			spoil: func(o *probeOptions) { o.reflectTo = "10.64.0.1" },
			want:  []string{"-reflect-to", "-canary", "ignored"},
		},
		{
			name:  "rekey-after without canary",
			spoil: func(o *probeOptions) { o.rekeyAfter = 8 },
			want:  []string{"-rekey-after", "-canary"},
		},
		{
			name:    "canary with dns",
			dnsBase: true,
			spoil:   func(o *probeOptions) { o.canary = true; o.reflectTo = "10.64.0.1" },
			want:    []string{"-dns", "-canary"},
		},
		{
			name:  "canary with non-default target",
			spoil: func(o *probeOptions) { o.canary = true; o.reflectTo = "10.64.0.1"; o.target = "8.8.8.8" },
			want:  []string{"-target", "-canary", "ignored"},
		},
		{
			name:  "canary inner equals reflect-to",
			spoil: func(o *probeOptions) { o.canary = true; o.reflectTo = "10.64.0.2" },
			want:  []string{"-inner", "-reflect-to"},
		},
		{
			name:  "reflect-to loopback",
			spoil: func(o *probeOptions) { o.canary = true; o.reflectTo = "127.0.0.1" },
			want:  []string{"-reflect-to", "loopback"},
		},
		{
			name:  "reflect-to IPv6",
			spoil: func(o *probeOptions) { o.canary = true; o.reflectTo = "fd00::1" },
			want:  []string{"-reflect-to", "IPv4"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := validICMP()
			if tc.dnsBase {
				o = validDNS()
			}
			tc.spoil(&o)
			_, err := validateProbeFlags(o)
			if err == nil {
				t.Fatalf("accepted a config that must be refused")
			}
			msg := err.Error()
			t.Log(msg)
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("refusal %q does not name %q, so it does not name the fix", msg, w)
				}
			}
		})
	}
}

func TestValidateProbeFlagsPathMTUDeadZoneNamesTheFlag(t *testing.T) {
	o := validICMP()
	o.pathMTU = 1280
	_, err := validateProbeFlags(o)
	if err == nil {
		t.Fatal("-path-mtu 1280 was accepted; udp-only NewSizing should refuse the IPv6 dead zone")
	}
	if !errors.Is(err, driver.ErrPathMTUDeadZone) && !errors.Is(err, driver.ErrConfig) {
		t.Fatalf("got %v, want ErrPathMTUDeadZone or ErrConfig", err)
	}
	if !strings.Contains(err.Error(), "-path-mtu") {
		t.Fatalf("dead-zone refusal does not name -path-mtu: %v", err)
	}
	t.Log(err.Error())
}

func TestValidateProbeFlagsInternalWhitespaceGatewayIDIsKept(t *testing.T) {
	o := validICMP()
	o.gatewayID = "wins gw 01"
	if _, err := validateProbeFlags(o); err != nil {
		t.Fatalf("internal whitespace is a name somebody may have meant; got %v", err)
	}
}

func TestWhitespaceOnlyGatewayIDDoesNotRecommendEmpty(t *testing.T) {
	o := validICMP()
	o.gatewayID = "   "
	_, err := validateProbeFlags(o)
	if err == nil {
		t.Fatal("whitespace-only -gateway-id was accepted")
	}
	msg := err.Error()
	if strings.Contains(msg, `Pass -gateway-id ""`) {
		t.Fatalf("refusal recommends the empty string, which is also illegal: %q", msg)
	}
	if !strings.Contains(msg, "non-empty") {
		t.Fatalf("refusal does not say to pass a non-empty id: %q", msg)
	}
}

func TestRefuseExtraProbeArgs(t *testing.T) {
	fs := flag.NewFlagSet("winn3-probe", flag.ContinueOnError)
	defineProbeFlags(fs)
	if err := fs.Parse([]string{"-gw", "127.0.0.1:51833", "leftover"}); err != nil {
		t.Fatal(err)
	}
	err := refuseExtraProbeArgs(fs)
	if err == nil {
		t.Fatal("leftover positional argument was accepted")
	}
	msg := err.Error()
	t.Log(msg)
	for _, w := range []string{"leftover", "positional", "-h", "-accept-transit", "-forward", "-resolver", "winn3-gateway"} {
		if !strings.Contains(msg, w) {
			t.Errorf("refusal %q does not name %q", msg, w)
		}
	}
	clean := flag.NewFlagSet("winn3-probe", flag.ContinueOnError)
	defineProbeFlags(clean)
	if err := clean.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if err := refuseExtraProbeArgs(clean); err != nil {
		t.Fatalf("no leftover args were refused: %v", err)
	}
}

func TestProbeEdgeWhitespaceReportSpellsInvisibleBytes(t *testing.T) {
	got := probeEdgeWhitespaceReport("winsgw01 ")
	for _, w := range []string{`trailing whitespace byte(s)`, "U+0020"} {
		if !strings.Contains(got, w) {
			t.Errorf("report %q missing %q", got, w)
		}
	}
	if utf8.RuneCountInString(" ") != 1 {
		t.Fatal("sanity")
	}
}

func TestReadProbeDirKeyNamesExpectedFile(t *testing.T) {
	dir := t.TempDir()
	_, err := readProbeDirKey(dir, "client.key")
	if err == nil {
		t.Fatal("missing client.key was accepted")
	}
	msg := err.Error()
	t.Log(msg)
	for _, w := range []string{"-dir", "client.key", "winn3-gateway -mode keygen"} {
		if !strings.Contains(msg, w) {
			t.Errorf("missing-key refusal %q does not name %q", msg, w)
		}
	}
}

func TestDefineProbeFlagsUnknownFlag(t *testing.T) {
	fs := flag.NewFlagSet("winn3-probe", flag.ContinueOnError)
	var sink strings.Builder
	fs.SetOutput(&sink)
	defineProbeFlags(fs)
	err := fs.Parse([]string{"-accept-transit=true"})
	if err == nil {
		t.Fatal("unknown flag -accept-transit was accepted; this binary is a client and has no such flag")
	}
	if !strings.Contains(err.Error(), "accept-transit") {
		t.Fatalf("parse error %v does not name the unknown flag", err)
	}
	t.Log(err.Error())
}

func TestNoReplyMessagesNameTheRemainingCause(t *testing.T) {
	for _, w := range []string{"-forward", "-accept-transit=true", "-forward-cidr", "-inner-v4", "-inner", "-target"} {
		if !strings.Contains(icmpNoReplyFix, w) {
			t.Errorf("ICMP no-reply %q does not name %q", icmpNoReplyFix, w)
		}
	}
	for _, w := range []string{"-dns", "-resolver", "-dns-server", "-inner-v4"} {
		if !strings.Contains(dnsNoReplyFix, w) {
			t.Errorf("DNS no-reply %q does not name %q", dnsNoReplyFix, w)
		}
	}
	for _, w := range []string{"-reflect-to", "reflector", "-inner-v4"} {
		if !strings.Contains(reflectNoReplyFix, w) {
			t.Errorf("reflect no-reply %q does not name %q", reflectNoReplyFix, w)
		}
	}
}

func TestMissingRequiredDoesNotBlameAFlagThatWasSet(t *testing.T) {
	o := validICMP()
	o.inner = ""
	_, err := validateProbeFlags(o)
	if err == nil {
		t.Fatal("missing -inner was accepted")
	}
	msg := err.Error()
	if strings.Contains(msg, "-gw is empty") || strings.Contains(msg, "-dir is empty") {
		t.Fatalf("missing -inner blamed a flag that was set: %q", msg)
	}
	if !strings.Contains(msg, "-inner is empty") {
		t.Fatalf("missing -inner did not name that flag as empty: %q", msg)
	}
}

func TestValidateProbeFlagsAcceptsZeroInterval(t *testing.T) {
	o := validICMP()
	o.interval = 0
	if _, err := validateProbeFlags(o); err != nil {
		t.Fatalf("-interval 0 is a documented accept (send with no gap), got %v", err)
	}
}

func TestNoReplyErrorDoesNotBlameGatewayForTheWrongCause(t *testing.T) {
	type tc struct {
		name            string
		dnsMode         bool
		reflectMode     bool
		sent, txDropped int
		budget          time.Duration
		want, mustNot   []string
	}
	cases := []tc{
		{
			name:    "sent zero is the device not the gateway",
			sent:    0,
			budget:  45 * time.Second,
			want:    []string{"not a gateway", "-forward", "-resolver"},
			mustNot: []string{"-accept-transit=true"},
		},
		{
			name:      "tx drop is tun not -forward",
			sent:      4,
			txDropped: 4,
			budget:    45 * time.Second,
			want:      []string{"tx_dropped_invalid", "-inner", "-target"},
			mustNot:   []string{"needs -forward and -accept-transit=true AND"},
		},
		{
			name:    "sub-second budget names -budget first",
			sent:    4,
			budget:  time.Millisecond,
			want:    []string{"-budget", "45s", "handshake"},
			mustNot: []string{"needs -forward and -accept-transit=true AND"},
		},
		{
			name:    "ICMP default budget names gateway companions",
			sent:    4,
			budget:  45 * time.Second,
			want:    []string{"-forward", "-accept-transit=true", "-forward-cidr"},
			mustNot: []string{"tx_dropped_invalid", "queued on the in-memory device"},
		},
		{
			name:    "DNS default budget names -resolver",
			dnsMode: true,
			sent:    4,
			budget:  45 * time.Second,
			want:    []string{"-dns", "-resolver", "-dns-server"},
			mustNot: []string{"-accept-transit=true AND"},
		},
		{
			name:        "reflect default budget names the reflector",
			reflectMode: true,
			sent:        4,
			budget:      45 * time.Second,
			want:        []string{"-reflect-to", "reflector"},
			mustNot:     []string{"-accept-transit=true AND"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := noReplyError(tc.dnsMode, tc.reflectMode, tc.sent, tc.txDropped, tc.budget)
			if err == nil {
				t.Fatal("noReplyError returned nil")
			}
			msg := err.Error()
			t.Log(msg)
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("got %q, missing %q", msg, w)
				}
			}
			for _, w := range tc.mustNot {
				if strings.Contains(msg, w) {
					t.Errorf("got %q, must not contain %q (wrong cause)", msg, w)
				}
			}
		})
	}
}
