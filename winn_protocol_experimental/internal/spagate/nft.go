// Package spagate turns an internal/knock Single Packet Authorization grant
// into a kernel-enforced firewall opening.
//
// # Why this exists when internal/knock already has a Gate
//
// internal/knock.Gate enforces authorization by WRAPPING a Go listener: an
// unauthorized datagram never reaches the quic-go socket, an unauthorized TCP
// connection is accepted and closed with zero bytes. That works, and it is what
// cmd/winn-carrier-server uses, but it can only protect a listener THIS PROCESS
// OWNS.
//
// The ports a production Winn node actually exposes are not owned by any Go
// process in this tree. udp/9110 is bound by amneziawg-go inside a
// --network host container, and tcp/80 and tcp/443 are bound by Xray. No
// amount of wrapping reaches them. docs/SPA_DESIGN.md §4.4 named this exact
// gap and left it: "A true SYN-level firewall block (the way fwknop's own
// default operates, by rewriting iptables/nftables rules) was considered and
// rejected for this deliverable ... It is a reasonable v2 for Linux fleet nodes
// specifically and is not implemented here."
//
// This package is that v2. It reuses internal/knock unchanged for every
// cryptographic and anti-abuse decision - Gate.Consider runs the same
// length-check, rate-limit, HMAC-verify, replay-reject sequence the wrapped
// path runs - and changes only what a grant DOES: instead of forwarding a
// datagram, it adds the source address to an nftables set that a kernel rule
// consults. Nothing here parses a knock, computes a MAC, or touches a key.
//
// # Why the kernel holds the authorization window, not this process
//
// A Gate slides its grace window forward on every datagram it forwards, so a
// live session never ages out. This package never sees tunnel traffic - that is
// the entire point, the kernel fast-paths it - so it cannot slide anything, and
// a userspace expiry timer here would de-authorize sessions that are actively
// carrying data. The window is therefore held by nftables itself: the set is
// declared `flags dynamic,timeout` and an `update @set { ip saddr timeout G }`
// statement re-arms the element in-kernel on every matching packet.
//
// Two things about that statement are load-bearing, and both were originally
// wrong in ways that were completely silent:
//
//   - It must actually be REACHED. An earlier ruleset put a terminating
//     `ct state established,related accept` ahead of it in the same chain, so
//     tunnel traffic was accepted first and the update never ran. Measured over
//     48s of one active flow: established 32 -> 192 packets, update frozen at 1,
//     element decaying 31s -> 23s -> 15s -> 7s -> EXPIRED. deploy/spa's ruleset
//     now puts the update in its OWN base chain at an earlier priority with no
//     verdict, so no ordering in the filtering chain can starve it - netfilter
//     runs every base chain registered at a hook, and an accept ends only the
//     chain it is in.
//
//   - It must carry an EXPLICIT timeout. `update @set { ip saddr }` re-arms
//     from the SET's default and silently discards the per-element timeout
//     Authorize granted, while `nft list set` continues to DISPLAY the granted
//     value. Measured: set default 10s, element granted `timeout 600s`, one
//     matching packet, element drops to `expires 7s967ms` still printing
//     `timeout 10m`.
//
// Because the set's timeout is what actually governs every refresh, Preflight
// refuses to start when it does not equal this daemon's grace. That makes the
// two-value divergence unshippable rather than merely documented.
//
// # Fail-open is deliberate here, and is not a weakening
//
// internal/knock fails CLOSED under pressure because a dropped knock costs one
// retry. This package guards the only server a population of users in Myanmar
// can reach, where a gate that fails closed on a daemon crash is an outage, not
// an inconvenience. So the failure posture is inverted ON PURPOSE and in
// exactly one place: the nftables ruleset lives in its own table, and the
// supervisor is expected to delete that table whenever the daemon is not
// running (systemd ExecStopPost, plus an independent watchdog). Deleting the
// table restores the node's pre-SPA behaviour atomically and cannot affect any
// other rule, including SSH. See deploy/spa/ and the operator documentation.
//
// The daemon never writes a rule, never creates a table and never closes a
// port. The only element it removes is one it is simultaneously re-adding, as
// half of the destroy+add renewal transaction described on Authorize. So the
// only things that can take authorization away are the kernel's own timeout and
// an operator action.
package spagate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Enforcer applies an authorization decision somewhere outside this process.
//
// Authorize must be idempotent: a client that re-knocks (which knockdial does
// before every dial) calls it again for an address that may already be
// authorized, and that must renew rather than fail.
type Enforcer interface {
	// Authorize grants ip access for at least grace, or renews an existing
	// grant. It must never widen the grant to any other address.
	Authorize(ctx context.Context, ip netip.Addr, grace time.Duration) error

	// DescribeForLog is a redacted one-line summary safe to write to a log.
	DescribeForLog() string
}

// DefaultNFTBinary is the nft(8) executable used when NFTConfig.Binary is
// empty. It is an absolute path deliberately: this process may run with a
// systemd-sanitised environment, and resolving "nft" through PATH would let a
// writable PATH entry decide what runs as root.
const DefaultNFTBinary = "/usr/sbin/nft"

// DefaultTable, DefaultSetV4 and DefaultSetV6 name the objects this package
// manages. The table is SEPARATE from any table the node's own firewall uses,
// which is what makes `nft delete table inet winn_spa` a complete,
// single-command revert that provably cannot disturb another rule.
const (
	DefaultFamily = "inet"
	DefaultTable  = "winn_spa"
	DefaultSetV4  = "spa_allow_v4"
	DefaultSetV6  = "spa_allow_v6"
)

// nftTimeout bounds how long a single nft(8) invocation may take. It is a
// local, non-blocking operation; anything slower than this means the binary is
// wedged, and blocking the knock loop on it would let one stuck call stall
// every subsequent authorization.
const nftTimeout = 5 * time.Second

var (
	// ErrNoSetForFamily means an address family arrived that this enforcer was
	// not configured with a set for - e.g. an IPv6 knock when only an IPv4 set
	// exists. It is reported rather than silently dropped so the operator
	// learns the deployment is half-configured.
	ErrNoSetForFamily = errors.New(
		"spagate: no nftables set is configured for this address family",
	)

	// ErrUnroutableAddress means the address is not something that may be
	// placed in an allow set - unspecified, multicast, or a zero value.
	ErrUnroutableAddress = errors.New(
		"spagate: refusing to authorize a non-unicast address",
	)
)

// NFTConfig configures an NFTEnforcer.
type NFTConfig struct {
	// Binary overrides DefaultNFTBinary.
	Binary string

	// Family and Table name the nftables objects. Empty Family/Table take
	// DefaultFamily/DefaultTable. Empty SetV4 or SetV6 disables that family
	// (they do NOT default to DefaultSetV4/DefaultSetV6); a node with no IPv6
	// address should not carry an IPv6 set. At least one set must be set.
	Family string
	Table  string
	SetV4  string
	SetV6  string

	// runner is a test seam. Nil uses the real exec path. stdin is fed to the
	// command when non-empty, which is how a multi-command nft(8) transaction
	// is submitted.
	runner func(ctx context.Context, name, stdin string, args ...string) ([]byte, error)
}

// NFTEnforcer adds an authorized source address to an nftables set.
//
// It shells out to nft(8) rather than speaking netlink directly. That is a
// deliberate tradeoff: it costs one short-lived fork per ACCEPTED knock, and it
// avoids adding a netlink dependency and a second, subtly different
// implementation of nftables' own semantics to this tree. The fork is not a
// denial-of-service surface, because reaching it requires a knock that already
// passed the length check, the per-source rate limit, HMAC verification against
// a real key, and the replay cache - an unauthenticated peer cannot cause one.
type NFTEnforcer struct {
	binary string
	family string
	table  string
	setV4  string
	setV6  string
	runner func(ctx context.Context, name, stdin string, args ...string) ([]byte, error)
}

var _ Enforcer = (*NFTEnforcer)(nil)

// NewNFTEnforcer builds an enforcer. It performs no I/O and does not verify
// that the table exists; the ruleset is the operator's to install and this
// process must not create firewall rules of its own. See PreflightError for how
// a missing table is surfaced at startup instead.
func NewNFTEnforcer(cfg NFTConfig) (*NFTEnforcer, error) {
	enforcer := &NFTEnforcer{
		binary: firstNonEmpty(cfg.Binary, DefaultNFTBinary),
		family: firstNonEmpty(cfg.Family, DefaultFamily),
		table:  firstNonEmpty(cfg.Table, DefaultTable),
		setV4:  cfg.SetV4,
		setV6:  cfg.SetV6,
		runner: cfg.runner,
	}
	if enforcer.setV4 == "" && enforcer.setV6 == "" {
		return nil, errors.New(
			"spagate: at least one of SetV4 or SetV6 must be configured",
		)
	}
	for _, name := range []string{
		enforcer.family, enforcer.setV4, enforcer.setV6,
	} {
		if name == "" {
			continue
		}
		if err := validateIdentifier(name); err != nil {
			return nil, err
		}
	}
	if err := validateTableName(enforcer.table); err != nil {
		return nil, err
	}
	if enforcer.runner == nil {
		enforcer.runner = runCommand
	}
	return enforcer, nil
}

// Authorize adds ip to the set for its address family with a fresh timeout, or
// renews it if it is already present.
//
// # Why this is destroy+add and not add
//
// An earlier version of this file asserted that `nft add element` on an address
// already present "REPLACES that element's timeout ... idempotent by
// construction". THAT IS FALSE, and it was measured to be false against a real
// kernel (nftables 1.0.9): a plain re-add of a live element left its deadline
// untouched and returned exit status 0, and so did a re-add carrying an
// explicit `timeout 90s`. An element created with a 30s timeout and re-added at
// t=10 still read `expires 19s989ms`. The daemon would log a successful
// renewal, the caller would see a nil error, and the authorization would expire
// on its ORIGINAL deadline anyway.
//
// `destroy element` is idempotent - it succeeds whether or not the element is
// present - so pairing it with `add` in ONE `nft -f -` transaction renews
// unconditionally, atomically, and in a single fork. Measured on the same
// kernel: `expires 26s993ms` before, `expires 29s987ms` after, and the same
// pair against an ABSENT element succeeds and creates it.
//
// The whole transaction is submitted on stdin rather than as argv so that the
// destroy and the add cannot be observed as two separate states by a packet
// arriving between them.
func (e *NFTEnforcer) Authorize(
	ctx context.Context, ip netip.Addr, grace time.Duration,
) error {
	set, err := e.setFor(ip)
	if err != nil {
		return err
	}
	// ip is a netip.Addr, so String() can only produce digits, dots, colons and
	// hex - never a shell metacharacter. There is no shell here in any case:
	// exec.CommandContext takes an argv slice and never invokes a shell. The
	// unicast check below is the real guard, and it is about correctness of the
	// grant, not about injection.
	if !isAuthorizableUnicast(ip) {
		return fmt.Errorf("%w: %s", ErrUnroutableAddress, ip)
	}
	transaction := fmt.Sprintf(
		"destroy element %s %s %s { %s }\nadd element %s %s %s { %s timeout %s }\n",
		e.family, e.table, set, ip.String(),
		e.family, e.table, set, ip.String(), nftDuration(grace),
	)
	ctx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	output, err := e.runner(ctx, e.binary, transaction, "-f", "-")
	if err != nil {
		return fmt.Errorf(
			"spagate: nft destroy+add element %s %s %s: %w: %s",
			e.family, e.table, set, err, strings.TrimSpace(string(output)),
		)
	}
	return nil
}

// Deadline reports how long ip's authorization still has to run, by asking the
// kernel rather than by trusting anything this process remembers.
//
// It exists so a test can assert the BEHAVIOUR that matters - that a renewal
// actually moved the deadline - instead of asserting the command string, which
// is what let the false `add element` renewal claim above survive review.
// Returns ok=false when the address is not currently authorized.
func (e *NFTEnforcer) Deadline(
	ctx context.Context, ip netip.Addr,
) (remaining time.Duration, ok bool, err error) {
	set, err := e.setFor(ip)
	if err != nil {
		return 0, false, err
	}
	ctx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()
	output, err := e.runner(
		ctx, e.binary, "", "list", "set", e.family, e.table, set,
	)
	if err != nil {
		return 0, false, fmt.Errorf(
			"spagate: nft list set %s %s %s: %w: %s",
			e.family, e.table, set, err, strings.TrimSpace(string(output)),
		)
	}
	return parseElementExpiry(string(output), ip)
}

// expiryPattern matches "<address> expires 1m29s972ms" in nft list output,
// tolerating the "timeout <d> expires <d>" form nft prints when an element
// carries a per-element timeout.
var expiryPattern = regexp.MustCompile(
	`([0-9a-fA-F.:]+)(?:\s+timeout\s+[0-9a-z]+)?\s+expires\s+([0-9a-z]+)`,
)

func parseElementExpiry(
	listing string, ip netip.Addr,
) (time.Duration, bool, error) {
	want := ip.String()
	for _, match := range expiryPattern.FindAllStringSubmatch(listing, -1) {
		candidate, parseErr := netip.ParseAddr(match[1])
		if parseErr != nil || candidate.Unmap() != ip.Unmap() {
			continue
		}
		remaining, durErr := time.ParseDuration(match[2])
		if durErr != nil {
			return 0, false, fmt.Errorf(
				"spagate: could not parse expiry %q for %s: %w",
				match[2], want, durErr,
			)
		}
		return remaining, true, nil
	}
	return 0, false, nil
}

// MinNFTVersion is the oldest nft(8) that understands `destroy element`, which
// Authorize depends on for renewal.
//
// Below this the renewal transaction is a SYNTAX ERROR, so every Authorize
// fails while the daemon itself stays perfectly healthy: systemd sees an active
// unit, ExecStopPost never runs, and the watchdog's `systemctl is-active` check
// is satisfied. That is a silent total lockout invisible to every safety
// mechanism, which is why it is a hard startup refusal rather than a warning.
// Ubuntu 24.04 ships 1.0.9; Debian 12 ships 1.0.6 and is NOT usable.
const MinNFTVersion = "1.0.8"

// Preflight checks, before any knock is accepted, that this node can actually
// enforce a grant: that nft(8) is new enough, that the configured sets exist,
// and that the set's timeout matches the grace this daemon will grant.
//
// This is the difference between "SPA is running" and "SPA appears to be
// running". Without it every knock would verify, every metric would increment,
// and no packet would ever be let through.
func (e *NFTEnforcer) Preflight(ctx context.Context, grace time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, nftTimeout)
	defer cancel()

	versionOutput, err := e.runner(ctx, e.binary, "", "--version")
	if err != nil {
		return fmt.Errorf(
			"spagate: cannot run %s: %w: %s",
			e.binary, err, strings.TrimSpace(string(versionOutput)),
		)
	}
	version, err := parseNFTVersion(string(versionOutput))
	if err != nil {
		return err
	}
	if compareVersions(version, MinNFTVersion) < 0 {
		return fmt.Errorf(
			"spagate: nft(8) is version %s but %s or newer is required: renewal "+
				"uses `destroy element`, which older nft does not parse, so every "+
				"authorization would fail while this daemon stayed healthy -- a "+
				"silent lockout no watchdog would catch. Ubuntu 24.04 ships 1.0.9; "+
				"Debian 12 ships 1.0.6 and cannot run this",
			version, MinNFTVersion,
		)
	}

	for _, set := range []string{e.setV4, e.setV6} {
		if set == "" {
			continue
		}
		output, err := e.runner(
			ctx, e.binary, "", "list", "set", e.family, e.table, set,
		)
		if err != nil {
			return fmt.Errorf(
				"spagate: nftables set %s %s %s is not present, so a knock would "+
					"authorize nothing: %w: %s",
				e.family, e.table, set, err, strings.TrimSpace(string(output)),
			)
		}
		setTimeout, found := parseSetTimeout(string(output))
		if !found {
			return fmt.Errorf(
				"spagate: nftables set %s %s %s declares no timeout, so an "+
					"authorization would never expire",
				e.family, e.table, set,
			)
		}
		// The set's timeout is what the kernel re-arms an element to on every
		// matching packet, so it -- not this daemon's -grace -- governs the real
		// sliding window. If they differ, the grace an operator configured here
		// applies only to the initial grant and is silently replaced by the
		// set's value on the first packet, while `nft list set` keeps showing
		// the granted number. Refusing is the only way to make that unshippable.
		if setTimeout != grace {
			return fmt.Errorf(
				"spagate: -grace is %s but nftables set %s %s %s has timeout %s. "+
					"These MUST be equal: the kernel re-arms every element to the "+
					"SET's timeout on each matching packet, so a mismatch means the "+
					"window silently collapses to %s on the first packet while the "+
					"set listing still displays the granted value. Fix by setting "+
					"WINN_SPA_GRACE=%s for winn-spa-nft apply, or -grace=%s here",
				grace, e.family, e.table, set, setTimeout,
				setTimeout, grace, setTimeout,
			)
		}
	}
	return nil
}

var nftVersionPattern = regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`)

func parseNFTVersion(output string) (string, error) {
	match := nftVersionPattern.FindStringSubmatch(output)
	if match == nil {
		return "", fmt.Errorf(
			"spagate: could not read an nft version from %q",
			strings.TrimSpace(output),
		)
	}
	return fmt.Sprintf("%s.%s.%s", match[1], match[2], match[3]), nil
}

// compareVersions returns -1, 0 or 1 comparing dotted numeric versions.
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		var aValue, bValue int
		if i < len(aParts) {
			aValue, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bValue, _ = strconv.Atoi(bParts[i])
		}
		switch {
		case aValue < bValue:
			return -1
		case aValue > bValue:
			return 1
		}
	}
	return 0
}

// setTimeoutPattern matches the set-level default timeout line, which nft emits
// on a line of its own inside the set block. Element timeouts always appear
// inside `elements = { ... }` and never on a bare line, so this cannot pick one
// up by accident.
var setTimeoutPattern = regexp.MustCompile(`(?m)^\s*timeout\s+(\S+)\s*$`)

func parseSetTimeout(listing string) (time.Duration, bool) {
	match := setTimeoutPattern.FindStringSubmatch(listing)
	if match == nil {
		return 0, false
	}
	parsed, err := time.ParseDuration(match[1])
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func (e *NFTEnforcer) setFor(ip netip.Addr) (string, error) {
	if ip.Is4() || ip.Is4In6() {
		if e.setV4 == "" {
			return "", fmt.Errorf("%w (IPv4)", ErrNoSetForFamily)
		}
		return e.setV4, nil
	}
	if e.setV6 == "" {
		return "", fmt.Errorf("%w (IPv6)", ErrNoSetForFamily)
	}
	return e.setV6, nil
}

// DescribeForLog names the objects this enforcer writes to. It contains no
// credential and no client address.
func (e *NFTEnforcer) DescribeForLog() string {
	return fmt.Sprintf(
		"nftables enforcer: binary=%s family=%s table=%s set_v4=%s set_v6=%s",
		e.binary, e.family, e.table,
		orNone(e.setV4), orNone(e.setV6),
	)
}

// DryRunEnforcer records what would have been authorized and changes nothing.
// It is what -dry-run selects, so an operator can run the full verification
// path against real traffic on a live node before any firewall rule exists.
type DryRunEnforcer struct {
	// OnAuthorize, if set, is called instead of touching the firewall.
	OnAuthorize func(netip.Addr, time.Duration)
}

var _ Enforcer = (*DryRunEnforcer)(nil)

// Authorize records the decision without applying it.
func (d *DryRunEnforcer) Authorize(
	_ context.Context, ip netip.Addr, grace time.Duration,
) error {
	if d.OnAuthorize != nil {
		d.OnAuthorize(ip, grace)
	}
	return nil
}

// DescribeForLog says plainly that nothing is being enforced, because an
// operator reading a log must never mistake a dry run for a live gate.
func (d *DryRunEnforcer) DescribeForLog() string {
	return "DRY RUN: knocks are verified and logged, no firewall rule is touched"
}

// isAuthorizableUnicast rejects addresses that must never be placed in an allow
// set. An unspecified address would be a wildcard grant; multicast and loopback
// cannot be a real remote client and would only ever arrive from a spoofed or
// malformed source.
func isAuthorizableUnicast(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	if ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return false
	}
	return true
}

// nftDuration renders d the way nft(8) parses it. Go's Duration.String can emit
// fractional seconds ("1.5s") and sub-second units ("500ms" is fine, "1.5s" is
// not) which nft rejects, so this rounds to whole seconds and never emits a
// unit smaller than one second.
func nftDuration(d time.Duration) string {
	seconds := int64(d / time.Second)
	if d%time.Second != 0 {
		seconds++ // round up, never shorten a grant by rounding
	}
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%ds", seconds)
}

// reservedNFTTableName reports whether name is a well-known netfilter base
// table. SPA revert is `nft delete table FAMILY TABLE`. Pointing that at
// `filter` (iptables-nft stores WINN3GW-FORWARD there as `ip filter`;
// firewalld/ufw-nft use `inet filter`) would destroy those rulesets rather
// than a dedicated SPA table.
func reservedNFTTableName(name string) bool {
	switch name {
	case "filter", "nat", "mangle", "raw", "security":
		return true
	default:
		return false
	}
}

func validateTableName(name string) error {
	if err := validateIdentifier(name); err != nil {
		return err
	}
	if reservedNFTTableName(name) {
		return fmt.Errorf(
			"spagate: nftables table %q is a reserved netfilter base table "+
				"(iptables-nft keeps WINN3GW-* in `ip filter`; firewalld/ufw "+
				"use `inet filter`). SPA revert is `nft delete table` of this "+
				"name and would destroy those rulesets. Use a dedicated table "+
				"(default %s)",
			name, DefaultTable,
		)
	}
	return nil
}

// validateIdentifier rejects an nftables object name that is not a plain
// identifier. These names come from operator flags, and while exec.Command
// never invokes a shell, a name containing whitespace or a brace would produce
// a confusing nft parse error at the worst possible moment rather than a clear
// refusal at startup.
func validateIdentifier(name string) error {
	if name == "" {
		return errors.New("spagate: an nftables object name must not be empty")
	}
	if len(name) > 64 {
		return fmt.Errorf("spagate: nftables object name %q is too long", name)
	}
	for _, character := range name {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '_' || character == '-':
		default:
			return fmt.Errorf(
				"spagate: nftables object name %q must be letters, digits, "+
					"underscore or hyphen", name,
			)
		}
	}
	return nil
}

func runCommand(
	ctx context.Context, name, stdin string, args ...string,
) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		command.Stdin = strings.NewReader(stdin)
	}
	var combined bytes.Buffer
	command.Stdout = &combined
	command.Stderr = &combined
	err := command.Run()
	return combined.Bytes(), err
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func orNone(value string) string {
	if value == "" {
		return "(none)"
	}
	return value
}
