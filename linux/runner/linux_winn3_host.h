#ifndef RUNNER_LINUX_WINN3_HOST_H_
#define RUNNER_LINUX_WINN3_HOST_H_

// The Linux host for Winn Protocol v3, the STANDALONE protocol.
//
// # This file is not the winn/1 relay host and shares nothing with it
//
// linux/runner/linux_winn_host.{h,cc} is the winn/1 relay: AmneziaWG keeps the
// tun and all of the cryptography, its outer datagrams are redirected to a
// loopback seam, and `cmd/winn-datapath` forwards them to the gateway. That is
// the SHIPPING AmneziaWG path and this file must never be mistaken for it.
//
// v3 was ruled a standalone protocol on 2026-08-08: its own handshake, its own
// crypto (winn3/core), its own inner-IP validator (winn3/tun), and no
// AmneziaWG and no Xray anywhere in the datapath. So there is no awg-quick, no
// seam, no `awg show winsvpn fwmark`, and no AmneziaWG classification table.
// Everything those things did for winn/1 this host has to do itself, and the
// three that matter are the tun device, the outer-socket exclusion and the
// routing posture.
//
// The two hosts are separate translation units in separate namespaces on
// purpose. A shared file would give a future edit one place to accidentally
// make a v3 decision on a v1 session, and the failure mode of that mistake is
// AmneziaWG datagrams fed to a v3 engine (double-encrypted, dropped) or inner
// IP packets fed to a v1 engine (CLEARTEXT to the gateway).
//
// # The engine invocation
//
//   winn-datapath -transport stdio -winn3 -winn3-keys PATH
//
// `-winn3` is the frame mode (cmd/winn-datapath/winn3_frame.go): the HOST owns
// the tun device, Inbound frames are inner IP packets on their way out and
// Outbound frames are inner IP packets on their way in. It is the same duplex
// framing windows/runner/winn_frame.h defines and the winn/1 host already
// drives; only the payload class changes, from `awg-datagram` to `ip-packet`.
//
// `-winn3-keys PATH` is not optional and is not a convenience. The frame
// channel's payload is peer-supplied by construction, so key material must not
// cross it -- the rule datapath/carrier.go already records for the winn/1
// carrier profile, and a static private key is strictly worse than a carrier
// configuration. The document this host writes CONTAINS NO KEY MATERIAL: it
// names the three key files by absolute path and the engine opens them under
// its own uid. `-winn3` without `-winn3-keys` is a hard refusal in the engine
// (winn3_frame.go:77-84), which is the shape this host wants -- an engine that
// defaulted to something would be an engine that could start unauthenticated.
//
// `-winn3-tun-fd` is deliberately NOT passed and would be refused
// (winn3_frame.go:92-98): it belongs to `-winn3-profile`, the desktop mode in
// which the engine holds the descriptor. Frame mode was chosen here because it
// is the mode the shipping host already speaks end to end, because
// `-transport stdio` cannot carry a descriptor at all, and because the pump is
// then the same shape on all five platforms.
//
// # How Linux v3 promotion differs from Linux v1, and from Windows
//
// This is the part that does not carry over, and assuming it did would put the
// user's default route on an unproven tunnel.
//
//   winn/1 on Linux (linux_tunnel_backend.cc:3081-3115): awg-quick has ALREADY
//   claimed the host's routing by the time the gate runs -- default route, DNS,
//   IPv6, the full route set and its own fwmark rule. So the gate decides
//   KEEP-vs-TEARDOWN. Its own comment says so and says why it is not the staged
//   promotion the other platforms have: narrowing awg-quick would mean running
//   the interface Table=off and owning every route by hand.
//
//   winn/1 on Windows (windows_tunnel_backend.cpp): routes are installed only
//   AFTER WaitForWinnTransportConvergence, so the gate decides INSTALL-vs-NOT.
//   Nothing is on the host until the proof lands.
//
//   winn/3 on Linux is NEITHER, and cannot be either.
//
// It cannot be the Linux v1 shape because there is no awg-quick to claim the
// routing in the first place -- this host owns the tun and every route on it.
//
// It cannot be the Windows v1 shape -- install nothing until proven -- because
// of what the v3 proof IS. `promotion_ready` is
// `Gate.State() == StateCarrying && Stats().RxPackets > 0`
// (cmd/winn-datapath/winn3_status.go:48-50), and RxPackets counts inner packets
// VALIDATED AND WRITTEN TO THE HOST DEVICE. A host that installs nothing has no
// device to deliver into, so RxPackets can never leave zero and the proof can
// never arrive. Deferring the device defers the proof forever.
//
// So Linux v3 must install something before the proof exists, and the whole
// job is making that something provably too narrow to capture anything:
//
//   BOOTSTRAP (before the engine can possibly carry): the inner address at /32
//   or /128, the MTU, AT MOST ONE route (the inner next hop), the outer-socket
//   exclusion, and NOTHING else. No default route, no IPv6, no resolver.
//   Built by winsvpn::winn3::BuildBootstrapPosture and then RE-CHECKED by
//   VerifyBootstrapIsNarrow, which tests the built object rather than trusting
//   the builder.
//
//   PROMOTED (only after promotion_ready): 0.0.0.0/1 + 128.0.0.0/1, IPv6 if the
//   plan floor can carry it, the resolvers, the full route set. One call.
//
// A third difference falls out of this and is worth naming, because it is the
// one that helps the user: a v3 REFUSAL costs the user nothing. On winn/1 a
// refusal has to restore routing that awg-quick already took, and that restore
// can itself fail. Here the user's default route was never taken -- the
// promoted posture uses the 0.0.0.0/1 + 128.0.0.0/1 pair precisely so it beats
// an existing default on specificity WITHOUT deleting it (winn3_posture.h:566)
// -- so a partial teardown leaves the host's own default intact.
//
// # The outer-socket exclusion, which is also genuinely different
//
// winn/1 on Linux excludes the engine's own socket with awg-quick's fwmark:
// awg-quick installs `ip rule not fwmark M lookup T`, so a datagram carrying
// mark M leaves by the physical route. There is no awg-quick here to publish a
// mark, and the engine's socket carries no SO_MARK -- it is opened by
// `cmd/winn-datapath` itself under `allow_own_socket`, and nothing in that
// process marks it.
//
// The equivalent for a standalone v3 session is a DESTINATION-scoped host
// route: `ip route add <gateway>/32 via <physical next hop> dev <physical
// interface>`. It needs no mark and no rule, and it works for exactly the
// reason the promoted posture uses two /1 routes instead of a default -- a /32
// beats a /1 on specificity, so the engine's outer datagrams keep leaving by
// the physical path after promotion widens everything else.
//
// It is installed IN THE BOOTSTRAP POSTURE, before any user traffic is
// possible, because installing it later means installing it after traffic has
// already been captured (winn3_posture.h:344-350).
//
// # Decision and privilege stay apart
//
// Nothing in this file executes an `ip` command, and nothing opens a socket to
// the gateway. It DECIDES and it RENDERS argument vectors, exactly as
// winn3_posture.h does and for the reason stated there: giving the policy a
// second way to reach the system puts the decision and the privilege in the
// same place, which is how a policy bug becomes a root bug. The caller supplies
// a LinuxWinn3PrivilegedRunner and owns every privileged execution.

#include "winn3_posture.h"

#include <cctype>
#include <cerrno>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace winsvpn::winn3host {

// ---------------------------------------------------------------------------
// Sizing: the C++ mirror of winn3/carrier/sizing.go and winn3/tun/params.go.
//
// WHY THIS IS DUPLICATED, KNOWINGLY. The interface MTU is a number the HOST
// must set, and §4.2 pins it to the plan floor EXACTLY -- not "at most".
// cmd/winn-datapath/winn3_create.go refusal 3 rejects any other value, so a
// host that asked the engine for the number over the frame channel would be
// deriving its own interface MTU from a value the peer supplied, and a host
// that guessed would fail to start rather than fail to start LOUDLY.
//
// Android pays the same cost for the same reason and guards it the same way:
// WinnV3Sizing.assertsAgreeWithGo() pins the worked examples the Go doc
// comments state. AssertsAgreeWithGo() below pins the identical seven, so a
// change to a Go header cost breaks a C++ test here instead of black-holing
// every full-size flow on a user's machine.
//
// THE NUMBER THAT MATTERS is the floor over every class the session may
// escalate TO, never the class it dialled. The gap is 84 bytes at a 1500-byte
// path (1443 for a dialled UDP/IPv4 carrier against 1359 for the plan), and
// sizing to the dialled carrier black-holes every full-size flow at the first
// migration while the tunnel still reads up.
// ---------------------------------------------------------------------------
namespace sizing {

// winn3/tun.Overhead() == core.TransportOverhead() + FrameOverhead
//                      == (8 + 2 + 16) + 3 == 29.
inline constexpr int kOverhead = 29;

// winn3/tun.UDPOverIPv4Overhead / UDPOverIPv6Overhead.
inline constexpr int kUdpOverIPv4Overhead = 28;
inline constexpr int kUdpOverIPv6Overhead = 48;

// winn3/tun.IPv6MinLinkMTU (RFC 8200) and winn3/tun.MinInnerMTUv4 (RFC 1122).
inline constexpr int kIPv6MinLinkMtu = 1280;
inline constexpr int kMinInnerMtuV4 = 576;

// carrier/sizing.go's header costs. Read the reasons there, not here.
inline constexpr int kIPv4HeaderBytes = 20;
inline constexpr int kIPv6HeaderBytes = 40;
inline constexpr int kUdpHeaderBytes = 8;
inline constexpr int kTcpHeaderBytes = 20 + 12;   // + RFC 7323 timestamps
inline constexpr int kTlsRecordBytes = 5 + 1 + 16;
inline constexpr int kLengthRecordOverhead = 2 + 16;

// session.MessageFloor() and core.MaxTransportPayload: the two clamps of
// session.MaxMessageSizeForPath.
inline constexpr int kMessageFloor = kOverhead;
inline constexpr int kMaxTransportPayload = 65535;

// carrier.DefaultPathMTU — the FLEET DEFAULT, raised 1280 -> 1450 on
// 2026-08-10. It must equal that constant exactly: this host and the engine
// planning at different numbers is a path-MTU mismatch on every session that
// omits path_mtu.
//
// It was 1280 and described as "a floor, not an estimate". 1280 is RFC 8200's
// minimum link MTU and belongs to the INNER interface; as an OUTER planning
// number it yields an inner MTU of 1139 over the shipping plan, which no kernel
// will put IPv6 on (ipv6_add_dev() returns -EINVAL — this host has that floor
// exactly as Android does). 1280..1420 is therefore a dead zone in which a
// session resolves, bootstraps, carries and can never promote; 1421 is where it
// ends and 1450 clears it with headroom.
inline constexpr int kDefaultPathMtu = 1450;

// winn3/tun.InnerMTU(carrierMaxMessage).
inline int InnerMtu(int carrier_max_message) {
  return carrier_max_message - kOverhead;
}

// winn3/tun.CarrierMessageFor(mtu).
inline int CarrierMessageFor(int mtu) { return mtu + kOverhead; }

// winn3/tun.InnerMTUForPath(pathMTU, outerOverhead). SINGLE CARRIER, and
// therefore the wrong number to configure an interface with whenever the
// session may migrate. It is here because params.go states its worked examples
// in these terms and AssertsAgreeWithGo pins them.
inline int InnerMtuForPath(int path_mtu, int outer_overhead) {
  return InnerMtu(path_mtu - outer_overhead);
}

// The class names that cross the create document: carrier.Class.String()'s own
// values. cmd/winn-datapath's winn3ClassNamed refuses anything else rather than
// charging it a default, so this refuses the same set.
std::vector<std::string> CarrierClasses();

// carrier.Overhead(class, family). Returns false for a class name this host
// does not know -- never a default, because a floor computed over a class
// nobody named is a floor that guarantees nothing.
bool CarrierOverhead(const std::string& carrier_class, bool ipv4, int* out);

// session.MaxMessageSizeForPath(pathMTU, carrierOverhead), clamps included.
int MaxMessageSizeForPath(int path_mtu, int carrier_overhead);

// carrier.Floor(pathMTU, classes...): the narrowest MaxMessageSize across every
// class in the plan, across BOTH address families. Refuses an empty plan and an
// unknown class, matching driver.NewSizing.
bool PlanFloorMessageSize(int path_mtu,
                          const std::vector<std::string>& carrier_classes,
                          int* out, std::string* error);

// driver.NewSizing(pathMTU, classes...).InnerMTU: the interface MTU §4.2 pins
// the host to, and the ONLY value winn3_create.go accepts for `inner_mtu`.
bool PlanFloorInnerMtu(int path_mtu,
                       const std::vector<std::string>& carrier_classes,
                       int* out, std::string* error);

// Whether the plan floor -- not the dialled carrier -- can carry inner IPv6.
// False is common and is not a defect: at a 1280-byte outer path inner IPv6 is
// impossible for any tunnel.
bool PlanCarriesInnerIPv6(int path_mtu,
                          const std::vector<std::string>& carrier_classes);

// The worked examples winn3/tun/params.go and winn3/carrier/sizing.go state in
// their own doc comments, asserted rather than trusted. Returns false and names
// the first disagreement. Identical to WinnV3Sizing.assertsAgreeWithGo() on
// Android, deliberately, so the three implementations pin the same numbers.
bool AssertsAgreeWithGo(std::string* error);

}  // namespace sizing

// ---------------------------------------------------------------------------
// The key document: `-winn3-keys PATH`.
//
// IT CONTAINS NO KEY MATERIAL, only absolute paths. That is the same rule
// LinuxWinnCarrierProfile follows for the winn/1 carrier credentials, and it is
// what keeps this host from ever holding a private key. This host never opens
// the three files; the engine does.
// ---------------------------------------------------------------------------
struct LinuxWinn3Keys {
  // winn3Keys.Role. This host is always the client. `gateway` exists in the Go
  // document so the binary can serve the lab's responding half, and is not a
  // value this host ever writes.
  std::string role = "client";

  // Binds the admission tag to one gateway, so an initiation captured at
  // gateway A cannot be replayed at gateway B during a shared-key rotation.
  std::string gateway_id;

  // Absolute paths. Never contents.
  std::string static_path;           // this device's static X25519 private key
  std::string gateway_static_path;   // the gateway's static X25519 public key
  std::string admission_path;        // the gateway's admission secret
  // Dual-signature attestation public keys (hex files). Both set together, or
  // both empty for a legacy session without the attestation.
  std::string dual_auth_ed25519_pub_path;
  std::string dual_auth_mldsa65_pub_path;

  // The host's own description of the exclusion it installed. The engine does
  // NOT parse it or act on it; it is required to be non-empty before a create
  // document may set allow_own_socket, so that a host cannot claim the
  // exclusion without writing down what it did, and it is echoed in the status
  // document so the claim sits beside the counters.
  //
  // Never set by hand: DescribeLinuxWinn3Exclusion() builds it from the SAME
  // fields RenderLinuxWinn3ExclusionCommands() renders, so the sentence and the
  // command cannot disagree.
  std::string outer_socket_exclusion;

  // False is StrictPQ and is the default. Harvest-now-decrypt-later is a live
  // threat for this user population, so the extra round trip is worth it.
  bool fast_pq = false;

  // Lowers the send-volume rekey trigger. Zero means core.RekeyAfterMessages.
  // MONOTONE: the engine refuses a value above the protocol default, so this
  // can only make the ratchet turn more often.
  uint64_t rekey_after_messages = 0;
};

// Serialises the key document. Contains private PATHS; do not log. Returns
// false and sets *error rather than emitting a document the engine will refuse.
bool BuildLinuxWinn3KeysJson(const LinuxWinn3Keys& keys, std::string* out,
                             std::string* error);

// Modes and roles only -- no path, no secret. Safe to log. Deliberately the
// same shape as winn3Keys.describeForLog() on the engine side, so the two log
// lines can be compared.
std::string DescribeLinuxWinn3Keys(const LinuxWinn3Keys& keys);

// Writes the key document under the per-user private data directory with mode
// 0600, set BEFORE any bytes are written so it is never briefly world-readable,
// and returns its absolute path in *path.
//
// It never falls back to a shared location such as /tmp: a world-readable file
// naming every key file on the device hands an attacker the map even though it
// holds no key material itself.
bool WriteLinuxWinn3KeysDocument(const LinuxWinn3Keys& keys, std::string* path,
                                 std::string* error);

// ---------------------------------------------------------------------------
// The resolver mechanism.
//
// ===========================================================================
// WHY THIS IS AN ENUM AND NOT `resolvectl`
// ===========================================================================
//
// Until 2026-08-10 RenderLinuxWinn3ResolverCommands emitted `resolvectl dns
// <iface> <ip>` and nothing else, and this header told a caller with no
// systemd-resolved to refuse promotion. That is not a policy, it is a platform
// restriction wearing a policy's clothes: BuildPromotedPosture refuses to
// promote with an empty resolver set (winn3_posture.h:794-803, and that refusal
// is CORRECT and stays), so on any Linux without systemd-resolved -- a
// container, Alpine or any other musl distro, a machine using plain
// /etc/resolv.conf or openresolv -- `resolvectl` is absent or cannot reach its
// bus, the command exits non-zero, and PROMOTION CAN NEVER SUCCEED. Measured on
// 2026-08-10: `resolvectl dns winsvpn3 10.64.0.1` -> exit 127 inside the
// real-kernel-tun lab, with both capturing /1 routes already installed.
//
// So the mechanism is DETECTED, by probing the host, and the three mechanisms
// below are supported. The mechanism that was chosen is carried in the posture
// result and published in this host's status document, because an operator
// looking at a machine whose DNS is wrong needs to know which of three code
// paths touched it.
// ---------------------------------------------------------------------------
enum class LinuxWinn3ResolverMechanism {
  // Not probed yet. Never a mechanism a command may be rendered for.
  kUnknown,
  // systemd-resolved, per link: `resolvectl dns <iface> <ips>` plus the `~.`
  // routing domain. Reverted with `resolvectl revert <iface>`.
  kSystemdResolved,
  // resolvconf / openresolv, per interface: the resolv.conf body is fed to
  // `resolvconf -a <iface>` ON STANDARD INPUT -- there is no argument form --
  // and removed with `resolvconf -d <iface>`.
  kResolvconf,
  // Direct /etc/resolv.conf rewrite. LAST RESORT, and the only mechanism that
  // can outlive the process; see RenderLinuxWinn3ResolverCommands for the
  // backup, the restore and what happens on an abnormal exit.
  kResolvConfFile,
  // Nothing on this host can install a resolver. Promotion must refuse, which
  // is the same answer BuildPromotedPosture already gives for an empty resolver
  // set and for the same reason.
  kNone,
};

// The stable short name, for logs and for the status document.
const char* LinuxWinn3ResolverMechanismName(LinuxWinn3ResolverMechanism value);

// ---------------------------------------------------------------------------
// The session parameters.
// ---------------------------------------------------------------------------
struct LinuxWinn3Params {
  // The tun interface this host creates and owns. Deliberately NOT `winsvpn`:
  // that name belongs to awg-quick on the winn/1 path, and a v3 session that
  // reused it could collide with a v1 teardown that is still running.
  std::string interface_name = "winsvpn3";

  // The real gateway, an IP literal "host:port". Never a hostname: resolving
  // one here would be a DNS lookup on the censored path, which is the exact
  // observable the staged posture exists to avoid.
  std::string gateway_endpoint;

  // The inner assignment and the inner next hop.
  std::string inner_address;
  std::string inner_next_hop;

  // The gateway's INNER DNS RESPONDER address, off the same ML-DSA-65-signed
  // descriptor `inner_next_hop` arrives on (`[winn] inner_resolver_v4`). Empty
  // on every descriptor that exists today.
  //
  // PARSED, STORED, AND SINCE 2026-08-12 CONSUMED -- BY DERIVATION, NEVER BY
  // ASSIGNMENT.
  //
  // The value had to be a KNOWN key before the control plane started emitting
  // it, because ParseLinuxWinn3Section refuses an unrecognised `[winn]` key
  // outright and would take standalone v3 down on this platform the day the
  // descriptor bumps -- not degrade DNS, refuse the whole configuration. The
  // `psk` branch below exists for exactly this reason and says so.
  //
  // It is now carried into `winsvpn::winn3::PostureInput::inner_resolver_v4`
  // and checked by `resolvers::NotInnerReason` in winn3_posture.h, which is
  // Apple's `WinsWinn3Resolvers` and Android's `WinnV3Resolvers` mirrored
  // clause for clause against the same hard 0xFFFFFF00 /24 floor. The hub pool
  // is pinned to a /24 precisely so that all four clients can derive against
  // that constant and agree about one descriptor.
  //
  // The line that must not be crossed, and the reason this comment is long:
  // NOTHING sets `dns_servers_are_inner` from this field. That boolean is a
  // host DECLARATION (winn3_posture.h calls it "the host's own declaration",
  // written into a local `[winn3]` file by somebody holding the machine),
  // whereas Apple and Android DERIVE the same predicate from address shape and
  // never accept it on the wire. Assigning the boolean from a served field
  // would turn a derived guarantee into a transported one -- the shape
  // conform.ServedWinnSectionCarriesNoPostureKey exists to forbid. The derived
  // path in BuildPromotedPosture does not read the boolean at all; it
  // re-derives, and refuses when it cannot.
  std::string inner_resolver;

  // The OUTER path MTU the floor is computed at. Zero means
  // sizing::kDefaultPathMtu.
  int path_mtu = 0;

  // Every class the session may escalate TO, never the one dialled. Empty is
  // refused rather than defaulted.
  std::vector<std::string> carrier_classes;

  // Opaque, echoed in the status document so a host can correlate a status line
  // to the tunnel it asked for. Never put on the wire.
  std::string session_id;

  // Node binding carried from the verified descriptor assembly path.
  std::string descriptor_node;
  std::string selected_node;

  // The routes and resolvers the PROMOTED posture installs. Ignored entirely
  // while building the bootstrap posture.
  std::vector<std::string> full_routes;
  std::vector<std::string> dns_servers;

  // The host's declaration that every resolver above is reachable ONLY through
  // the tunnel. Required before any resolver is installed at promotion; see
  // winn3_posture.h:118-127.
  bool dns_servers_are_inner = false;

  // Whether a machine with neither systemd-resolved nor resolvconf may be
  // promoted by rewriting /etc/resolv.conf directly.
  //
  // True by default, because false means a plain-resolv.conf Linux can never
  // promote at all -- which is the defect this flag sits beside rather than a
  // safe default. It is here so a deployment that would rather refuse than
  // accept the one window that mechanism has (a hard kill, then never starting
  // again; see RenderLinuxWinn3ResolverCommands) can choose that, and get a
  // refusal that names itself instead of a silent difference in behaviour.
  bool allow_direct_resolv_conf = true;

  // Pins the resolver mechanism instead of probing for it. kUnknown -- the
  // default -- means detect, which is what a shipping session does.
  //
  // It is here for an operator who knows their fleet and would rather state the
  // mechanism than have each machine probe for it, and it is what a test uses
  // to drive one mechanism's commands at a host that would have chosen another.
  // A pinned mechanism is NOT verified: pinning systemd-resolved on a machine
  // that has none produces exactly the failure of 2026-08-10, which is the
  // point when the pin is a test and the risk when it is a deployment.
  LinuxWinn3ResolverMechanism resolver_mechanism_override =
      LinuxWinn3ResolverMechanism::kUnknown;

  // The outer-socket exclusion, as the two facts it needs: the physical
  // interface the gateway is reachable on and the next hop on it. Both are
  // required. The host reads them from `ip route get <gateway>` BEFORE it
  // installs anything, which is the only moment they can be read honestly --
  // after promotion the answer is the tunnel.
  std::string physical_interface;
  std::string physical_next_hop;

  // The key files, by absolute path.
  LinuxWinn3Keys keys;
};

// Splits "1.2.3.4:51820" or "[2001:db8::1]:51820" into host and port, refusing
// anything that is not an IP literal with a nonzero port.
bool SplitLinuxWinn3Endpoint(const std::string& endpoint, std::string* host,
                             std::string* port);

// ---------------------------------------------------------------------------
// The served `[winn]` section.
//
// ===========================================================================
// WHAT WAS MISSING HERE, AND IT WAS NOT A SPELLING
// ===========================================================================
//
// Apple, Android and Windows each read a `[winn]`-shaped document for winn/3
// and each read a DIFFERENT one, which is the divergence this contract exists
// to close. Linux read none. Everything above this line -- the sizing mirror,
// the key document, the create payload, both postures, the promotion predicate
// -- was written and tested, and the only thing that could ever fill
// LinuxWinn3Params was a caller writing the struct out by hand. There is no
// such caller: linux_tunnel_backend.cc parses `[winn]` with
// ParseLinuxWinnSection, which is the winn/1 AmneziaWG path and knows nothing
// about v3.
//
// So Linux was not diverging from the served contract, it was ABSENT from it.
// That is a worse state and a quieter one: a divergence shows up the first time
// two hosts are compared, and an absence shows up as a platform that simply
// never appears in the comparison at all.
//
// ===========================================================================
// THE CARRIER SELECTS, THE SECTION DOES NOT
// ===========================================================================
//
// `carrier = winn3` is the discriminator, exactly as on Apple and (since
// 2026-08-09) on Windows. ParseLinuxWinnSection refuses any carrier it cannot
// build, so the two parsers cannot both claim one configuration.
//
// ===========================================================================
// THIS HOST WRITES THE KEY FILES; THE DOCUMENT STILL HOLDS ONLY PATHS
// ===========================================================================
//
// A served section carries key VALUES, base64, because the control plane cannot
// name a path on a device it has never seen. `LinuxWinn3Keys` still holds only
// paths and the engine still opens the files itself -- see
// WriteLinuxWinn3KeyFiles, which writes them 0600 beside the key document.
// ---------------------------------------------------------------------------

// The `[winn] carrier` value that selects a STANDALONE v3 session.
// lib/winn_protocol_dispatch.dart's kWinnCarrierWinn3.
inline constexpr char kLinuxWinnCarrierWinn3[] = "winn3";

// True for a configuration carrying `[winn] carrier = winn3`.
//
// A configuration that does not select v3 is not this host's business, and this
// never speaks for the winn/1 parser.
bool LinuxConfigSelectsWinn3(const std::string& raw_config);

// Normalize the hub node-slug alphabet without Unicode or locale folding.
bool NormalizeLinuxWinn3NodeIdentity(const std::string& raw, std::string* out);

// The base64 key material a served section carries, before it becomes files.
//
// Held separately from LinuxWinn3Params on purpose: params carries PATHS and is
// what the rest of this header consumes, and nothing downstream of the parse
// should be able to reach a key value even by accident.
struct LinuxWinn3ServedKeyMaterial {
  // The 32 raw X25519 key bytes, decoded. `winn3ReadKeyFile` accepts 32 raw
  // bytes as readily as 64 hex characters, so nothing is re-encoded: one fewer
  // encoding is one fewer place two ends can disagree about a value neither of
  // them ever transmits.
  std::string static_private;
  std::string gateway_static;

  // The admission secret's OWN BYTES -- keygen's 64 ASCII hex characters --
  // with the transport base64 removed and NOTHING ELSE DONE TO THEM. Never
  // hex-decoded: that keys 32 bytes against the gateway's 64, and the gateway
  // then admits the datagram, BUILDS a session and goes completely silent.
  std::string admission_secret;

  // Dual-signature attestation public keys, already lowercase hex. Empty as a
  // pair on a legacy session. ParseLinuxWinn3Section refuses a half pair.
  std::string auth_ed25519_hex;
  std::string auth_mldsa65_hex;
};

// ParseLinuxWinn3Section parses and validates a served `[winn]` section.
//
// AN UNRECOGNISED KEY IS A REFUSAL rather than something to drop, matching
// ParseWinn3Section, ParseWindowsWinnSection, WinnEngineConfig.from and
// loadWinn3Profile's DisallowUnknownFields. A host that misspells a key and is
// told nothing believes a setting took effect that did not, and the settings
// that could silently not take effect here are the migration plan and the inner
// address.
//
// `params->keys` is filled with everything EXCEPT the three paths, which are
// only knowable once WriteLinuxWinn3KeyFiles has chosen a directory. Never
// partially fills either output.
bool ParseLinuxWinn3Section(const std::string& raw_config,
                            LinuxWinn3Params* params,
                            LinuxWinn3ServedKeyMaterial* material,
                            std::string* error);

// Bind the two served node fields to the independently selected Flutter
// picker slug before a native tunnel start is admitted.
bool ValidateLinuxWinn3IndependentSelectedNode(
    const std::string& raw_config, const std::string& caller_selected_node,
    std::string* error);

bool RemoveLinuxWinn3KeyFiles(std::string* error);

// Writes the three required key files 0600 under the per-user private data
// directory, plus the dual-auth public-key pair when the served section
// carried one, and fills `params->keys`' path fields.
//
// Mode is set BEFORE any bytes are written, so a secret is never briefly
// world-readable -- the same rule WriteLinuxWinn3KeysDocument follows, and for
// the same reason. A legacy session unlinks leftover dual-auth files so a
// stale pair cannot be rebound.
bool WriteLinuxWinn3KeyFiles(const LinuxWinn3ServedKeyMaterial& material,
                             LinuxWinn3Params* params, std::string* error);

// Builds the OpCreate payload for `-winn3` frame mode.
//
// Three fields are fixed and no caller can override them:
//   payload           "ip-packet". `awg-datagram` here would ask a v3 engine to
//                     forward AmneziaWG datagrams it has no implementation for.
//   owns_tun          false. THIS host owns the device.
//   allow_own_socket  true, and honest only because the caller has installed
//                     the destination-scoped exclusion first and declared it in
//                     the key document. `-transport stdio` cannot carry a
//                     descriptor, so the engine opens its own socket and this
//                     is the only combination winn3_create.go refusal 4 admits.
//
// `inner_mtu` is the plan floor and equality with it is checked here as well as
// in the engine, so a sizing drift is a failed unit test on this side rather
// than a failed start on a user's machine.
bool BuildLinuxWinn3CreateJson(const LinuxWinn3Params& params, std::string* out,
                               std::string* error);

// ---------------------------------------------------------------------------
// Rendering. Argument vectors, never shell strings: the caller executes an
// argv, and a renderer that emitted shell syntax would invite the quoting bug
// argument vectors exist to remove.
// ---------------------------------------------------------------------------

// The one-sentence description of the exclusion, for the key document and for
// the log. Built from the same fields the commands below render.
std::string DescribeLinuxWinn3Exclusion(const LinuxWinn3Params& params);

// `ip route add <gateway>/32 via <next hop> dev <physical interface>`.
//
// Empty when the parameters cannot describe an exclusion, which every caller
// must treat as a refusal: BuildBootstrapPosture already refuses an empty
// outer_socket_exclusion, and a v3 session without this exclusion sends its own
// outer datagrams into the tunnel it carries the moment promotion widens the
// routes.
std::vector<std::vector<std::string>> RenderLinuxWinn3ExclusionCommands(
    const LinuxWinn3Params& params);

// The exclusion's removal, for teardown -- and, since 2026-08-10, for the
// REPAIR that opens every bootstrap.
//
// One vector with one token swapped, so the add and the del cannot describe
// different routes. That property is what makes this safe to run speculatively
// at the start of a session: `ip route del` carrying both `via` and `dev` is
// matched by the kernel on both (fib_table_delete skips any entry whose oif or
// gw differs from the request), so this removes the exclusion THIS PRODUCT
// writes and is incapable of removing a route to the same destination that
// somebody else wrote. See ApplyLinuxWinn3BootstrapPosture for why that
// distinction is the whole rule.
std::vector<std::vector<std::string>> RenderLinuxWinn3ExclusionTeardown(
    const LinuxWinn3Params& params);

// The PostureInput winn3_posture.h takes, assembled from the session
// parameters and this host's exclusion description. One assembler, so the
// bootstrap and the promotion cannot be built from two different inputs.
winsvpn::winn3::PostureInput LinuxWinn3PostureInput(
    const LinuxWinn3Params& params);


// One command, and the standard input it needs.
//
// `stdin_bytes` exists because openresolv has NO argument form: `resolvconf -a
// <iface>` reads the resolv.conf body from standard input, and the direct
// rewrite writes a file the same way. It is a byte string handed to the
// executor, never a shell fragment -- the argv discipline this header states
// at the top is unchanged, and nothing here is ever interpolated into a
// command line.
//
// `best_effort` marks a teardown command whose failure is NOT a failed
// teardown: `resolvectl revert` on an interface the kernel has already removed
// fails, and treating that as an error would report every clean stop as dirty.
struct LinuxWinn3Command {
  std::vector<std::string> argv;
  std::string stdin_bytes;
  bool best_effort = false;
};

// Resolver commands for the promoted posture, for ONE mechanism.
//
// winn3_posture.h's RenderLinuxPostureCommands deliberately renders no
// resolver -- there is no single Linux mechanism to render -- so a caller that
// used it alone would silently drop every resolver BuildPromotedPosture put in
// the plan. That silent drop is the defect this exists to prevent: name
// resolution over the censored path is exactly what DNS-at-promotion is for.
//
// Empty for kNone and kUnknown, and empty when the plan carries no resolver.
// An empty return is therefore never "install nothing and promote anyway": the
// caller checks the mechanism, and BuildPromotedPosture has already refused the
// empty resolver set before this is reached.
//
// ===========================================================================
// THE /etc/resolv.conf PATH, AND WHAT HAPPENS IF THIS PROCESS IS KILLED
// ===========================================================================
//
// kResolvConfFile is the one mechanism whose effect outlives this process. If
// the host dies after the rewrite, the tun device disappears with its last
// descriptor and every route on it goes with it -- but /etc/resolv.conf does
// not, and the user is left pointing at a resolver inside a tunnel that no
// longer exists. Their name resolution stops working and nothing on the
// machine says why. That is the same fail-open class as the defect above, so
// it is designed for rather than hoped about:
//
//   1. THE BACKUP IS PERSISTENT, not in /run. /run is a tmpfs and a reboot
//      would destroy the only copy of the user's original resolvers, turning a
//      recoverable state into a permanent one. It is
//      /var/lib/winsvpn/winn3-resolv.conf.orig.
//   2. THE FILE EXPLAINS ITSELF. The rewritten /etc/resolv.conf opens with
//      comment lines naming this product, saying the original was saved and
//      giving its absolute path. An operator who finds a stranded machine
//      reads the cause out of the file that is causing it.
//   3. THE NEXT START REPAIRS IT. A backup that already exists when promotion
//      begins means a previous session was killed before its teardown ran, so
//      it is restored FIRST and re-taken, and the backup is therefore always
//      the user's own resolv.conf and never a previous session's tunnel one.
//
// What remains, stated rather than hidden: a machine killed hard and then
// never started again keeps the tunnel resolvers until someone acts on the
// comment block. That is why kResolvConfFile is the LAST mechanism tried, and
// why LinuxWinn3Params::allow_direct_resolv_conf can switch it off for a
// deployment that would rather refuse to promote than accept that window.
std::vector<LinuxWinn3Command> RenderLinuxWinn3ResolverCommands(
    const std::string& interface_name, const winsvpn::winn3::PosturePlan& plan,
    LinuxWinn3ResolverMechanism mechanism);

// The removal of whatever the mechanism above installed. Best effort by
// construction; see LinuxWinn3Command::best_effort.
std::vector<LinuxWinn3Command> RenderLinuxWinn3ResolverTeardown(
    const std::string& interface_name, LinuxWinn3ResolverMechanism mechanism);

// Re-checks the RENDERED bootstrap commands, after the plan-level check.
//
// winsvpn::winn3::VerifyBootstrapIsNarrow checks the PLAN. This checks what
// will actually be EXECUTED, which is not the same object and not the same
// risk: a renderer that emitted the default-route pair for a plan whose
// `default_route` is false would sail past every plan-level check in the
// system, and the plan is not what moves the user's traffic -- the argument
// vectors are. The shared renderer is used by two desktop hosts and a change to
// it for one of them lands on the other, so the last thing between the policy
// and the kernel is worth checking on its own terms.
//
// It is given the POSTURE commands only, never the exclusion: the exclusion is
// legitimately an `ip -6` command when the gateway is reachable over IPv6, and
// a check that could not tell those apart would refuse a working session.
bool VerifyLinuxWinn3BootstrapCommandsAreNarrow(
    const std::vector<std::vector<std::string>>& commands, std::string* error);

// Teardown, in the order that leaves the host safest if it stops part way:
// the promoted default-route halves first, as explicit `ip route del` (best
// effort, and the mirror of the start path's `add`s), then the resolvers,
// then the link, then the exclusion.
//
// The /1 pair is deleted EXPLICITLY rather than only by deleting the link.
// The link deletion does sweep tun-scoped routes -- when it runs. A teardown
// that stops part way, or a host whose link delete was refused, must not be
// left with the /1 pair still pointing at a device that is about to go away,
// which is the state the fleet measured after a stop that ran neither half of
// the v3 teardown. The dels are best effort because the engine's tun
// descriptor close, which StopLinuxWinn3Standalone performs first, usually
// deletes the interface and the routes with it before they run.
//
// The exclusion is removed LAST on purpose. While it is still installed the
// gateway is merely reachable by its own physical path, which is what it was
// before the tunnel existed; removing it first would leave a window in which
// tunnel routes still exist and the engine's own datagrams match them.
//
// `mechanism` is the one the promotion actually used, from the posture result.
// Passing kUnknown renders no resolver removal at all, which is right for a
// session that never promoted and wrong for one that did -- so a caller keeps
// the mechanism it was given rather than re-detecting at teardown, when the
// answer can already have changed.
std::vector<LinuxWinn3Command> RenderLinuxWinn3TeardownCommands(
    const LinuxWinn3Params& params, LinuxWinn3ResolverMechanism mechanism);

// ---------------------------------------------------------------------------
// The promotion gate.
// ---------------------------------------------------------------------------

// Three states rather than two, for the reason WinnTransportGate gives on the
// winn/1 side: "not proven yet" and "can never be proven" call for opposite
// handling, and collapsing them is what produced the fail-open that lane found.
enum class LinuxWinn3Promotion {
  // promotion_ready is true. This is the ONLY value that may widen a posture.
  kPromote,
  // No proof yet and nothing says there cannot be one. Keep polling until the
  // caller's deadline; the deadline itself is fail-closed.
  kNotYet,
  // This session can never produce the proof. Refuse now rather than spend the
  // budget on a verdict already known.
  kRefuse,
};

// Decides over the engine's own status document.
//
// It reads `promotion_ready`, which cmd/winn-datapath computes ONCE, in Go,
// beside the counters, as `Gate.State() == StateCarrying && Stats().RxPackets
// > 0`. This host does not recompute that conjunction: two hosts computing it
// in two languages will eventually compute it differently, and the obvious
// mistake -- rx_offered for rx_packets -- is the difference between "a payload
// arrived" and "an inner packet was validated and reached the host device".
//
// It is nonetheless not a bare boolean read. A document that says ready with
// zero deliveries disagrees with itself, and BuildPromotedPosture refuses it;
// this refuses it here too, so the disagreement is diagnosed at the gate rather
// than surfacing as an unexplained posture failure.
//
// `engine_running` is the caller's liveness answer. An engine that has exited
// answers with an empty document forever, so a caller that kept polling would
// spend its whole budget on nothing.
//
// *reason receives a non-secret sentence. The v3 status document carries no
// endpoint, no address and no session identifier (winn3_status.go:81-85), so
// unlike the winn/1 document it is safe to quote -- but the refusal text is
// written from the parsed fields anyway, so a future field cannot leak into it.
LinuxWinn3Promotion DecideLinuxWinn3Promotion(
    bool engine_running, const std::string& status_json,
    winsvpn::winn3::EngineStatus* parsed, std::string* reason);

// ---------------------------------------------------------------------------
// The privileged executor.
//
// Supplied by the caller. Returns true when the argument vector ran and
// succeeded. Nothing in this file ever executes one.
//
// `stdin_bytes` is written to the command's standard input, which is then
// closed; an empty string means the command gets no input and must see EOF
// immediately. It is not optional and it is not a convenience: openresolv has
// no argument form for the resolvers it installs, so a runner that could not
// carry standard input would leave `sh -c` as the only way to reach it, and a
// shell string is exactly the quoting bug argument vectors exist to remove.
// ---------------------------------------------------------------------------
using LinuxWinn3PrivilegedRunner =
    std::function<bool(const std::vector<std::string>& argv,
                       const std::string& stdin_bytes, std::string* error)>;

// Probes this host and returns the mechanism a promotion would use.
//
// EVERY BRANCH IS A PROBE, NOT A GUESS. The systemd-resolved test runs
// `resolvectl --no-pager status`, which touches the D-Bus service rather than
// only the binary: a machine that has /usr/bin/resolvectl and no running
// resolved answers a version query happily and fails every real one, and
// choosing the mechanism off the binary's existence is how the 2026-08-10 run
// arrived at a half-applied posture. The order is systemd-resolved, then
// resolvconf/openresolv, then the direct file, then kNone, and it is the order
// of how well the host itself manages the change: the first two are undone by
// a single command the system already understands, and the third is a file
// this host has to put back.
//
// *detail, when non-null, receives a non-secret sentence naming what was
// probed and what answered -- the same shape DecideLinuxWinn3Promotion's
// reason takes, and safe to log.
LinuxWinn3ResolverMechanism DetectLinuxWinn3ResolverMechanism(
    const LinuxWinn3Params& params, const LinuxWinn3PrivilegedRunner& run,
    std::string* detail);

// ---------------------------------------------------------------------------
// THE RESULT OF A POSTURE ATTEMPT, WHICH IS NOT A BOOLEAN
// ===========================================================================
//
// BOTH appliers return this type. `ApplyLinuxWinn3PromotedPosture` stopped
// being a boolean earlier on 2026-08-10, for the reason below;
// `ApplyLinuxWinn3BootstrapPosture` stopped later the same day, for a DIFFERENT
// measured reason set out at its own declaration further down. The two hazards
// are not the same and the header says so in both places rather than asserting
// symmetry -- but the shape that answers them is the same shape, and one
// vocabulary the caller has to learn once is worth more than two that differ in
// their spelling and not in their meaning.
//
// It used to be. `ApplyLinuxWinn3PromotedPosture` ran its rendered commands in
// order, stopped at the first failure and returned false, and the false said
// nothing about how far it had got. Measured on 2026-08-10, one run:
//
//   ip route add 0.0.0.0/1 dev winsvpn3      -> exit 0
//   ip route add 128.0.0.0/1 dev winsvpn3    -> exit 0
//   resolvectl dns winsvpn3 10.64.0.1        -> exit 127
//   ApplyLinuxWinn3PromotedPosture           -> returned FALSE
//
// Both capturing routes stayed installed. `ip route get 1.1.1.1` afterwards
// answered `dev winsvpn3 src 10.64.0.2` -- the full tunnel was live -- while
// the function told its caller promotion had not happened. A caller reading
// false as "nothing was applied", which is the natural reading and the one the
// comment above implied, has a machine whose entire default route is captured
// while its own state says bootstrap. For a user in Myanmar that is the worst
// shape of failure available: they believe they are unprotected and are
// routing everything into a tunnel nobody is managing, or the reverse.
//
// WHY A RESULT TYPE RATHER THAN ONLY A ROLLBACK. A rollback can itself fail
// part way, and a rollback that fails silently leaves a THIRD state nobody
// enumerated -- which is the same defect one layer down. So the rollback is
// attempted (a machine that can be put back in the narrow posture should be),
// and its outcome is a VALUE the caller receives: kRolledBack when every
// applied command was reversed, kPartiallyApplied when one was not. Neither of
// those is kApplied and neither can be mistaken for it.
//
// WHY IT IS NOT CONVERTIBLE TO bool. There is deliberately no operator bool
// and no `ok` field. Every existing `if (!ApplyLinuxWinn3PromotedPosture(...))`
// is now a COMPILE ERROR rather than a silently-wrong reading, because a new
// return shape that callers can discard fixes nothing at all. That is not a
// theory about compilers, and the two changes were rejected in two different
// words, which is worth writing down rather than smoothing over:
//
//   promoted, 2026-08-10 -- `no match for 'operator!' (operand type is ...
//     LinuxWinn3PostureResult)` at each of its four call sites.
//   bootstrap, 2026-08-10 -- `too many arguments to function` at all five of
//     its own, because dropping the `std::string* error` out-param (the result
//     carries the sentence now) changes the arity as well as the type. The
//     driver's site drew BOTH that and `cannot convert
//     'LinuxWinn3PostureResult' to 'const bool' in initialization`, which is
//     the one that proves the type is not bool-convertible.
//
// And `[[nodiscard]]` closes the remaining hole: a caller that simply calls
// either function and drops the value is `-Werror=unused-result`, measured.
// The compile errors ARE the caller-side migration.
enum class LinuxWinn3PostureOutcome {
  // Every command succeeded. The ONLY value that means the posture is in place
  // -- promoted for the promoted applier, narrow-and-excluded for the bootstrap.
  kApplied,
  // Refused before a single command ran, so the kernel is untouched by this
  // call: exactly as the bootstrap left it for a promotion, exactly as it was
  // before the session for a bootstrap. The cheap, common, safe failure, and
  // the ONLY failure after which an immediate retry is known to be clean.
  kNotAttempted,
  // A command failed after others had succeeded, AND every one that had
  // succeeded was reversed. For a promotion the kernel is back in the narrow
  // posture: not promoted, not capturing, and it may keep running unpromoted or
  // be torn down. For a bootstrap the kernel is back to before the session and
  // NOTHING of this attempt outlives the process -- so a retry is clean.
  kRolledBack,
  // A command failed after others had succeeded and the reversal did not fully
  // succeed. Something this call installed is STILL IN THE KERNEL, and which
  // hazard that is depends on the posture:
  //   promoted  -- IT MAY STILL BE CAPTURING. Read `capturing`. The session
  //                must be torn down rather than left running.
  //   bootstrap -- it cannot be capturing, but read `exclusion_installed`: the
  //                outer-socket exclusion is a host route on the PHYSICAL
  //                interface, so unlike everything on the tun it does not go
  //                when the descriptor closes, and it is the first command the
  //                NEXT bootstrap runs.
  // This is the state the old booleans both reported as plain `false`.
  kPartiallyApplied,
  // BOOTSTRAP ONLY. The outer-socket exclusion could not be installed, and the
  // repair that runs before it did not clear the way -- so the destination this
  // session must reach by its physical path is routed by an entry THIS HOST DID
  // NOT WRITE. Nothing was applied and nothing was reversed; `applied` is empty
  // and `exclusion_installed` is false, because the route in the way is not
  // ours and counting it as our residue would invite a teardown to delete
  // somebody else's route.
  //
  // IT IS A SEPARATE VALUE BECAUSE EVERY OTHER VALUE WOULD LIE ABOUT THE RETRY.
  // That is the whole argument, and it is the same argument kPartiallyApplied
  // was added on:
  //   kNotAttempted     promises the executor was never reached and a retry is
  //                     clean. The executor WAS reached, and a retry fails
  //                     identically until someone removes that route.
  //   kRolledBack       promises "a retry starts clean". Same lie, louder.
  //   kPartiallyApplied promises something WE installed is still in the kernel,
  //                     which would point a repair at the wrong route.
  // A caller that meets this must not retry on a timer. It must surface the
  // destination to the operator; the sentence in `error` names it and gives the
  // one read-only command that shows what is there.
  kExclusionBlocked,
};

// The stable short name, for logs and for the status document.
const char* LinuxWinn3PostureOutcomeName(LinuxWinn3PostureOutcome value);

struct LinuxWinn3PostureResult {
  LinuxWinn3PostureOutcome outcome = LinuxWinn3PostureOutcome::kNotAttempted;

  // WHICH posture this result describes. Carried in the value rather than
  // inferred from which function the caller happened to call, because the two
  // hazard fields below are read differently for each and a result that has
  // been passed, logged or stored no longer remembers its origin.
  winsvpn::winn3::Posture posture = winsvpn::winn3::Posture::kPromoted;

  // Why, in a non-secret sentence. Empty only for kApplied.
  std::string error;

  // The commands that RAN AND SUCCEEDED, in the order they ran. This is the
  // answer to "how far did it get", which the boolean could not carry.
  std::vector<std::vector<std::string>> applied;

  // The one that failed. Empty for kApplied and for kNotAttempted.
  std::vector<std::string> failed;

  // Whether what is still installed captures traffic, decided by
  // winsvpn::winn3::VerifyPromotedCommandsCapture over the commands that are
  // actually in the kernel -- the same predicate that decides whether a
  // promotion widened at all, asked about the residue instead of the intent.
  // A caller reading a PROMOTED result and nothing else must read this one.
  //
  // For a bootstrap result it is STRUCTURALLY false, and that is a fact about
  // the posture rather than a shortcut here: VerifyBootstrapIsNarrow and
  // VerifyLinuxWinn3BootstrapCommandsAreNarrow both run before a single
  // bootstrap command, so no command that could capture was ever in the list to
  // survive. It is computed by the same predicate over the same residue anyway,
  // so the field has ONE meaning in every outcome of both appliers instead of
  // two. A bootstrap caller must read the next field instead.
  bool capturing = false;

  // Whether the outer-socket exclusion -- `ip -4 route add <gw>/32 via <hop>
  // dev <physical>` -- is in the kernel as of this call returning.
  //
  // This is the BOOTSTRAP's hazard field, and it asks a different question from
  // `capturing` rather than a weaker version of it. `capturing` asks whether
  // the residue moves the user's traffic. This asks whether the residue
  // SURVIVES THIS PROCESS. A tun opened with TUNSETIFF and no TUNSETPERSIST
  // disappears with its last descriptor and takes every address and route on it
  // with it, so everything a promoted posture installs is swept away by the
  // process dying. The exclusion is on the interface the machine KEEPS, and is
  // swept away by nothing.
  //
  // MEASURED 2026-08-10 -- real kernel, real `ip`, exclusion installed and the
  // very next command refused, kernel asked after the process had exited:
  //
  //   ip route show      -> `172.31.77.2 via 172.31.77.1 dev eth0`  (survives)
  //   ip -4 route add 172.31.77.2/32 via 172.31.77.1 dev eth0
  //                      -> `RTNETLINK answers: File exists`, exit 2
  //
  // Read it with `outcome`, the way `capturing` is read with `outcome`:
  //   kApplied          + true -> normal. The session owes a teardown, and
  //                               RenderLinuxWinn3TeardownCommands removes it
  //                               LAST for the reason stated there.
  //   kRolledBack       + false -> nothing of this attempt outlives the process.
  //   kPartiallyApplied + true -> the reversal of the exclusion FAILED. The next
  //                               bootstrap on this machine will fail on its
  //                               first command with EEXIST, permanently, with
  //                               no message naming the cause.
  //
  // Computed structurally -- a surviving command scoped to a device that is not
  // the tun -- rather than by matching the exclusion's own argument vector. The
  // exclusion is today the only command a Winn v3 posture puts on the physical
  // interface, and computing it this way means a future one is counted without
  // anyone having to remember to count it.
  //
  // NOT a general "does anything outlive this process" flag, and deliberately
  // not named as one: the /etc/resolv.conf resolver mechanism also leaves state
  // a dying process will not clean up, and the field that tells a caller about
  // THAT is `resolver_mechanism` below, whose kResolvConfFile value is the
  // whole subject of the promoted lane's stranding section.
  bool exclusion_installed = false;

  // Whether a PREVIOUS process's outer-socket exclusion was found in the kernel
  // and removed before this attempt ran its first command.
  //
  // True is not an error and not a warning about this session -- it is this
  // session reporting on the LAST one. It means the machine was carrying a
  // stranded `<gw>/32 via <hop> dev <phys>` when the bootstrap began, which is
  // what a SIGKILL between the exclusion and the teardown leaves, and what a
  // kPartiallyApplied result with `exclusion_installed` true leaves. Without the
  // repair that route makes the very next `ip route add` -- the first command of
  // every later bootstrap -- fail EEXIST forever.
  //
  // It is worth carrying out to the caller rather than being silent because it
  // is the only in-band evidence that a previous session died hard. A host that
  // reports this on every start is a host something is killing.
  //
  // Always false on a promoted result: the promotion does not install the
  // exclusion and does not repair it.
  bool stale_exclusion_repaired = false;

  // The reversal, when there was one.
  bool rollback_attempted = false;
  std::vector<std::vector<std::string>> rollback_failed;

  // Which resolver mechanism this attempt chose, and why. Carried out to the
  // caller so a teardown removes what was installed rather than what a second
  // detection would guess, and published in the status document.
  //
  // Always kUnknown on a bootstrap result, and not from an oversight: the
  // bootstrap posture installs NO resolver at all. BuildBootstrapPosture leaves
  // `dns_servers` empty and the tests assert it, because the route set and the
  // resolver set move together or neither moves -- and the bootstrap moves
  // neither. A bootstrap that reported a mechanism would be reporting a
  // detection it never ran.
  LinuxWinn3ResolverMechanism resolver_mechanism =
      LinuxWinn3ResolverMechanism::kUnknown;
  std::string resolver_detail;
};

// One line for a log or an event, naming the posture, the outcome, the residue,
// the mechanism and the counts. Contains no address and no key path.
std::string DescribeLinuxWinn3PostureResult(
    const LinuxWinn3PostureResult& result);

// ---------------------------------------------------------------------------
// Applies the bootstrap posture: the exclusion first, then the narrow link.
//
// The ORDER is the contract, not an implementation detail. The exclusion is
// installed from the FIRST posture (winn3_posture.h:344-350) because installing
// it later means installing it after traffic has already been captured.
//
// The plan is built by winsvpn::winn3::BuildBootstrapPosture and then re-checked
// by VerifyBootstrapIsNarrow before one command runs -- the built object is
// checked rather than the builder trusted, which is the shape the iOS provider
// already uses and the shape the tun contract asks the other four platforms to
// copy verbatim.
//
// `status` is the CreateAck's document, which is where the authoritative
// inner MTU comes from. Passing an invalid one is a refusal: without it the MTU
// is unknown and a bootstrap posture with no MTU is not a posture.
//
// ===========================================================================
// WHY THIS ALSO STOPPED BEING A BOOLEAN, 2026-08-10
// ===========================================================================
//
// It returned `bool` and ran its commands through a shared `RunAll` helper --
// since deleted, because this was its last caller -- which stops at the first
// failure, so the `false` could not say how far it had got. The
// mitigating fact is real and it is stated first, because it is the reason this
// was NOT simply assumed to need the same treatment as the promotion:
//
//   NOTHING THE BOOTSTRAP INSTALLS CAPTURES TRAFFIC. A /32 inner address, an
//   MTU, and one /32 host route to the inner next hop. A half-applied bootstrap
//   cannot put the user's default route on a tunnel nobody is managing, which
//   is exactly what a half-applied promotion could and did.
//
// So the question was decided by measurement rather than by symmetry. In the
// real-kernel container, with the exclusion installed and the very next command
// (`ip -4 address add`) made to fail, the kernel was asked directly after the
// process exited:
//
//   ip -4 route add 172.31.77.2/32 via 172.31.77.1 dev eth0  -> exit 0
//   ip -4 address add 10.64.0.2/32 dev winsvpn3              -> refused
//   ApplyLinuxWinn3BootstrapPosture                          -> FALSE
//
//   $ ip route show
//   default via 172.31.77.1 dev eth0
//   172.31.77.0/24 dev eth0 proto kernel scope link src 172.31.77.3
//   172.31.77.2 via 172.31.77.1 dev eth0        <-- survived the process
//
//   $ ip -4 route add 172.31.77.2/32 via 172.31.77.1 dev eth0
//   RTNETLINK answers: File exists              <-- exit 2
//
// THE SECOND MEASUREMENT IS THE RULING. The tun device did not survive -- it
// never does -- so the address and the inner-next-hop route are not the
// hazard. The exclusion is, because it is on the physical interface, and
// because the command that fails EEXIST above is verbatim the FIRST command
// this function runs. One half-applied bootstrap therefore refuses every later
// session on that machine, permanently, with no message that names the reason.
// That is not a fail-open, and it is not the same class of harm as a captured
// default route; it is a self-inflicted permanent denial of the tunnel, which
// under this threat model reads to the user exactly like a censor.
//
// WHY THE RESIDUE IS REVERSED RATHER THAN ONLY REPORTED. Once the bootstrap has
// failed the exclusion protects nothing -- its whole job is to keep the gateway
// reachable by its physical path WHILE tunnel routes exist, and there are none.
// It is pure cost. And the reversal is the same one-token `add` -> `del` swap
// RenderLinuxWinn3ExclusionTeardown already uses, so it cannot describe a
// different route from the thing it undoes.
//
// WHY A RESULT TYPE AND NOT JUST A ROLLBACK. Identical to the promoted lane's
// argument and it is not weaker here: `ip route del` can fail, and a rollback
// that fails silently leaves a third state nobody enumerated. kRolledBack and
// kPartiallyApplied are distinct values for that reason, and
// `exclusion_installed` says whether the state that outlives the process is the
// one that matters.
//
// ===========================================================================
// REPAIR FIRST, THEN TAKE -- THE ROUTE ANALOGUE OF THE /etc/resolv.conf RULE
// ===========================================================================
//
// Everything above reverses what THIS call installed. Nothing above repairs an
// exclusion stranded by a PREVIOUS one, and the two are not the same problem:
// a session that is SIGKILLed after the exclusion goes in never reaches its own
// rollback at all, and a rollback that itself fails returns kPartiallyApplied
// with `exclusion_installed` true and leaves the route exactly where it was. In
// both cases the next bootstrap's FIRST command is that identical `ip route
// add` and `ip` answers `RTNETLINK answers: File exists`, exit 2. One hard kill
// refused every later session on that machine, permanently, with no message
// naming the cause.
//
// So the bootstrap now opens with the exclusion's own `del`, best effort, and
// its SUCCESS is the signal that a previous session died hard --
// `stale_exclusion_repaired`. This is deliberately the same shape as the
// kResolvConfFile mechanism's step 2 above ("REPAIR BEFORE BACKUP"), which was
// already the promoted lane's answer to the same class of stranding.
//
// WHY A SPECULATIVE `del` AND NOT `ip route replace`. Because the teardown is
// derived from the add by swapping one token, and there is no `replace` whose
// one-token swap is a removal -- the derivation would have to be replaced by a
// second, independently written vector, which is exactly the drift this file
// refuses everywhere else. And `replace` succeeds by OVERWRITING: it would
// silently stomp a route to that destination the user or another tool put
// there, which is the one outcome this whole design is arranged to prevent.
//
// WHY THE `del` RATHER THAN RECOGNISING EEXIST, AND RATHER THAN PROBING WITH
// `ip route show`. Both alternatives were considered and both lose to it:
//
//   RECOGNISING EEXIST cannot be done inside this contract, and would not be
//   enough if it could. LinuxWinn3PrivilegedRunner is `bool(argv, stdin, char*
//   error)` -- it carries NO exit status and NO errno, so "EEXIST" could only
//   be a substring match on a message the caller's runner happened to produce.
//   `RTNETLINK answers: File exists` is strerror(EEXIST), which glibc
//   TRANSLATES; on a host running in Burmese or German that string never
//   appears, and a repair that only works in English is not a repair for the
//   users this product exists for. And even in English EEXIST says only that
//   the DESTINATION is taken. It cannot distinguish our own residue from
//   somebody else's route, which is the only distinction that matters here --
//   so a caller would still need the probe below, having paid a locale
//   dependency for nothing.
//
//   PROBING WITH `ip route show` needs standard OUTPUT, which the runner does
//   not carry either, plus a parser for iproute2's human format -- a second
//   place where this host would have to agree with `ip` about what a route
//   looks like.
//
//   THE `del` IS ITS OWN PROBE and needs neither. It answers by exit status,
//   which the runner does carry; it is the vector RenderLinuxWinn3ExclusionTeardown
//   already builds, so it cannot drift from the add; and the kernel matches it
//   on `via` and `dev` as well as on the destination. So its exit status is
//   precisely the question worth asking: "is the thing in the way the thing we
//   would have written?"
//
// (A third option was rejected for a reason worth recording: the conflict could
// be PROVEN by adding the same route into an unused routing table, since a
// success there shows the arguments are valid and the failure in the main table
// must therefore be EEXIST. That buys a decisive diagnosis by writing state
// into the kernel whose own cleanup can fail -- inventing a second stranding
// hazard to diagnose the first. Not worth it.)
//
// ===========================================================================
// THE RULE, AND THE TENSION IT RESOLVES
// ===========================================================================
//
// The obvious rule is "repair unconditionally"; the obvious objection is that a
// route to our gateway via a DIFFERENT next hop is probably stale from another
// network and repairing only an exact match is safer. Both are half right, and
// the correct split is neither:
//
//   A route to our gateway via a next hop that is not on this network is the
//   MOST broken state available, not the least. It makes the gateway
//   unreachable whether or not this session ever starts. So it must never be
//   passed over in silence.
//
//   But it is also the one state we CANNOT PROVE IS OURS. Our exclusion is
//   `<gw>/32 via <this network's hop> dev <this interface>`; anything else at
//   that destination might be a previous session of ours from another network,
//   or a policy route the user needs, or another tool's own exclusion for the
//   same server. A privileged process that deletes it is guessing, and unlike
//   the resolv.conf mechanism it has NO BACKUP to put it back from -- the
//   teardown removes our vector and only our vector, so a route we deleted on a
//   guess is gone permanently and invisibly.
//
// SO THE AXIS IS NOT "benign versus dangerous". IT IS "PROVABLY OURS VERSUS
// NOT", and that is the only axis on which root should be willing to delete:
//
//   exact match (dest + via + dev)  -> OURS. Removed, and the add proceeds.
//                                     `stale_exclusion_repaired` says so.
//   anything else at that dest      -> NOT OURS. Never deleted. The bootstrap
//                                     REFUSES, loudly, as kExclusionBlocked,
//                                     with the destination named in `error`
//                                     and the command to inspect it.
//
// The refusal is what keeps the second case from being the silent unreachable
// state the objection warns about. Deleting the route would not reliably fix
// reachability anyway -- falling back to the default may or may not reach the
// gateway -- whereas a named refusal tells the operator exactly which route to
// look at, and costs nothing that was working.
//
// Note what the two branches cost when they are wrong, which is why the split
// sits here. Repairing an exact match that was somehow not ours re-adds the
// identical route a moment later: a no-op. Deleting a mismatch that was not
// ours destroys configuration with no record of what it was.
//
// The common case -- killed and restarted on the SAME network -- is the exact
// match, and it repairs itself with no operator anywhere near it.
//
// WHAT THIS DOES NOT DO. It does not publish into the host status document.
// SetLinuxWinn3ResolverStatus writes the keys `resolver_mechanism` and
// `promoted_posture`, and a bootstrap outcome published under a key named
// `promoted_posture` would be a lie in a document whose whole value is that an
// operator can read it literally. A bootstrap result goes to its caller, which
// is the process that is about to decide whether the session lives.
[[nodiscard]] LinuxWinn3PostureResult ApplyLinuxWinn3BootstrapPosture(
    const LinuxWinn3Params& params, const winsvpn::winn3::EngineStatus& status,
    const LinuxWinn3PrivilegedRunner& run, winsvpn::winn3::PosturePlan* plan);

// Widens to the promoted posture. Refuses unless the status document proves the
// datapath, and refuses again if the built plan is not the narrow one plus the
// widenings.
//
// It installs the DELTA, not the whole posture. RenderLinuxPostureCommands
// renders a complete posture, and the promoted one is the bootstrap's plus the
// widenings — so rendering it whole re-issues `ip -4 address add`, which the
// bootstrap already ran and which `ip` answers with "Address already assigned",
// exit 2. The run stops at the first failing command, so promotion would have
// failed on its FIRST command with every route still unmoved. Verified by
// execution on a live Linux 6.8 kernel on 2026-08-09: the repeated address add
// exits 2, a repeated route add gives "RTNETLINK answers: File exists", and the
// `ip link set … mtu … up` in both postures is idempotent.
//
// And the delta is re-checked for CAPTURE before one command runs, by
// winsvpn::winn3::VerifyPromotedCommandsCapture. That is the mirror of what
// VerifyLinuxWinn3BootstrapCommandsAreNarrow does to the other posture, asking
// the opposite question: not "did the narrow posture stay narrow" but "did the
// wide one actually widen". A promotion gate that reports success on a posture
// capturing nothing is worth less than no gate — no gate leaves an operator
// knowing the state is unproven, and a gate reporting success leaves them
// believing a proof happened.
//
// The resolver mechanism is detected here, with `run`, before the delta is
// built: a host that cannot install a resolver at all must refuse BEFORE it
// installs a capturing route, not after.
[[nodiscard]] LinuxWinn3PostureResult ApplyLinuxWinn3PromotedPosture(
    const LinuxWinn3Params& params, const winsvpn::winn3::EngineStatus& status,
    const LinuxWinn3PrivilegedRunner& run, winsvpn::winn3::PosturePlan* plan);

// ---------------------------------------------------------------------------
// The running session. One at a time.
// ---------------------------------------------------------------------------

// Opens /dev/net/tun and attaches `interface_name` with IFF_TUN | IFF_NO_PI.
//
// IFF_NO_PI matters: winn3/tun.Device's contract is "an IP packet starting at
// its version nibble", and Linux's 4-byte PACKET_INFO prefix would be read by
// the inner-IP validator as a malformed packet. Every packet would be dropped
// and the counter that says so is tx_dropped_invalid, not a parse error.
//
// Returns the descriptor, or -1 with *error set. Linux only; on any other host
// it refuses rather than pretending.
int OpenLinuxWinn3Tun(const std::string& interface_name, std::string* error);

// The argv for the engine subprocess.
//
// A pure function because this is the ONE place the protocol is selected, and
// the mistakes are not subtle: `-winn3` missing starts a winn/1 relay under a
// session the gateway negotiated as v3 (silent downgrade), `-winn3-keys`
// missing is a hard engine refusal, and `-carrier-profile` or `-winn3-tun-fd`
// present is a refusal too. Pinning it in a test is cheaper than discovering
// any of that on a user's machine, and it is the same shape Android's
// WinnV3Host.engineArguments already has.
std::vector<std::string> LinuxWinn3EngineArguments(
    const std::string& engine_path, const std::string& keys_path);

// Starts `winn-datapath -transport stdio -winn3 -winn3-keys PATH`, sends the
// Create frame and waits for the CreateAck.
//
// OWNERSHIP OF tun_fd PASSES TO THIS CALL ON EVERY OUTCOME, success or failure,
// so a caller has one rule to remember rather than two. Fail-closed: on false
// nothing is left running and *error says what happened.
//
// On success *ack carries the parsed CreateAck status document, which is the
// authoritative inner MTU for the bootstrap posture.
bool StartLinuxWinn3Engine(const std::string& engine_path, int tun_fd,
                           const LinuxWinn3Params& params,
                           winsvpn::winn3::EngineStatus* ack,
                           std::string* error);

// Stops the engine and both pumps. Safe when nothing is running.
void StopLinuxWinn3Engine();

// ---------------------------------------------------------------------------
// The unified standalone teardown.
// ---------------------------------------------------------------------------
//
// ===========================================================================
// WHY THESE EXIST: STOPPING A STANDALONE SESSION IS TWO ACTS, NOT ONE
// ===========================================================================
//
// StopLinuxWinn3Engine tears down the PROCESS half: the Close frame, the
// SIGTERM, the reap, the tun descriptor close. The tun descriptor close is
// what usually deletes the interface and sweeps every route scoped to it, so
// for a long time "stop the engine" LOOKED like the whole stop. It is not:
// the outer-socket exclusion is a /32 route on the PHYSICAL interface, a
// promoted resolver set is state in systemd-resolved (or a rewritten
// /etc/resolv.conf), and neither goes when the descriptor closes. The fleet
// measured the residue: after a dev-session teardown the tun, the /1 pair,
// the exclusion /32, the systemd-resolved settings and the engine process all
// stayed up, because nothing on the stop path called either half of the v3
// teardown.
//
// StopLinuxWinn3Standalone is BOTH acts in one function, and it is the ONLY
// function any caller may use: production stop (linux_tunnel_backend.cc
// StopTunnel), the start path's own failure exits and the tun e2e harness all
// call it, so a "stop" cannot tear down differently from a "start failed and
// cleaned up after itself". It is idempotent: with no session remembered it
// runs nothing and succeeds, so a stop on a host where nothing is up costs no
// privilege and can never fabricate a failure.

// Remembers the session a standalone v3 start is about to install, so a later
// StopLinuxWinn3Standalone can render the EXACT teardown vectors the start
// path rendered. Safe to call repeatedly; the latest call wins. A stop with
// nothing remembered reverses nothing and runs nothing.
void RememberLinuxWinn3Session(const LinuxWinn3Params& params);

// Whether a standalone session was remembered in this process. This is the
// gate StopTunnel uses to decide whether the awg-quick stop applies at all:
// a standalone session never started awg-quick, so running its stop would
// fabricate a failure on a clean machine.
bool LinuxWinn3StandaloneSessionWasStarted();

// Stops the engine (idempotent; graceful Close then SIGTERM then reap) and
// then reverses the posture through `run`, in the order
// RenderLinuxWinn3TeardownCommands renders: the promoted /1 route dels, the
// resolver restore, the tun deletion, and the outer-socket exclusion removal
// LAST. Commands whose residue goes away with the device are best effort, so
// a clean stop is not reported as dirty. Returns false and sets *error only
// when a must-succeed command (the resolver-file restore, or the exclusion
// removal while an exclusion is actually installed) failed. On success the
// session is forgotten, so the next call is a no-op. Safe when nothing is up.
[[nodiscard]] bool StopLinuxWinn3Standalone(const LinuxWinn3PrivilegedRunner& run,
                                            std::string* error);

// True while the engine subprocess is running AND the frame channel is up.
// Deliberately not "the process exists": a live process with a dead channel
// carries nothing, and reporting that as a working tunnel is the exact failure
// this project has already been bitten by on the winn/1 path.
bool LinuxWinn3EngineRunning();

// The engine's status document, obtained with a StatusRequest frame, or "" when
// no engine is running.
std::string LinuxWinn3EngineStatusJson();

// The gate, over a freshly requested status document.
LinuxWinn3Promotion LinuxWinn3PromotionState(
    winsvpn::winn3::EngineStatus* parsed, std::string* reason);

// Sends ONE minimal inner reachability probe: an ICMP echo, sourced from the
// session's own inner assignment (params.inner_address) and addressed to the
// inner next hop (params.inner_next_hop), over a datagram ICMP "ping" socket so
// the unprivileged tunnel provider can send it itself.
//
// Why it exists: the promotion gate is gate == carrying AND rx_packets > 0,
// and nothing sends the first inner packet pre-promotion
// against a reactive gateway, so a healthy carrying session starves the gate
// to its deadline on a quiet host. The echo is the one packet the gateway is
// guaranteed to answer: the v3 reflector returns IPv4 addressed to its own
// assignment, which is the inner next hop.
//
// Why it is containment-safe: the bootstrap posture routes exactly ONE
// address, the inner next hop's /32, so the echo can only enter the tunnel --
// it can never resolve onto the physical default route, and it is dropped or
// refused nowhere differently than before. The return value is advisory: a
// host whose kernel keeps ping_group_range closed (non-systemd default)
// cannot create the socket and gets false, and the caller keeps polling and
// keeps its deadline fail-closed.
bool SendLinuxWinn3InnerPromotionProbe(const LinuxWinn3Params& params);

// The probe's collision refusals as a pure function, separated from the
// socket code so it builds and RUNS on the development host: an inner next
// hop equal to the carrier endpoint's IP (the endpoint's /32 is pinned to
// the physical interface, so the echo could leave on the censored path) or
// equal to this host's own inner_v4 (it would never reach the gateway) is
// returned as a refusal sentence; an empty string means the echo may
// proceed. SendLinuxWinn3InnerPromotionProbe calls it and logs the refusal
// before any socket exists.
std::string LinuxWinn3InnerPromotionProbeCollisionRefusal(
    const LinuxWinn3Params& params);

// The HOST's own tun-pump counters as JSON. Every field is an integer this file
// counted itself -- no address, no endpoint, no packet byte -- so unlike the
// winn/1 status document this is safe to log in full.
//
// Since 2026-08-10 it also carries the resolver mechanism the last promotion
// attempt chose and the outcome of that attempt. Those are not counters, and
// they are here anyway: this is the host's own status document, an operator
// looking at a machine whose name resolution is wrong needs to know which of
// three code paths touched it, and a mechanism that is only ever a local
// variable is a mechanism nobody can see from outside the process. Both fields
// are strings from a closed set -- no path, no address, no resolver IP.
std::string LinuxWinn3PumpStatsJson();

// The resolver mechanism and posture outcome the last promotion attempt
// recorded, as a JSON object, for a caller that wants them without the
// counters. `{"resolver_mechanism":"unknown","promoted_posture":"not-attempted"
// ,"resolver_detail":""}` before any attempt.
std::string LinuxWinn3ResolverStatusJson();

// Records what a promotion attempt chose, so the two functions above can
// publish it. Called by ApplyLinuxWinn3PromotedPosture; exposed because the
// posture functions are pure with respect to the session and a driver that
// applies a posture without starting an engine still has a status to publish.
void SetLinuxWinn3ResolverStatus(const LinuxWinn3PostureResult& result);

// ---------------------------------------------------------------------------
// Bootstrap status publishing and operator-visible retry semantics.
//
// The promoted path publishes under the closed-set keys `resolver_mechanism`
// and `promoted_posture` which the status document can carry literally.
// The bootstrap path deliberately does NOT publish under `promoted_posture`
// (a bootstrap outcome published there would be a lie -- see
// ApplyLinuxWinn3BootstrapPosture), so it publishes under its OWN key. That is
// the only reason these are separate: the two results are measured on different
// hazard fields and an operator needs to read the one that matches the posture
// the session actually attempted.
//
// kExclusionBlocked is the value that MUST NOT be retried on a timer. It means
// `ip route add <gw>/32 via <hop> dev <phys>` was refused and the repair that
// opens every bootstrap proved the route in the way is NOT ours (different via
// or dev). A timer that retries it spins forever -- the destination is taken by
// a route this host will never delete, and the exact message names the
// destination and the command to inspect it. The helper below is the single
// place that decides which outcomes are retryable, so a future caller cannot
// re-invent the decision.
const char* LinuxWinn3PostureOutcomeErrorCode(
    LinuxWinn3PostureOutcome outcome);
bool LinuxWinn3PostureOutcomeShouldRetry(LinuxWinn3PostureOutcome outcome);

// The bootstrap's own status document, for a caller that wants it without the
// counters. `{"bootstrap_posture":"not-attempted",...}` before any attempt.
// Mirrors LinuxWinn3ResolverStatusJson in shape so the two can be read side by
// side without guessing which key is which.
std::string LinuxWinn3BootstrapStatusJson();
void SetLinuxWinn3BootstrapStatus(const LinuxWinn3PostureResult& result);

// The single source for the `[winn]` resolver-file paths. Declared here so the
// privileged argv allowlist in linux_tunnel_backend.cc can reference the SAME
// strings the kResolvConfFile renderer in linux_winn3_host.cc emits -- if they
// drift, an allowlist matching the renderer today accepts nothing tomorrow, and
// the whole posture silently refuses for a reason that reads as a host defect.
extern const char kResolvConfPath[];
extern const char kResolvConfBackupDir[];
extern const char kResolvConfBackup[];

// ---------------------------------------------------------------------------
// Generation-bound typed start proof. Ordinary fallback is authorized only by
// a matching generation AND positively proven network evidence.
// ---------------------------------------------------------------------------
//
// A v3 gateway that cannot authenticate answers nothing. A censor that drops
// UDP also answers nothing. Collapsing every pre-accept failure into one
// start error is what used to turn a wrong static key, a pinning failure, a
// replay, or a malformed proof into a v1 fallback. The four wire names below
// are the closed set:

inline constexpr char kLinuxWinn3InterfaceName[] = "winsvpn3";
inline constexpr char kWinn3ProofOutcomeConnected[] = "connected";
inline constexpr char kWinn3ProofOutcomeOrdinaryConnectivity[] =
    "ordinary_connectivity";
inline constexpr char kWinn3ProofOutcomeTerminalSecurity[] =
    "terminal_security";
inline constexpr char kWinn3ProofOutcomeUnknownTerminal[] = "unknown_terminal";

enum class Winn3ProofOutcome {
  kConnected,
  kOrdinaryConnectivity,
  kTerminalSecurity,
  kUnknownTerminal,
};

struct Winn3StartProof {
  int64_t generation = 0;
  int64_t start_token = 0;
  std::string selection_generation;
  std::string failed_node;
  Winn3ProofOutcome outcome = Winn3ProofOutcome::kUnknownTerminal;
  bool canceled = false;
  // Exact platform OS error captured at the failing syscall. Never derived
  // from diagnostic prose. Zero means no structured OS error was captured.
  int os_error = 0;
};

inline constexpr int kLinuxEnetdown = 100;
inline constexpr int kLinuxEnetunreach = 101;
inline constexpr int kLinuxEhostdown = 112;
inline constexpr int kLinuxEhostunreach = 113;
inline constexpr int64_t kWinn3AwgXrayGrantTtlMs = 60000;

// Structured OS-error slot for a standalone v3 start. Production captures the
// exact errno from the gateway datagram connect and stores it here. The
// classifier consumes that integer; diagnostic prose is never parsed for it.
inline int& LinuxWinn3CapturedOsErrorSlot() {
  static thread_local int os_error = 0;
  return os_error;
}

inline void RememberLinuxWinn3OsError(int os_error) {
  LinuxWinn3CapturedOsErrorSlot() = os_error;
}

inline int PeekLinuxWinn3OsError() { return LinuxWinn3CapturedOsErrorSlot(); }

inline int TakeLinuxWinn3OsError() {
  const int os_error = LinuxWinn3CapturedOsErrorSlot();
  LinuxWinn3CapturedOsErrorSlot() = 0;
  return os_error;
}

inline int CaptureCurrentLinuxOsError() { return errno; }

inline bool IsWinn3SelectionGeneration(const std::string& value) {
  if (value.size() < 8 || value.size() > 64) return false;
  const unsigned char first = static_cast<unsigned char>(value[0]);
  if (!std::isalnum(first)) return false;
  for (size_t i = 1; i < value.size(); ++i) {
    const unsigned char c = static_cast<unsigned char>(value[i]);
    if (std::isalnum(c) || c == '.' || c == '_' || c == ':' || c == '-') {
      continue;
    }
    return false;
  }
  return true;
}

inline bool IsConcreteWinn3NodeSlug(const std::string& value) {
  if (value.empty()) return false;
  std::string lower = value;
  for (char& c : lower) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return lower != "auto";
}

enum class Winn3CoverLeg { kAwg, kXray };

inline bool ParseWinn3CoverLeg(const std::string& text, Winn3CoverLeg* out) {
  if (out == nullptr) return false;
  if (text == "awg") {
    *out = Winn3CoverLeg::kAwg;
    return true;
  }
  if (text == "xray") {
    *out = Winn3CoverLeg::kXray;
    return true;
  }
  return false;
}

enum class Winn3GrantConsumeResult {
  kOk,
  kEmpty,
  kExpired,
  kMismatch,
  kWrongLeg,
};

struct Winn3AwgXrayGrant {
  int64_t start_token = 0;
  int64_t start_generation = 0;
  std::string selection_generation;
  std::string failed_v3_node;
  std::string exact_v1_target;
  int64_t issued_monotonic_ms = 0;
  Winn3CoverLeg next_leg = Winn3CoverLeg::kAwg;
  bool target_bound = false;
};

inline bool Winn3AwgXrayGrantExpired(const Winn3AwgXrayGrant& grant,
                                     int64_t now_monotonic_ms) {
  if (grant.start_token <= 0 || grant.issued_monotonic_ms <= 0) return true;
  if (now_monotonic_ms < grant.issued_monotonic_ms) return true;
  return (now_monotonic_ms - grant.issued_monotonic_ms) > kWinn3AwgXrayGrantTtlMs;
}

inline bool ArmWinn3AwgXrayGrant(int64_t start_token, int64_t start_generation,
                                 const std::string& selection_generation,
                                 const std::string& failed_v3_node,
                                 int64_t issued_monotonic_ms,
                                 Winn3AwgXrayGrant* out) {
  if (out == nullptr) return false;
  if (start_token <= 0 || start_generation <= 0 || issued_monotonic_ms <= 0 ||
      !IsWinn3SelectionGeneration(selection_generation) ||
      !IsConcreteWinn3NodeSlug(failed_v3_node)) {
    *out = Winn3AwgXrayGrant();
    return false;
  }
  Winn3AwgXrayGrant grant;
  grant.start_token = start_token;
  grant.start_generation = start_generation;
  grant.selection_generation = selection_generation;
  grant.failed_v3_node = failed_v3_node;
  grant.issued_monotonic_ms = issued_monotonic_ms;
  *out = grant;
  return true;
}

inline Winn3GrantConsumeResult ConsumeWinn3AwgXrayGrant(
    Winn3AwgXrayGrant* grant, int64_t start_token, int64_t start_generation,
    const std::string& selection_generation, const std::string& failed_v3_node,
    const std::string& exact_v1_target, Winn3CoverLeg requested_leg,
    int64_t now_monotonic_ms) {
  if (grant == nullptr || grant->start_token <= 0) {
    return Winn3GrantConsumeResult::kEmpty;
  }
  if (Winn3AwgXrayGrantExpired(*grant, now_monotonic_ms)) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kExpired;
  }
  if (start_token != grant->start_token ||
      start_generation != grant->start_generation ||
      selection_generation != grant->selection_generation ||
      failed_v3_node != grant->failed_v3_node ||
      !IsConcreteWinn3NodeSlug(exact_v1_target)) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kMismatch;
  }
  if (grant->target_bound && exact_v1_target != grant->exact_v1_target) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kMismatch;
  }
  if (requested_leg != grant->next_leg) {
    *grant = Winn3AwgXrayGrant();
    return Winn3GrantConsumeResult::kWrongLeg;
  }
  if (requested_leg == Winn3CoverLeg::kAwg) {
    grant->exact_v1_target = exact_v1_target;
    grant->next_leg = Winn3CoverLeg::kXray;
    grant->target_bound = true;
    return Winn3GrantConsumeResult::kOk;
  }
  *grant = Winn3AwgXrayGrant();
  return Winn3GrantConsumeResult::kOk;
}

inline const char* Winn3ProofOutcomeName(Winn3ProofOutcome outcome) {
  switch (outcome) {
    case Winn3ProofOutcome::kConnected:
      return kWinn3ProofOutcomeConnected;
    case Winn3ProofOutcome::kOrdinaryConnectivity:
      return kWinn3ProofOutcomeOrdinaryConnectivity;
    case Winn3ProofOutcome::kTerminalSecurity:
      return kWinn3ProofOutcomeTerminalSecurity;
    case Winn3ProofOutcome::kUnknownTerminal:
      return kWinn3ProofOutcomeUnknownTerminal;
  }
  return kWinn3ProofOutcomeUnknownTerminal;
}

namespace winn3_proof_detail {

inline std::string AsciiLower(std::string value) {
  for (char& c : value) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  return value;
}

inline bool Contains(const std::string& lower, const char* token) {
  return lower.find(token) != std::string::npos;
}

inline bool HasSecurityEvidence(const std::string& lower) {
  return Contains(lower, "admission") || Contains(lower, "replay") ||
         Contains(lower, "pinning") || Contains(lower, "pin mismatch") ||
         Contains(lower, "descriptor pin") ||
         Contains(lower, "static key") || Contains(lower, "gateway id") ||
         Contains(lower, "gateway_id") ||
         Contains(lower, "unauthenticated") || Contains(lower, "credential") ||
         Contains(lower, "could not be opened") ||
         Contains(lower, "none of them could be opened") ||
         Contains(lower, "unopenable") || Contains(lower, "malformed") ||
         Contains(lower, "stale ack") ||
         Contains(lower, "disagrees with itself") ||
         Contains(lower, "proof integrity") ||
         Contains(lower, "not a single json") ||
         Contains(lower, "duplicate json") ||
         Contains(lower, "rx_offered but not") ||
         Contains(lower, "connection details could not be used") ||
         Contains(lower, "unexpected adapter name");
}

inline bool IsLinuxOrdinaryNetworkOsError(int os_error) {
  return os_error == kLinuxEnetdown || os_error == kLinuxEnetunreach ||
         os_error == kLinuxEhostdown || os_error == kLinuxEhostunreach;
}

inline bool LooksCanceled(const std::string& lower) {
  return Contains(lower, "canceled") || Contains(lower, "cancelled");
}

}  // namespace winn3_proof_detail

inline Winn3ProofOutcome ClassifyWinn3ProofDiagnostic(
    const std::string& diagnostic, int os_error = 0, bool timed_out = false) {
  const std::string lower = winn3_proof_detail::AsciiLower(diagnostic);
  if (winn3_proof_detail::HasSecurityEvidence(lower)) {
    return Winn3ProofOutcome::kTerminalSecurity;
  }
  if (timed_out) return Winn3ProofOutcome::kUnknownTerminal;
  if (winn3_proof_detail::IsLinuxOrdinaryNetworkOsError(os_error)) {
    return Winn3ProofOutcome::kOrdinaryConnectivity;
  }
  return Winn3ProofOutcome::kUnknownTerminal;
}

inline Winn3StartProof ClassifyWinn3StartFailure(
    int64_t generation, bool canceled, const std::string& diagnostic,
    int os_error = 0, int64_t start_token = 0,
    const std::string& selection_generation = "",
    const std::string& failed_node = "", bool timed_out = false) {
  Winn3StartProof proof;
  proof.generation = generation;
  proof.start_token = start_token;
  proof.selection_generation = selection_generation;
  proof.failed_node = failed_node;
  proof.os_error = os_error;
  proof.canceled = canceled ||
                   winn3_proof_detail::LooksCanceled(
                       winn3_proof_detail::AsciiLower(diagnostic));
  if (proof.canceled) {
    proof.outcome = Winn3ProofOutcome::kUnknownTerminal;
    return proof;
  }
  proof.outcome =
      ClassifyWinn3ProofDiagnostic(diagnostic, os_error, timed_out);
  return proof;
}

// Production start-failure classifier. Consumes RememberLinuxWinn3OsError.
// Passing os_error=0 is the defect this helper exists to prevent.
inline Winn3StartProof ClassifyCapturedWinn3StartFailure(
    int64_t generation, bool canceled, const std::string& diagnostic,
    int64_t start_token = 0, const std::string& selection_generation = "",
    const std::string& failed_node = "", bool timed_out = false) {
  return ClassifyWinn3StartFailure(
      generation, canceled, diagnostic, TakeLinuxWinn3OsError(), start_token,
      selection_generation, failed_node, timed_out);
}

inline Winn3StartProof MakeConnectedWinn3StartProof(
    int64_t generation, int64_t start_token = 0,
    const std::string& selection_generation = "",
    const std::string& failed_node = "") {
  Winn3StartProof proof;
  proof.generation = generation;
  proof.start_token = start_token;
  proof.selection_generation = selection_generation;
  proof.failed_node = failed_node;
  proof.outcome = Winn3ProofOutcome::kConnected;
  proof.canceled = false;
  return proof;
}

inline int64_t Winn3AuthorizationToken(const Winn3StartProof& proof) {
  if (proof.canceled) return 0;
  if (proof.outcome != Winn3ProofOutcome::kOrdinaryConnectivity) return 0;
  if (proof.start_token <= 0 || proof.generation <= 0) return 0;
  return proof.start_token;
}

inline bool Winn3StartProofAuthorizesOrdinaryFallback(
    const Winn3StartProof& proof, int64_t expected_generation,
    int64_t expected_token = 0) {
  if (Winn3AuthorizationToken(proof) <= 0) return false;
  if (proof.generation != expected_generation) return false;
  if (expected_token > 0 && proof.start_token != expected_token) return false;
  return true;
}

// Liveness for a remembered standalone v3 session. winsvpn3 plus the v3
// engine; never the v1 `winsvpn` interface or the winn/1 engine.
inline bool LinuxWinn3StandaloneIsLive(bool winsvpn3_present,
                                       bool linux_winn3_engine_running) {
  return winsvpn3_present && linux_winn3_engine_running;
}

// When a standalone v3 session is remembered, IsTunnelRunning must consult
// only this path. Falling through to v1 while v3 is promoted is the defect
// that reports a live AmneziaWG leftover as the user's tunnel.
inline bool LinuxTunnelRunningConsideringV3(bool v3_session_started,
                                            bool winsvpn3_present,
                                            bool linux_winn3_engine_running,
                                            bool v1_running) {
  if (v3_session_started) {
    return LinuxWinn3StandaloneIsLive(winsvpn3_present,
                                      linux_winn3_engine_running);
  }
  return v1_running;
}

}  // namespace winsvpn::winn3host

#endif  // RUNNER_LINUX_WINN3_HOST_H_
