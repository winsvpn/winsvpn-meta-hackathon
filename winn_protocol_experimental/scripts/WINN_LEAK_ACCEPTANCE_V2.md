# Winn leak acceptance v2

This suite is acceptance infrastructure, not proof that the leak gate has
passed. A pass exists only after the orchestrator completes all six real-host
scenarios and preserves their evidence:

| Family | Graceful | Gateway outage/recovery | Acknowledged SIGKILL/recovery |
|---|---:|---:|---:|
| IPv4 full tunnel (`0.0.0.0/0`) | required | required | required |
| IPv6 full tunnel (`::/0`) | required | required | required |

The two families are separate passes because the current production Linux
direct-AWG controller is single-family. These results must not be described as
simultaneous dual-stack coverage.

## Build

Build all three artifacts from deterministic manifests produced by
`scripts/source_manifest.sh`. The helper asks `go list` for every main-module
input, so untracked and generated Go/embed inputs are included. Archive the
three manifests beside the binaries:

```sh
install -d -m 0700 /opt/winn-lab/manifests

CLIENT_DIGEST=$(CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  ./scripts/source_manifest.sh ./cmd/winn-leak-v2 \
  /opt/winn-lab/manifests/winn-leak-v2.source.sha256)

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags "-X main.sourceTreeDigest=$CLIENT_DIGEST" \
  -o /opt/winn-lab/bin/winn-leak-v2 ./cmd/winn-leak-v2

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  ./scripts/source_manifest.sh ./cmd/winn-leak-v2/webrtc \
  /opt/winn-lab/manifests/winn-webrtc-v2.source.sha256
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -o /opt/winn-lab/bin/winn-webrtc-v2 ./cmd/winn-leak-v2/webrtc
chmod 0755 /opt/winn-lab/bin/winn-webrtc-v2
# OpenRoot-based self-integrity hashing needs read and traverse access.
chmod 0755 /opt/winn-lab/bin

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  ./scripts/source_manifest.sh ./cmd/winn-leak-v2/orchestrator \
  /opt/winn-lab/manifests/winn-leak-orchestrator-v2.source.sha256
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -o /opt/winn-lab/bin/winn-leak-orchestrator-v2 \
  ./cmd/winn-leak-v2/orchestrator

sha256sum /opt/winn-lab/bin/winn-leak-v2 \
  /opt/winn-lab/bin/winn-webrtc-v2 \
  /opt/winn-lab/bin/winn-leak-orchestrator-v2 \
  >/opt/winn-lab/manifests/winn-leak-v2.artifacts.sha256
```

Regenerate each manifest immediately after its build and require `cmp` against
the archived copy if anything else can write to the source tree during the
build. The orchestrator hashes the three executables, browser, and four hooks;
its final result also hashes every regular evidence file except the result that
contains the hash map.

## Required host separation

- The client is a disposable Linux VM or namespace with real
  `systemd-resolved`, nftables, `ip`, AmneziaWG, and a sandbox-capable Chromium.
  The orchestrator and client need root, but `webrtc_user` must identify a
  dedicated non-root account. The orchestrator drops UID, GID, and
  supplementary groups for the WebRTC runner inside the same client network
  namespace and gives it a private temporary HOME/TMPDIR/runtime directory. Do
  not add `--no-sandbox`. The WebRTC helper must be executable and its ancestor
  directories readable/traversable by that account because the helper hashes
  itself and Chromium through race-resistant `OpenRoot` handles. The
  orchestrator rejects the deployment before starting a scenario otherwise.
  AICORE's verified browser path is `/usr/bin/google-chrome`; the runner resolves
  and records its canonical target before hashing and execution.
- The gateway is a dedicated disposable, dual-stack forwarding host. Its AWG
  interface, peer, keys, addresses, and provider firewall must already be
  provisioned. The gateway lease script does not create peers or persistent
  configuration.
- The public observer must be independently routed from the gateway, preferably
  in a different provider account. It hosts controlled HTTP and STUN endpoints
  and owns the only authoritative evidence used to assert the source IP. A
  gateway-local listener is not independent source-observation evidence.
- The tunnel DNS resolver and UDP challenge-echo canary must be controlled.
  DNS must be observable over both UDP and TCP port 53.

`gateway_identity` and `observer_identity` in the config are mandatory and
must differ. They are evidence labels, not proof of account separation; the
operator must verify the separation before running.

## Private config

Start with `winn_leak_acceptance_v2.example.json`. Store the real config in a
mode-0600 regular file. Its parent and `evidence_root` must be real,
non-symlinked private directories. `run_seed` must be fresh lowercase 64-hex;
reusing it intentionally fails because the exclusive batch evidence directory
already exists.

`client_args` contains the production client flags other than those controlled
by the orchestrator. Never put key material in JSON. Point
`-client-private-key-file` and `-psk-file` to mode-0600 files.

Before starting, enumerate every pre-tunnel physical, ISP, cloud-private,
ULA/GUA, and VPN-underlay address from the client. Put them in
`forbidden_addresses`. Put only the expected tunnel interface literal in
`allowed_host_addresses`; an empty list is valid when Chromium uses mDNS host
candidates.

## Hook ABI

Each hook is an absolute, executable regular file. The orchestrator invokes it
directly—never through a shell—with:

```text
HOOK ACTION RUN_ID FAMILY SCENARIO SCENARIO_EVIDENCE_DIRECTORY
```

Every action must be bounded, noninteractive, and return nonzero unless it has
performed and verified the exact requested operation. Hooks should copy their
pcaps, counters, resolver state, routes, and remote logs into the supplied
private scenario evidence directory before returning. Standard output and
standard error are independently captured and fsync'd by the orchestrator.

Required actions:

| Hook | Actions |
|---|---|
| `gateway_hook` | `start`, `status`, `outage`, `recover`, `stop`, `residue` |
| `observer_hook` | `start`, `status`, `assert-prepared`, `assert-verified`, `assert-committed`, `assert-outage-fail-closed`, `assert-recovered`, `assert-crashed-fail-closed`, `assert-stopped`, `stop`, `residue` |
| `probe_hook` | `prepared`, `verified`, `committed`, `outage-fail-closed`, `recovered`, `crashed-fail-closed`, `stopped`, `residue` |
| `recovery_hook` | `recover-crash`, `cleanup`, `residue` |

`gateway_hook outage` must cause a controlled, reversible gateway-path outage;
it must not disable the client's physical interface or falsify the kill-switch
test. `recover` must restore the exact prior gateway path. `stop` must restore
forwarding/NAT state. `residue` must prove that provider rules, nftables tables,
processes, and temporary state created for the run are absent.

`recovery_hook recover-crash` owns cleanup only after the production client has
written `crashing` and died from exact `SIGKILL`. It must first preserve the
fail-closed state, then invoke the same external recovery path expected after a
real application crash. `cleanup` is the idempotent emergency rollback action.

## Mandatory probe assertions

- `prepared`: the kill switch is installed, general IPv4/IPv6 Internet and
  ordinary DNS are blocked, the default route is not committed, and only the
  protected endpoint/verification traffic is possible.
- `verified`: fresh AWG handshake, controlled protected DNS, UDP echo canary,
  and bidirectional verification succeeded; general Internet is still blocked.
- `committed`: the family default route is through the Winn interface,
  `resolvectl status INTERFACE` owns the controlled resolver and `~.`, and
  controlled DNS succeeds over UDP and forced TCP 53. Public HTTP/STUN traffic
  must be seen by the independent observer only from the expected gateway
  egress. Client and gateway pcaps/counters must show bidirectional encrypted
  carriage with no direct fallback.
- `outage-fail-closed`: HTTP, DNS, STUN, and fresh sockets cannot escape by the
  physical interface. The independent observer must see no client/ISP source.
- `recovered`: the same committed route/resolver/source assertions pass without
  rebuilding the acceptance VM.
- `crashed-fail-closed`: the client died by exact acknowledged SIGKILL while
  the kill switch remains and all direct fallback remains blocked.
- `stopped` and every `residue`: interface, routes, policy rules, resolver
  ownership, nftables tables, helper processes, forwarding/NAT changes, and
  temporary credentials are absent or restored byte-for-byte to the recorded
  baseline.

The probe hook—not an in-process mock—must run the real Internet, UDP DNS, TCP
DNS, route, resolver, pcap, and counter checks.

## Real Chromium WebRTC rule

At every committed phase the orchestrator launches `winn-webrtc-v2`. The
runner:

- identifies and hashes the Chromium executable and hashes itself;
- refuses root instead of weakening the browser sandbox;
- launches a clean headless Chromium profile;
- places Chromium in a dedicated process group, terminates that exact group,
  waits for it to disappear, removes the profile, and records both residue
  assertions;
- drives a real `RTCPeerConnection` through CDP against the controlled
  IP-literal STUN endpoint;
- requires ICE gathering to complete and a server-reflexive candidate to equal
  the expected gateway egress;
- rejects every listed pre-tunnel address, every unapproved literal host
  address, and unexpected related or candidate types;
- writes exclusive mode-0600 JSON evidence.

Missing Chromium, a fake executable, CDP failure, STUN failure, no
server-reflexive candidate, or an unsafe candidate fails the suite. There is no
synthetic fallback.

## Run and cleanup

```sh
/opt/winn-lab/bin/winn-leak-orchestrator-v2 \
  -config=/opt/winn-lab/private/winn-leak-acceptance-v2.json
```

The orchestrator derives a distinct run ID for each of the six scenarios,
drives the exact `prepared`, `verified`, and `committed` barriers, verifies
graceful exit or exact SIGKILL as appropriate, and invokes rollback on any
failure. Rollback terminates the client, restores an outstanding outage, calls
the recovery cleanup hook, stops gateway/observer roles, and runs every residue
check. Any cleanup or residue failure is joined to the acceptance failure.

Every locally launched hook, runner, and client also owns an exact process
group. Timeouts signal only that recorded group; the suite never uses broad
`pkill`. A normal hook or graceful client exit that leaves its group alive is
an acceptance failure. After the deliberate client SIGKILL, its recorded PID
is also the process-group ID; the recovery hook must use that identity and the
scenario state rather than a process-name match.

The hook config records an underlay interface and pinned provider-management
IP for each address family. On a multi-NIC client these values may differ.
Provider control uses TCP 22 only, an exact destination-and-port policy rule,
and two exact provider-address/TCP-22/physical-interface allows inserted into
the live fail-closed chain and revalidated at every phase. The audit chain
counts those flows but does not mutate their packet mark. Reapplying a route
mark to every IPv6 TCP packet can change its flow label during rerouting and
is therefore forbidden. IPv6 acceptance must not reuse an IPv4-only interface
or bypass the IPv6 kill switch through an IPv4 management socket.

Do not promote results if `suite-result.json` is absent, `passed` is false,
fewer than six scenarios passed, an observer artifact is unavailable, or a
provider console/API shows a leftover billable test resource.
