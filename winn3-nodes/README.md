# winn3-nodes -- gateway deploy assets (Lane C)

The two scripts the supervisor runs to stand up and verify the live winn/3 demo
gateways (`demo-gw-a` = gateway-vm-a `203.0.113.10`, `demo-gw-b` =
gateway-vm-b `203.0.113.20`, both listening on UDP/TCP 9111).

| file | role |
|---|---|
| `provision_gw.sh <demo-gw-a\|demo-gw-b>` | Stages everything one gateway needs in this lane: gateway static keypair, admission secret, cover material, peer registry, env file, systemd unit, firewall oneshot, hub-VM verification profile. Private material is written `0600` under `keys/<role>/` and never printed. |
| `deploy_and_verify.sh <deploy\|verify-node\|verify-hub\|rollback> <role>` | Supervisor-run on the VMs: installs the staged bundle, brings up the `winn3-gateway` unit plus firewall oneshot, then verifies handshake + ICMP carriage through the NAT (`verify-hub`), node-local posture (`verify-node`), or removes everything (`rollback`). |

These scripts never contact any host themselves; the supervisor pushes the
staging bundle with their own ssh/scp/rsync (`deploy_and_verify.sh stage-help`
prints the exact manifest).

## What is deliberately NOT in this directory

- `keys/` (entirely excluded): gateway private halves, admission secrets, cover
  keys, verification client keys, and `PUBSUMMARY.md` all live in the
  supervisor's lane workdir. Only public fingerprints ever reach stdout.
- `out/` and `nodes/`: compiled binaries + generated unit/firewall/env files.
  The two scripts above regenerate them; the source of record for the engine
  binaries is the Win's VPN source repository.
- The winn/3 engine source (`module/`): it is the same closed source as the
  Win's VPN client, available to judges on request through a separate private
  repo share (see the top-level README).

## Where the signed descriptors come from

The descriptor signing ceremony (`tools/winn3_sign_descriptor.py`) is run by
the supervisor offline; the private signing key never enters any lane workdir
or this repo. The hub twin serves the finished envelopes verbatim from
`staging-hub/descriptors/<slug>.json`, which are also supervisor-landed and
therefore excluded here. The G1 public key and descriptor ring sha256 are
public and supervisor-supplied at deploy time.

## Reference

Winn Protocol v3 transport details, the gateway runbook, and the install
tooling referenced throughout these scripts live in the Win's VPN source
repository (`docs/WINN3_STANDALONE_V3_OPERATOR_RUNBOOK_20260812.md`,
`server/wins_winn3_gateway_install.sh`,
`tools/winn3_gateway_provision_keys.sh`). See the top-level README for how to
request access.