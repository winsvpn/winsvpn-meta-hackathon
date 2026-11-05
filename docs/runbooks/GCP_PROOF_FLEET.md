# GCP proof fleet

This contract covers one fresh, isolated three-VM proof on a linux/amd64
operator host:

- `control`: the control plane and `wins-hub.service`
- `data-winn3`: the Winn Protocol v3 gateway and data plane
- `data-cover`: the distinct Winn Protocol v1 AWG/Xray fallback node

Same-node downgrade is forbidden. A blocked Winn v3 path may rotate only to
`data-cover`. The proof VPC rule includes UDP `20000-32767` for rotated AWG
ports. Ubuntu 24.04 from `ubuntu-os-cloud`, OS Login, no VM service account,
shielded settings, deletion protection, a new VPC, and caller-provided
non-production instance names remain mandatory.

Live proof schemas are v4 (`winsvpn.gcp_proof_fleet.plan.v4`,
`apply.v4`, `verify.v4`, `reset.v4`, `acceptance_receipt.v4`,
`winsvpn.gcp_proof_evidence.collector_bundle.v4`). Observation envelopes are
v3. Deployment execution receipts are v3. Older v2 bundles and v1 observation
envelopes are rejected and cannot be promoted into new receipts.

**Retired installer (design v17 2.8, slice S6).** The `data-winn3` role deploys
`server/wins_winn3_gateway_install.sh`. That installer is now a tombstone: it
prints a pointer to the data-plane installer and exits 2, because the
data-plane installer carries the gateway. Until the retarget below lands, the
`data-winn3` steps cannot pass, no GCP acceptance receipt can be produced, and
`tools/fin_release_gate.sh` stays fail closed on its GCP acceptance receipt
requirement and its six-hour receipt window. That is the intended state. Do not
start a proof run from this runbook, do not retire this tooling, and do not
weaken the release gate to get past it. Existing receipts must not be promoted
to certify the changed deployment contract: gate G21 carries an explicit
interim blocker ("S6 GCP deployment contract retarget is pending after S4")
that no supplied receipt can clear, because the gate checks only that the
receipt path is a regular file. Remove that blocker only together with the
completed post-S4 retarget and a receipt validation against the current
deployment contract; never add an override. The tests that pin the role's
installer text read the frozen copy under
`server/testdata/winn3_gateway_install_retired/`.

Required retarget, a named post-S4 item (slice S7 or INT, not S6): it waits for
S4, because until the data-plane `main()` drives the gateway block a proof of
`--deploy` would prove an installer that does not install the gateway. In
`tools/gcp_proof_deploy.py` (`EXPECTED_STEPS`), `tools/gcp_proof_remote_install.py`
(`EXPECTED_STEPS`) and `tools/gcp_proof_fleet.py` (the same six triples), the
sequence becomes exactly:

```python
EXPECTED_STEPS: tuple[tuple[str, str, str], ...] = (
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--preflight"),
    ("control", "server/wins_control_plane_setup_ONETOUCH.sh", "--deploy"),
    ("data-winn3", "server/wins_data_plane_setup_ONETOUCH.sh", "--preflight"),
    ("data-winn3", "server/wins_data_plane_setup_ONETOUCH.sh", "--deploy"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--preflight"),
    ("data-cover", "server/wins_data_plane_setup_ONETOUCH.sh", "--deploy"),
)
LAST_ROLE_STEP = {"control": 1, "data-winn3": 3, "data-cover": 5}
```

The former standalone triples and the separate `PROOF_KEY_PROVISION_ID` step
are removed, and `GATEWAY_INSTALLER` is deleted once the data-plane installer
persists the gateway keys. Both proof data VMs then install the gateway and
cover services, and the data-plane installer writes `data-cover` to
`/etc/winsvpn/role` on both, so the host-role payloads become
`{"control": b"control\n", "data-winn3": b"data-cover\n", "data-cover": b"data-cover\n"}`
(`ROLE_FILE_PAYLOADS`). The gateway and cover-runtime applicability checks in
`tools/gcp_proof_remote_install.py` stop being mutually exclusive, and every
pin test reads the data-plane installer. Service expectations, runtime
identities, forbidden-component checks, deployment-input closure, cleanup
expectations, authenticated onboarding and the evidence producers and consumers
change together with their tests.

Placeholders below are local paths and names only. Do not substitute production
project ids, sim-fleet names, or credential values.

| Placeholder | Meaning |
|---|---|
| `$WINS_PYTHON314` | Pinned CPython 3.14.7 executable from `tools/toolchain-pins.json` |
| `$REPO` | Absolute canonical repository root |
| `$STATE` | Absolute private proof state directory, mode 0700 |
| `$GCLOUD_ARCHIVE` | Already downloaded official Google Cloud CLI 582.0.0 archive |
| `$GCLOUD_SDK` | Extracted official SDK tree that is byte-identical to that archive |
| `$CREDENTIAL` | Absolute mode-0400 workload-identity or service-account document |
| `$WIF_ACCOUNT` | Impersonated service-account email bound by that document |
| `$PROOF_PROJECT` | Dedicated proof project id; it must contain `proof` and must not contain `prod`, `production`, `xprize`, `staging`, or `live` |
| `$REVISION` | Frozen shared revision recorded into `RELEASE_INPUT_INDEX.json`; `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` |
| `$ADMIN_CIDR` | Restricted IPv4 admin source CIDR; `0.0.0.0/0` is refused |
| `$CLIENT_CIDR` | Restricted IPv4 dataplane source CIDR; defaults to `$ADMIN_CIDR` if omitted |
| `$PROBE` | Absolute, regular, executable, single-link copy of `tools/gcp_proof_live_probe.py` |

Run every Python command in this runbook with `$WINS_PYTHON314`. Ambient
`python3` is not an authenticated runtime. Set the local Python receipt before
any deployment-input, plan, deploy, or collect command:

```sh
export WINS_GCP_PYTHON_RUNTIME_RECEIPT=/absolute/private/python-runtime-receipt.json
export WINS_GCP_REMOTE_PYTHON_RUNTIME_RECEIPT=/absolute/private/remote-python-runtime-receipt.json
```

Those receipts must be mode 0400 and match contract `winsvpn-gcp-python-runtime-v1`,
kind `winsvpn.gcp_proof.python_runtime.v1`, implementation `cpython`, and version
`3.14.7`. There is no reviewed producer CLI for either receipt. A missing,
writable, stale, or substituted receipt fails closed. Version-only ambient
Python is refused.

## Safety boundary

`tools/gcp_proof_fleet.py` is an emit-only planner, verifier, and reset
planner. It never executes gcloud. `plan`, `apply`, `verify`, `reset`, and
`emergency-cleanup` emit or bind argv and local documents. They do not
authenticate, create, update, or delete cloud resources.

`tools/gcp_proof_deploy.py` and `tools/gcp_proof_evidence.py` are different:
during a separately authorized live run they execute reviewed drivers with one
fixed explicit argv vector per action and `subprocess.run(..., shell=False)`.
They never accept a caller-authored transcript, start/end time, or command
list.

No gcloud, SSH, cloud, or production command is executed by the unit tests or
by preparing this contract. Dedicated tests inject a fake runner. A fake runner
cannot mint an acceptance receipt or a production PASS. Test-only Google Cloud
CLI receipts and `create_test_only` are not production commands.

JSON `ok: true` from a dry-run, `would_apply`, `would_reset`, `verdict:
inconclusive`, `verdict: blocked`, or `acceptance: false` is not proof and is
not an acceptance receipt.

The deployment helper copied to each VM's `/tmp` directory is untrusted staged
data, not an executable trust anchor. The fixed SSH command starts a root-owned
inline Python bootstrap, opens the staged helper with `O_NOFOLLOW`, binds the
read to one regular single-link inode, checks the reviewed SHA-256, and executes
only those already-read bytes in memory. It never asks root's Python to execute
the `/tmp` pathname directly.

## 1. Google Cloud CLI custody

Every command-executing proof entrypoint requires Google Cloud CLI 582.0.0 from
the reviewed official platform archive. A self-reported version is not
sufficient. Extract the archive to `$GCLOUD_SDK` first so that tree is
byte-identical to the archive, then create the local SDK receipt:

```sh
"$WINS_PYTHON314" tools/create_gcloud_custody_receipt.py \
  --archive "$GCLOUD_ARCHIVE" \
  --install-root "$GCLOUD_SDK"
```

`--pin-manifest` defaults to `tools/toolchain-pins.json`. The producer verifies
the archive filename and SHA-256 against that pin, compares the complete
installed tree with a safe archive extraction, retains the exact pinned archive
bytes as `.winsvpn-gcloud-official-archive` at mode 0400, and writes a new
mode-0400 `.winsvpn-gcloud-custody-v1.json` receipt inside the SDK root.

Production receipt creation also requires an existing external owner issuance
document at `/var/lib/winsvpn/gcloud-owner-issuance.json`. That file must be
outside the repository, not owned by the current uid, not writable, and inside
the six-hour freshness window. No tool in this repository mints or rewrites
that issuance. Same-uid chmod 0444 files and source-freeze producer execution
are not a trust root. Missing, mutable, stale, substituted, test-only, or
self-authored synthetic pin/receipt state fails before the next compute or SSH
command.

Python deployment and live-probe entrypoints independently re-extract the
retained pinned archive and require its derived tree hash to match both the
receipt and installed SDK. Every gcloud operation they run uses a fresh
private, read-only extraction of the already verified archive bytes, then
rechecks the installed tree, archive, receipt, and executable identity.
Swapping and restoring the writable installed pathname cannot select the
executed command.

Pass `--gcloud-bin "$GCLOUD_SDK/bin/gcloud"` into `plan`. Later live runners
resolve that basename/path but still require this exact 582.0.0 runtime before
the first cloud command.

## 2. Workload identity

Live deploy and collect require one descriptor-authenticated identity. They
accept `--credential-kind workload_identity` or `--credential-kind
service_account`. Application-default credentials, ambient `gcloud auth`,
impersonation flags, and credential environment overrides are stripped or
refused.

The credential file must be an absolute regular single-link file at mode 0400.
For workload identity the JSON type is `external_account` with exactly these
keys: `type`, `audience`, `subject_token_type`, `token_url`,
`service_account_impersonation_url`, `credential_source`. `token_url` must be
`https://sts.googleapis.com/v1/token`. `subject_token_type` must be
`urn:ietf:params:oauth:token-type:jwt`. `audience` must be a global
`//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`
value. `service_account_impersonation_url` must be the documented
`iamcredentials.googleapis.com` `generateAccessToken` URL for `$WIF_ACCOUNT`.
`credential_source` may contain only `file`, and that path must be absolute.

`--credential-account` must equal `$WIF_ACCOUNT`. `--credential-project` must
equal `$PROOF_PROJECT`. A mismatched account or project fails closed.

`tools/gcp_proof_deploy.py` takes those values as flags.
`tools/gcp_proof_evidence.py` has no credential flags; it reads:

```sh
export WINS_GCP_PROOF_CREDENTIAL_KIND=workload_identity
export WINS_GCP_PROOF_CREDENTIAL_PATH="$CREDENTIAL"
export WINS_GCP_PROOF_CREDENTIAL_ACCOUNT="$WIF_ACCOUNT"
export WINS_GCP_PROOF_CREDENTIAL_PROJECT="$PROOF_PROJECT"
```

The live probe may take the same values as optional `--credential-*` flags.
Do not print, commit, or paste the credential document.

## 3. Release input index

`plan` binds one exact `RELEASE_INPUT_INDEX.json` by absolute path and SHA-256.
The index must stay under `.artifacts/`, include every canonical freeze
platform (`android`, `wear_os`, `ios`, `macos`, `windows`, `linux`,
`extension`), and remain `publication_authorized: false`. The dedicated proof
client is verified against the `linux` platform of that same index.

```sh
"$WINS_PYTHON314" tools/release_dependency_freeze.py freeze-shared \
  --repo "$REPO" \
  --revision "$REVISION" \
  --output .artifacts/freeze/SHARED_INPUTS.json

"$WINS_PYTHON314" tools/release_dependency_freeze.py snapshot-platform \
  --repo "$REPO" --platform android \
  --shared-manifest .artifacts/freeze/SHARED_INPUTS.json \
  --output .artifacts/freeze/ANDROID_INPUTS.json
"$WINS_PYTHON314" tools/release_dependency_freeze.py snapshot-platform \
  --repo "$REPO" --platform wear_os \
  --shared-manifest .artifacts/freeze/SHARED_INPUTS.json \
  --output .artifacts/freeze/WEAR_OS_INPUTS.json
"$WINS_PYTHON314" tools/release_dependency_freeze.py snapshot-platform \
  --repo "$REPO" --platform ios \
  --shared-manifest .artifacts/freeze/SHARED_INPUTS.json \
  --output .artifacts/freeze/IOS_INPUTS.json
"$WINS_PYTHON314" tools/release_dependency_freeze.py snapshot-platform \
  --repo "$REPO" --platform macos \
  --shared-manifest .artifacts/freeze/SHARED_INPUTS.json \
  --output .artifacts/freeze/MACOS_INPUTS.json
"$WINS_PYTHON314" tools/release_dependency_freeze.py snapshot-platform \
  --repo "$REPO" --platform windows \
  --shared-manifest .artifacts/freeze/SHARED_INPUTS.json \
  --output .artifacts/freeze/WINDOWS_INPUTS.json
"$WINS_PYTHON314" tools/release_dependency_freeze.py snapshot-platform \
  --repo "$REPO" --platform linux \
  --shared-manifest .artifacts/freeze/SHARED_INPUTS.json \
  --output .artifacts/freeze/LINUX_INPUTS.json
"$WINS_PYTHON314" tools/release_dependency_freeze.py snapshot-platform \
  --repo "$REPO" --platform extension \
  --shared-manifest .artifacts/freeze/SHARED_INPUTS.json \
  --output .artifacts/freeze/EXTENSION_INPUTS.json

"$WINS_PYTHON314" tools/release_dependency_freeze.py create-index \
  --repo "$REPO" \
  --manifest-dir .artifacts/freeze \
  --output .artifacts/freeze/RELEASE_INPUT_INDEX.json

"$WINS_PYTHON314" tools/release_dependency_freeze.py verify-index \
  --repo "$REPO" \
  --index .artifacts/freeze/RELEASE_INPUT_INDEX.json \
  --platform linux
```

`begin-build` / `finish-build` / `verify-receipt` mint store-artifact freeze
receipts. They are not the GCP proof-client build receipt. Do not pass a freeze
finish-build receipt as `--client-build-receipt`.

## 4. Proof client artifact and build receipt

The live client is a dedicated linux/amd64 executable. The builder refuses any
target this host cannot execute, and the binding refuses any platform other
than `linux`. The compiled identity target must be `linux/amd64`. `go version`
must report the pinned Go from `tools/toolchain-pins.json` on `linux/amd64`.
Build and later collect on linux/amd64 only.

```sh
"$WINS_PYTHON314" tools/build_gcp_proof_client.py \
  --repo-root "$REPO" \
  --release-input-index "$REPO/.artifacts/freeze/RELEASE_INPUT_INDEX.json" \
  --output "$REPO/.artifacts/gcp-proof/winsvpn-gcp-proof-client-linux-amd64" \
  --receipt "$REPO/.artifacts/gcp-proof/winsvpn-gcp-proof-client-linux-amd64.receipt.json" \
  --goos linux \
  --goarch amd64

"$WINS_PYTHON314" tools/gcp_client_release_binding.py \
  --repo-root "$REPO" \
  --client-platform linux \
  --release-input-index "$REPO/.artifacts/freeze/RELEASE_INPUT_INDEX.json" \
  --build-receipt "$REPO/.artifacts/gcp-proof/winsvpn-gcp-proof-client-linux-amd64.receipt.json" \
  --artifact "$REPO/.artifacts/gcp-proof/winsvpn-gcp-proof-client-linux-amd64"
```

`--output` must be a new path named exactly
`winsvpn-gcp-proof-client-linux-amd64`. `--receipt` must be a new path. Both
must stay inside `$REPO`. The receipt contract is
`winsvpn-gcp-proof-client-build-receipt-v1` with `publication_authorized`
false. The artifact mode must be `0555`.

The frozen client interface used by the collector for actions 3 through 16 is
`--winsvpn-proof-identity` and `--winsvpn-proof-action <action>` with a fixed
JSON argv. Operators do not invoke that interface; `gcp_proof_evidence.py`
owns the argv.

Copy the reviewed probe driver to `$PROBE`, keep a regular single-link file,
make it executable and not group/world writable, and keep it byte-identical to
`tools/gcp_proof_live_probe.py`. Record its SHA-256. A substituted probe
driver cannot reach final acceptance.

## 5. Deployment-input manifest

Create the immutable server/runtime closure before `plan`. The manifest path
must be absolute, outside the repository, and new. It binds the three
architecture-matched Winn v3 proof-client ELFs (`winn3-gateway`, `winn3-probe`,
`winn-ech-keygen`) plus the linux/amd64 AWG v3.1.20260828 and Xray v26.9.30
client-runtime ELFs. Caller-authored digest, tag, or commit arguments do not
exist on this CLI. `awg-quick` is intentionally absent: upstream ships it as a
Bash script, and the proof broker directly starts `amneziawg-go` and applies
the fixed client configuration with the custodied `awg` ELF.

```sh
"$WINS_PYTHON314" tools/gcp_deployment_inputs.py create \
  --repo-root "$REPO" \
  --output /absolute/private/DEPLOYMENT_INPUTS.json \
  --winn3-gateway-artifact "$REPO/path/to/winn3-gateway-linux-amd64" \
  --winn3-probe-artifact "$REPO/path/to/winn3-probe-linux-amd64" \
  --winn-ech-keygen-artifact "$REPO/path/to/winn-ech-keygen-linux-amd64" \
  --amneziawg-go-artifact "$REPO/path/to/amneziawg-go-linux-amd64" \
  --awg-artifact "$REPO/path/to/awg-linux-amd64" \
  --xray-artifact "$REPO/path/to/xray-linux-amd64"

"$WINS_PYTHON314" tools/gcp_deployment_inputs.py verify \
  --repo-root "$REPO" \
  --manifest /absolute/private/DEPLOYMENT_INPUTS.json
```

## 6. Emit the plan

`$STATE` must be a new owner-only mode-0700 directory, or `plan` will create
that directory. Instance names must be distinct, must not be reserved sim or
production names (`control-sim`, `data-sim`, `core-sim`, `data-sim-winn3gw`,
`xprize-hub`, `xprize-route-a`, `xprize-route-b`), and must not carry those
markers.

```sh
"$WINS_PYTHON314" tools/gcp_proof_fleet.py plan \
  --control-instance proof-control-a1 \
  --winn3-data-instance proof-winn3-a1 \
  --cover-data-instance proof-cover-a1 \
  --project "$PROOF_PROJECT" \
  --state-dir "$STATE" \
  --admin-source-cidr "$ADMIN_CIDR" \
  --dataplane-source-cidr "$CLIENT_CIDR" \
  --gcloud-bin "$GCLOUD_SDK/bin/gcloud" \
  --repo-root "$REPO" \
  --deployment-inputs /absolute/private/DEPLOYMENT_INPUTS.json \
  --release-input-index "$REPO/.artifacts/freeze/RELEASE_INPUT_INDEX.json" \
  --client-build-receipt "$REPO/.artifacts/gcp-proof/winsvpn-gcp-proof-client-linux-amd64.receipt.json" \
  --client-artifact "$REPO/.artifacts/gcp-proof/winsvpn-gcp-proof-client-linux-amd64"
```

`--repo-root`, `--deployment-inputs`, `--release-input-index`,
`--client-build-receipt`, and `--client-artifact` are required for `plan` and
refused on every later phase. Those later phases reuse only the immutable
plan-bound inputs.

`plan.json` and its SHA-256 sidecar are mode 0400. The output contains cloud
creation argv and the exact eight installer steps. Installer
`execution_owner` is `gcp_proof_deploy.py`. The gateway installer and on-VM
key provision appear only for `data-winn3`; `data-cover` receives the data-plane
installer. `plan` is `dry_run: true` and does not create cloud resources.

Default zones and machines, if omitted, are `us-east1-b` / `e2-standard-2` for
control, `us-central1-a` / `e2-medium` for `data-winn3`, and `us-east1-b` /
`e2-medium` for `data-cover`. The image family/project must remain Ubuntu 24.04
LTS from `ubuntu-os-cloud`.

## 7. Bind the apply state

Bind apply **before** creating VMs. Deploy later requires every VPC, subnet,
firewall, and instance creation timestamp to be strictly after
`apply.json`'s `created_utc` and inside a six-hour freshness window.

Without `--confirm-apply` the command is a dry-run (`would_apply: true`) and
writes nothing.

```sh
"$WINS_PYTHON314" tools/gcp_proof_fleet.py apply \
  --control-instance proof-control-a1 \
  --winn3-data-instance proof-winn3-a1 \
  --cover-data-instance proof-cover-a1 \
  --project "$PROOF_PROJECT" \
  --state-dir "$STATE" \
  --confirm-apply
```

This still does not run cloud commands. It writes an immutable apply record and
sidecar at mode 0400. The collector, deployer, and verifier refuse a missing,
writable, tampered, stale-schema, or plan-mismatched immutable apply state. The
apply record is an operator-state binding, not proof by itself that cloud
mutation occurred.

## 8. Create the fleet from emitted plan argv

The planner remains responsible for creating resources. There is no
custody-wrapped executor for the emitted create argv. After apply is bound,
execute those argv in order with the same `$GCLOUD_SDK/bin/gcloud` named in
the plan: custom VPC, regional subnets, four firewall rules, then the three
apply-bound VMs. Do not reuse existing VMs. Existing, mislabeled, or
pre-apply resources are refused by deploy preflight.

## 9. Deploy the eight installer steps

```sh
"$WINS_PYTHON314" tools/gcp_proof_deploy.py \
  --repo-root "$REPO" \
  --plan "$STATE/plan.json" \
  --apply "$STATE/apply.json" \
  --deployment-inputs /absolute/private/DEPLOYMENT_INPUTS.json \
  --output "$STATE/deployment-execution.json" \
  --confirm-live-deployment \
  --credential-path "$CREDENTIAL" \
  --credential-kind workload_identity \
  --credential-account "$WIF_ACCOUNT" \
  --credential-project "$PROOF_PROJECT"
```

`--output` must be a new absolute file named `deployment-execution.json`
inside `$STATE`. `--confirm-live-deployment` is required for a live install.
The executor transfers an exact manifest-only bundle and runs this one valid
order:

1. `control` `wins_control_plane_setup_ONETOUCH.sh --preflight`
2. `control` `wins_control_plane_setup_ONETOUCH.sh --deploy`
3. `data-winn3` `wins_winn3_gateway_install.sh --install`
4. `data-winn3` on-VM key provision `--on-vm-generate`
5. `data-winn3` `wins_winn3_gateway_install.sh --preflight`
6. `data-winn3` `wins_winn3_gateway_install.sh --start`
7. `data-cover` `wins_data_plane_setup_ONETOUCH.sh --preflight`
8. `data-cover` `wins_data_plane_setup_ONETOUCH.sh --deploy`

Operators do not run those installers locally or over ad-hoc SSH. A passed
receipt has `status: passed`. `cleaned` is not a passed install.
`--confirm-cleanup` authorizes bounded proof-resource deletion on failure or
as a cleanup-only run without `--confirm-live-deployment`. Cleanup is not
success until exact-name describes prove each VM, firewall, subnet, and
network is absent. A cleanup failure is never converted into a passing result.

## 10. Collector command contract

The collector owns this exact 16-action order:

1. `inventory`
2. `deployment`
3. `route-decision`
4. `connect-primary`
5. `connect-cover-awg`
6. `connect-cover-xray`
7. `inject-awg-block`
8. `probe-awg-block`
9. `restore-awg`
10. `inject-winn3-block`
11. `probe-winn3-block`
12. `withdraw-cover`
13. `probe-cover-withdrawn`
14. `restore-cover`
15. `restore-winn3`
16. `teardown-check`

Collection requires a passed `deployment-execution.json` in the same state
directory as the plan/apply pair. Evidence must start after that execution
ended, stay inside a four-hour proof window, and remain inside the six-hour
freshness window. Stale deployment evidence is refused.

Every command receives the exact fleet, run, session, correlation, client
artifact path/SHA-256/byte length, client build identity, plan-bound release
index and build receipt, deployment execution identity, project, gcloud
binary, image family/project, custom VPC, fleet tag, and each instance's name,
zone, machine type, and subnet. The command identity hashes the index, action,
complete argv, and all bindings. Missing, duplicated, forged, or reordered
commands fail.

The collector captures raw stdout, raw stderr, integer exit code, start UTC,
and end UTC for every command. Streams are stored as base64 plus byte length
and SHA-256. Each record hashes its complete content and the previous record
hash. The bundle also binds the collector, verifier, probe driver, exact client
artifact, immutable plan, immutable apply, and deployment execution files by
path, SHA-256, and byte length.

Each successful command must emit one JSON observation envelope. The envelope
contains facts, not `pass`, `ok`, `success`, `verdict`, or `acceptance` tokens.
The verifier derives its result from facts such as instance power state,
service state, descriptor/selected-node equality, carried byte counters,
protocol attempt order, negative-control state, refusal code, and exact
resource lists.

The inventory driver parses live `gcloud ... describe --format=json` results.
The verifier does not treat those argv values as proof. It independently
rebuilds the expected posture from the immutable apply-bound specification and
requires exact equality for:

- custom VPC name, custom-subnet mode, regional routing, every subnet name,
  region, CIDR, and parent VPC
- each instance name, zone, machine type, RUNNING state, VPC, and subnet
- the resolved immutable Ubuntu image name/ID and its exact
  `ubuntu-os-cloud` Ubuntu 24.04 family/project
- instance-level OS Login enabled, zero attached identities, zero OAuth scopes,
  Secure Boot, vTPM, integrity monitoring, and deletion protection
- exact proof labels and exact fleet/role tags

The deployment action independently reads `/etc/os-release`, the deployed role
file, exact systemd unit states, and the remote Python runtime receipt over the
isolated proof fleet. Ubuntu 24.04 and the exact role-specific units are
required. The remaining parsers derive and require:

- hub carrier `winn3`, a verified descriptor, and descriptor node equal to the
  selected `data-winn3` node
- Winn v3 first and nonzero Winn v3 carried traffic
- an AWG handshake and Xray connection on `data-cover`
- AWG blocked, followed by Xray on `data-cover`
- Winn v3 blocked, followed by AWG on the distinct `data-cover` node
- cover withdrawn while Winn v3 is blocked, followed by
  `same_node_downgrade_refused` and zero same-node downgrade attempts
- restoration of AWG, Winn v3, and the cover node
- exact proof-resource scope with no unexpected target, foreign resource,
  credential-file read, or production resource touch

If collection fails after a negative control is active, the collector attempts
the corresponding fixed restoration argv before refusing and writes no
evidence.

## 11. Run the authorized collector

```sh
"$WINS_PYTHON314" tools/gcp_proof_evidence.py \
  --plan "$STATE/plan.json" \
  --apply "$STATE/apply.json" \
  --probe-driver "$PROBE" \
  --run-id run-20260825-001 \
  --session-id session-20260825-001 \
  --correlation-id correlation-20260825-001 \
  --confirm-live-collection \
  --output "$STATE/evidence.json"
```

`--confirm-live-collection` is required. The output path must be new and inside
a mode-0700 directory. A successful bundle and sidecar are mode 0400. Document
permissions are checked on the same opened inode that is hashed. Output
publication holds an opened, non-symlink, mode-0700 parent directory
descriptor through creation, fsync, and the final identity check. Caller-provided
start/end times, transcript paths, and client-artifact flags do not exist in
this CLI; the client artifact comes from the plan-bound release binding.
`--timeout-seconds` defaults to 600 and must stay between 1 and 3600.

Run ids, session ids, and correlation ids must match
`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`.

## 12. Verify and mint the receipt

```sh
"$WINS_PYTHON314" tools/gcp_proof_fleet.py verify \
  --control-instance proof-control-a1 \
  --winn3-data-instance proof-winn3-a1 \
  --cover-data-instance proof-cover-a1 \
  --project "$PROOF_PROJECT" \
  --state-dir "$STATE" \
  --evidence "$STATE/evidence.json" \
  --probe-driver "$PROBE" \
  --run-id run-20260825-001 \
  --session-id session-20260825-001 \
  --correlation-id correlation-20260825-001
```

Without `--evidence`, verify returns `verdict: inconclusive` and
`acceptance: false`. That is not a receipt. Missing probe-driver, run, session,
or correlation identity with evidence present is a refusal.

Verification reopens and rehashes every bound file, capture, command record,
and source closure. It then independently parses command stdout and derives the
checks. Edited output, recomputed but false facts, wrong client hash, wrong
client build identity, wrong probe driver, missing apply state, or a changed
collector/verifier closes the gate.

Final acceptance additionally requires the reviewed live probe bytes and a
distinct required release artifact for each of the 16 collector actions. A
single Linux proof client is not those 16 store artifacts. When that gate is
blocked, verify returns `verdict: blocked` and `acceptance: false` and writes
no receipt. Only a passing re-verification can write a mode-0400 acceptance
receipt at `$STATE/acceptance-receipt.json`.

## 13. Bind the proof to cross-store readiness

The acceptance receipt remains usable only while the complete evidence chain is
within the proof verifier's six-hour freshness window. Cross-store readiness
reopens and revalidates the immutable receipt, plan, apply record, evidence
bundle, command hash chain, verifier closure, proof client, and exact
`RELEASE_INPUT_INDEX.json` path and SHA-256. A receipt from another checkout,
release index, proof client, or observation window fails closed.

Source-only reporting remains available before the live proof and never claims
upload authorization:

```sh
"$WINS_PYTHON314" tools/cross_store_upload_readiness.py evaluate --repo "$REPO"
```

After a current mode-0400 receipt exists, record final local cross-store
evidence. Repeat `--receipt` once for each of the 16 required upload targets
in one invocation. `--gcp-proof-acceptance-receipt` may be omitted only when
`WINS_GCP_PROOF_ACCEPTANCE_RECEIPT` already names that same path.

```sh
"$WINS_PYTHON314" tools/cross_store_upload_readiness.py record \
  --repo "$REPO" \
  --output .artifacts/cross-store/UPLOAD_READINESS.json \
  --index .artifacts/freeze/RELEASE_INPUT_INDEX.json \
  --gcp-proof-acceptance-receipt "$STATE/acceptance-receipt.json" \
  --receipt android-phone-tablet-aab=.artifacts/upload-receipts/android-phone-tablet-aab.json \
  --receipt android-tv-aab=.artifacts/upload-receipts/android-tv-aab.json \
  --receipt wear-os-aab=.artifacts/upload-receipts/wear-os-aab.json \
  --receipt ios-app-store-ipa=.artifacts/upload-receipts/ios-app-store-ipa.json \
  --receipt macos-app-store-pkg=.artifacts/upload-receipts/macos-app-store-pkg.json \
  --receipt windows-x64-installer=.artifacts/upload-receipts/windows-x64-installer.json \
  --receipt windows-x64-partner-center=.artifacts/upload-receipts/windows-x64-partner-center.json \
  --receipt windows-arm64-installer=.artifacts/upload-receipts/windows-arm64-installer.json \
  --receipt windows-arm64-partner-center=.artifacts/upload-receipts/windows-arm64-partner-center.json \
  --receipt linux-x64-package=.artifacts/upload-receipts/linux-x64-package.json \
  --receipt linux-arm64-package=.artifacts/upload-receipts/linux-arm64-package.json \
  --receipt linux-flathub-manifest=.artifacts/upload-receipts/linux-flathub-manifest.json \
  --receipt linux-snap-manifest=.artifacts/upload-receipts/linux-snap-manifest.json \
  --receipt chrome-extension-package=.artifacts/upload-receipts/chrome-extension-package.json \
  --receipt edge-extension-package=.artifacts/upload-receipts/edge-extension-package.json \
  --receipt firefox-extension-package=.artifacts/upload-receipts/firefox-extension-package.json
```

This command executes no cloud or store operation.
`store_upload_authorized` remains false. Missing, writable, stale, tampered,
or release-substituted GCP proof state prevents final readiness from being
recorded. Even a valid proof does not itself perform or authorize a store
upload; owner and store-specific gates remain separate.

## 14. Teardown

### Passed acceptance receipt

`reset` requires a matching immutable passing receipt. Without
`--confirm-reset` it is a dry-run and emits no delete argv.

```sh
"$WINS_PYTHON314" tools/gcp_proof_fleet.py reset \
  --control-instance proof-control-a1 \
  --winn3-data-instance proof-winn3-a1 \
  --cover-data-instance proof-cover-a1 \
  --project "$PROOF_PROJECT" \
  --state-dir "$STATE" \
  --confirm-reset
```

Reset rechecks the immutable plan, apply record, receipt, fleet, and verifier.
It emits only proof-fleet deletion-protection, instance, firewall, subnet, and
VPC deletion argv. It never runs those commands. Execute the emitted argv, then
independently confirm that the three VMs, firewall rules, subnets, and proof
VPC no longer exist.

### Failed live deploy

Authorized deletion without an acceptance receipt is
`tools/gcp_proof_deploy.py --confirm-cleanup` with `--output` still required to
be the unused `$STATE/deployment-execution.json`. Combine it with
`--confirm-live-deployment` to roll back a failing install, or omit
`--confirm-live-deployment` for cleanup-only when no execution receipt exists
yet. After a live deploy has already written that file, the output path cannot
be reused and this CLI cannot start a second cleanup against the same state
directory.

### Emergency cleanup evidence

```sh
"$WINS_PYTHON314" tools/gcp_proof_fleet.py emergency-cleanup \
  --control-instance proof-control-a1 \
  --winn3-data-instance proof-winn3-a1 \
  --cover-data-instance proof-cover-a1 \
  --project "$PROOF_PROJECT" \
  --state-dir "$STATE" \
  --confirm-emergency-cleanup
```

This phase requires `--confirm-emergency-cleanup`, a bound apply record, and a
deployment execution receipt, and it refuses if an acceptance receipt already
exists. It writes `emergency-cleanup-evidence.json` with
`acceptance: false` and `deletion_implemented: false`. It does not emit or
run delete argv.

## Exact live order

1. Provision the pinned CPython 3.14.7 runtime receipts and the external
   Google Cloud CLI owner issuance, then create the official 582.0.0 SDK
   custody receipt.
2. Freeze shared and platform manifests and create
   `.artifacts/freeze/RELEASE_INPUT_INDEX.json`.
3. Build and bind the linux/amd64 proof client against that index. Copy the
   reviewed probe driver to `$PROBE`.
4. Create and verify `/absolute/private/DEPLOYMENT_INPUTS.json`.
5. Emit `plan`, then bind `apply` with `--confirm-apply`.
6. Execute the emitted create argv so the VPC, subnets, firewalls, and VMs are
   strictly newer than `apply.json`.
7. Run `gcp_proof_deploy.py --confirm-live-deployment` with the workload-identity
   input. It runs the eight installer steps.
8. Export the collector credential and Python-receipt environment and run
   `gcp_proof_evidence.py --confirm-live-collection` once. It will execute, in
   order: `inventory`, `deployment`, `route-decision`, `connect-primary`,
   `connect-cover-awg`, `connect-cover-xray`, `inject-awg-block`,
   `probe-awg-block`, `restore-awg`, `inject-winn3-block`, `probe-winn3-block`,
   `withdraw-cover`, `probe-cover-withdrawn`, `restore-cover`, `restore-winn3`,
   and `teardown-check`.
9. Re-run `verify` against the unchanged plan, apply record, driver, client,
   and evidence. A `pass` receipt is written only when every derived check and
   the 16-artifact acceptance gate succeed.
10. After a passing receipt, execute the separately emitted reset argv and
    independently confirm absence. After a failed deploy, use authorized
    deploy cleanup. `emergency-cleanup` records identity only.

No VM observation, negative-control run, acceptance receipt, or post-reset
absence observation exists until those authorized live actions execute.

## Trust limit

- Local hashes and record chaining detect editing and reject old or malformed
  evidence. Without a hardware or externally held signing trust anchor, they
  cannot cryptographically distinguish the reviewed collector from a hostile
  local administrator who can replace every source, evidence, and expected
  hash. The final proof therefore also requires controlled-host custody and
  independent review of the frozen collector and probe-driver hashes.
