# Production deployment owner-input evidence

This directory closes the source-side part of deployment audit finding 7. It
does not pretend that missing owner or external evidence has been supplied.
`PENDING-OWNER-INPUT.json` is the complete production-server deployment input
inventory derived from the deployment audit, design, and three exact lane
briefs. Its committed state is deliberately:

```text
status=PENDING-OWNER-INPUT
deployment_authorized=false
```

Store reviewer accounts and store submission credentials are not in this
inventory. The audited decision boundary is production server deployment, and
the audit says store readiness was separate and had no effect on its verdict.
The exclusion is also machine-readable in `scope_exclusions`.

## Evidence states

- `supplier_kind` identifies who can supply each record. The top-level
  `PENDING-OWNER-INPUT` label names this production-deployment owner and
  external input evidence pack; it does not mean every record is an owner
  decision. In the current 37-item inventory, 22 records name the owner, while
  15 name a provider console, final auditor, authorized producer, external
  tester, or preceding lane. Those 15 must not be converted into owner
  attestations.
- `PENDING-OWNER-INPUT`: the required supplier has not provided usable
  evidence.
- `PRESENT-UNVERIFIED`: stable bytes and custody metadata were collected, but
  no owner or auditor authority is inferred.
- `CONFLICT`: collected bytes disagree with a supplied expected digest.
- `VERIFIED`: reserved for an external auditor's finalized artifact. The
  collector refuses this state in its inputs and never emits it.

The schema can represent a later terminal `VERIFIED` pack. Such a pack requires
every required item to be verified, one exact approved SHA, and an external
auditor attestation bound to that SHA. This collector does not create or sign
that attestation.

## Mac inventory captured on 2026-09-02

The pending manifest records only safe metadata for the current workstation:

- the deployment SSH private-key file exists as a one-link 0600 file, but its
  bytes and digest are not recorded;
- `known_hosts` exists as a 0600 file and has entries for the three VPS
  addresses, but no fresh provider-console comparison exists;
- three Kansas/control environment files exist as 0600 candidates, but the
  deployment design says they are mixed-role snapshots and forbids reuse
  without a fresh role-content audit;
- the current deployment audit report exists, but its verdict is NO-GO;
- `cloudflared` was absent from `PATH`; and
- no authorized production `winn3-gateway`, matching checksum, or retained
  producer receipt was found in the inspected workspace.

`LOCATED-UNVERIFIED` is not an input state and cannot satisfy a gate. It appears
only in `workstation_observations` so later reviewers know what was checked.

## Owner workflow

All generated files stay outside Git. Use an owner-controlled directory whose
ancestors are not group- or world-writable:

```bash
python3 tools/deployment_owner_inputs.py \
  init-bindings /owner-controlled/deployment-input-bindings.json
```

The generated 0600 binding document contains every input ID with null path and
digest fields. `claimed_approved_sha`, when supplied, must be the 40- or 64-hex
Git object ID of the collecting checkout. It is checked against HEAD but is not
copied into the pack's auditor-controlled `approved_sha`. For each supplied
input, set `path` to one canonical absolute path. Set `expected_sha256` only
when that digest came from the named owner, provider, auditor, or authorized
producer. Never change an expected digest to fit collected bytes.

Secret values are not a binding type. A recovery ID, token, passphrase, private
key, or other secret must stay in its owner-controlled source file or in a
secret-safe attestation. Do not paste it into JSON. For role input sets, bind
the exact file or owner-only envelope directory requested by the manifest.

Collect into a new directory:

```bash
python3 tools/deployment_owner_inputs.py collect \
  --bindings /owner-controlled/deployment-input-bindings.json \
  --output-dir /owner-controlled/deployment-input-evidence-20260902
```

The output directory is created as 0700 and must not already exist. The JSON
and checksum are 0600. File reads are descriptor-bound and stable across
pre-read and post-read identity checks. The collector refuses symlink leaves,
symlink ancestors, special files, extra hard links, wrong ownership, broad
permissions, empty files, unsafe directory members, and output reuse.
Directories receive a deterministic digest over sorted relative names, modes,
sizes, and exact member SHA-256 values. Contents are never printed or copied.

The collector exits `3` after writing a structurally valid but unauthorized
pack. Exit `3` is the expected outcome until a separate auditor verifies every
required item. Exit `2` is a fail-closed input or collection error. Validation
alone exits `0` when an unauthorized document is structurally valid. A
structurally valid document that claims authorization exits `3`, so this tool's
validation result can never be treated as deployment authority:

```bash
python3 tools/deployment_owner_inputs.py \
  validate deploy/production-input-evidence/PENDING-OWNER-INPUT.json
```

The JSON Schema uses Draft 2020-12. The standard-library validator keeps a
closed supported-keyword set and refuses an unknown keyword or unresolved
reference, so future schema additions cannot be silently ignored. The
collector and schema required-field sets are checked in both directions. Every
validated pack must also retain the committed item ID set, immutable item
requirements, source documents, scope exclusions, and workstation
observations. Removing an input or changing `required` to `false` is refused.

## What the pack proves

A collected pack binds exact artifact bytes, directory closure, file mode,
owner UID/GID, capture time, collector source, schema source, pending template,
repository HEAD, and worktree cleanliness. It can establish presence and
identity. It cannot establish that a provider console statement is true, that
the owner approved a topology, that a producer is authorized, or that an
external carriage test passed. Those judgments remain with the named supplier
and the final auditor.
