# REPO_PLAN.md - Judged Repository Plan

Goal: a clean private GitHub repo the judges can read, containing everything that shows the hackathon work, containing nothing that leaks.

## Repo name and visibility

- Name: OWNER-FILL (suggested: wins-gemini-router)
- Visibility: PRIVATE. Judges get access as collaborators, not a public repo.

## Live deployment this repo backs

The router source in `router/` is what runs the live Google Cloud Run service at https://AI_ROUTER_HOST (model gemini-3-flash-preview, structured output, deterministic fallback). The staging hub in `staging-hub/` and the winn3 gateway assets in `winn3-nodes/` back the Compute Engine deployment in the project "Win's VPN XPRIZE". The repo is the readable source of record for all of it. Judges can open the live URL themselves; the evidence/ folder proves the source and the deployment match.

## Contents (final repo tree)

```
README.md              judge-facing entry point (outline below)
SPEC.md                the demo spec v2 (winn/3 transport; supersedes the dead AWG spec)
router/                Cloud Run Gemini router source: decision service, deterministic gate,
                       decision log, dark dashboard, /hoppy/escalate, tests (Lane A output;
                       live on https://AI_ROUTER_HOST)
staging-hub/           Compute Engine hub source: FastAPI /nodes + /free/verify serving
                       winn/3 config, Caddy TLS config, admin health trigger, router client,
                       tests (Lane B output)
winn3-nodes/           winn3 gateway deploy assets: provisioning + deploy_and_verify scripts,
                       descriptor ring PUBLIC summary (G1 public key + ring sha256), node
                       systemd/firewall notes (Lane C output; public-safe files only)
apk/                   staging debug APK binary (org.winsvpn.app.debug v1.0.15) +
                       apk-sha256.txt
build_apk.sh           APK build script with the exact flutter build apk-debug command
                       and dart-defines from SPEC.md (values redacted, see below)
docs/                  this workdir's drafts, verbatim: SUBMISSION_DRAFT.md, VIDEO_SCRIPT.md,
                       EVIDENCE_CHECKLIST.md, REVENUE_TEMPLATE.md, REPO_PLAN.md, FACTS.md,
                       LANE_REPORT.md, CONTINUE.md
evidence/              the evidence pack captured per EVIDENCE_CHECKLIST.md: decisions JSON
                       + curl tee + JSONL, Cloud Run + hub + GCE console screenshots,
                       dashboard switch mp4, phone screenshots, gateway verify receipts,
                       hub /nodes + admin state exports, apk-sha256.txt, winn3-descriptor-ring.txt,
                       secret-scan-output.txt, nonprofit certificate
LICENSE                proprietary, all rights reserved (see license note)
```

## Exclusions (hard rules)

Never committed, never staged, checked twice. Delete or scrub before staging, then run the gitleaks command below.

- NO private keys of any kind (server, peer, signing, SSH). The winn3 descriptor signing key is never in this repo; the repo holds only the G1 public key and the ring sha256, which are meant to be public.
- NO admission keys. The signed descriptor envelopes ride an `admission_secret` inside the payload, so the REAL descriptor files (staging-hub/descriptors/*.json, awg-nodes/keys/demo-gw-*/winn3-gateway-admission.key) must NOT be committed. The repo ships no descriptor envelopes, or only clearly-labeled test fixtures with dummy secrets and a README note.
- NO g1.pem. The descriptor-ring signing key file never enters the repo or any lane workdir.
- NO state.json with device static keys. The hub runtime state file holds per-device winn3_static_private keys and sticky allocations; it is EXCLUDED entirely. If a sample is wanted, commit a schema-only example with dummy values, named state.example.json, with the real runtime file never written into the repo.
- NO .env files, service account JSONs, gcloud config directories, or Cloud Run deploy flags containing secrets.
- NO tokens in docs: router URLs with embedded keys, Gemini API keys, or the X-Demo-Key in test commands. The live router URL has no embedded key and is safe to include.
- NO dead AWG artifacts: install_amnezia.sh, provision.sh, verify.sh, amnezia params, and awg_compat_public_key fields are stripped. The winn3 deploy assets in this repo come from the current live lane (provision_gw.sh, deploy_and_verify.sh, keys/PUBSUMMARY.md, module/ public docs, out/ binaries + sha256); keys/demo-gw-* (private halves, admission keys, cover keys, client.key) stay out.
- Working-tree directories that are not judged content: dashboard/, keys/, pb_*/, logs/, briefs/, google-cloud-sdk/, .venv, __pycache__, .pytest_cache.

The build script takes STAGING_BASE_URL and STAGING_HOSTNAME from environment variables at build time, and the README says so. No real hostnames or IPs of production systems anywhere. Staging hostnames, the staging hub URL https://<STAGING_HUB_SSLTIP_HOST>, the live demo router URL, and the two demo gateway egress IPs are fine.

## Secret scan (run before every push)

Exact command line:

```bash
gitleaks detect --source . --no-git --redact -r evidence/secret-scan-output.txt
```

Save the output to evidence/secret-scan-output.txt. The scan must report zero findings before the repo is shared. If it finds something, remove the secret, rotate the credential, rescan. Do not just add it to .gitignore after exposure. Note: gitleaks pattern-matches; it does not judge intent. The hard-rule exclusions above must be enforced by hand BEFORE the scan, because the scan cannot know that a state.json key is a live device static key.

Alternative if gitleaks is unavailable:

```bash
trufflehog filesystem --directory . --only-verified
```

## Repo creation and access (OWNER performs; no git commands during lane work)

1. Create private repo on GitHub (web UI or gh): `gh repo create OWNER-FILL/wins-gemini-router --private`
2. Push contents after the secret scan passes.
3. Add judge access:
   - `gh api repos/OWNER-FILL/wins-gemini-router/collaborators/testing@devpost.com -X PUT -f permission=read`
   - `gh api repos/OWNER-FILL/wins-gemini-router/collaborators/judging@hacker.fund -X PUT -f permission=read`
4. Record the repo URL in the Devpost submission.

## Full VPN client source

The router, hub, nodes, build script, and docs go in the judged repo. The complete Win's VPN client application is a larger production codebase. It is available to judges on request through a separate private repo share (OWNER-FILL repo name, granted to the same judge emails on request via the Devpost discussion tab). The README states this plainly so nobody thinks the client is hidden.

## License

Proprietary. All rights reserved, Win's VPN Inc. and Win Empire LLC. Judges and Devpost reviewers receive evaluation access for the duration of judging. No open-source license is granted by sharing the repo. The LICENSE file states exactly that in three sentences.

## README for judges (outline)

1. What this is: Gemini adaptive routing for a nonprofit anti-censorship VPN, built for the Build with Gemini XPRIZE, running live on Google Cloud Run.
2. Architecture: the chain from SPEC.md (phone -> staging hub -> Cloud Run Gemini router -> winn3 gateways), one diagram, one paragraph. Transport: Winn Protocol v3 (X25519 + ML-KEM-768, Ed25519-signed descriptors, fail-closed).
3. The decision flow, five numbered steps (probe -> /route -> Gemini structured decision -> deterministic gate -> tunnel switch).
4. Live proof (SUPERVISOR RECEIPT 2026-08-17): the router is live at https://AI_ROUTER_HOST (open /decisions), plus pointers into evidence/ (decisions JSON showing the keep [STABLE_LINK, LATENCY_OPTIMIZED] and the switch, dashboard recording, route-demo-003 console screenshot, hub /nodes screenshot, gateway verify receipts, phone screenshots, APK hash).
5. How to run the judge test: install APK, account 9999-9999-9999 + any 4-digit PIN, connect Route A, ask supervisor (or use the provided trigger) to flip route A via POST /admin/health, watch the switch. Expected timings.
6. Pre-existing work disclosure, copied verbatim from SUBMISSION_DRAFT.md: the VPN client and nonprofit predate the window minimally and are disclosed; the Gemini adaptive routing layer, the Cloud Run deployment, and the v3 demo gateway network were built during the hackathon window for this submission.
7. What is NOT in this repo (secrets, production configs, admission keys, g1.pem, hub runtime state.json with device keys, full client) and how to request the client source share.
8. License note.