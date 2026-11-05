# Deploy input envelopes — file list + SHA-256 manifest rows

Lane: BUILD DEPLOY INPUTS (D5 authorized lane work, 2026-09-03/04 UTC).
All envelope files live under `~/.xprize/owner-inputs/` (mode 0700, owner
workstation, OUTSIDE git). This file binds their identities (digests, modes,
sizes) without containing any secret value, node address, or file bytes.

Re-hash after any owner fill: `shasum -a 256 <file>` must be re-recorded in
the deploy-lane report before binding as evidence.

| Envelope file (under `~/.xprize/owner-inputs/`) | SHA-256 | Mode | Bytes | Status |
|---|---|---|---|---|
| `hub-defaults.env` | `1a59703ef35f8be8ebd195b91dd29f3c84dde8a9d59761c7311ce9d487005984` | 0600 | 5386 | COMPLETE (D5 split; owner confirms freshness) |
| `hub-secrets.names` | `91dd46731da310db10b399de400dbf5a16418234332883414589dc22166b64db` | 0600 | 1160 | NAMES-ONLY manifest; `hub-secrets.env` PENDING-OWNER-VALUES |
| `spain-defaults.env` | `7b6abe7b2c56cc4175b3505ba9232687fec6a867f41959b51c54067bea0ddd45` | 0600 | 460 | COMPLETE (D4-bound) |
| `spain-secrets.env` | `a4da52e691ea9ba46bc3e082b0f7754c80c1f2a750a5fcc532348a92e8a09aff` | 0600 | 469 | SCAFFOLD (empty, fail-closed); values PENDING deploy-time mint |
| `germany-defaults.env` | `4d6019fa0063b0f4dfe62aedee088bbbd75e8ae32d3296676796634cdd1e1760` | 0600 | 558 | COMPLETE (D4-bound) |
| `germany-secrets.env` | `977a705b0e7401530af76ec0e6d0d36d80c6eb9dfd5bf17aa583b33defe4aa9c` | 0600 | 393 | SCAFFOLD (empty, fail-closed); values PENDING deploy-time mint |
| `aicore-defaults.env` | `324c341bb9f4f3fa8a3beb03d4bc1b0bb7027979cb6d1512169d0c9de01d5df4` | 0600 | 499 | COMPLETE (D4-bound; 4 brief-pinned lines byte-exact) |
| `aicore-secrets.env` | `f1a932832d80c4fdc1f92226cdae5624ecbabdb21c156479dec3edf55f275786` | 0600 | 408 | SCAFFOLD (empty, fail-closed); values PENDING deploy-time mint |
| `spain-winn3-gateway-deploy.env` | `1d1604c017e2b8a3cbc891ddd78186e6906d3017278b5adbc44d827d4b07fbfc` | 0600 | 1156 | COMPLETE (structure + D4 values; material bytes pending) |
| `germany-winn3-gateway-deploy.env` | `121ce1c2a1edf0d3a70504b48a5567456e7f2c9a630a44a1c4a74939e61937e9` | 0600 | 1167 | COMPLETE (structure + D4 values; material bytes pending) |
| `management-access.env` | `27f915857b81b0f97acb82ea4473011f4cf2f3bc2ae4daa8a8e169e29167020d` | 0600 | 500 | SCAFFOLD (empty, fail-closed); pair PENDING Cloudflare dashboard (D8-6) |
| `spain-winn3-material/MATERIAL-LISTING.md` | `345661075a2193553ba9b1b595c620450e5e1ff7c3e356db79b75c72d0270435` | 0600 | 799 | LISTING ONLY; dir EMPTY, all members PENDING |
| `germany-winn3-material/MATERIAL-LISTING.md` | `949175b4aa290e55b7e019a82c91a7b8f85b18e4817356bd5234a1b8d207572f` | 0600 | 800 | LISTING ONLY; dir EMPTY, all members PENDING |
| `ROLE-CONTENT-AUDIT.md` | `80dce21d32c80b121396aae4c4b6ad478d124b598bdfde56b74e2298c1247949` | 0600 | 3706 | COMPLETE (names-only log, no values) |

## What remains for the deploy lanes (nothing in this lane can close these)

- OWNER-HANDS values: `hub-secrets.env` (49 names), deploy-time mints
  (`NODE_TOKEN`, `XRAY_UUID`, `CORE_TOKEN`, `CORE_BOOTSTRAP_TOKEN`,
  `RCLONE_CONFIG_SOURCE`), Cloudflare Access pair (D8-6), winn3 material
  bytes (producer binary + checksum, fresh static/admission keys, operator
  cover/ECH/leaf per node), recovery points + attestations, LUKS/FDE
  custody, fingerprints, WAN/physical reports (see manifest items).
- PRODUCER artifacts: authorized `winn3-gateway` linux/amd64 binary +
  checksum + digest-bound receipt; audit-approved `cloudflared` client +
  digests (`CLOUDFLARED_EXPECTED_SHA256`, `NODE_CLOUDFLARED_EXPECTED_SHA256`).
- AUDIT gate: Daybreak Blue GO naming one exact SHA (D2); `AUDIT_APPROVED_SHA`
  export; clean tree at that SHA; hub PASS before dataplanes.
