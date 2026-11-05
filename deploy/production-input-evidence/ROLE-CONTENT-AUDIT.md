# D5 role-content audit — names-only evidence log (2026-09-03/04 UTC)

Lane: BUILD DEPLOY INPUTS, Fable D5 authorized lane work.
NO secret values, NO node addresses, NO file bytes in this file.
Owner copy: ~/.xprize/owner-inputs/ROLE-CONTENT-AUDIT.md.

## Sources
kansas_working.env: 168 assignments / 168 unique / no dupes.
kansas_winsvpn-secrets.env: 175 assignments / 172 unique / 3 dupes (last-wins).
Working names subset of secrets names, plus 4 secrets-only names.

## Classification
SECRET (46 in working file): credentials, commerce set, credential pointers.
hub-secrets.names only (49 entries incl. 3 secrets-file-only names).
CORE-ROLE (10): DOUBLE_VPN_CORE_* identity names, excluded from hub files.
PUBLIC (112): carried verbatim to hub-defaults.env.
Coverage: 168 working = 112 carried + 56 excluded. Verified by set arithmetic.

## Gates
Refusal regexes CLEAN. bash -n OK. Winn3 gates OK. No key blobs. Scaffolds empty.

## D4
Spain spain-madrid/free; Germany germany-de1/free; subnets verified disjoint.
Aicore pinned lines byte-exact; CORE_ID aicore-core0; CORE_REGION owner-lan.
Inner .1s and gateway IDs lane-assigned, owner-confirmable. No invented hostnames.
