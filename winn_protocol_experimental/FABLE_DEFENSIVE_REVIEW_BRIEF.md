# Winn Protocol V3 — Authorized Defensive Review Brief

## Purpose and authorization

This is an authorized cyber-defense, privacy, and reliability review of a VPN
protocol and its test harnesses owned and controlled by the requester. The work
is limited to local source code, the requester's attached test devices, the
requester's AICORE Ubuntu host, and explicitly provisioned test infrastructure.

The permitted goals are:

- protect VPN traffic confidentiality and integrity;
- minimize linkable metadata and prevent DNS, route, and fail-open leaks;
- improve reliability, interoperability, censorship resilience, and safe
  degradation;
- validate bounded parsing, canonical evidence, cryptographic state handling,
  and resource-exhaustion defenses;
- run defensive unit, fuzz, mutation, race, sanitizer, interoperability, and
  owner-controlled lab tests;
- identify vulnerabilities and recommend fixes before production deployment.

## Explicitly out of scope

Do not provide or perform:

- unauthorized access, intrusion, credential theft, persistence, malware,
  destructive actions, or exploitation of third-party systems;
- targeting, reconnaissance, or operational instructions against people,
  organizations, public services, or infrastructure not owned by the requester;
- evasion of lawful monitoring for criminal activity;
- concealment of compromise, exfiltration, or abuse.

Censorship-resilience review here means evaluating whether an authorized user's
VPN connection can remain private and available under restrictive or unreliable
networks. It does not authorize compromising, disrupting, or bypassing access
controls on third-party computers.

## Requested Fable 5 role

Perform a read-only, independent defensive review of the exact source snapshot
identified in the accompanying review packet. Concentrate on concrete code
defects, unsafe assumptions, missing negative tests, privacy leaks, reliability
failures, and evidence-integrity gaps. Cite file paths and line numbers. Separate
observed facts from hypotheses and recommendations. Do not access cloud consoles,
SSH hosts, credentials, or physical devices.

If a requested subtopic is too broad or could be interpreted as offensive,
continue with the clearly safe subset: source review, defensive test design, and
remediation advice. State the narrowed scope instead of abandoning the entire
review.

## Model-attribution rule

Record the model identifier at the start, at every major section boundary, and
immediately before the final report. If execution switches away from Fable 5:

- preserve findings produced before the switch as a partial Fable 5 review;
- label all later material with the actual model identifier;
- treat fallback Opus output as a context-contaminated continuation, not as a
  substitute for a fresh standalone Opus 5 review; it inherited Fable's prompt,
  partial analysis, tool state, and remaining context budget;
- never describe post-switch material as Fable 5 output;
- stop after the current safe section instead of repeatedly retrying and wasting
  quota.

This brief authorizes defensive analysis only; it does not expand the technical
or infrastructure scope of the accompanying review packet.
