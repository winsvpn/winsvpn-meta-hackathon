# Audit outreach drafts — OTF and OSTIF

Prepared 2026-08-03. **Send from admin@winsvpn.org. Do not send until you have
read the accuracy notes at the bottom** — every figure here is measured, and the
value of the letter depends on it staying that way.

---

## Message 1 — OSTIF

**To:** contact via <https://ostif.org/contact/>
**Subject:** Audit scoping enquiry — Winn Protocol, post-quantum censorship-resistant transport (AGPL-3.0, pre-release)

Hello,

I am the founder of Win's VPN Inc., a US 501(c)(3) public charity building
censorship-circumvention tools for users in Myanmar and other closed networks.
I am writing to ask how you scope audits, and when in a project's life you
prefer to be approached.

**What it is.** Winn Protocol is a censorship-resistant transport protocol we
have written from scratch in Go. Sessions use hybrid post-quantum TLS 1.3 key
agreement (X25519 with ML-KEM, via the named groups in Go 1.26's `crypto/tls`,
so the KEM implementation is the standard library's rather than ours).
Authentication is **ML-DSA-65/87** signatures via `cloudflare/circl`, verified
independently alongside ECDSA P-384 in X.509, so both must pass rather than
either. Hashing is SHA-256 throughout. It carries traffic over several
interchangeable outer transports, including HTTP/2, HTTP/3 and MASQUE with
Encrypted Client Hello, plus a direct AmneziaWG underlay option, so the
observable traffic shape can change without changing the inner session.

**Threat model.** The adversary is a national-scale operator running deep packet
inspection and active probing, with the ability to block by protocol
fingerprint. Users are people for whom being identified as a circumvention-tool
user carries physical risk. I am not a neutral party here: my parent was
assassinated by the Myanmar junta in 2025, and that is why this exists.

**Size and shape.**

- 112,237 lines of Go across 333 non-test files and 95 packages
- 87,553 lines of tests across 244 files, a 0.78 test-to-source ratio
- 7 direct third-party dependencies: quic-go, golang.org/x/crypto,
  golang.org/x/net, golang.org/x/sys, httpsfv, uritemplate, pgx/v5
- Go 1.26, 5 verified build tuples; 24 fuzz targets in the tree

**Licence.** AGPL-3.0, with a separate commercial licence available for
organisations that cannot accept the AGPL's source-disclosure obligation. The
source will be public.

**Where it honestly stands.** This is pre-release and not yet carrying user
traffic. Today only the direct AmneziaWG carrier completes a session end to end,
and it does so on Linux; the platform integrations for Android, iOS, macOS and
Windows are written and compile, but currently exercise the protocol against
test harnesses rather than a live peer. I would rather tell you that now than
have an auditor discover it.

**My questions.** Do you engage with projects at this stage, or do you prefer to
audit code that is already deployed and has users? Given the size above, what
sort of scope and duration would you expect, and what would it cost? And is the
absence of an existing user base disqualifying, given your focus on widely
relied-upon projects?

If it is too early, I would welcome being told what to come back with.

Thank you for the work you do.

---

## Message 2 — OTF

**To:** via <https://www.opentech.fund/> contact form, or the Security Lab intake
**Subject:** Winn Protocol — post-quantum censorship-resistant transport for Myanmar users, seeking security review

Hello,

I am the founder of Win's VPN Inc., a US 501(c)(3) public charity. We build
censorship-circumvention and cybersecurity tools for users in Myanmar and other
closed networks, and I am writing about a security review of the transport
protocol we have built.

**Why this exists.** My parent was assassinated by the Myanmar junta in 2025.
Since the 2021 coup, access to uncensored information inside Myanmar has been
systematically closed off. Our users are people for whom being identified as a
circumvention-tool user carries physical risk, so the protocol's resistance to
fingerprinting is not an academic property.

**What we built.** Winn Protocol is a censorship-resistant transport written
from scratch in Go. Sessions use hybrid post-quantum TLS 1.3 key agreement
(X25519 with ML-KEM through Go 1.26's `crypto/tls` named groups, so we do not
implement the KEM ourselves), with **ML-DSA-65/87** authentication via
`cloudflare/circl` verified independently alongside ECDSA P-384 in X.509, and
SHA-256 hashing. It carries traffic over interchangeable outer transports,
including HTTP/2, HTTP/3 and MASQUE with Encrypted Client Hello, plus a direct
AmneziaWG underlay option, so the observable traffic shape can change without
disturbing the inner session. The design goal is to survive deep packet
inspection and active probing by a national-scale adversary.

**Size.** 112,237 lines of Go across 333 non-test files and 95 packages, with
87,553 lines of tests, 7 direct dependencies, building for 5 verified platform
and architecture targets.

**Licence.** AGPL-3.0. Source will be public, with a commercial licence
available separately for organisations that cannot meet the AGPL obligation.

**Current state, stated plainly.** Pre-release. Not yet carrying user traffic.
One carrier completes a session end to end today and only on Linux; the mobile
and desktop integrations compile and are tested against harnesses rather than a
live peer. We are some weeks from a first real deployment.

**What I am asking.** Whether OTF's Security Lab would consider a review of a
protocol at this stage, and if not, what milestone we should reach first. I
would also welcome guidance on whether the Internet Freedom Fund or another
programme is the right door, given that we are a small non-profit rather than an
established project with years of release history.

I am happy to provide the repository, the threat model document, and the test
suite for scoping.

Thank you for considering this.

---

## Accuracy notes — read before sending

**Re-derive every number immediately before sending.** The figures below were
measured on 2026-08-03 in
`source/wins_vpn/winn_protocol_experimental` and they are already the *second*
set — an earlier measurement the same day gave 108,674 / 325 / 92 / 82,998
because the tree grew several thousand lines while parallel work was landing.
Nothing was wrong with either count; the tree is simply moving. A funder or
auditor who re-runs these commands and gets a different answer will wonder what
else drifted, so measure at the moment of sending and, better, name the commit.

```bash
cd source/wins_vpn/winn_protocol_experimental
find . -name "*.go" -not -name "*_test.go" -not -name "._*" -not -path "*/vendor/*" -not -path "*/testdata/*" | wc -l                     # 333
find . -name "*.go" -not -name "*_test.go" -not -name "._*" -not -path "*/vendor/*" -not -path "*/testdata/*" -exec cat {} + | wc -l      # 112237
find . -name "*_test.go" -not -name "._*" -not -path "*/vendor/*" | wc -l                                                                # 244
find . -name "*_test.go" -not -name "._*" -not -path "*/vendor/*" -exec cat {} + | wc -l                                                 # 87553
find . -name "*.go" -not -name "._*" -not -path "*/vendor/*" -exec dirname {} \; | sort -u | wc -l                                        # 95
```

The `-not -name "._*"` exclusion is not cosmetic: the working tree carries tens
of thousands of macOS AppleDouble sidecar files, and counting them inflates every
figure. The `vendor` and `testdata` exclusions keep the count to code this
project wrote and maintains.

**Do not remove the "current state" paragraph from either letter.** It is the
part that makes the rest credible. Auditors and funders read a lot of outreach
that overstates readiness, and the ones worth having are good at spotting it.
Saying plainly that only one carrier works, and only on Linux, costs nothing and
buys the assumption that the other claims are also accurate.

**Do not claim the protocol is audited, reviewed, or production-ready** until it
is. The organisation has already had one app-store rejection for claims that
outran the evidence.

**Do not say "post-quantum secure."** Say what it does: a hybrid key exchange
using ML-KEM with X25519. Hybrid means classical security is retained if the
post-quantum component fails, which is the honest and more defensible framing.

**Optional paragraph worth considering, once the upstream reports are filed.**
`docs/UPSTREAM_DISCLOSURE_HTTPSFV.md` holds a verified remote crash in
`dunglas/httpsfv` that reaches `quic-go/masque-go`'s client dial path. Telling
OSTIF and OTF that the project found a panic in a dependency, understood its
reachability, shipped a guard, and reported it upstream says more about
engineering practice than any size figure does. **Only add it after the reports
are actually filed**, phrase it as a reported bug rather than a CVE unless an
identifier has been assigned, and keep it to two sentences. Do not add it while
the reports are still unfiled drafts.

**Before sending, decide the licence properly.** AGPL-3.0 plus commercial
dual-licensing requires that Win's VPN Inc. owns all copyright in the code. If
anyone else has contributed, they need to sign a contributor licence agreement
first, or the dual-licensing offer cannot be made.
