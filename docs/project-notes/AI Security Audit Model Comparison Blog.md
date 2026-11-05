# Seven AI Security Auditors, Seven Different Answers: What I Learned From Auditing One Codebase With Multiple Models

> **Publication note:** This case study deliberately omits credentials, infrastructure identifiers, source paths, vulnerable code, and exploit details. The purpose is to compare security-review methods—not to publish a roadmap to unresolved weaknesses.

## The short version

I asked seven AI models to independently review the same large, cross-platform software project. An eighth, smaller model was evaluated afterward as a follow-up.

They did not produce seven copies of the same report.

One model found the widest range of credible issues. Another was especially good at authentication and state transitions. A third was conservative and produced relatively little noise, but missed important attack paths. Others generated useful hypotheses mixed with severity inflation, duplicate findings, misunderstandings of intentional design, and claims that sounded serious but did not survive source-level verification.

The central lesson was not that one model “won.” It was this:

> **Different models provide different threat-model perspectives, but only disciplined human adjudication turns their output into a security assessment.**

Using several models improved coverage. It also increased review time and false positives. The approach was worthwhile because the models’ errors were not perfectly correlated—but the raw reports were not safe to treat as implementation instructions.

## Why this was a difficult test

The target was not a small web application. It was a production-oriented, cross-platform system spanning mobile and desktop applications, shared application logic, privileged operating-system components, backend and serverless services, build and release automation, deployment scripts, and billing-related workflows.

That breadth matters. Security controls that are correct in one environment can be inappropriate in another. A desktop service legitimately needs privileges that would be alarming in an ordinary application. A mobile permission may be necessary for a user-facing feature but still create a distribution-policy obligation. A local administrative tool may intentionally execute arbitrary commands, while the same behavior in a remotely reachable endpoint would be a critical defect.

AI models are often good at recognizing dangerous-looking syntax. The harder task is determining whether untrusted data can actually reach it, which identity executes it, what security boundary is crossed, and whether the behavior is intentional.

## How I ran the comparison

Each model received the same authorized directory scope, the same OWASP Top 10 and CWE/SANS Top 25 focus, and the same severity rubric. They were asked to examine secrets handling, injection, dependencies, privilege boundaries, cryptography, and deployment hazards.

The important step came afterward. I treated every model finding as a hypothesis and checked it against the current source.

Each claim was placed into one of seven dispositions:

1. **Confirmed vulnerability:** A reachable security boundary could be crossed under the stated threat model.
2. **Defense-in-depth improvement:** The recommendation was useful, but the claimed exploitability or severity was overstated.
3. **Policy or compliance concern:** Important for a platform, marketplace, or operational review, but not itself a software vulnerability.
4. **Intentional design:** Privilege, visibility, or administrative capability existed because the feature required it and was bounded appropriately.
5. **Duplicate:** The underlying issue was real but had already been described more accurately elsewhere.
6. **Conditional or historical:** The claim depended on deleted code, stale configuration, an inactive deployment, or another fact requiring separate confirmation.
7. **False positive or out of scope:** The claimed attack path was unreachable, rested on a false assumption, or examined material outside the authorized scope.

This taxonomy prevented a common failure: counting every alarming sentence as a separate vulnerability.

## What the numbers actually showed

The final adjudication log contained **33 disputed claim categories** from the seven primary reports:

- **26 were rejected as standalone vulnerabilities.**
- **7 were merged, downgraded, classified as conditional, or excluded as out of scope.**

Those figures do not mean the models found nothing. The validated implementation brief retained dozens of legitimate remediation and hardening items. They do show how much filtering was required before the reports became safe engineering input.

I am intentionally not publishing the live findings, their locations, or their severity distribution. That information would add little to the model comparison while potentially exposing unresolved weaknesses.

The later compact-model review provides a useful, fully adjudicated miniature example. It produced eight headline claims:

| Final disposition | Count | What that means |
|---|---:|---|
| Technically actionable | 2 | One corroborated an already-known issue; one added a new defense-in-depth item. |
| Policy/compliance checkpoint | 1 | Worth reviewing, but not a vulnerability under the project’s threat model. |
| Intentional or context-sensitive design | 2 | The model saw a dangerous-looking pattern but misunderstood why it existed. |
| Rejected or materially overstated | 3 | The proposed exploit boundary was absent or the severity was unsupported. |

Its headline “Critical” claim was not a security control failure at all. It had mistaken reversible obfuscation of public information for encryption of a secret. This is a textbook example of why category labels such as “weak cryptography” are not enough: the reviewer must first establish whether confidentiality was ever a security requirement.

## How the models compared

This was a case study, not a controlled academic benchmark. The reports differed in length and style, and the consolidated record did not preserve a claim-by-claim attribution matrix sufficient to calculate defensible precision percentages for every model. I will not manufacture precise-looking scores from incomplete data.

The qualitative comparison below reflects verified signal, unique contribution, coverage, severity calibration, and review effort.

| Model | Strongest contribution | Main weakness | False-positive tendency | Best role |
|---|---|---|---|---|
| **GPT 5.6 Sol Extra High** | Broadest coverage and strongest overall signal across application, platform, release, server, and operational boundaries | Occasionally over-severe and prone to proposing larger fixes than the threat justified | Moderate | Primary deep reviewer, followed by calibration |
| **Fable 5 Max** | Concise analysis of a narrow backend and authenticated service area | Missed several important platform and deployment paths; overcalled inactive or historical material | Moderate | Focused specialist or second opinion |
| **Opus 4.8 Max** | Valuable unique findings in fleet identity and deployment configuration | Several claims depended on optional hardening being treated as mandatory security controls | Moderate to high | Strong secondary reviewer for infrastructure |
| **Gemini 3.6 Flash High** | Broad, readable coverage and useful attention to replay, shared authority, and web controls | Frequent severity inflation and several unsupported boundary assumptions | High unless carefully calibrated | Fast breadth pass and hypothesis generator |
| **Grok 4.5 High** | Good authentication, logout, recovery, and state-machine thinking | Misread some intentional administrative and product-design surfaces; one proposed remedy would have weakened security | Moderate to high | Auth-flow and abuse-case reviewer |
| **GLM 5.2 Max** | Clear, cautious findings with relatively low noise | Lower recall; missed several high-impact cross-component paths and occasionally mis-ranked severity | Low, but with low recall | Precision-oriented confirmation pass |
| **Kimi K2.7 Code** | Corroborated a handful of real build, web, and cleanup concerns | Large amount of out-of-scope material, generic syntax matching, public identifiers called secrets, and obsolete advice | Very high | Brainstorming only; requires heavy filtering |
| **Qwen 3.6 27B Q4** | Compact review that still surfaced two actionable items | Misclassified intentional behavior, policy, and hardening as vulnerabilities; severe headline was unsupported | 3 of 8 rejected or materially overstated; 2 more were intentional/context-sensitive | Inexpensive follow-up pass, not a final authority |

The most important comparison is not “which model found the most.” A model can maximize finding count by labeling every privileged API, broad permission, environment variable, or cryptographic primitive as dangerous. That produces high recall on paper and poor engineering value in practice.

## Four recurring ways AI security reviews go wrong

### 1. Mistaking a dangerous primitive for a reachable vulnerability

A command interpreter, privileged service, broad platform permission, or reversible transformation deserves attention. None is automatically exploitable.

A credible finding needs a complete chain:

**attacker-controlled input → reachable code path → missing or bypassed control → boundary crossed → concrete impact**

Several reports identified the first or second element and inferred the rest.

### 2. Confusing intentional capability with privilege escalation

VPN software, installers, system services, and administrative maintenance tools necessarily interact with privileged resources. The right question is not “does this run with privilege?” It is “can a less-trusted principal obtain more authority than intended?”

Some models treated administrator-only functionality as escalation even when the alleged attacker already possessed equivalent operating-system authority.

### 3. Treating policy risk as a code vulnerability

Platform permissions and marketplace rules matter. A permission may require strong user disclosure, a declaration, and evidence that a feature genuinely needs it. That is a product and compliance concern.

It becomes a security vulnerability only when there is an abuse path—for example, data is collected unexpectedly, transmitted without authorization, or exposed across a trust boundary. Keeping these categories separate gives both engineering and compliance teams clearer work.

### 4. Assuming every use of cryptography protects a secret

Models are trained to flag hard-coded keys, XOR transformations, short hashes, missing pinning, and nonstandard encodings. That instinct can be useful, but context determines whether cryptography is serving confidentiality, integrity, authenticity, obfuscation, compatibility, or no security purpose at all.

Replacing reversible obfuscation with device-specific authenticated encryption sounds stronger. It may also make a public recovery mechanism impossible to bootstrap, adding complexity without protecting anything. The correct fix begins with the asset and threat model, not the algorithm name.

## Where multiple models genuinely helped

Model diversity improved the audit for three reasons.

First, **models emphasized different attack surfaces**. Some were stronger on native platform boundaries, others on authentication state, fleet operations, web abuse controls, or release engineering.

Second, **independent corroboration increased confidence**. When several models identified the same underlying control failure from different angles, verification became faster—even though the duplicates counted as one final issue.

Third, **disagreement exposed hidden assumptions**. A disputed finding forced questions such as:

- Is this value actually secret?
- Can a remote user control this input?
- Does the attacker already need administrator access?
- Is this code active in production?
- Is the control required for security, or merely optional hardening?
- Would the proposed fix preserve the product’s intended behavior?

Those questions often mattered more than the model’s initial conclusion.

## Why “use every model” is not quite the right lesson

There were diminishing returns. Every additional report added triage cost, duplicates, inconsistent terminology, stale line references, and occasionally unsafe remediation advice.

The better principle is:

> **Use enough independent models to create diversity of reasoning, then spend at least as much discipline on adjudication as on generation.**

For this project, a strong broad reviewer, a conservative confirmation reviewer, and one or two specialists would capture much of the value. Additional models remain useful when the system is high risk, unusually cross-platform, or contains operational areas that the first reviewers did not understand well.

Model diversity is most valuable when it creates **uncorrelated coverage**, not merely more text.

## A practical workflow for AI-assisted security review

### Step 1: Freeze the review target

Record the commit, authorized directories, active deployment assumptions, and excluded test material. Otherwise, reports cannot be compared reliably.

### Step 2: Define severity before the review

Require an explicit rubric based on exploit preconditions and impact. Terms such as “Critical” should not be model-generated adjectives; they should be conclusions derived from agreed criteria.

### Step 3: Ask for exploit chains, not pattern matches

Every claim should identify the attacker, input source, reachable path, failed control, security boundary, and resulting impact. Missing links should reduce confidence.

### Step 4: Run reviewers independently

Do not show one model another model’s findings during the discovery pass. Independence reduces anchoring and makes corroboration meaningful.

### Step 5: Normalize and deduplicate

Map different descriptions of the same root cause into one issue. Preserve which models corroborated it, but do not inflate the total.

### Step 6: Adjudicate against source and architecture

Verify control flow, deployment state, platform behavior, and trust boundaries. When necessary, use tests or a safe reproduction. Never accept a vulnerability solely because a model supplied a convincing code block.

### Step 7: Review the proposed fix as a new security change

AI remediation can introduce regressions, break required privileges, move secrets into weaker channels, or create a new network credential from low-entropy local data. A plausible fix is not automatically a safe fix.

### Step 8: Produce two outputs

Maintain a private technical remediation brief with exact evidence and a sanitized executive report describing themes, process, and risk without exposing exploit details.

## Better metrics than raw finding count

Teams evaluating AI security reviewers should track:

- **Precision:** confirmed claims divided by reviewed claims.
- **Unique contribution:** validated issues not already found by another reviewer.
- **Recall by attack surface:** coverage of platform, backend, build, identity, storage, and operational boundaries.
- **Severity calibration:** how often the final rating matches the model’s rating.
- **Duplicate rate:** repeated descriptions of an existing root cause.
- **Context-miss rate:** policy issues or intentional designs incorrectly labeled as vulnerabilities.
- **Remediation safety:** whether the proposed fix preserves trust boundaries and product behavior.
- **Verification cost:** human time required to validate each retained finding.

A model with fewer findings can be more valuable if its precision is high. A noisy model can still be useful if it contributes one important issue no one else noticed. The economic question is the value of the marginal confirmed finding compared with the cost of reviewing the noise.

## What I would change in the next experiment

For a future benchmark, I would maintain a structured claim ledger from the beginning. Every raw finding would receive a stable identifier and fields for model, location, claimed severity, final disposition, root-cause cluster, uniqueness, verification time, and remediation quality.

That would support defensible per-model precision and unique-contribution percentages. It would also distinguish two models that both appear “wrong” but fail differently: one may generate many duplicates of real issues, while another invents attack paths that do not exist.

I would also conduct a blind second adjudication by another security reviewer. Human validation is better than model self-validation, but it can still be biased.

## Final takeaway

No single model understood the whole system. The broadest model still overreached. The most cautious model still missed important paths. The noisiest models still occasionally contributed useful evidence.

The advantage of using multiple AI models was not consensus. It was **productive disagreement**.

AI can scale hypothesis generation across a large codebase. Security expertise is still required to define assets, trace data and authority, distinguish capability from escalation, calibrate severity, and reject fixes that would make the system worse.

Used this way, multiple models can make a security review more comprehensive. Used without verification, they can turn one codebase into a pile of confident contradictions.

The winning workflow is neither “trust the best model” nor “count every finding.” It is:

> **Generate broadly. Verify rigorously. Deduplicate ruthlessly. Fix according to risk. Publish responsibly.**

---

# LinkedIn-ready condensed version

I asked seven AI models to independently security-review the same cross-platform software project, then evaluated an eighth model as a follow-up.

They produced very different results.

- One had the best overall coverage, but sometimes exaggerated severity.
- One was conservative and had relatively few false positives, but lower recall.
- Several were strong in narrow areas such as authentication, infrastructure, or platform security.
- The noisiest model examined out-of-scope material and frequently confused public identifiers, intentional administrative features, or dangerous-looking syntax with vulnerabilities.

After source-level adjudication, the consolidated log contained 33 disputed claim categories. Twenty-six were rejected as standalone vulnerabilities; seven were merged, downgraded, made conditional, or ruled out of scope. Dozens of legitimate remediation and hardening items still survived—but I am intentionally withholding technical details that could expose unresolved weaknesses.

A later compact model offered a useful miniature example: eight headline claims became two actionable items, one policy checkpoint, two intentional/context-sensitive designs, and three rejected or materially overstated claims.

My biggest lesson: **AI security reports are hypothesis generators, not verdicts.**

A real finding needs a complete chain:

**attacker-controlled input → reachable path → failed control → security boundary crossed → concrete impact**

Using multiple models helped because their blind spots were different. It also created more duplicates, severity inflation, and review work. The benefit came from productive disagreement, not from voting or adding up raw finding counts.

If you use AI for code security, measure precision, unique contribution, severity calibration, context-miss rate, remediation safety, and human verification cost—not just how many issues a model prints.

My recommended workflow:

1. Freeze the commit and scope.
2. Define severity criteria in advance.
3. Run models independently.
4. Require an exploit chain for every claim.
5. Deduplicate by root cause.
6. Verify against source and architecture.
7. Security-review the proposed fixes too.
8. Keep exact technical evidence private until remediation is complete.

The practical conclusion is simple:

**Generate broadly. Verify rigorously. Deduplicate ruthlessly. Fix according to risk. Publish responsibly.**

#ApplicationSecurity #CyberSecurity #ArtificialIntelligence #SecureSoftware #OWASP #DevSecOps #CodeReview

