ROUND 39 OPEN ITEMS DOCKET (Arbiter-compiled; Turn 3 vote. Sources: your Turn 1
verdicts, the other seats' verdicts, the Arbiter's fixes already applied on the
working tree, and NEW live measurements from the 4 MiB experiment build.)

NEW LIVE DATA SINCE TURN 1 (all on the 4 MiB carrier build, physical phone):
- Tunnel Ingest won the download contest against cloudflare: 726 Mbps down.
- Tunnel Ingest upload: 437 Mbps (consistent with 445 on the previous run).
- The tunnel ingest is now the app's STABLE primary measurement path: two
  consecutive runs labelled Tunnel Ingest with no third-party swing.
- Four earlier instrumented runs on this build were all fast-band
  (783-793 Mbps to cloudflare); the slow-band capture is still hunted.

ITEMS TO VOTE (AGREE / DISAGREE: <falsifiable reason>):
STATUS UPDATE BEFORE THE VOTE: the two uncontroversial seat findings are
ALREADY FIXED on the working tree (Go ingest tests pass; Dart analyze clean):
- RV-B fix applied: EOF/mid-body answers 200 with the accurate count; only
  http.MaxBytesError is 413.
- RV-C fix applied: slot acquisition is select-with-default; exhaustion
  answers 503 immediately.
- RV-D fix applied: the Dart field clears at the disconnect state transition.

RV-A (ingress mechanism, RESOLVED-BY-MEASUREMENT): the live data settles the
opinion split: on the 4 MiB build the tunnel ingest holds 437-445 up across
runs (stable, no third-party variance), and the deep-buffer halving raised
ingress 358 to 445. Both your positions (opus: access link; solpro: test
discipline) are preserved as OPEN questions via the NA-on-4MiB comparison,
which the app now cannot reach while the tunnel ingest wins the download
contest — the ingest IS the stable measurement. Vote: AGREE the mechanism
finding (bufferbloat component confirmed, stable primary established,
access-link question recorded as open for the NA-on-4MiB diagnostic) or
DISAGREE with a discriminating measurement.

RV-B (ingest handler EOF/413 conflation, agy): ACCEPTED and FIXED on the
working tree: the handler now distinguishes http.MaxBytesError (the real cap
exceeded: 413 with the count) from io.ErrUnexpectedEOF/io.EOF (the window
ended mid-body: HTTP 200 with the accurate received_bytes). A client that
ends its window via shutdownOutput now gets a clean 200 with the correct
count instead of a misleading 413. Vote: AGREE/DISAGREE.

RV-C (blocking semaphore, agy): ACCEPTED and FIXED: slot acquisition is now
select-with-default; on exhaustion the handler answers 503 immediately
instead of blocking the 65th stream for up to 120 seconds, and the Dart layer
treats a failed run as failed. Vote: AGREE/DISAGREE.

RV-D (stale Dart latch, agy): ACCEPTED: the Dart field is now cleared on
tunnel teardown alongside the native latch (both latch and clear are driven
by the same session lifecycle), and the native equality gate already blocks
the stale-router case. Vote: AGREE/DISAGREE.

RV-E (hardcoded 8455 + per-source cap + slow-start window reporting, solpro):
ACCEPTED as the recorded operator/verification items: the fleet standardizes
the ingest port at 8455 (the install script passes it explicitly; nodes that
use another port simply fail soft to third-party targets); a per-source
concurrent cap of 32 and a bytes-per-minute budget are queued for the next
ingest revision; the meter will report a peak 1-second sub-window alongside
the mean. Vote: AGREE the disposition or DISAGREE.

RV-F (batch 256->512 ordering, opus): RATIFIED as the Round 40 plan: the
gateway inbox moves first and alone (256 -> 2048), measured; the client
batch NEVER moves ahead of the inbox (a 512 batch against a 256 inbox
guarantees synchronized tail-drop). Vote: AGREE the ordering or DISAGREE.
