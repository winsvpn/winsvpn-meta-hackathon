# Round 41 stage2 (turn 2): claude-opus5

## STEELMAN

**solpro (b):** Their window-depth arithmetic is the sharpest number anyone brought, 1024 tokens at 44k to 60k pps is only 17 to 23 ms of reorder budget, which shows the window is undersized in time terms even if force-advance never overshot, so a rekey queued behind one MLO link switch can age out with the window behaving exactly as specified.

**agy (d):** A writeLoop stall is the one hypothesis requiring no protocol defect at all, and a single-threaded tun writer fed by an MLO Tx link at 3843 Mbps is precisely where an 8 s burst would be expected to wedge on back-pressure.

Neither survives the corrected counters. solpro's aging releases the moment the burst stops, so it predicts rx resumes and the retried rekey lands; rx never resumed. agy's stall sits downstream of the counter that kept advancing.

## VOTES

**OI-1 AGREE.** The accept path is the only stage between the two counters that moved differently: carrier receives climbed post-burst while tun delivery was flat, which locates the refusal at the token filter and nowhere else. The corrected numbers strengthen this beyond the text as written. Gateway outbound is 383,255 + 14,548 = 397,803; carrier receives 397,332; wire loss is therefore 471 datagrams, 0.12%. N3's 5% MacBook loss does not transfer to the phone at forty times that rate, so the path was effectively clean on the downlink too. Falsifier: a post-burst drop-reason histogram attributing the frozen datagrams to AEAD authentication failure or queue-full rather than beyond-window/replay.

**OI-2 AGREE.** Each part removes a separate necessary condition, and (1) is the only one that addresses the latch itself. One sequencing condition: part (2) is safe only when shipped with (1) and the Degraded gate, because a recoverable rollover on top of a latched window converts a fast visible teardown into an unbounded silent carry. Falsifier: the old epoch has no RejectAfter bounds in the current code, in which case (2) has no terminal condition today and depends on new work rather than on enforcement of existing work.

**OI-3 DISAGREE: the loss attribution is arithmetically wrong.** 397,332 carrier receives minus 383,255 tun deliveries is 14,077 datagrams that the phone received and then discarded before tun. Only 471 of the 14,548 is path loss. So the accept path was already rejecting at 3.5% during the burst, and the latch at 06:13:41 is the end state of a process running through the whole burst, not a clean step change. Calling all 14,548 ordinary TCP-recoverable loss hides that. Replacement text for OI-3 sentence three: "Of the 14,548 shortfall, 471 are wire loss (0.12%) and 14,077 were received by the carrier and rejected by the accept path during the burst; the clamp in OI-2(1) is expected to recover most of those as well, and only the terminal latch was fatal." The window-size ruling itself (keep DefaultTokenWindow at 1024 pending D23-conformant re-derivation) I AGREE with unchanged.

**OI-4 AGREE.** Deriving the latch from the active plan plus a generation guard removes both the stale-write race and the divergent-copy problem in one move. Falsifier: any start path reaches carrying without traversing that callback, which is why the check is an enumeration of start paths, not inspection of the one callback.

**OI-5 DISAGREE: the stated verification can pass while still latched.** The rekey fires on a jittered 5 min timer and the death needed it at session second 348; two speedtests with a 60 s gap run two to three minutes total and may never fire one, so a latched build survives the repro and reads as fixed. Replacement text for the verification clause: "pass requires both (a) post-burst rx_packets continuing to track messages_received within the wire-loss delta for at least 120 s after burst end, and (b) a forced rekey within 20 s of burst end completing without StateFailed; drop-reason instrumentation on the post-burst receive path is recorded in both cases." With that added, the ordering ruling (this ships before throughput work) I AGREE with.

Tally: AGREE on OI-1, OI-2, OI-4. DISAGREE on OI-3 and OI-5, both on stated text only, both with replacement text supplied and neither touching the root-cause finding.

## NEXT

Arbiter: recheck 397,803 / 397,332 / 383,255 from the raw counter dump and confirm the 471 versus 14,077 split from first principles at a second podium, since OI-3 turns entirely on it. Circulate the two replacement strings to all seats for a Turn 3 vote on identical text. Confirm from source whether the old epoch's RejectAfter bounds exist today, which determines whether OI-2(2) is enforcement or new work. Both of my DISAGREE items are text corrections; if the arithmetic holds and the replacements are adopted verbatim, I vote AGREE on all five without a further cycle.
