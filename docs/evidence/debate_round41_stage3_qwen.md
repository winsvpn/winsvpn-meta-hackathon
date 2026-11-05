# Round 41 stage3 (turn 3): qwen

AUDIT FINDINGS

The arithmetic in the adopted OI 3 replacement checks against the Turn 2 counters. The packet says "phone messages_received 397,332 = CARRIER receives" and gives phone tun delivery as 383,255. 397,803 minus 397,332 is 471. 397,332 minus 383,255 is 14,077. 471 plus 14,077 is 14,548. The arbiter note says the 471 figure is sample dependent and that the material claim, accept path rejections dwarf wire loss, holds across samples.

The source note says "only core.RejectAfterMessages is enforced today (session/batch.go:135)" and "No RejectAfterBytes/Time terminal enforcement exists for the old epoch". That makes OI 2 part 2 a requirement to add epoch bounds, not only to enforce existing bounds.

The adopted OI 5 verification clause requires both 120 s tracking after burst end and a forced rekey within 20 s. That removes the weak repro where two speedtests might never fire the jittered rekey timer.

VOTES

1. **OI-1** AGREE. The corrected counters show carrier receives advanced while tun delivery froze, placing the refusal at the accept filter; falsified if post burst drop attribution names auth failure, queue pressure, or decode error instead of beyond window or replay.

2. **OI-2** AGREE. The source note shows the rollover bound must add RejectAfterBytes and RejectAfterTime because only RejectAfterMessages exists today; falsified if the fix lets an old epoch terminate or continue with only RejectAfterMessages as the terminal bound.

3. **OI-3** AGREE. The amended split of 471 wire loss and 14,077 accept path rejects follows from the Turn 2 counters; falsified if the audited counters do not sum 471 plus 14,077 to the 14,548 shortfall.

4. **OI-4** AGREE. The record shows teardown cleared the staged latch and reconnect produced "latched=null"; falsified if an engine initiated reconnect reaches carrying and latchedInnerRouterV4 is still null under the derived latch rule.

5. **OI-5** AGREE. The amended verification requires both 120 s tracking and forced rekey, so a jittered timer can no longer hide the defect; falsified if a build passes with only the two speedtests and no forced rekey.

NEXT
