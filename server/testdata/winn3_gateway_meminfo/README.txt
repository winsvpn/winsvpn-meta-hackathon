/proc/meminfo fixtures for the winn3 gateway installer's session-count cap
(OI-K4). Values are the fleet's MemTotal as read on 2026-09-23 (MiB * 1024)
plus exact 2/4/8/12 GiB hosts, the 4-session floor boundary, a 128 TiB host
the other installer tests use so their explicit session counts still fit,
and two malformed files that must fail closed.
2026-10-10 (TUNNEL-SPEED-2): the 4-session floor moved with the formula.
floor_4 is 950272 kB (half is 475136 = 212992 + 4 * 65536 KiB) and
below_floor 950270 kB (half is 475135, which fits 3).
