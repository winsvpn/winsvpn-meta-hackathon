#!/usr/bin/env python3
"""Round 40 addendum: the D23 inbox correction, the carrier SNDBUF A/B null,
and the RV-41 path discriminator evidence. Asks the three seats to re-rank
the ingress ceiling candidates under the corrected facts and to rule on the
Round 41 send-pacing design. Seat import only (no new dispatch mechanics)."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import importlib.util
import pathlib

_spec = importlib.util.spec_from_file_location(
    "r37", "/Users/owner/xprize/winsvpnv3/tools/run_round37_verify.py"
)
r37 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r37)
r36 = r37.r36

PACKET = """
ROUND 40 ADDENDUM PACKET: INBOX CORRECTION (D23), CARRIER A/B NULL, AND THE
RV-41 PATH DISCRIMINATOR. (Answer from THIS PACKET ONLY: no tools, no network.
Zero em/en dashes; banned cliches; bold only list keys. UNVERIFIED-LIVE marks
inline where you cannot check a fact.)

CONTEXT: Round 40 ratified deepening the production per-session inbox from
256 to 2048. Before deploy, the pinned D23 audit tests fired and the premise
was found WRONG. Read the three facts below, verify them against your prior
model of the geometry, and answer the mandate.

FACT 1 (D23 correction): production sessions never use carrier pipe depth
(DefaultPipeDepth 256). The per-session inbox is DERIVED from the token
window: DefaultTokenWindow 1024 / 2 = 512, reorder tolerance 511. Raising the
inbox to 2048 requires DefaultTokenWindow 4096, and the 4096-datagram-death
shape (Spain UDP death at seq 4095) is pinned by nonce_window_past_4096_test.go
and inbox_4096_ceiling_test.go. The 256 to 2048 change was REVERTED before
deploy; DefaultPipeDepth now carries a correction comment. During the 358 to
445 Mbps ingest runs the inbox NEVER dropped a datagram (counters clean).

FACT 2 (carrier A/B null): client carrier SO_SNDBUF 8 MiB vs 4 MiB on the
ingest tool measured 358 to 445 vs 437 to 447 Mbps: no material difference.
Default restored to 8 MiB. Bufferbloat-vs-socket-size is settled: socket
buffer size does not move the ingest.

FACT 3 (RV-41 path discriminator, 2026-09-21, iptables-verified arrivals on
canada, sender on the same Wi-Fi LAN as the phone, Wi-Fi 6E 6 GHz 160 MHz,
link rate 1729):
  a. Randomized-payload UDP 1400 B datagrams to canada carrier port 9111:
     300 Mbps offered -> 303 arrived (0.84% loss); 400 -> 374 (8.27%);
     500 -> 480 (5.95%); 550 -> 519 (7.40%). A sustained 600 Mbps for 24 s
     delivered roughly 560 to 580 with about 5% loss and ZERO
     UdpRcvbufErrors and ZERO UdpInErrors at canada (the gateway drained
     everything the kernel handed it; engine CPU flat).
  b. LAN control: 905 Mbps offered to the home router with 0.95% ENOBUFS:
     the MacBook Wi-Fi is not the cap.
  c. CONSTANT-payload UDP ('x'*1400) is dropped near 100% at every rate
     including 150 Mbps. Random-payload passes. A payload-pattern filter
     (scrubber) exists somewhere upstream of canada's INPUT chain. Winn
     carrier datagrams are AEAD ciphertext (high entropy) and pass.
  d. Single TCP stream upload to Cloudflare from the same LAN measured
     310 to 350 Mbps (curl). A 32-stream python TLS attempt was INVALID
     (missing Content-Length; server stalled the body) and is NOT evidence.
  e. Phone Tunnel Ingest upload, measured earlier on the same LAN:
     358 to 445 Mbps inner across runs, 644 Mbps inner offered by the
     engine in the best run. Inner 437 approx carrier 470 (about +7% Winn
     overhead). Phone measurement of tun0 TX / wlan0 TX / carrier deltas is
     queued: the app camouflage PIN on both test phones now REJECTS the
     standing default 1357 on both submit paths (digit auto-submit and
     equals). Owner must supply the PIN; no brute force attempted.

MANDATE (answer every item):
1. Given facts 1 to 3, re-rank the ingress ceiling candidates for the
   phone's 437 to 445 Mbps inner plateau. Name the single most probable
   cause and the falsification that would kill your ranking. Candidates:
   (i) loss-limited TCP: 5 to 8% path loss at 400 to 600 Mbps offered makes
   32 inner TCP streams collapse well below the UDP knee; (ii) phone Wi-Fi
   radio below the MacBook's 1729 link rate; (iii) Winn client send path
   (TUN burst reader, seam, AF_UNIX batches, engine encrypt loop); (iv)
   token window 1024 pacing the carrier loop; (v) gateway side.
2. Ruling on Round 41 carrier send pacing: a token-bucket pacer at the
   measured drain rate on the client engine's carrier sends. Does it
   plausibly recover inner throughput toward the 600 Mbps UDP knee (by
   smoothing the queue the inner TCP observes), or does it fight physics
   and only cut latency? If you ratify it, state the exact design: bucket
   rate source, burst size, where it sits in the engine, interaction with
   the token window and D23 geometry, and the measurement that proves it.
3. Ruling on the 1000/1000 target from THIS home vantage: path UDP knee
   measured around 600 with 5 to 8% loss; ingest down measured 1166; ingest
   up 358 to 445. Is 1000-up achievable on this access network at all, or
   is this an owner-report item (ISP plan, phone radio, or cellular vantage
   for the headline number)? Be explicit about what the product should
   promise on a 2000/500-class home plan versus a 2000/2000-class plan.
4. The scrubber (fact 3c): does constant-pattern UDP being dropped upstream
   change any Winn v3 design assumption (probe datagrams, keepalives, cover
   traffic patterns)? Name any probe or keepalive we ship that is
   constant-pattern and would die under such a filter.
5. NEXT: the single most valuable check available without the phone PIN.

End with VERDICT: per item, AGREE or DISAGREE with one falsifiable reason.
"""


def stage1() -> None:
    print("=== ROUND 40 ADDENDUM STAGE 1 ===", flush=True)
    packet = r36.clean_text(PACKET)
    outdir = r37.RECEIPTS.parent / "round40"
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "packet_addendum_dispatched.txt").write_text(packet, encoding="utf-8")
    print(
        f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}",
        flush=True,
    )
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r40add_stage1_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r40addstage1"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r40addstage1"))
            else:
                def solpro_with_fallback():
                    try:
                        return r36.query_openrouter(packet, r36.SYSTEM_SEATS[seat], 12000)
                    except RuntimeError:
                        return r37.query_openrouter_model(
                            "openai/gpt-5.6-sol-pro:batch", packet, r36.SYSTEM_SEATS[seat], 12000
                        )
                tasks[key] = (seat, ex.submit(solpro_with_fallback))
        for key, (seat, fut) in tasks.items():
            result = fut.result()
            r37.update_cache(key, result)
            fname = f"debate_round40_addendum_stage1_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(
                f"# Round 40 addendum stage1: {seat}\n\n{result}\n", encoding="utf-8"
            )
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 40 ADDENDUM STAGE 1 COMPLETE", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage1", action="store_true")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
