#!/usr/bin/env python3
"""Round 39: verification of the live RV-B implementation (ingest handler,
client raw-socket wiring, canada firewall + deploy) and the carrier ingress
investigation kick-off."""

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
ROUND 39 DELIBERATION PACKET: RV-B IMPLEMENTATION VERIFICATION + CARRIER
INGRESS INVESTIGATION. (Answer from THIS PACKET ONLY: no tools, no network.
Zero em/en dashes; banned cliches; bold only list keys.)

PART 1: RV-B IMPLEMENTED AND LIVE (verify coherence and attack the design).

1. Gateway ingest (cmd/winn3-gateway/speedtest_ingest.go, new file):
   - HTTP server bound ONLY to the inner IPv4 (assign.V4) on
     -speedtest-ingest-port (flag, default 0 = OFF, so existing deploys are
     byte-for-byte unchanged). Flag wired through serveOptions; the listener
     starts only inside the -forward branch after newSharedGatewayTun.
   - Handlers: POST /speedtest/up reads with io.Copy(io.Discard) under
     http.MaxBytesReader (1 GiB cap) and answers
     {"received_bytes":N,"elapsed_ms":M} — the server-ACKNOWLEDGED byte count
     is the measurement, not the client's socket-buffer writes.
     GET /speedtest/down?bytes=N serves N zero bytes (default 256 MiB, cap
     1 GiB). Method gating 405. Concurrency semaphore 64 (the first deploy
     used 2 and benchmarked at 242 Mbps serving 2 of 32 streams; 64 raised
     the same measurement to 358 Mbps).
   - Server timeouts: ReadHeaderTimeout 10s, Read/Write 120s, Idle 60s,
     MaxHeaderBytes 4 KiB.
   - Go tests (speedtest_ingest_test.go): byte counting, requested-bytes
     serving, cap enforcement, method gating, concurrency bound. All pass.
   - The cover listener's probe-resistance contract is untouched: the ingest
     answers only on the INNER address, where answering is the service.
2. Client wiring (MainActivity.kt + lib/main.dart):
   - Dart prepends the primary target 'Tunnel Ingest'
     (http://<inner_router_v4>:8455/speedtest/down?bytes=52428800) when
     connected; <inner_router_v4> comes from the signed descriptor, latched
     into state when verifyWinn3Descriptor succeeds.
   - The upload leg uses a NEW native method measureUploadViaTunnelIngest
     over RAW TCP SOCKETS (32 streams, 128 KiB zero chunks, shared window,
     shutdownOutput, then reads the server's JSON received_bytes as the
     authoritative count). RAW SOCKET rationale: Android's cleartext HTTP
     policy (enforced by OkHttp; the first live test failed with
     UnknownServiceException CLEARTEXT) governs HTTP stacks; its purpose
     (keeping user data off plaintext internet paths) does not apply to
     traffic that never leaves the encrypted tunnel. The native gate accepts
     only a dotted-quad router EQUAL to the session-latched
     inner_router_v4; teardown clears the latch.
   - Fail-soft verified live: against the OLD gateway binary the primary
     cost one refused request and the test fell back to the North America
     family (771.6 Mbps measured).
   - Latch subtlety found live and fixed: the first latch site (MTU block)
     read a config string that does not carry the [winn] section on the
     staged-start path (latched=null observed on device); the latch moved to
     the staged-start path itself, right after WinnV3SessionPlan.from, using
     WinnV3SessionPlan.innerNextHopOf(winnSection).
3. Canada deployment (production, live):
   - New linux/amd64 binary staged and installed at
     /usr/local/libexec/winn/winn3-gateway; unit flag
     -speedtest-ingest-port 8455 added; WINN3GW-INPUT rule 6 inserted:
     tcp/8455 ACCEPT from 10.10.0.0/24 to 10.10.0.1 (before the DROP),
     persisted via netfilter-persistent save.
   - LIVE RESULT on the physical phone: 'Last VPN test: Tunnel Ingest',
     1166 Mbps DOWN (highest in-app download ever measured — pure tunnel,
     no internet transit), ingest upload measured 358.5 Mbps (all 32
     streams HTTP 200, 358 MB server-received in the 8 s window).
   - Deployment incident, caught and fixed: a sed insertion put a literal
     backslash-n into the unit's ExecStart, which systemd split into a bare
     token; Go's flag package stopped at the first non-flag argument, which
     surfaced as a bogus '-peer-registry missing' refusal. Line rewritten
     properly; also the first binary swap landed on a wrong filename and was
     corrected. Both incidents are why the verify cycle runs after deploys.

PART 2: CARRIER INGRESS INVESTIGATION (the 1000/1000 blocker).

The ingest tool now isolates directions: tunnel download (gateway→client)
measured 1166 Mbps; tunnel upload (client→gateway) measured 358 Mbps. The
3.3x asymmetry is INSIDE Winn v3. Client→gateway packet path: Kotlin TUN
burst reader (JNI bulk read) -> seam slab queue (8192 packets) -> AF_UNIX
framed batches (256 frames) -> client Go engine -> encrypt -> carrier UDP
send (client SO_SNDBUF 8 MiB default) -> gateway demux -> per-session pipe
inbox (carrier pipe depth 256 frames; a full inbox DROPS) -> per-session
driver loop -> gatewayForwardDevice -> kernel winn3gw0 -> ingest socket.
Gateway→client path: gateway TUN read -> engine -> carrier UDP -> client
demux -> client seam -> Kotlin TUN write. Structural differences in the
client→gateway direction: the carrier pipe inbox (256, drops when full) and
the single per-session driver loop consuming it.

MANDATE:
1. Verify the implementation items 1-3 (coherence, missing pieces, new
   defects). Specifically attack: the raw-socket upload's Content-Length
   budget accounting (client budget 4 GiB / 32 = 128 MiB per stream, window
   8 s at 1 Gbps would push ~1 GB — does the window end mid-body safely?
   The server answers only at EOF: with shutdownOutput at window end the
   server's count is final — confirm); the 64-request semaphore under
   32-stream reuse; the latch cleared at teardown while the Dart field
   persists (stale-router reuse after reconnect to a DIFFERENT node).
2. Ingress: rank the ceiling candidates for 358 Mbps asymmetric ingress
   (pipe inbox 256 drops, single driver loop per session, client SNDBUF
   8 MiB, AF_UNIX batch 256, demux contention) and name the cheapest
   measurement or code change that would discriminate. Batch scaling
   256->512 at the AF_UNIX/TUN framing layer is on the table: state whether
   it plausibly doubles ingress or is bounded elsewhere.
3. UNVERIFIED-LIVE marks inline. Zero em/en dashes; banned cliches; bold
   only list keys. End with NEXT: the single most valuable local check.
"""


def stage1():
    print("=== ROUND 39 STAGE 1 ===", flush=True)
    packet = r36.clean_text(PACKET)
    (r37.RECEIPTS.parent / "round39").mkdir(parents=True, exist_ok=True)
    (r37.RECEIPTS.parent / "round39" / "packet_dispatched.txt").write_text(packet, encoding="utf-8")
    print(f"packet bytes: {len(packet)} sha256: {hashlib.sha256(packet.encode()).hexdigest()}", flush=True)
    cache = r37.load_cache()
    tasks = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        for seat in r36.SEAT_KEYS:
            key = f"r39_stage1_{seat}"
            if cache.get(key):
                print(f"[{seat}] cached", flush=True)
                continue
            if seat == "agy":
                tasks[key] = (seat, ex.submit(r36.query_agy, packet, "r39stage1"))
            elif seat == "claude-opus5":
                tasks[key] = (seat, ex.submit(r36.query_claude, packet, "r39stage1"))
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
            fname = f"debate_round39_stage1_{seat.replace('claude-opus5', 'opus5')}.md"
            (r36.DOCS_EVIDENCE / fname).write_text(f"# Round 39 stage1: {seat}\n\n{result}\n", encoding="utf-8")
            print(f"-> {key} complete ({len(result)} bytes)", flush=True)
    print("ROUND 39 STAGE 1 COMPLETE", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage1", action="store_true")
    args = parser.parse_args()
    if args.stage1:
        stage1()


if __name__ == "__main__":
    main()
