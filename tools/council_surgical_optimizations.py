#!/usr/bin/env python3
"""
Winthos Tripartite Presidential Council: Next Surgical Optimizations for Wire-Speed Symmetrical Upload.
Supervisor & Orchestrator: Antigravity (Gemini 3.8 Flash High Thinking)
Podium 1: GLM 5.3 Flash (Max thinking/effort via baseten/fp8)
Podium 2: GPT-5.6 Sol Pro (Extra High thinking/effort via openai/flex)
"""

from __future__ import annotations

import json
import os
import pathlib
import ssl
import sys
import time
import urllib.request
import certifi

REPO_ROOT = pathlib.Path("/Users/owner/xprize/winsvpnv3").resolve()
DOCS_EVIDENCE = REPO_ROOT / "docs" / "evidence"
DOCS_EVIDENCE.mkdir(parents=True, exist_ok=True)


def get_openrouter_key() -> str:
    env_key = os.environ.get("OPENROUTER_API_KEY")
    if env_key:
        return env_key.strip()
    auth_file = pathlib.Path.home() / ".local" / "share" / "opencode" / "auth.json"
    if auth_file.exists():
        try:
            data = json.loads(auth_file.read_text(encoding="utf-8"))
            key = data.get("openrouter", {}).get("key")
            if key:
                return key.strip()
        except Exception:
            pass
    raise RuntimeError("OpenRouter API key not found in environment or ~/.local/share/opencode/auth.json")


def clean_text(text: str) -> str:
    # Strictly remove em dashes and en dashes
    return text.replace("\u2014", ": ").replace("\u2013", "-")


def query_glm_5_3_flash(prompt: str, system_role: str) -> str:
    key = get_openrouter_key()
    ctx = ssl.create_default_context(cafile=certifi.where())
    payload = {
        "model": "z-ai/glm-5.3-flash",
        "messages": [
            {"role": "system", "content": system_role},
            {"role": "user", "content": prompt},
        ],
        "provider": {
            "order": ["BaseTen"],
            "quantizations": ["fp8"],
            "allow_fallbacks": True,
        },
        "reasoning": {
            "effort": "max",
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://winsvpn.org",
            "X-Title": "Winthos Council: GLM 5.3 Flash Deliberation",
        },
    )
    for attempt in range(5):
        try:
            print(f"[GLM 5.3 Flash] Querying via BaseTen fp8 (attempt {attempt+1})...", flush=True)
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                choice = res_data["choices"][0]["message"]
                content = choice.get("content", "").strip()
                print(f"[GLM 5.3 Flash] Completed successfully.", flush=True)
                return clean_text(content)
        except Exception as e:
            print(f"[GLM 5.3 Flash] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(4 * (attempt + 1))
    raise RuntimeError("GLM 5.3 Flash query failed after 5 attempts")


def query_gpt_5_6_sol_pro(prompt: str, system_role: str) -> str:
    key = get_openrouter_key()
    ctx = ssl.create_default_context(cafile=certifi.where())
    payload = {
        "model": "openai/gpt-5.6-sol-pro",
        "messages": [
            {"role": "system", "content": system_role},
            {"role": "user", "content": prompt},
        ],
        "provider": {
            "order": ["OpenAI"],
            "allow_fallbacks": True,
        },
        "reasoning": {
            "effort": "xhigh",
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=data,
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://winsvpn.org",
            "X-Title": "Winthos Council: GPT-5.6 Sol Pro Deliberation",
        },
    )
    for attempt in range(5):
        try:
            print(f"[GPT-5.6 Sol Pro] Querying via OpenAI flex xhigh (attempt {attempt+1})...", flush=True)
            with urllib.request.urlopen(req, context=ctx, timeout=300) as resp:
                res_data = json.loads(resp.read().decode("utf-8"))
                choice = res_data["choices"][0]["message"]
                content = choice.get("content", "").strip()
                print(f"[GPT-5.6 Sol Pro] Completed successfully.", flush=True)
                return clean_text(content)
        except Exception as e:
            print(f"[GPT-5.6 Sol Pro] Attempt {attempt+1} failed: {e}", file=sys.stderr, flush=True)
            time.sleep(4 * (attempt + 1))
    raise RuntimeError("GPT-5.6 Sol Pro query failed after 5 attempts")


def main():
    print("=== Initializing Winthos Tripartite Presidential Council ===", flush=True)
    print("Supervisor: Antigravity (Gemini 3.8 Flash High Thinking)", flush=True)
    print("Podium 1: GLM 5.3 Flash (BaseTen fp8, Max Thinking)", flush=True)
    print("Podium 2: GPT-5.6 Sol Pro (OpenAI flex, Extra High Thinking)", flush=True)

    system_role = (
        "You are an elite systems, kernel, and network datapath architect on the Winthos Presidential Council. "
        "Your task is to analyze and review the Next Surgical Optimizations for Winn Protocol v3 to eliminate upload "
        "asymmetry and achieve multi-gigabit wire speed (800-1200+ Mbps upload matching 1218 Mbps download) on "
        "a physical Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL) connected to local gateway aicore "
        "(192.168.4.36:9111) over 2000 Mbps symmetrical fiber.\n"
        "Rules: Zero em dashes or en dashes (use colons, commas, periods, or parentheses). Zero AI clichés. "
        "Provide precise, rigorous technical review, examine exact code diffs, verify invariants, detect any potential "
        "deadlocks, starvation, race conditions, or cache thrashing, and vote AFFIRMATIVE or propose specific code adjustments."
    )

    deliberation_prompt = """
# Council Deliberation Docket: Next Surgical Optimizations for Wire-Speed Symmetrical Upload

## 1. System Target & Telemetry
- Target Device: Physical Samsung Galaxy S26 Ultra (SM-S948U1, serial REDACTED_SERIAL, Snapdragon 8 Elite).
- Gateway: Local aicore server (192.168.4.36:9111), winn3gw0 (MTU 1373, FQ qdisc limit 20480, flow_limit 512, clamp-mss-to-pmtu).
- Network: Wi-Fi 7 to 2000 Mbps symmetrical fiber.
- Baseline Run 1: 1,218 Mbps download, 117 Mbps upload, 13 ms idle ping, 0 packet drops (tx_dropped_sink: 0, send_failed: 0).
- Key Diagnostic: tx_packets: 425,857 vs messages_sent: 217,026 (average 1.96 packets per outer carrier message). The pipeline fragmented into 1-2 packet micro-batches.

## 2. Proposed Next Surgical Optimizations

### Component A: Kotlin Android TUN Burst Reader (`WinnV3AndroidTun.kt`)
```kotlin
private fun runBurstReader(device: WinnV3BurstTunDevice, generation: Long, buffer: ByteArray) {
    val miniBatchSize = 64
    val scratchBuffers = Array(miniBatchSize) { ByteArray(packetCapacity + 1) }
    val scratchLengths = IntArray(miniBatchSize)

    while (!closed.get() && readerGeneration.get() == generation) {
        if (!device.awaitReadable(READ_POLL_TIMEOUT_MS)) continue
        var drained = 0
        while (drained < MAX_BURST_PACKETS) {
            var batchCount = 0
            var endOfStream = false
            var kernelEmpty = false

            while (batchCount < miniBatchSize && drained + batchCount < MAX_BURST_PACKETS) {
                val n = device.readNonBlocking(scratchBuffers[batchCount])
                if (n < 0) {
                    kernelEmpty = true
                    break
                }
                if (n == 0) {
                    endOfStream = true
                    break
                }
                if (n > device.mtu || n > packetCapacity || n > scratchBuffers[batchCount].size) {
                    throw IOException("Winn tun packet exceeds configured MTU")
                }
                scratchLengths[batchCount] = n
                batchCount++
            }

            if (batchCount > 0) {
                var stale = false
                var overflowCount = 0
                synchronized(state) {
                    if (closed.get() || readerGeneration.get() != generation) {
                        stale = true
                    } else {
                        for (i in 0 until batchCount) {
                            if (!enqueue(scratchBuffers[i], scratchLengths[i], notify = false)) {
                                overflowCount++
                            }
                        }
                    }
                }
                if (stale) return
                if (overflowCount > 0) {
                    recordDrop("outbound queue full")
                }
                drained += batchCount
            }

            if (endOfStream) {
                notifyPending(generation)
                markReaderEnded(generation)
                return
            }
            if (kernelEmpty) {
                break
            }
        }
        if (drained > 0) {
            notifyPending(generation)
        } else {
            Thread.yield()
        }
    }
}
```

### Component B: Go Frame Ingestion Drain (`cmd/winn-datapath/winn3_frame.go`)
```go
func (s *winn3FrameServer) serve(ctx context.Context, input io.Reader) error {
	reader := duplex.NewReader(input, false)
	bufInput, _ := input.(*bufio.Reader)
	for {
		opcode, payload, err := reader.Read()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			_ = s.writer.Write(duplex.OpError, []byte(err.Error()))
			return err
		}
		done, err := s.handle(ctx, opcode, payload)
		if err != nil {
			return err
		}
		if done {
			return nil
		}

		if bufInput != nil {
			for bufInput.Buffered() >= duplex.HeaderSize && !s.closed.Load() {
				op, pay, err := reader.Read()
				if err != nil {
					break
				}
				d, err := s.handle(ctx, op, pay)
				if err != nil || d {
					return err
				}
			}
		}
	}
}
```

### Component C: Go Frame Device Micro-Cooperation & Batch Sizing (`cmd/winn-datapath/winn3_frame_device.go`)
```go
func (d *winn3FrameDevice) ReadBatch(bufs [][]byte) ([]int, error) {
	if len(bufs) == 0 {
		return nil, nil
	}
	var first []byte
	select {
	case pkt, ok := <-d.toEngine:
		if !ok {
			return nil, errWinn3DeviceClosed
		}
		first = pkt
	case <-d.closed:
		select {
		case pkt := <-d.toEngine:
			first = pkt
		default:
			return nil, errWinn3DeviceClosed
		}
	}

	lengths := d.readLengths[:0]
	if cap(lengths) < len(bufs) {
		lengths = make([]int, 0, len(bufs))
	}
	n0 := copy(bufs[0], first)
	d.recycle(first)
	lengths = append(lengths, n0)

	for i := 1; i < len(bufs); i++ {
		select {
		case pkt, ok := <-d.toEngine:
			if !ok {
				d.readLengths = lengths
				return lengths, nil
			}
			ni := copy(bufs[i], pkt)
			d.recycle(pkt)
			lengths = append(lengths, ni)
		default:
			if i < 16 {
				runtime.Gosched()
				select {
				case pkt, ok := <-d.toEngine:
					if !ok {
						d.readLengths = lengths
						return lengths, nil
					}
					ni := copy(bufs[i], pkt)
					d.recycle(pkt)
					lengths = append(lengths, ni)
					continue
				default:
				}
			}
			d.readLengths = lengths
			return lengths, nil
		}
	}
	d.readLengths = lengths
	return lengths, nil
}
```

## 3. Deliberation Questions
1. In `winn3_frame_device.go`: Does `if i < 16` provide optimal vector batch accumulation, or should this check be `if i < 64` to match Kotlin's `miniBatchSize = 64` and the engine's 64-packet carrier batch?
2. In `winn3_frame.go`: Does the userspace drain loop `bufInput.Buffered() >= duplex.HeaderSize` guarantee that consecutive `OpInbound` packets do not cause thread starvation or head-of-line blocking on control frames?
3. In `WinnV3AndroidTun.kt`: Is the monitor lock acquisition pattern (single `synchronized(state)` per 64-packet burst) completely leak-free, race-free, and safe under sudden socket closure?
4. Are there any hidden performance bottlenecks or configuration issues on the physical device or Go engine that would prevent reaching 800 to 1200+ Mbps upload?
5. State your final vote: AFFIRMATIVE (ratified as is) or AMENDMENT (with exact minimal diffs required).
"""

    glm_opinion = query_glm_5_3_flash(deliberation_prompt, system_role)
    sol_opinion = query_gpt_5_6_sol_pro(deliberation_prompt, system_role)

    result_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "supervisor": "Antigravity (Gemini 3.8 Flash High Thinking)",
        "podium_1_glm": {
            "model": "z-ai/glm-5.3-flash",
            "provider": "BaseTen (fp8)",
            "effort": "max",
            "opinion": glm_opinion,
        },
        "podium_2_sol_pro": {
            "model": "openai/gpt-5.6-sol-pro",
            "provider": "OpenAI (flex)",
            "effort": "xhigh",
            "opinion": sol_opinion,
        },
    }

    raw_path = DOCS_EVIDENCE / "tripartite_deliberation_raw.json"
    raw_path.write_text(json.dumps(result_data, indent=2), encoding="utf-8")
    print(f"Raw debate written to {raw_path}", flush=True)

    print("\n=================== GLM 5.3 FLASH OPINION ===================", flush=True)
    print(glm_opinion[:1000] + ("..." if len(glm_opinion) > 1000 else ""))

    print("\n================= GPT-5.6 SOL PRO OPINION ===================", flush=True)
    print(sol_opinion[:1000] + ("..." if len(sol_opinion) > 1000 else ""))


if __name__ == "__main__":
    main()
