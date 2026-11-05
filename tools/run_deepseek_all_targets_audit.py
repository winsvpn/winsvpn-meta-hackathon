#!/usr/bin/env python3
"""Run DeepSeek V4.1 Flash Static & Dynamic Analysis Across All Targets.

Targets audited:
- Windows (x86, arm64): windows_tunnel_backend.cpp, named pipe IPC, Job Object lifecycle
- Linux (x86, arm64): linux_tunnel_backend.cc, root custody, BPF helper, signal handling
- macOS (x86, arm64): MainFlutterWindow.swift, route posture, memory ceiling
- Android (x86, arm64) & AndroidTV: AndroidManifest.xml, Leanback launcher, touchscreen, protect()
- iOS & tvOS: AppDelegate.swift, enforceRoutes, excludeLocalNetworks, NEPacketTunnel memory (15MB)
- Browser Extensions: manifest V3/V2 (Chrome, Firefox, Edge, Safari), PAC script, webRequestAuth
- Servers: Kansas Hub control plane, SQLite concurrency, iptables chain isolation, token entropy
- Core Dart App: lib/main.dart, protocol anti-downgrade, generation dispatch, error handling
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from deepseek_debate_harness import call_deepseek

REPO_ROOT = Path(__file__).resolve().parents[1]

AUDIT_PROMPT = """You are conducting an exhaustive, uncompromising static and dynamic analysis, vulnerability audit, and fuzz testing review for the WinsVPN codebase across ALL target platforms:

1. Windows (x86, arm64): windows/runner/windows_tunnel_backend.cpp, named pipe IPC, job object process containment, privileged service separation (WINS_TUNNEL_SERVICE_CORE vs client).
2. Linux (x86, arm64): linux/runner/linux_tunnel_backend.cc, tools/build_linux_release.sh, root custody validation (validate_root_owned_path), BPF helper invocation, FD leaks, signal handling on teardown.
3. macOS (x86, arm64): macos/Runner/MainFlutterWindow.swift, network extension bridge, route loop prevention, memory limits.
4. Android (x86, arm64) & AndroidTV: android/app/src/main/AndroidManifest.xml, Leanback launcher compatibility (android.software.leanback, android.hardware.touchscreen required=false, LEANBACK_LAUNCHER category), VpnService socket protection (protect()), split tunnel package isolation.
5. iOS & tvOS: ios/Runner/AppDelegate.swift, enforceRoutes=true, excludeLocalNetworks=true, NEPacketTunnelProvider 15MB strict memory ceiling, background refresh limits.
6. Browser Extensions (Chrome, Firefox, Edge, Safari): extension/manifest/ (chrome.jsonc, firefox.jsonc, edge.jsonc, safari.jsonc), extension/src/, MV3 service worker vs Firefox background event page, webRequest / webRequestAuthProvider permissions, proxy PAC generation, store listing metadata, native messaging origin binding.
7. Servers (Control Plane & Data Planes): server/wins_control_plane_setup_ONETOUCH.sh, server/wins_data_plane_setup_ONETOUCH.sh, web/_worker.js, FastAPI async/sync safety, SQLite concurrency, dedicated iptables chains (WINVPN-*) vs broad flushing (-F), single-use activation secrets, and datetime timezone normalization.
8. Core App & Protocol Engine (Shared Dart): lib/main.dart, lib/winn_protocol_dispatch.dart, lib/winn3_cover_fallback.dart, strict protocol dispatch, anti-downgrade enforcement (Winn v3 -> v1 -> AWG -> XRay fallback), and generation authorization.

CURRENT ENVIRONMENT FACTS:
- Connected physical device: iPhone 16 Pro Max (iOS 26.6.2, Darwin arm64) via devicectl.
- Local host: macOS Darwin arm64 (macOS 26.6.2).
- Local network machine: NVIDIA DGX Spark (Linux 6.17 aarch64, 192.168.4.38).
- Remote live control plane: Kansas Hub (<KANSAS_HUB_IP>, Linux x86_64).
- Android AVDs: duress_test (Phone), wear_test (Wear).

TEST & FUZZING OBSERVATIONS:
- parse_iso_datetime was hardened to normalize offset-aware datetimes (dt.astimezone(timezone.utc).replace(tzinfo=None)) to prevent TypeError on Kansas.
- Worker URL normalization downloadAssetDecision was hardened with length limits, %2e/%2f/%5c/%00 rejection, and dot segment rejection.
- AndroidManifest.xml currently lacks `<uses-feature android:name="android.software.leanback" android:required="false" />` and `<uses-feature android:name="android.hardware.touchscreen" android:required="false" />` and `<category android:name="android.intent.category.LEANBACK_LAUNCHER" />`, which blocks Android TV installation or hides the launcher banner.
- Flutter analyze is 100% clean (0 issues).
- Flutter protocol test suite (46 test cases) passes.

TASK:
1. Perform a deep static and dynamic vulnerability analysis across each of the 8 target areas.
2. Identify every true defect, race condition, crash trigger, memory leak, security risk, and multiplatform misconfiguration.
3. For each finding, provide:
   - Target and Component
   - Severity (Critical, High, Medium, Low)
   - Root Cause Analysis
   - Exact, complete, production-ready code implementation to fix it (no placeholders, no omissions).
4. Address cross-platform compatibility edge cases (e.g. x86 vs arm64 alignments, Apple 15MB memory ceiling, Android TV remote navigation vs touch input, Windows Job Object termination, Extension MV3 worker suspension).
"""

def main():
    print("Calling DeepSeek V4.1 Flash (Max reasoning effort) for comprehensive all-targets audit...")
    content, reasoning = call_deepseek(
        messages=[
            {"role": "system", "content": "You are a world-class Principal Systems and Security Engineer auditing a high-security multiplatform VPN ecosystem. You produce rigorous, highly specific findings with complete code solutions and zero placeholders."},
            {"role": "user", "content": AUDIT_PROMPT},
        ],
        reasoning_effort="max",
        timeout=300,
    )
    
    out_dir = REPO_ROOT / "docs" / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    audit_file = out_dir / "deepseek_all_targets_audit.md"
    with audit_file.open("w", encoding="utf-8") as f:
        f.write("# DeepSeek V4.1 Flash All-Targets Audit\n\n")
        f.write("## Reasoning Trace\n\n")
        f.write("```\n")
        f.write(reasoning)
        f.write("\n```\n\n")
        f.write("## Audit Findings and Exact Implementation Codes\n\n")
        f.write(content)
        f.write("\n")

    print(f"Audit completed! Output written to {audit_file}")
    print(f"Reasoning length: {len(reasoning)} chars | Content length: {len(content)} chars")

if __name__ == "__main__":
    main()
