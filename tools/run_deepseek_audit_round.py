#!/usr/bin/env python3
"""Run DeepSeek V4.1 Flash Deep Audit with Max Thinking Effort."""

import json
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.deepseek_debate_harness import call_deepseek

def load_sanitized_context() -> str:
    # Gather code snippets and diffs without any secrets
    context = []
    
    context.append("# WinsVPN Full System Audit Context\n")
    context.append("## 1. Triple-Protocol Client Architecture (lib/main.dart)")
    context.append("""
Key implementation details in Flutter client:
- User can select between 'Winn Protocol v3 (Next-Gen Multiplexed)' and 'Winn Protocol v1 (AmneziaWG Primary / XRay Backup)'.
- Selection stored in vpn_settings.txt as `selected_protocol_version`.
- Capability flags derivation:
```dart
Map<String, bool> get _winnCapabilityFlags {
  final flags = Map<String, bool>.from(winnClientCapabilities(
    operatingSystem: Platform.operatingSystem,
    spaKeyProvisioned: _winnSpaKeyProvisioned,
  ));
  if (_userSelectedProtocolVersion == kWinnProtocolV1) {
    flags['supports_winn3'] = false;
    flags['supports_winn3_descriptor'] = false;
  }
  return flags;
}
```
- Protocol dispatch:
```dart
if (strictWinnProtocolVersion(directConfig) == kWinnProtocolV1 &&
    !_winn3OrdinaryConnectivityAuthorized) {
  await armWinn1PrimaryHubDispatchAuthorization();
}
```
- Active protocol label reflects either connected config version or default user preference.
""")

    context.append("## 2. Web Download Portal & Worker Routing (web/_worker.js & web/index.html)")
    context.append("""
- Cloudflare Pages Worker routing:
```javascript
export function downloadAssetDecision(pathname, redirects, authorizedPaths) {
  if (!pathname.startsWith('/downloads/') && pathname !== '/downloads') {
    if (pathname.startsWith('/pkg/') || pathname === '/pkg') {
      return { action: 'reject', status: 404 };
    }
    return { action: 'ignore' };
  }
  const filename = pathname.slice('/downloads/'.length);
  if (!authorizedPaths.includes(filename)) {
    return { action: 'reject', status: 404 };
  }
  return { action: 'serve', assetPath: pathname };
}
```
- Direct downloads on web/index.html link directly to https://sync.winsvpn.org/downloads/<asset>.
- Hash-pinned CSP on inline styles and scripts.
""")

    context.append("## 3. Control Plane Account Expiration & Activation Keys (server/wins_control_plane_setup_ONETOUCH.sh)")
    context.append("""
- Lifetime account representation:
  Previously, lifetime accounts stored literal string 'Lifetime Access' or NULL, which caused parse_iso_datetime to return None or fail numeric comparisons.
  Reconciled to store an ISO 8601 UTC timestamp exactly 10 calendar years from provision:
  `expiry = (utcnow() + relativedelta(years=10)).isoformat()`
  `UPDATE users SET status = 'active', expiration_date = ? WHERE account_number = ?`
- Device enrollment / setup key:
  `secret = secrets.token_urlsafe(32)`
  `UPDATE users SET activation_secret_hash = ? WHERE account_number = ?`
  Plaintext setup key is delivered once via TLS SMTP to the user's email, never logged or stored.
- Activation email template:
  Direct links to raw .exe/.apk/.tar.gz removed to prevent spam classification.
  Email now links to:
  - Official download portal: `https://winsvpn.org/#download`
  - Google Cloud Storage mirror: `https://storage.googleapis.com/winsvpn/winsvpn.org#download`
  - Cryptographic checksums: `https://sync.winsvpn.org/downloads/SHA256SUMS.txt`
""")

    context.append("## 4. Data Plane Fleet Runtime (server/wins_data_plane_setup_ONETOUCH.sh)")
    context.append("""
- Nodes: Oregon, UK, Netherlands, Germany, Canada, Chicago, France, Singapore.
- Multi-engine concurrent operation:
  - AmneziaWG (amneziawg-go awg0) on port 9110
  - XRay (vless-ws) on port 80 / 443 fallback
  - Winn Protocol v3 gateway (winn3-gateway) on port 9111 with winn3gw0 TUN interface (10.10.0.1/24)
- Kansas control plane periodically probes data plane nodes and resyncs peer state.
""")

    return "\n".join(context)


def main():
    print("Preparing sanitized context for DeepSeek V4.1 Flash...")
    context = load_sanitized_context()
    
    prompt = f"""You are a Principal Security Engineer and Core Systems Auditor performing a comprehensive, adversarial audit of the WinsVPN system.

Here is the exact architectural and implementation context across the client, web delivery, control plane, and data plane:

{context}

Please perform a deep, rigorous audit covering:
1. Triple-Protocol Client Contract & Fallback:
   - Identify any race conditions, state leakages, route-loop issues, or fail-open paths between Winn v3 and Winn v1 (AWG first, XRay fallback).
   - Check if cached configurations or protocol switches could lead to desynchronized state or traffic leaks.
2. Web Delivery & Download Routing:
   - Check downloadAssetDecision logic for directory traversal, bypasses, or edge cases.
   - Analyze CSP and link structure.
3. Control Plane Account Expiration & Setup Key Flow:
   - Analyze the 10-year ISO 8601 expiration transition from literal 'Lifetime Access'.
   - Verify activation secret hashing and device enrollment authentication flow.
   - Check email delivery and anti-spam link structures.
4. Data Plane Multi-Engine Isolation & Concurrency:
   - Analyze potential collisions between awg0, winn3gw0, and XRay on the same host (routing tables, firewall marks, iptables NAT/forwarding, DNS resolver binds).

For EVERY finding:
- Explain the vulnerability / defect / edge case.
- Assess the severity (Critical, High, Medium, Low).
- Provide the EXACT code diff or implementation you recommend to solve it.
"""

    messages = [
        {"role": "system", "content": "You are DeepSeek V4.1 Flash, an expert security architect and systems programmer. Think deeply with maximum reasoning effort and provide exact, complete code solutions."},
        {"role": "user", "content": prompt}
    ]

    print("Submitting audit request to DeepSeek V4.1 Flash (Reasoning Effort: Max)...")
    content, reasoning = call_deepseek(messages, reasoning_effort="max", timeout=240)
    
    output_path = Path("docs/evidence/deepseek_round1_audit.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        f.write("# DeepSeek V4.1 Flash Security & Architecture Audit (Round 1)\n\n")
        f.write("## Reasoning Trace Summary\n\n")
        f.write(f"Reasoning length: {len(reasoning)} characters\n\n")
        f.write("## Audit Findings & Recommended Implementations\n\n")
        f.write(content)
        f.write("\n")

    print(f"Audit completed! Output saved to {output_path}")
    print("\n--- DEEPSEEK AUDIT FINDINGS ---\n")
    print(content)

if __name__ == "__main__":
    main()
