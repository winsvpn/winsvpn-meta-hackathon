from __future__ import annotations

import os
import shutil
from hashlib import sha256
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "pdf" / "wins-vpn-blueprint.pdf"
DATED_OUTPUT = ROOT / "output" / "pdf" / f"Wins_VPN_Architecture_Blueprint_{datetime.now().strftime('%Y-%m-%d')}.pdf"


BRAND_BLUE = colors.HexColor("#1D6CFF")
INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#5E6A7D")
PANEL = colors.HexColor("#F4F7FB")
LINE = colors.HexColor("#D9E2EF")
GREEN = colors.HexColor("#18A058")
AMBER = colors.HexColor("#B76E00")


def p(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(text, style)


def bullet(items: list[str], style: ParagraphStyle) -> list[Paragraph]:
    return [Paragraph(f"- {item}", style) for item in items]


def table(data: list[list[str]], col_widths: list[float]) -> Table:
    body = [
        [Paragraph(cell, STYLES["TableHeader" if row_index == 0 else "TableCell"]) for cell in row]
        for row_index, row in enumerate(data)
    ]
    t = Table(body, colWidths=col_widths, repeatRows=1, hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.25, LINE),
                ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


def callout(title: str, body: str, accent=BRAND_BLUE) -> Table:
    data = [[Paragraph(f"<b>{title}</b><br/>{body}", STYLES["Callout"])]]
    t = Table(data, colWidths=[7.0 * inch], hAlign="LEFT")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), PANEL),
                ("BOX", (0, 0), (-1, -1), 0.75, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def file_sha256(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()


def file_size_mb(path: Path) -> str:
    return f"{path.stat().st_size / (1024 * 1024):.2f} MB"


def artifact_row(label: str, path: Path) -> list[str]:
    # Kept out of the f-string expression below: Python versions before 3.12
    # (including the macOS-default Python 3.9 this tool must run under)
    # reject a backslash inside an f-string expression part.
    normalized = str(path).replace("\\", "/")
    if not path.exists():
        return [label, normalized, "MISSING"]
    return [
        label,
        f"{normalized} ({file_size_mb(path)})",
        file_sha256(path),
    ]


def architecture_diagram() -> Table:
    rows = [
        [
            "<b>Clients</b><br/>Android app<br/>Windows app",
            "<b>Discovery</b><br/>Gist<br/>Website<br/>Cloudflare aliases",
            "<b>Control Hub</b><br/>FastAPI<br/>SQLite<br/>PayPal<br/>SMTP",
            "<b>Data Planes</b><br/>AmneziaWG<br/>Xray WS<br/>AdGuard DNS",
            "<b>Internet</b><br/>Filtered egress<br/>No traffic logs",
        ],
        ["local keygen", "gateway failover", "auth and provisioning", "tunnel exit", "web/apps"],
    ]
    body = [[Paragraph(cell, STYLES["DiagramBox"]) for cell in row] for row in rows]
    t = Table(body, colWidths=[1.35 * inch] * 5, hAlign="CENTER")
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.white),
                ("BACKGROUND", (0, 1), (-1, 1), PANEL),
                ("BOX", (0, 0), (-1, -1), 0.25, LINE),
                ("GRID", (0, 0), (-1, -1), 0.25, LINE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def header_footer(canvas, doc):
    canvas.saveState()
    width, height = letter
    canvas.setFillColor(BRAND_BLUE)
    canvas.rect(0, height - 0.42 * inch, width, 0.42 * inch, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(0.55 * inch, height - 0.27 * inch, "Win's VPN Architecture Blueprint")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(0.55 * inch, 0.36 * inch, "Generated from the local private project workspace. Secrets and credentials intentionally omitted.")
    canvas.drawRightString(width - 0.55 * inch, 0.36 * inch, f"Page {doc.page}")
    canvas.restoreState()


def add_title(story: list):
    logo = ROOT / "web" / "assets" / "wins-vpn-logo.webp"
    if logo.exists():
        try:
            story.append(Image(str(logo), width=1.15 * inch, height=1.15 * inch, kind="proportional"))
            story.append(Spacer(1, 0.08 * inch))
        except Exception:
            pass
    story.append(p("Win's VPN System Blueprint", STYLES["Title"]))
    story.append(p("Control plane, data planes, apps, website, security operations, and deployment order", STYLES["Subtitle"]))
    story.append(Spacer(1, 0.18 * inch))
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    story.append(callout("Purpose", "This document records the intended production architecture as of "
                         f"{generated_at}, plus the live validation results from the current workspace. "
                         "It is designed for rebuilds, audits, and handoff without including passwords, API tokens, or private keys.", GREEN))
    story.append(Spacer(1, 0.22 * inch))
    story.append(architecture_diagram())
    story.append(Spacer(1, 0.25 * inch))
    story.extend(
        bullet(
            [
                "Primary user traffic enters a selected data plane through modified AmneziaWG. Smart Protocol can fall back to modified Xray WebSocket/TCP when direct UDP is blocked.",
                "Wi-Fi + Mobile Data / Smart Boost is parked for the public stable release. The last experimental work is preserved under docs/SMART_BOOST_WIFI_MOBILE_PARKED.md and docs/parked_smart_boost/, while the release app uses the stable Winn Protocol path.",
                "The IONOS control hub is for account state, PayPal provisioning, node registry, security monitoring, backups, and admin operations. It is not intended to be the normal exit node.",
                "Gist, website, Cloudflare, hub DNS, direct hub IP, regional aliases, and SPA emergency paths provide multiple discovery and activation options under censorship.",
                "The no-log VPN goal is preserved by keeping content traffic and browsing history off the servers. The hub stores account, device-count, referral, payment, and security event metadata only.",
            ],
            STYLES["Body"],
        )
    )


def add_components(story: list):
    story.append(PageBreak())
    story.append(p("1. Component Inventory", STYLES["Heading1"]))
    story.append(
        table(
            [
                ["Layer", "Main Files / Services", "Responsibility", "Operational Notes"],
                [
                    "Android app",
                    "lib/main.dart, lib/gateway_failover.dart, Android native VPN plugin, bundled Xray assets",
                    "Calculator camouflage, paid activation, free server, local client key generation, Smart Protocol, split tunneling, referral sharing, real map pre-VPN background, named country scenes, and regional fallback scenes for remaining countries.",
                    "Calculator mode is phone/tablet only. Wi-Fi + Mobile Data / Smart Boost is removed from the stable app UI/code path. Public referral links use branded winsvpn.org / winsvpn.com routes.",
                ],
                [
                    "Windows app",
                    "windows/runner, installer/windows, build/windows-installer/WinsVPN-Setup.exe",
                    "Desktop client with the same VPN control concepts as Android except calculator camouflage.",
                    "Installer bundles app assets and required helper packages so normal users should not install separate dependencies.",
                ],
                [
                    "Control hub",
                    "server/wins_control_plane_setup_ONETOUCH.sh generates /root/vpn_auth/main.py and services",
                    "FastAPI API, SQLite account/device/node DB, PayPal webhook engine, SMTP2GO email, referrals, free server routing, node registry, IDS alert processing.",
                    "Admin APIs require the admin token. SSH key is generated on the hub and distributed to data planes during setup.",
                ],
                [
                    "Data plane",
                    "server/wins_data_plane_setup_ONETOUCH.sh, awg0, Xray, Nginx, AdGuard Home",
                    "VPN exit node, AWG UDP tunnel, Xray WebSocket stealth transport, DNS filtering, node heartbeat, canary, backup, hardening.",
                    "Data planes only accept hub SSH after deployment and replay peers from the hub after maintenance restarts. Smart Boost server code is parked for future native-engine work and is not installed/opened by stable deployments unless BOOST_ENABLED=1 is deliberately set.",
                ],
                [
                    "Website",
                    "web/index.html, web/_headers, web/_worker.js, web/_redirects, web/assets/hero/*, web/downloads/*",
                    "Public marketing page, dynamic coarse-geo hero scene, download links, referral and payment redirects, AI support chat, language support, legal sections.",
                    "Production is published through Cloudflare Pages via the connected GitHub repo, which builds and deploys automatically on push.",
                ],
                [
                    "Cloudflare and anchors",
                    "Gist active gateway, website active-gateway.txt, sync.winsvpn.org, sync.winsvpn.com, hub.winsvpn.org, regional stealth aliases",
                    "Gateway discovery, Cloudflare proxying, anti-censorship path diversity, WebSocket support.",
                    "The Winn Protocol direct path uses DNS-only/IP paths where appropriate; Cloudflare is used for HTTP(S)/WebSocket stealth, not raw UDP.",
                ],
            ],
            [0.95 * inch, 1.55 * inch, 2.5 * inch, 2.0 * inch],
        )
    )


def add_flows(story: list):
    story.append(PageBreak())
    story.append(p("2. Primary Flows", STYLES["Heading1"]))
    flows = [
        ("Paid Activation", [
            "User enters a paid account number or completes PayPal provisioning.",
            "The app generates the client key on-device and sends only the client public key to the hub.",
            "The hub validates account status, device limit, and expiration, then allocates a VPN internal IP.",
            "The hub syncs the peer to the selected data plane over hub-to-node SSH.",
            "The app receives server public key, endpoint, DNS, obfuscation values, and optional Xray fallback data.",
        ]),
        ("Free Server", [
            "Free users are assigned account number 9999-9999-9999 in the app experience.",
            "The free identity is limited to the configured free node. Current test default is the Los Angeles node until London is deployed.",
            "Free access logs privacy-preserving device/source buckets and key fingerprints, not browsing activity.",
            "The same tunnel stack is used: AWG first, Xray fallback where censorship blocks direct UDP.",
        ]),
        ("Smart Protocol", [
            "The app starts with direct AmneziaWG for speed.",
            "If direct route checks or handshakes fail, it attempts Xray WebSocket through the stealth gateway and regional aliases.",
            "TCP fallback and SPA emergency paths remain last-resort activation/discovery tools rather than the normal data path.",
            "Double VPN UI is present as a future option and currently falls back to regular VPN until the Florida server is live.",
        ]),
        ("Smart Boost Wi-Fi + Mobile Data Parked", [
            "Smart Boost proved useful research, but the Kotlin userspace path did not beat direct Winn Protocol/AWG in live phone tests.",
            "The stable public app removes the Wi-Fi + Mobile Data UI, removes Smart Boost config/status calls, removes the Kotlin engine and native bridge from compiled Android source, and disables the C++ native build hook.",
            "The last experimental service and native bridge snapshots are preserved under docs/parked_smart_boost/ for future v2 work.",
            "Future work requires a true native TUN/socket/crypto engine with per-path congestion control, loss handling, reordering, MTU handling, and proof that real phone tests beat AWG before any public UI returns.",
        ]),
        ("PayPal and Referrals", [
            "Website and app payment links are tracked through branded routes before reaching PayPal.",
            "PayPal webhooks are verified, deduplicated, retried, and synchronized into SQLite.",
            "Successful referred purchases grant 20 percent extra validity to the referrer and referred user.",
            "Donation receipts are handled through SMTP2GO without exposing tax-status wording in the email body.",
        ]),
        ("Node Heartbeat and Bandwidth", [
            "Each data plane posts heartbeat and bandwidth counters to the hub.",
            "The admin menu can list node status, selected endpoint, stealth endpoint, and live Mbps estimates.",
            "Weekly data-plane maintenance re-registers the node and asks the hub to resync active peers after AWG restart.",
        ]),
    ]
    for title, items in flows:
        story.append(KeepTogether([p(title, STYLES["Heading2"]), *bullet(items, STYLES["Body"]), Spacer(1, 0.12 * inch)]))


def add_security(story: list):
    story.append(PageBreak())
    story.append(p("3. Security and Privacy Controls", STYLES["Heading1"]))
    story.append(callout("No-log boundary", "Data planes are not designed to log browsing, DNS query history, source traffic contents, or user destinations. The control hub stores account and device metadata needed for billing, device limits, referrals, free access abuse control, and security operations.", GREEN))
    story.append(Spacer(1, 0.14 * inch))
    story.append(
        table(
            [
                ["Control", "Where", "Current Design"],
                ["Client key generation", "Android and Windows app model", "Client private keys are generated on the device. The hub receives the public key only."],
                ["Privacy-preserving rate limits", "Control hub", "Source IP, device, user-agent, and referer values are bucketed/hmac-hashed before rate limit or click tracking storage."],
                ["SSH hardening", "Hub and data planes", "Data planes restrict SSH to the hub. SSH is key-only after setup. The hub defaults to password SSH for one-touch recovery, but HUB_SSH_PASSWORD_AUTH=0 makes it key-only after an admin public key is installed. Login attempts are rate-limited with Fail2Ban and sshd settings."],
                ["VPS disk encryption", "Hub and data planes after reset", "The one-touch scripts support REQUIRE_LUKS_ROOT=1 to enforce LUKS-backed root and encrypted swap before VPN secrets/services are written. If LUKS is present, dropbear-initramfs remote unlock is configured for controlled reboots."],
                ["IDS/IPS", "Control hub required, data planes optional", "Suricata logs retained locally for 180 days. Email alerts are limited to P1/P2 after suppressing known noisy false positives."],
                ["Security email", "SMTP2GO", "P1/P2 events are sent to security@winsvpn.com in Eastern time with aligned labels. User home IP and trusted source exemptions suppress email while preserving desired logs."],
                ["Backups", "Hub and data planes", "Initial backup runs after successful deployment. Scheduled backups and rclone/Google Drive paths are managed by systemd timers."],
                ["Weekly maintenance", "Hub and data planes", "All apt-managed programs are full-upgraded Sundays at 4 AM local server time, followed by service validation/restarts and canary checks."],
                ["DNS and leak prevention", "Data planes and apps", "IPv6 is disabled/blocked on nodes and mobile tunnel testing showed public IPv6 blocked. AdGuard Home provides DNS filtering inside the VPN."],
                ["Fallback canaries", "Hub and nodes", "Gist, website, Cloudflare hub, direct hub IP, DNS hub, stealth-zone, and node stealth health are checked to detect censorship path failures."],
                ["Website security headers", "Cloudflare Pages edge", "CSP, frame denial, nosniff, referrer policy, permissions policy, and same-origin opener policy are defined in web/_headers and verified by tools/website_security_audit.py."],
                ["Website dynamic hero", "Cloudflare Pages static site and geo-scene Worker route", "The first viewport no longer hardcodes Los Angeles. It selects a copyright-safe local hero by coarse country/region headers, with locale/timezone fallback and no IP storage."],
                ["Public function abuse controls", "Cloudflare Pages Worker routes", "AI chat and translation endpoints restrict CORS to known site origins and include lightweight per-IP throttling."],
                ["Tech E&O readiness", "Legal docs, quality docs, and insurance supplement", "Legal version 2026-06-30.v6 adds active cyber-insurance wording, insurance-policy acceptable-use language, and Winn Protocol® branding. Internal docs retain Technology Errors and Omissions readiness controls."],
            ],
            [1.5 * inch, 1.55 * inch, 3.95 * inch],
        )
    )


def add_deployment(story: list):
    story.append(PageBreak())
    story.append(p("4. Deployment Order", STYLES["Heading1"]))
    story.append(p("Control Hub One-touch Order", STYLES["Heading2"]))
    story.extend(
        bullet(
            [
                "Require root, install/upgrade packages, then enforce/configure LUKS root policy before writing VPN secrets when REQUIRE_LUKS_ROOT=1.",
                "Apply hub sysctl settings, write root-owned environment, and generate the hub SSH key.",
                "Back up any existing SQLite DB, write the FastAPI app, bootstrap schema, and install Python dependencies.",
                "Write systemd service, harden SSH, configure Nginx, Cloudflare hub DNS, and firewall rules.",
                "Install IDS/IPS, security alert monitor, security event CLI, PayPal sync timer, backups, admin menu, weekly maintenance, and gateway canary.",
                "Run the first backup. Website publishing is handled separately by Cloudflare Pages' GitHub integration, outside this install flow.",
            ],
            STYLES["Body"],
        )
    )
    story.append(p("Data Plane One-touch Order", STYLES["Heading2"]))
    story.extend(
        bullet(
            [
                "Require root, refuse to install on the hub, install/upgrade packages, enforce/configure LUKS root policy when REQUIRE_LUKS_ROOT=1, and fetch the hub SSH public key.",
                "Collect or auto-discover node slug/name/host/stealth alias values, then write /root/node.env.",
                "Apply Linux forwarding, TCP buffer, BBR, RPS, and IPv6 leak-prevention tuning.",
                "Install or reconcile AmneziaWG, including obfuscation values Jc/Jmin/Jmax/S1-S4/H1-H4 without replacing the server private key on reruns.",
                "Install Xray, AdGuard Home, Nginx, firewall matrix, SSH hardening, node register/diagnose/canary, backups, rclone config, and weekly maintenance. First install and weekly maintenance both use apt full-upgrade for apt-managed programs. Smart Boost is parked and not deployed unless explicitly opted in for future research.",
                "Run the first node backup after deployment. Weekly maintenance now re-registers the node and calls the hub peer-resync API after AWG restarts.",
            ],
            STYLES["Body"],
        )
    )
    story.append(Spacer(1, 0.12 * inch))
    story.append(
        table(
            [
                ["Fresh Install Command", "Purpose"],
                ["HUB_API_BASE=https://sync.winsvpn.org NODE_MANAGEMENT_TUNNEL_ENABLED=1 ./deploy.sh --deploy", "Data-plane install through hostname-only API and outbound management tunnel."],
                ["./deploy.sh --deploy", "Control hub install when the control script is copied to the hub."],
                ["wins-menu", "Hub admin menu for accounts, nodes, backups, PayPal dead letters, and node status."],
                ["/usr/local/bin/wins-node-diagnose", "Data-plane local diagnostic for AWG/Xray/Nginx/DNS/firewall/heartbeat state."],
                ["tools/test_gateway_failover.ps1", "Local workstation probe for Gist, website, Cloudflare, direct hub, and stealth-node paths."],
            ],
            [3.15 * inch, 3.85 * inch],
        )
    )


def add_dns(story: list):
    story.append(PageBreak())
    story.append(p("5. DNS, Cloudflare, and Censorship Resilience", STYLES["Heading1"]))
    story.extend(
        bullet(
            [
                "Keep the public website apex on Cloudflare Pages. Do not replace winsvpn.org apex with the hub while Cloudflare Pages owns that hostname.",
                "Use hub.winsvpn.org as the Cloudflare-proxied control hub hostname.",
                "Use sync.winsvpn.org as the working Cloudflare-proxied API/payment/referral sync hostname; retain app-cloud aliases as separately tested fallbacks.",
                "Use data-plane regional aliases like united-states-los-angeles.app-cloud-sync.net for Xray WebSocket stealth.",
                "Use direct IP and hub DNS as fallback discovery paths, not as the normal public brand surface.",
                "Cloudflare can proxy HTTP(S)/WebSocket Xray stealth, but it cannot proxy raw UDP AmneziaWG. The Winn Protocol direct path must use DNS-only/IP endpoints.",
                "Gist and website active-gateway files are independent discovery anchors. The app ignores invalid/HTML gateway responses.",
                "SPA emergency knock remains available for strong censorship cases and should stay last in the fallback order.",
            ],
            STYLES["Body"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    story.append(callout("Production publishing rule", "Production website deploys are pushed through Cloudflare Pages via the connected wins-backend GitHub repository, and should only be pushed after local checks pass. Cloudflare Pages builds and publishes automatically on push to the tracked branch; the control-plane script does not install or trigger a separate deploy hook.", AMBER))


def add_version_history(story: list):
    story.append(PageBreak())
    story.append(p("6. Successful Version History", STYLES["Heading1"]))
    story.append(
        table(
            [
                ["Version", "Date", "Scope", "Verification Gate"],
                [
                    "Smart Protocol baseline",
                    "2026-06-28",
                    "Direct modified AmneziaWG, modified Xray TCP/WebSocket fallback, Cloudflare/Netlify/Gist discovery, free server, PayPal provisioning, node heartbeat, and no-log data-plane boundary.",
                    "Phone tunnel checks showed working internet, IPv6 blocked, and hub/device activation flow operational.",
                ],
                [
                    "Smart Boost v2",
                    "2026-06-30",
                    "Added separate Wi-Fi/cellular UDP paths, AES-GCM encrypted boost frames, ping/pong health checks, RTT/load-aware path selection, and data-plane wins-boostd.",
                    "Flutter build/tests, shellcheck, embedded daemon py_compile, phone reinstall/launch smoke, and local protocol simulator introduced.",
                ],
                [
                    "Smart Boost v2.1",
                    "2026-06-30",
                    "Fixed reorder startup bug by initializing expected data sequence to 1. Increased reorder tolerance to 240 ms and 2048 packets to handle asymmetric and bursty cross-path jitter.",
                    "tools/local_release_gate.ps1 passed clean, lossy, asymmetric, and bursty Smart Boost profiles with no unexpected, duplicate, out-of-order, decrypt, or payload failures.",
                ],
                [
                    "Smart Boost v3 native groundwork",
                    "2026-06-30",
                    "Added an Android NDK C++ native path scheduler, TUN read burst batching, data-plane Go daemon buffer pooling/in-place decrypt/one-lock path sequencing, v3-adaptive simulator profile, and phone benchmark/qualification tooling. Android keeps vetted AES-GCM crypto until a separately audited native crypto engine is ready.",
                    "Flutter analyze/tests passed, release APK built with libwinsboostnative.so, v3-adaptive stress delivered all non-lost frames correctly, data-plane Go source compiled for linux/amd64 from both standalone and embedded one-touch sources, and fresh phone install/free activation connected through AWG while Smart Boost remained gated because the LA node is not boost_qualified.",
                ],
                [
                    "Smart Boost v8.14.1/v8.15 live guard",
                    "2026-07-02",
                    "Live LA tests showed the Kotlin userspace Smart Boost path was slower than direct Winn Protocol/AWG on the connected Android phone. v8.14.1 removed the over-aggressive cellular capacity floor, raised the cellular/secondary qualification thresholds, and restores Winn Protocol when Smart Boost cannot prove enough speed. v8.15 compiles a guarded Android NDK native scheduler hook into the APK as the next migration step.",
                    "Fresh Android uninstall/install passed. Legal free activation succeeded. Wi-Fi + Mobile toggle feedback worked. Direct AWG median was 128.8 Mbps and v8.14 Smart Boost median was 78.6 Mbps on the bounded Sonic LA phone benchmark, so the v8.15 safe-batch APK fell back to Winn Protocol with public IPv4 <HISTORICAL_NODE_IP>.",
                ],
                [
                    "Stable Android Smart Boost removal",
                    "2026-07-02",
                    "Parked Wi-Fi + Mobile Data / Smart Boost for public release. The compiled Android app removes the toggle, Smart Boost config/status calls, Kotlin engine path, native bridge, and C++ build hook. Stable data-plane deployment now disables/removes wins-boostd by default and does not open the boost UDP port; the last experimental state remains under docs/parked_smart_boost/.",
                    "flutter analyze, flutter test, Xray asset prep, release APK build, APK content search, fresh USB phone uninstall/install/free-route tunnel test, bash -n, and shellcheck passed. The stable APK hash is 23E291DB5E92F72FCCD1D53A7C2840316DC7E759774684410DD4CF3130A29379.",
                ],
                [
                    "App size/security hardening",
                    "2026-06-30",
                    "Replaced runtime activation logo PNG with WebP and removed unused launcher source PNG from Flutter asset bundle. APK reduced from about 65.8 MB to about 59.0 MB.",
                    "flutter analyze, flutter test, release APK build, Windows release build, installer build, and phone fresh uninstall/install smoke passed.",
                ],
                [
                    "Website OWASP local gate",
                    "2026-06-30",
                    "Added CSP/security headers, restricted function CORS, function throttling, and repeatable website audit script.",
                    "tools/website_security_audit.py passed 30/30. Production winsvpn.org headers and download endpoints returned HTTP 200 after the batched Netlify deploy.",
                ],
                [
                    "Server deploy safety",
                    "2026-06-30",
                    "Aligned first-install package maintenance with weekly full-upgrade behavior and made Netlify publishing opt-in to preserve limited build credits.",
                    "tools/local_release_gate.ps1 passed after the script-order change: Flutter analyze/tests, shellcheck, embedded wins-boostd py_compile, Smart Boost profiles, function syntax, and website audit.",
                ],
                [
                    "Live redeploy hardening",
                    "2026-06-30",
                    "Patched the control bootstrap to add missing legacy SQLite columns before index creation, quote Suricata HOME_NET for Suricata 7 validation, and add an opt-in HUB_SSH_PASSWORD_AUTH=0 key-only hub SSH mode.",
                    "Live hub redeploy completed with RC=0, Suricata test passed, Fail2Ban active, legal endpoint current, and LA node re-registered with Smart Boost enabled. Key-only hub SSH was not forced live to avoid lockout.",
                ],
                [
                    "Regional scene expansion",
                    "2026-06-30",
                    "Added app WebP regional fallback scenes for Africa, Central Asia, East Asia, Europe, Latin America, Middle East, Oceania, South Asia, Southeast Asia, and New York. Added website hero scenes and a read-only geo-scene function so the website hero is selected by coarse country/region instead of a fixed LA image.",
                    "tools/local_release_gate.ps1 passed 35/35 website/security checks plus Flutter analyze/tests, shellcheck, embedded Python syntax, Smart Boost stress profiles, and Netlify function syntax including geo-scene.js. Fresh Android uninstall/install/launch smoke passed on the connected USB phone.",
                ],
                [
                    "Tech E&O legal readiness",
                    "2026-06-30",
                    "Added insurance/risk-transfer language to controlling legal text, app fallback legal text, and website legal terms. Added a Technology Errors and Omissions readiness program and generated a broker-ready DOCX supplement with copy-ready application language and policy-status placeholders.",
                    "tools/local_release_gate.ps1 passed. Android release APK rebuilt and fresh-installed on the USB-debug phone with no suspicious AndroidRuntime/WinsVpnService errors. Windows release and installer rebuilt successfully. The DOCX supplement was metadata-scrubbed and Word/PDF-render checked.",
                ],
                [
                    "VPS LUKS encryption readiness",
                    "2026-07-02",
                    "Inspected the live IONOS hub and InterServer LA data plane and confirmed both current root filesystems are plain ext4, not LUKS. Added an enforced post-reset LUKS policy to both one-touch scripts plus dropbear-initramfs remote unlock configuration when root is already encrypted.",
                    "bash -n and shellcheck passed for both one-touch scripts. The policy runs immediately after apt installation and before VPN secrets/services are written. docs/VPS_DISK_ENCRYPTION_RUNBOOK.md records the reset/reinstall and unlock procedure.",
                ],
            ],
            [1.1 * inch, 0.75 * inch, 3.0 * inch, 2.15 * inch],
        )
    )


def add_tests(story: list):
    story.append(PageBreak())
    story.append(p("7. Current Verification Evidence", STYLES["Heading1"]))
    story.append(
        table(
            [
                ["Area", "Result"],
                ["Mobile Wi-Fi tunnel", "PASS. Android default-route check used tun0 with tunnel IP 10.8.1.5. Public IPv4 was <HISTORICAL_NODE_IP>. Public IPv6 was blocked. Future route canaries should avoid Cloudflare/Google DNS because those may be blocked in Burma."],
                ["Mobile data handoff", "PASS. Wi-Fi disabled, mobile data active, public IPv4 remained <HISTORICAL_NODE_IP> and public IPv6 remained blocked."],
                ["Wi-Fi restore handoff", "PASS. Wi-Fi was re-enabled and connected; tunnel route and public exit IP remained stable."],
                ["Gateway failover", "PASS. Gist, Netlify, stealth-zone Cloudflare, hub.winsvpn.org, direct hub IP, hub DNS, verify routes, and LA stealth health all returned expected shapes."],
                ["Flutter analysis", "PASS. flutter analyze reported no issues."],
                ["Flutter tests", "PASS. Gateway failover and widget tests passed."],
                ["Smart Boost stress", "PASS. tools/local_release_gate.ps1 runs clean, lossy, asymmetric, bursty, and v3-adaptive profiles. The latest v3-adaptive run delivered all non-lost encrypted frames with no payload, decrypt, duplicate, unexpected, or out-of-order failures."],
                ["Android phone smoke", "PASS on 2026-07-02 after stable Smart Boost removal. Fresh uninstall/install on device 365c61de, free activation, legal terms, VPN/notification permissions, direct Winn Protocol tunnel, dashboard SECURED state, public IPv4 <HISTORICAL_NODE_IP>, and clean disconnect all passed. The Wi-Fi + Mobile Data UI was absent."],
                ["Deployment scripts", "PASS. bash -n and shellcheck clean for both one-touch scripts after LUKS policy insertion and stable Smart Boost deployment removal. Stable data planes disable/remove wins-boostd unless BOOST_ENABLED=1 is explicitly set."],
                ["VPS disk encryption readiness", "READY FOR NEXT RESET. Live hub and LA data plane are currently unencrypted ext4 roots. After provider reset/reinstall with LUKS2 root and encrypted swap, running with REQUIRE_LUKS_ROOT=1 will abort before secrets if encryption is missing and will configure initramfs SSH remote unlock when present."],
                ["Live control hub redeploy", "PASS. The patched control script completed on the redacted control origin with Netlify deploy disabled, backed up the DB, validated Suricata, kept wins-hub/nginx/suricata/fail2ban active, and exposed the current legal document endpoint."],
                ["Live data plane redeploy", "PASS from prior live test. Current stable script keeps Xray/nginx/AdGuardHome/firewall hardening and node registration, while Smart Boost is parked and disabled by default for the next reset/redeploy."],
                ["Smart Boost parking", "COMPLETE on 2026-07-02. Direct Winn Protocol/AWG beat the Kotlin userspace Smart Boost path on the same Android phone and LA node, so Wi-Fi + Mobile Data / Smart Boost was removed from the stable app UI/code path and preserved only as parked future work."],
                ["Website local OWASP gate", "PASS. tools/website_security_audit.py passed 35/35 checks for headers, CSP, redirects, DOM sinks, function CORS, throttling, secrets, and download artifacts."],
                ["Website local downloads", "PASS. web/downloads/WinsVPN-Setup.exe and web/downloads/wins-vpn-android.apk were refreshed from the latest verified Windows installer and Android release APK. Netlify production deploy was not triggered to preserve build credits."],
            ],
            [1.7 * inch, 5.3 * inch],
        )
    )
    story.append(Spacer(1, 0.12 * inch))
    story.append(
        table(
            [
                ["Artifact", "Current Path", "SHA256"],
                artifact_row("Android APK", ROOT / "web" / "downloads" / "wins-vpn-android.apk"),
                artifact_row("Windows installer", ROOT / "web" / "downloads" / "WinsVPN-Setup.exe"),
                artifact_row("Architecture PDF", DATED_OUTPUT if DATED_OUTPUT.exists() else OUTPUT),
            ],
            [1.45 * inch, 3.3 * inch, 2.25 * inch],
        )
    )


def add_risks(story: list):
    story.append(PageBreak())
    story.append(p("8. Remaining Production Items", STYLES["Heading1"]))
    story.extend(
        bullet(
            [
                "Deploy the planned London free server, then switch FREE_ACCESS_NODE_SLUG from the Los Angeles test node to the London slug.",
                "Deploy additional country nodes and confirm each regional alias resolves through Cloudflare for Xray stealth while direct AWG remains DNS-only/IP based.",
                "Reset/reinstall each VPS with Ubuntu 24.04 on LUKS2-encrypted root and encrypted swap, test one remote unlock through TCP 2222, then run the matching one-touch script with REQUIRE_LUKS_ROOT=1 before writing production secrets.",
                "Set up the Florida physical server before enabling real Double VPN. Until then, the app should continue falling back to regular VPN.",
                "Bind an active Technology Errors and Omissions policy before answering Yes to applications that require active Tech E&O coverage; keep the binder/declarations page with the insurance evidence package.",
                "Keep Wi-Fi + Mobile Data / Smart Boost parked for public users until tools/smart_boost_phone_benchmark.ps1 and tools/smart_boost_qualify.ps1 show a future native engine beating AWG by the configured margin on real phones.",
                "Build the next Smart Boost native packet engine before marketing it as Speedify-class: native TUN/socket loop, audited native crypto, packet batching, multi-core workers, per-path congestion control, loss/reorder handling, and proof that one-flow and multi-flow tests beat AWG.",
                "If Smart Boost resumes, run live tests after each engine change: Wi-Fi only, cellular only, Wi-Fi plus cellular, Wi-Fi-to-cellular handoff, cellular-to-Wi-Fi handoff, rapid reconnects, low-signal/locked-screen cases, and Speedtest-style single-flow checks.",
                "After confirming an admin public key is installed on the control hub, rerun the control script with HUB_SSH_PASSWORD_AUTH=0 to move the hub from password SSH plus Fail2Ban to key-only root SSH.",
                "Run Windows installer on a clean Windows VM for final TAP/Wintun driver behavior and power-management validation before public release.",
                "Perform Play Store pre-launch report, antivirus reputation submission, code signing, and privacy policy review before broad distribution.",
                "For post-quantum goals, prefer upstream-supported protocol/library updates after stable mobile and desktop clients exist. Do not bolt on custom crypto in the tunnel path.",
            ],
            STYLES["Body"],
        )
    )
    story.append(Spacer(1, 0.12 * inch))
    story.append(callout("Do not publish secrets", "This PDF intentionally omits live passwords, tokens, webhook secrets, private keys, and payment credentials. Keep the private repo and deployed root-owned env files protected.", AMBER))


def build():
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=letter,
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.65 * inch,
        bottomMargin=0.65 * inch,
        title="Win's VPN System Blueprint",
        author="Win's VPN",
        subject="Architecture and deployment blueprint",
    )
    story: list = []
    add_title(story)
    add_components(story)
    add_flows(story)
    add_security(story)
    add_deployment(story)
    add_dns(story)
    add_version_history(story)
    add_tests(story)
    add_risks(story)
    doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
    if OUTPUT != DATED_OUTPUT:
        shutil.copy2(OUTPUT, DATED_OUTPUT)
    print(str(OUTPUT))
    print(str(DATED_OUTPUT))


styles = getSampleStyleSheet()
STYLES = {
    "Title": ParagraphStyle(
        "Title",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=26,
        leading=31,
        textColor=INK,
        alignment=TA_CENTER,
        spaceAfter=8,
    ),
    "Subtitle": ParagraphStyle(
        "Subtitle",
        parent=styles["BodyText"],
        fontSize=11,
        leading=15,
        textColor=MUTED,
        alignment=TA_CENTER,
        spaceAfter=14,
    ),
    "Heading1": ParagraphStyle(
        "Heading1",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=16,
        leading=20,
        textColor=INK,
        spaceBefore=2,
        spaceAfter=10,
    ),
    "Heading2": ParagraphStyle(
        "Heading2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=BRAND_BLUE,
        spaceBefore=8,
        spaceAfter=4,
    ),
    "Body": ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12.4,
        textColor=INK,
        alignment=TA_LEFT,
        spaceAfter=3,
    ),
    "Callout": ParagraphStyle(
        "Callout",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12.5,
        textColor=INK,
    ),
    "TableCell": ParagraphStyle(
        "TableCell",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10.5,
        textColor=INK,
    ),
    "TableHeader": ParagraphStyle(
        "TableHeader",
        parent=styles["BodyText"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10.5,
        textColor=colors.white,
    ),
    "DiagramBox": ParagraphStyle(
        "DiagramBox",
        parent=styles["BodyText"],
        fontSize=8.3,
        leading=10.5,
        textColor=INK,
        alignment=TA_CENTER,
    ),
}


if __name__ == "__main__":
    os.chdir(ROOT)
    build()
