# Windows Winn Protocol v3 — elevated verification runbook

This is for the four things that need administrator rights and could not be
checked by `tools/verify_windows_winn_seam.cpp` (which needs none, on
purpose, so it can run on any Windows machine). It is written for you to run
personally on your own Windows laptop. You do not need to read or debug the
scripts to use this — just run the one command below and paste back what it
prints.

Nothing in this asks for a password, key, token, or any credential. If
anything ever does, stop and don't enter it.

## The one command

Open an **Administrator** PowerShell:

- Start menu → type `PowerShell` (or `Terminal`) → right-click → **Run as
  administrator**.

Then, at the repository root:

```
powershell -ExecutionPolicy Bypass -File tools\verify_windows_winn_elevated.ps1
```

That builds and runs it in one step. First time through it will take a
minute or two (it compiles three files with MSVC); after that it's seconds.

If you still have `winn-datapath.exe` from your `verify_windows_winn_seam.ps1`
run, pass it too — this additionally runs the engine-kill test:

```
powershell -ExecutionPolicy Bypass -File tools\verify_windows_winn_elevated.ps1 `
    -Engine C:\path\to\winn-datapath.exe
```

Don't have that binary anymore? Stage it from a signed Winn release on any
machine with `/usr/bin/python3` (does not need to be the Windows box):

```
./tools/build_windows_winn_engine.sh --release /path/to/signed-release
```

That verifies the release signature and digests, then writes
`build/windows/winn3/x64/winn-datapath.exe` (and the arm64 one beside it).
For a dev engine from a clean git checkout instead:

```
./tools/build_winn_protocol_engine.sh datapath-windows-amd64 winn-datapath.exe
```

then copy `winn-datapath.exe` to the Windows box and point `-Engine` at it.

## What it checks, in two tiers

The program prints which tier it's running as it goes. You don't need to
track this yourself — just read the section headers (`== TIER A: ... ==`,
`== TIER B: ... ==`) in the output.

**TIER A — needs administrator rights only, no gateway. Runs every time.**

1. **The pinned `/32` survives a competing wider route.** Pins a synthetic
   `/32` host route on your real physical network adapter (the same adapter
   your normal internet traffic uses), adds a second, wider competing route,
   and proves Windows still routes the pinned address through the `/32`
   rather than the wider one. This is the core mechanism the app depends on
   to keep the Winn/AmneziaWG gateway connection on your physical NIC once
   the VPN's own routes are installed.
2. **Killing the real engine mid-session is noticed** (only if `-Engine` was
   given). Starts the real `winn-datapath.exe`, kills it without going
   through the normal shutdown path, and proves the host notices within 10
   seconds rather than believing a dead engine is still carrying traffic.

**TIER B — needs administrator rights AND a real AmneziaWG gateway AND a
real winn/3 server config, already connected through the app.** This program
cannot fake that state — only a real gateway and a real server proves it —
so this tier is a **read-only status probe**: it asks the Win's VPN tunnel
service what it currently sees, using the exact same request the app itself
uses. It runs automatically every time too, but until you have a real
winn/3 tunnel connected, it will correctly report **skip**, not fail. See
"Tier B: the part that needs a real connection" below.

## What a pass looks like

Tier A, without `-Engine`, ends with a block like this (abbreviated):

```
ok   this PowerShell window is running as Administrator
ok   running elevated

== TIER A: a pinned /32 host route survives a competing wider route ==
ok   found a physical IPv4 default route to pin the synthetic carrier against
ok   pinned a synthetic carrier /32 on the physical LUID, ...
ok   GetBestRoute2 resolves the pin BEFORE any competing route exists (baseline...)
ok   found the loopback pseudo-interface to carry the harmless stand-in wide route
ok   add a wide /24 route covering the same address, ...
ok   THE CORE CLAIM (item 1): GetBestRoute2 still resolves the physical /32 ...
ok   creating the IDENTICAL /32 a second time is refused with ERROR_OBJECT_ALREADY_EXISTS, ...
ok   the refused duplicate does not believe it owns anything, ...
ok   the original pin is untouched after the refused duplicate attempt
ok   cleanup: the wide competing route was removed
ok   cleanup: the synthetic carrier /32 was removed
ok   cleanup PROOF: a fresh route-table scan finds neither synthetic route ... anywhere
ok   cleanup ON A FORCED FAILURE PATH: ...

  skip TIER A engine-kill test -- no <config.ini> <winn-datapath.exe> given ...

== TIER B: live status probe (read-only; needs a REAL winn/3 tunnel already ==
  skip TIER B status probe -- could not reach the WinsVpnTunnelManager service: ...

15/15 checks passed, 0 failed, 2 skipped
```

The exact numbers don't matter; what matters is **`0 failed`** and that every
line says `ok` or `skip`, never `FAIL`. `skip` lines are expected and are not
a problem — they mean "this needs something you haven't provided yet"
(the engine binary, or a live connection), never "something is broken."

The process exits `0` on a clean pass, `1` if anything failed, `2` if it
couldn't even start (not elevated, bad arguments, or a build failure).

## If something says `FAIL`

The program is written to fail with a specific, actionable reason on the
same line — you shouldn't need to guess. A few you might see:

| If you see... | It means | What to do |
|---|---|---|
| `FAIL: this process is not running elevated` | You didn't open PowerShell as Administrator | Close it, reopen via **Run as administrator**, `cd` back into the repo, re-run |
| `vswhere.exe not found` | No Visual Studio installer detected | Install "Visual Studio Build Tools" with the "Desktop development with C++" workload, or pass `-VsInstallPath` |
| `No active physical network connection with a default route was found` | You're offline, or a VPN is currently connected and hiding the physical route | Connect to Wi-Fi/Ethernet, disconnect any active VPN, re-run |
| `found the loopback pseudo-interface...` shows `FAIL` | Unexpected — every Windows install has a loopback interface | Paste this back verbatim; this points at something unusual about the machine |
| `expected exactly one running process matching the engine path` | Another `winn-datapath.exe` (same exact path) is already running, or it isn't running at all | Close any other instance of it and re-run |
| The build itself fails (compiler/linker errors before anything runs) | Real `cl.exe`/`link.exe` — the toolchain this actually ships against — has never touched this file before your run (see "Honesty about what this is," below) | Paste the **compiler output** back verbatim — that's more useful to fix than a description |

For anything not in this table: **paste the whole output back verbatim**,
starting from `ok   this PowerShell window is running as Administrator`
through the final `N/N checks passed...` line. Don't summarize or retype it.

## Tier B: the part that needs a real connection

Tier A can't reach items 2 and 3, or the full version of item 4, because
they only mean something against a real AmneziaWG gateway and a real winn/3
server — faking that would prove nothing. This is the one manual step:

1. In the Win's VPN app, connect to a server that actually negotiates
   **Winn Protocol v3** (a `[winn] enabled = true` config from the real
   server, not a hand-written one).
2. While it's still connected, in the **same or another Administrator**
   PowerShell, re-run:
   ```
   powershell -ExecutionPolicy Bypass -File tools\verify_windows_winn_elevated.ps1
   ```
   (No `-Engine` needed for this part — the status probe only talks to the
   already-running privileged service, it doesn't start anything itself.)
3. Look at the `== TIER B ==` section. Once connected, instead of `skip` you
   should see:
   ```
   == TIER B: live status probe (read-only; needs a REAL winn/3 tunnel already ==
        raw kStatus response: running;...;winn=1;winn_engine=1;winn_transport=1
   ok   TIER B (item 4, in full): the privileged service reports winn_engine=1 ...
   ok   TIER B (item 3, second half): the privileged service reports winn_transport=1 ...
   ```
   `winn=1` means a winn/3 tunnel is what's active. `winn_engine=1` means the
   engine process and its channel are both alive **inside the real
   privileged service** (this is item 4, done completely — Tier A only ever
   proved this in a standalone test process). `winn_transport=1` means
   `transport_observed_both_ways` has latched, which is the second half of
   item 3's promotion gate.
4. **What this does not directly show, and how to see it anyway:**
   - **Item 1 in the real session** (not the synthetic Tier A version):
     while still connected, run `route print -4` in an Administrator
     Command Prompt or `Get-NetRoute -AddressFamily IPv4` in PowerShell.
     You should see a host route (`/32`) to your server's real IP address
     with a **specific** metric/interface (your physical adapter), alongside
     the VPN's own `0.0.0.0/0`-covering routes on the tunnel adapter. If the
     server's `/32` is missing, or the tunnel adapter's routes look like
     they're the only match for it, paste back the output of that command.
   - **Item 2, the peer endpoint rewrite**: the surest sign it's working is
     simply that traffic flows at all with `winn_transport=1` true — if the
     AmneziaWG runtime had NOT loaded `127.0.0.1:<seam>`, the engine would
     never see any datagrams to classify and `winn_transport` would never
     reach `1`. `winn_transport=1` is downstream proof of item 2, not a
     direct read of the AmneziaWG UAPI (this program deliberately never
     reads or prints that raw UAPI response, key material lives there).
   - **Item 3's ordering** (AWG convergence before Winn transport
     convergence, both before any `/0` route): this is enforced by the
     shipping code's call order in `InstallPrivilegedTunnel`
     (`windows/runner/windows_tunnel_backend.cpp`) and is not independently
     re-checked by this probe. `winn_transport=1` alongside working traffic
     is the practical signal that both gates passed; if you want the
     ordering itself reviewed, that's a source read
     (`WaitForAwgConvergence` then `WaitForWinnTransportConvergence` then
     `InstallWindowsTunnelRoutes`, in that order), not something a runtime
     probe can show you differently.
5. Disconnect normally through the app when you're done. This probe changes
   nothing, so there is nothing it needs to undo.

## What to paste back

For a full run: everything from `ok   this PowerShell window is running as
Administrator` to the final `N/N checks passed, N failed, N skipped` line,
for **both** the Tier-A-only run and (separately, once you've connected a
real winn/3 tunnel) the Tier B run. If the build itself failed, paste the
compiler/linker output instead — nothing ran yet at that point.

## Honesty about what this is

This harness was written on a Mac, which has no MSVC, no Windows SDK, and no
PowerShell — with one exception that appeared partway through writing it, so
the accounting differs by file:

- **`verify_windows_winn_elevated.cpp`**: this Mac gained a real
  cross-compilation toolchain (Apple clang in `--driver-mode=cl` mode
  against a genuine, unmodified copy of Microsoft's Windows SDK + MSVC CRT
  headers and import libraries). Using it, this file — and the two real,
  unmodified files it depends on, `windows/runner/windows_winn_engine.cpp`
  and `windows/runner/windows_tunnel_service_client.cpp` — **were actually
  compiled to object files here**, individually, under this project's own
  `/W4 /WX /EHsc /std:c++17` flags, against the real `iphlpapi.h` /
  `winsock2.h` / `tlhelp32.h` and the real `iphlpapi.lib`, for both
  `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`. All six compiles
  exited 0 with zero warnings, and `file` independently confirmed genuine
  "Intel amd64 COFF" / "Aarch64 COFF" object files. That is real, verified
  evidence these files are well-formed against the actual Microsoft headers
  for both architectures — not just internally self-consistent against a
  hand-written approximation of them (which is all an earlier pass, using
  stub headers, could show).
  **What that compile step could not reach, and still has not:** no
  COFF/PE-capable linker (`lld-link` or otherwise) exists in this
  environment — checked directly, not assumed — so these objects were never
  linked into a runnable `.exe` here, and a link-time problem (an
  unresolved symbol, an ODR mismatch across the three files) is exactly the
  class of bug this step cannot catch. clang-cl is also a close, not
  byte-identical, approximation of real `cl.exe`; its warning behavior can
  differ in edge cases. And naturally: nothing here can hold administrator
  rights or touch a routing table, so zero Tier A/B checks have executed,
  anywhere, by anyone, until you run them.
- **`verify_windows_winn_elevated.ps1`** could not be checked at all — this
  Mac has no PowerShell interpreter, not even to parse it. It was written to
  mirror `tools/verify_windows_winn_seam.ps1`'s already-proven structure as
  closely as possible, with one constructor call (`::new()`) deliberately
  matched to an idiom already used elsewhere in this repo's own scripts
  (`tools/windows_non_elevated_uapi_probe.ps1`) rather than a pattern only
  reasoned about from memory.

**Your run is still the first time either file meets the toolchain it
actually ships against** — real `cl.exe` and `link.exe`, not clang-cl with
no linker — **the first parse of the `.ps1` of any kind, and the first
execution of anything, full stop.** That is exactly why the build-failure
path above says to paste back compiler output, not just a "pass/fail" — if
the very first thing that happens on real hardware is a build error, that
is expected to be plausible, not a sign anything is wrong with you or your
machine.

## Safety, in case you want to double check it yourself

- The route test only ever touches addresses in `203.0.113.0/24`
  (RFC 5737 TEST-NET-3, reserved for documentation, never real traffic). It
  never creates, modifies, or even briefly touches `0.0.0.0/0` or any route
  that could affect your real internet traffic.
- Every route it creates is deleted before the program exits, including on
  a failure partway through (`ok   cleanup PROOF: ...` and `ok   cleanup ON
  A FORCED FAILURE PATH: ...` in the output are the program independently
  re-checking its own cleanup, not just trusting it happened).
- If you `Ctrl+C` the program mid-run instead of letting it finish, a
  `203.0.113.113/32` or `203.0.113.0/24` route could in principle be left
  behind (RAII cleanup runs on normal return, not on a hard interrupt). If
  that ever happens: `route delete 203.0.113.113` and
  `route delete 203.0.113.0` from an Administrator prompt removes them; they
  cannot affect real traffic even if left in place, since nothing on the
  real internet lives in that block.
- Nothing is written outside the temporary `-WorkDir` (a fresh
  `%TEMP%\winnelevated-<random>` folder each run) and the routing table
  entries described above. No file in this repository is modified by
  running it.
- No credential, key, or token is ever read, requested, or printed. The
  Tier B status string is exactly what the shipping app itself already
  reads on every status poll — see the header comment in
  `tools/verify_windows_winn_elevated.cpp` for why that string is
  structurally incapable of containing key material.

## Files

- `tools/verify_windows_winn_elevated.cpp` — the program. Long header
  comment at the top explains every design decision, including the one
  place it deliberately differs from what production code does (see "why a
  `/24` on loopback, never a real `/0`" and "why this calls
  `CreateIpForwardEntry2`/`GetBestRoute2` directly" in that comment).
- `tools/verify_windows_winn_elevated.ps1` — builds and runs it. Same MSVC
  discovery logic as `tools/verify_windows_winn_seam.ps1`.
- `tools/verify_windows_winn_seam.cpp` / `.ps1` — the unprivileged
  companion (already verified 46/46 on real hardware); read its header for
  what it covers instead of this file.
