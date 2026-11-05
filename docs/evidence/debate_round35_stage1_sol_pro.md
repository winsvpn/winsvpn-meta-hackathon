# Stage 1 Submission: stage1_sol_pro

# Stage 1 Proposal

## 1. Decision

Apply an IPv4-only DNS policy to the upload client. Do not modify the frozen download client or download datapath.

Keep `https://speed.cloudflare.com/__up` as the URL. Do not replace the hostname with an IPv4 literal because the TLS SNI and certificate identity must remain `speed.cloudflare.com`.

Do not use either global property:

```kotlin
System.setProperty("java.net.preferIPv4Addresses", "true")
System.setProperty("java.net.preferIPv4Stack", "true")
```

The first key is not a standard Java networking property. The second is process-wide, so it can alter address selection outside the upload test, including frozen code. A dedicated OkHttp `Dns` implementation gives a directly testable invariant: every address returned to the upload connection layer is an `Inet4Address`.

Do not remove `::/0` from `VpnTunnelService.kt` during this round. That is a VPN routing configuration change, while the IPv4-only upload client fixes the demonstrated failure without touching the download path.

## 2. Mathematical Basis

The live single-stream upload produced:

\[
21.7\ \text{MB/s} \times 8 = 173.6\ \text{Mbps}
\]

The minimum ideal stream count for 1,000 Mbps is:

\[
N = \left\lceil \frac{1000}{173.6} \right\rceil = 6
\]

With 24 streams, the required average per stream is:

\[
\frac{1000}{24} = 41.67\ \text{Mbps}
\]

Converted to bytes per second:

\[
\frac{41.67}{8} = 5.21\ \text{MB/s}
\]

Each stream therefore needs only:

\[
\frac{41.67}{173.6} = 24.0\%
\]

of the measured single-stream rate.

The physical upload ceiling is
