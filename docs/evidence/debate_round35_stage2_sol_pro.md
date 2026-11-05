# Stage 2 Cross-Rebuttal: stage2_sol_pro

# Podium 2 Stage 2 Cross-Rebuttal

## 1. Ratification decision

Apply an upload-only OkHttp client with IPv4-filtered DNS.

Keep the URL exactly:

```text
https://speed.cloudflare.com/__up
```

Retain 24 streams, a 2 ms stagger, 256 KiB writes, HTTP/1.1 chunked transfer, and a common measurement deadline. Use a 2,000 ms connect timeout and graceful response completion before cancellation.

Do not connect `HttpsURLConnection` to a literal IPv4 address.

Do not use process-wide Java networking properties.

Do not modify any download method, download target, tunnel receive loop, or download configuration.

A conditional IPv6 VPN configuration is the correct permanent repair, but it must gate every IPv6 address, route, and DNS entry. Omitting only `::/0` is not sufficient to prove either blocking or leak prevention.

## 2. Facts established by the docket

The failure is not an upload capacity failure.

The direct IPv4 curl test returned HTTP 200 through Winn Protocol v3. That establishes all of the following for that test path:

1. The tunnel carried outbound upload bytes.
2. The gateway forwarded IPv4 upload traffic.
3. Cloudflare accepted chunked upload traffic.
4. The server response returned through the tunnel.

The observed timeout also matches the control-flow failure:

\[
2 \times 5{,}000\text{ ms IPv6 stalls} + 6{,}000\text{ ms body interval}
= 16{,}000\text{ ms}
\]

That leaves no scheduling, TLS, response, or shutdown margin inside a 16 second parent deadline.

One numerical inconsistency must be recorded. A 10 MB transfer completed in 389 ms implies:

\[
\frac{10{,}000{,}000 \times 8}{0.389 \times 10^6}
= 205.66\text{ Mbps}
\]

If 10 MiB was intended:

\[
\frac{10{,}485{,}760 \times 8}{0.389 \times 10^6}
= 215.65\text{ Mbps}
\]

Neither result equals the separately stated 21.7 MB/s, which is 173.6 Mbps. I therefore use
