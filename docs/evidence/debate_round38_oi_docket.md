ROUND 38 OPEN ITEMS DOCKET (Arbiter-compiled; post-Turn-1 measurements attached.
All measurements below were run by the Arbiter from the physical S26 Ultra
through the production Canada tunnel, and from <CANADA_MGMT_SSH_ALIAS>, after your Turn 1
verdicts. Vote AGREE or DISAGREE: <falsifiable reason> per item.)

MEASUREMENT EVIDENCE M-1 (IPv6, refutes opus H1): curl -6 to
speed.cloudflare.com from the phone through the tunnel fails with
'Could not resolve host' (exit 6): the tunnel DNS serves no AAAA for the
target, so the Global family cannot ride IPv6 at all. Every upload is IPv4.
The IPv6 penalty question in the dynamic MTU is therefore dormant on this
path (kept as correctness for other networks).

MEASUREMENT EVIDENCE M-2 (per-connection endpoint limit): six sequential
single-stream curl -T /dev/zero uploads from the phone to
https://speed.cloudflare.com/__up (same resolved IP 172.66.0.218 every time)
measured 19.0 to 25.3 MB/s (about 152 to 202 Mbps). From <CANADA_MGMT_SSH_ALIAS> DIRECT
(no tunnel), the identical single-stream upload measured 39.6 MB/s
(about 316 Mbps). The endpoint itself caps a single connection near
200-316 Mbps regardless of tunnel.

MEASUREMENT EVIDENCE M-3 (mechanism resolution): in lib/main.dart the
speedtest downloads from BOTH target families in order, keeps the best
download, and derives the label AND the upload URL from that winner
(_uploadUrlForDownloadUrl maps ONLY speed.cloudflare.com to /__up; every
other winner, including cachefly, falls back to the same /__up). Therefore
the family label is CHOSEN BY THE RUN'S OWN DOWNLOAD SPEED, and the upload
number follows the same run-time Cloudflare path quality. The perfect
label-number correlation is a selection effect, not a tunnel-state change
and not run-order. This also refutes solpro's run-order alternative: the
order is deterministic per node but the label is computed from the measured
download, not from position.

RESOLVED ITEMS:
RV-A (endpoint finding): the interpretation is upgraded from 'endpoint
selection by the app' to 'run-time Cloudflare service quality, with the
label as a within-run proxy'. Both disagreeing seats' mechanisms (colo
capacity, run-order) are superseded by M-2 + M-3. Vote: AGREE the resolution
or DISAGREE with a discriminating measurement.
RV-B (product fix design): all three seats converged on 'measure the
tunnel, gate the result, disclose the target' (opus D, solpro D-variant,
agy C-as-cheap-stopgap). The ratified design:
  1. Primary speedtest target: an authenticated upload/download ingest on
     the EXIT NODE itself (gateway-side endpoint), which measures the actual
     tunnel and removes anycast variance and the third-party connection from
     the exit IP (a privacy improvement for the high-threat population).
  2. Validity gate: a run counts only with a 2xx response, at least ~25 MiB
     transferred or 5 seconds of steady state, slow-start excluded; failed
     runs are reported as failed, never as a number.
  3. Third-party families (cloudflare, cachefly, regional) demoted to
     fallback, best-of-N within one family, never mixed into one headline,
     with the target disclosed beside the number.
  4. Per-family history retained for diagnostics (solpro's point 5).
Vote: AGREE the four-point design or DISAGREE with an amendment. Note the
gateway ingest endpoint is new server-side surface: it must be authenticated
and rate-limited like the rest of the control plane; implementation lands
after this vote in Round 39 with the gateway install script.
RV-C (buffer + warm-up state): the 4 MiB experiment and warm-up are reverted;
carrier buffers are back on the 8 MiB default both dial paths; Go suites
pass; MainActivity carries the full measured table and the corrected
mechanism comment. Vote: AGREE the revert or DISAGREE.
RV-D (wording corrections accepted): solpro's data-qualification points are
accepted (one Global run was null, not a number; the 32-parallel curl proof
lacks logged bytes; 'every run' claims are narrowed to 'every numeric run').
Future Arbiter measurement claims will carry per-run tables. Vote:
AGREE/DISAGREE.
RV-E (RV-2 restatement for the User, non-voting): opus + solpro recommend
(b) local-only chat route; agy recommends (c). The fork stays with the User.
