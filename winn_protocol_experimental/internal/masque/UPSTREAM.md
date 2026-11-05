# MASQUE dependency provenance

This directory is an internal, client-focused fork of
`github.com/quic-go/masque-go` version `v0.4.0`, source commit
`03179c5407a332f0509fa8e165244e6410ac165a`. The annotated `v0.4.0` tag
object is `0a4c589699c80369a1c4548d81d06fa9cf864a65`.

The selected client, request, transport, and request-parsing source files and
`UPSTREAM_README.md` were copied without changes before the Winn-specific
repairs. Winn does not compile the upstream general-purpose `Proxy` because its
H3 server has a fixed-target, authenticated relay implementation. The original
MIT license is preserved in `LICENSE`.

Winn carries the package inside the main module so that its reproducible source
manifest covers every compiled fork source file. The local changes:

- never receive from the nil `C` field of a timer created by
  `time.AfterFunc`;
- replace a canceled read context when an expired deadline is cleared or
  extended;
- generation-fence timer callbacks so a stale callback cannot cancel a newer
  deadline; and
- make connection close ownership idempotent, reject post-close deadline
  changes, and retire deadline state under its mutex; and
- observe close errors in `transport.go` that upstream discarded.

`conn_deadline_test.go` contains regression tests for the deadlock, context
renewal, and stale-callback cases.
