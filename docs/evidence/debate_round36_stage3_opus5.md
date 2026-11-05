# Round 36 stage3: claude-opus5

OI-1: AGREE
OI-2: AGREE
OI-3: AGREE
OI-4: AGREE
OI-5: AGREE
OI-6: AGREE
OI-7: AGREE
OI-8: AGREE
OI-9: AGREE
OI-10: AGREE
OI-11: AGREE
OI-12: AGREE
OI-13: AGREE
OI-14: AGREE
OI-15: AGREE
OI-16: AGREE
OI-17: AGREE
OI-18: AGREE
OI-19: AGREE
OI-20: AGREE
OI-21: AGREE
OI-22: AGREE
OI-23: AGREE
OI-24: AGREE
OI-25: AGREE
OI-26: AGREE
OI-27: AGREE
OI-28: AGREE
OI-29: AGREE
OI-30: AGREE
OI-31: AGREE
OI-32: AGREE
OI-33: AGREE
OI-34: DISAGREE: the pinned digest is the only runtime binding between the bytes served to a downloader and the reviewed release, so "log and serve anyway" converts the single detection point for substituted or truncated installer bytes into a log line no user sees. The stated availability defect has a different cause: the deploy step updates the asset without updating the pin. Fix that ordering (write the pin in the same deploy transaction that publishes the asset, and fail the deploy if they disagree) and a runtime mismatch can then only mean unreviewed bytes, which must stay fail-closed. Falsifiable test: publish an asset whose bytes differ from the committed pin and confirm the proposed behavior returns 200 with the modified payload.
OI-35: DISAGREE: the quoted loop tests availability with `command -v "$pkg"` and then installs the same string, so substituting the package name docker.io makes `command -v docker.io` fail on every run and the loop reinstalls unconditionally, while a host that already has a working engine is never detected. The item is only correct once the command name and the package name are separate fields (for example command docker maps to package docker.io, command git maps to package git). It also needs a stated position on engine ownership, because satisfying the docker check suppresses btcpayserver-docker's own engine and Compose v2 provisioning path. Falsifiable test: run `command -v docker.io` on a Debian host with docker.io installed and observe exit status 1.
OI-36: AGREE
OI-37: AGREE
OI-38: AGREE
OI-39: AGREE
OI-40: AGREE
OI-41: AGREE
OI-42: AGREE
OI-43: AGREE
OI-44: AGREE
OI-45: AGREE
OI-46: AGREE
OI-47: AGREE
OI-48: AGREE
OI-49: AGREE
OI-50: AGREE

RATIFICATION STATEMENT

Unresolved after this vote:

- **OI-34**: settled by one of two artifacts. Either a deploy-pipeline excerpt showing the asset upload and the pin update committed in a single atomic step with a failing gate on divergence (in which case fail-closed stays and the item is withdrawn), or a measured case where a correct, synchronized deploy still produces a runtime hash mismatch (in which case the check is unsound and my objection falls).
- **OI-35**: settled by the current text of the package loop in server/spain_crypto_payments_setup.sh showing whether command names and package names are separate fields, plus the btcpayserver-docker setup path at the reviewed commit showing whether it provisions the engine and Compose v2 itself when docker is already present.

Selections recorded, not disputes:

- **OI-9**: my AGREE selects queries-first with the Play Permissions Declaration Form only as a demonstrated fallback, not deletion without a working picker.
- **OI-22**: my AGREE selects the explicit-declaration option (keep 0 out of the silent default, require a declared value with `:?`, echo the resolved mode in preflight), not the flip to 1.

Items that close in specification only, with residual operational exposure the certificate should carry as exceptions: OI-3 (the on-host copy stays unreconciled until the capture and diff are actually performed), OI-38 (deployed gateways stay nonconforming until the key rotation ceremony), OI-50 (reachability of spain-mgmt is an operator action, and the CI check cannot pass until it is done).
