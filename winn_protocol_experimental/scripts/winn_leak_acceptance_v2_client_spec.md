# Winn leak acceptance v2 disposable client specification

This VM is an acceptance instrument, not a production Winn node. It must be
new, have no production credentials or workloads, and be destroyed after the
six-scenario evidence bundle and billing checks are complete. AICORE, either
existing gateway, and developer laptops are explicitly excluded.

## Required VM

- Ubuntu Server 24.04 LTS, x86_64, KVM virtualization.
- 2 dedicated or shared vCPU, 4 GiB RAM, and 40–60 GB SSD. No GPU is needed:
  packet forwarding, Chromium ICE collection, and the acceptance driver are
  CPU/network workloads.
- One globally routed IPv4 address and one globally routed IPv6 address.
  Outbound UDP and TCP must not be provider-NATed or filtered.
- Hostname exactly `winn-leak-client-v2`.
- No provider snapshot containing Winn production data. Destroy the instance
  rather than repurposing it after acceptance.

## Host and resolver requirements

- Real systemd, nftables, iproute2, `systemd-resolved`, tcpdump, jq, ca-certificates,
  and the DNS tools used for manual cross-checks.
- `/etc/resolv.conf` must be the normal systemd-resolved stub symlink, and
  `resolvectl status` must report the real client links.
- Google Chrome 150 or a later pinned stable build at a recorded canonical path.
  User namespaces and the Chromium sandbox must work; `--no-sandbox` is
  forbidden.
- A dedicated non-root `winn-webrtc` account with no sudo access, login shell,
  home data, or supplementary privileged groups.
- The exact Linux-amd64 acceptance binaries, hooks, source manifests, and AWG
  binaries under `/opt/winn-leak-v2` and `/opt/winn-lab/bin`. The latter and
  `winn-webrtc-v2` are mode 0755 so the dedicated non-root browser account can
  execute and hash that helper. Root-only client binaries remain mode 0700.
- Root-owned mode-0600 configs and key files under `/etc/winn-leak-v2`. The
  file `/etc/winn-leak-v2/DISPOSABLE_ACCEPTANCE_CLIENT` is created only after
  the image, hostname, addresses, and firewall have been checked.

## Provider firewall

Inbound to the client:

- TCP 22 only from the operator/AICORE public IP, using key authentication.
- No inbound VPN, HTTP, DNS, STUN, or management ports.

Outbound required for the test:

- UDP 42844 to `<NODE_EXIT_CHI>` for the IPv4 AWG lane.
- UDP 42846 to
  `<NODE_EXIT_CHI_V6>` for the IPv6 AWG lane.
- TCP 46380 and UDP 46378 to `<NODE_CONTROL_ATL>`.
- TCP 46381 and UDP 46379 to
  `<NODE_CONTROL_ATL_V6>`.
- TCP 22 to both providers over the same address family and physical underlay
  being tested. Pin both the IPv4 and IPv6 ED25519 host-key identities. The
  acceptance policy allows only those provider IPs on TCP 22 inside its own
  fail-closed output chain; no general underlay management bypass is allowed.
- Package-mirror and time-sync access only during image preparation.

The controlled DNS (`10.251.4.1:53` and `[fd42:251:6::1]:53`) and UDP canary
(`10.251.4.1:7007` and `[fd42:251:6::1]:7007`) are inner-tunnel destinations
and must never be opened on the provider firewall.

Record all client physical IPv4, private RFC1918, IPv6 link-local, ULA/GUA, and
provider metadata addresses before the run. Those values populate the
orchestrator's `forbidden_addresses`; they are never guessed.

## Secure peer preparation

Run `prepare-client` on this VM, not on the operator Mac. It generates each
client private key and PSK locally. Only the public key and the PSK file are
copied to CHI using the explicitly pinned SSH identity and ED25519 host key.
Secret values never appear in command arguments, logs, JSON, or terminal
output. CHI's public keys are copied back.

The deployment wrapper records `GATEWAY_PEER_MODE=acceptance` and refuses a
run without the matching private material marker. After retrieving evidence,
run `cleanup-client`; it restores CHI's non-traffic fixture peer and removes
the exact client and provider acceptance keys. Then remove the provider
fixture and destroy the VM.

## Mandatory pre-run gates

1. Capture provider console instance ID, region, hourly price, public
   addresses, and firewall attachment.
2. Confirm the client has no production role and no access to production
   databases or signing keys.
3. Confirm root SSH key-only access and record the SSH public-key fingerprint.
4. Confirm real IPv4 and IPv6 Internet reachability before installing the
   fail-closed test policy.
5. Confirm Chrome launches sandboxed as `winn-webrtc`.
6. Capture baseline addresses, routes, policy rules, resolver status,
   nftables, sockets, and relevant sysctls.
7. Run the exact v4/v6 × graceful/outage/crash matrix once. Do not call a
   fixture lifecycle smoke an acceptance pass.
8. Retrieve and hash all evidence, run every residue action, clean matched
   peer material, remove the provider fixture, and verify both provider
   consoles have no leftover billable acceptance resource.
