# Snap Strict-Confinement Design and Interface Request

Status: OWNER APPROVED 2026-08-31; COUNSEL REVIEW PENDING. This marking does not state or imply that counsel reviewed this request.

Prepared submission text only. No Snap Store action, upload, interface request, or publication is authorized.

## Approved Design

The approved target design, which is not the current packaging, uses strict confinement with two applications in one snap:

- An unprivileged Flutter GUI uses the `desktop`, `desktop-legacy`, `wayland`, `x11`, `opengl`, `network`, and `password-manager-service` snapd interfaces only where the final build proves they are needed. `display` and `network-client` are not snapd interface names and must not appear in the recipe or Store request.
- A root daemon owns VPN interfaces, routes, DNS, and firewall state. It exposes a protected local IPC socket with peer authentication and a closed, versioned, typed schema. It accepts only bounded connect, disconnect, status, and cleanup requests. It never accepts arbitrary shell commands, executable paths, filesystem paths, environment variables, or raw firewall scripts.
- The daemon requests `network-control`, `network-observe`, and `firewall-control`. It requests `network-bind` only if the final IPC implementation binds a network socket rather than using a Unix-domain socket.
- Disconnect, daemon failure, snap refresh, and removal paths must clean up routes, DNS, firewall rules, interfaces, and local IPC state.

Classic confinement is not approved. As of 2026-08-31 the committed recipe generator `linux/packaging/snap/manifest_artifact.py` still emits `confinement: classic` with a single `wins-vpn` app and no daemon, and its own contract validator requires `confinement: classic` and rejects a `network-control` plug, so that generator and its tests must be replaced before this design can be built at all. The current classic/native packaging path must not be represented as this strict design until the daemon boundary exists and passes tests.

## Store Interface and Auto-Connect Request Text

Use the following text in the Snap Store interface request for the exact reviewed snap. Do not send it unless every claim in it is true of that snap and the evidence listed at the end of this document exists, because it asserts peer authentication, a closed message schema, and route, DNS, firewall, and interface cleanup that are not implemented today.

> Win's VPN is a user-facing VPN client. Its strictly confined, unprivileged Flutter GUI asks a root daemon in the same snap to create and remove VPN interfaces, configure only the routes and DNS state required for the selected tunnel, observe interface state, and apply or remove leak-prevention firewall rules. These are the snap's core advertised functions and cannot work without `network-control`, `network-observe`, and `firewall-control`.
>
> The daemon communicates over a protected local IPC endpoint. It authenticates the local peer and accepts a closed, versioned set of bounded VPN lifecycle messages. It does not execute caller-supplied commands, accept arbitrary paths, expose a general-purpose root API, or grant the GUI direct privileged network access. Failure and disconnect paths restore routes, DNS, firewall, and interface state.
>
> We request review and auto-connection of `network-control`, `network-observe`, and `firewall-control` because requiring manual connections would leave the installed VPN unable to perform its primary function. We do not request `network-bind` unless the final reviewed IPC implementation needs to bind a network socket. We will provide the exact snap revision, plugs, slots, daemon command, IPC schema, AppArmor denials, and cleanup test evidence with the request.

## If Auto-Connect Is Not Granted

Do not claim the VPN works immediately after installation. Once a strict-confined snap exists and manual connection is actually required, put these commands in the listing and first-run instructions, using the final snap name. They must not appear in any published listing, README, or install guide while no strict-confined snap exists:

```sh
sudo snap connect wins-vpn:network-control
sudo snap connect wins-vpn:network-observe
sudo snap connect wins-vpn:firewall-control
```

Add `sudo snap connect wins-vpn:network-bind` only if the reviewed snap declares that plug and the IPC design actually requires it.

## Evidence Required Before a Later Request

- Exact strict-confined `snapcraft.yaml` and built snap revision.
- AppArmor and seccomp review with no broad bypass.
- IPC peer-authentication and hostile-message tests.
- Route, DNS, firewall, and interface cleanup tests for crash, refresh, removal, and interrupted connect.
- Proof that the GUI cannot invoke the privileged operations directly.
- Manual-connect and disconnected-interface user experience.

The interface request remains prepared but unsubmitted.
