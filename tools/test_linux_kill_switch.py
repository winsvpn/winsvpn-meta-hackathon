#!/usr/bin/env python3
"""Regression checks for the fail-closed Linux physical-interface kill switch."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "linux/runner/linux_tunnel_backend.cc"


def require(text: str, literal: str, message: str) -> None:
    if literal not in text:
        raise AssertionError(message)


def require_order(text: str, *literals: str) -> None:
    cursor = -1
    for literal in literals:
        position = text.find(literal, cursor + 1)
        if position < 0:
            raise AssertionError(f"Missing ordered Linux kill-switch token: {literal}")
        if position <= cursor:
            raise AssertionError(f"Linux kill-switch order is unsafe near: {literal}")
        cursor = position


def modeled_verdict(
    *,
    destination: str,
    output_interface: str,
    packet_mark: int,
    routing_mark: int,
    local_destination: bool,
    allowed_ips: tuple[str, ...],
) -> str:
    """Model the deliberately small WINSVPN_KS chain encoded in the source."""

    if output_interface == "winsvpn":
        return "allow_tunnel"
    if packet_mark == routing_mark:
        return "allow_outer_or_explicit_bypass"
    address = ipaddress.ip_address(destination)
    for cidr in allowed_ips:
        network = ipaddress.ip_network(cidr)
        if address.version == network.version and address in network:
            return "allow_local" if local_destination else "reject_bound_escape"
    return "allow_destination_exclusion"


def modeled_chain_is_ours(*, rules: tuple[str, ...], tag: str) -> bool:
    """Model winsvpn_chain_is_ours: every rule in the chain must carry our tag.

    Ownership is decided by what the chain contains, not by a marker file in
    /run. /run is tmpfs, so a marker cannot survive the reboot that a host
    running iptables-persistent uses to restore the chain itself; a comment
    inside the rule can, because iptables-save/restore preserves it verbatim.
    """

    if not rules:
        # No rules means no policy to destroy, and the kernel refuses to delete
        # a chain anything still jumps to.
        return True
    return all(f"--comment {tag}" in rule for rule in rules)


def main() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    match = re.search(r'return R"WINS\((.*?)\)WINS";', source, re.DOTALL)
    if match is None:
        raise AssertionError("Unable to extract the Linux privileged helper script")
    helper = match.group(1)

    for literal, explanation in (
        ("cleanup_kill_switch()", "own a complete rollback path"),
        ("configure_kill_switch()", "install the protection after AWG starts"),
        ("KS_CHAIN=WINSVPN_KS", "use a dedicated chain"),
        ("kill-switch-active", "persist root-owned lifecycle ownership"),
        ("refused to modify an unowned Linux firewall chain", "fail closed on collisions"),
        ('section == "peer"', "read only the peer route set"),
        ('key != "allowedips"', "derive protection from dynamic AllowedIPs"),
        ("for (item_index=1; item_index <= count; item_index++)", "avoid awk built-in identifiers while parsing routes"),
        ("grep -Eq '^(0x0+|0+)$'", "reject every zero-valued AWG routing mark"),
        ('-o "$NAME"', "allow traffic already using the tunnel"),
        ('--mark "$ROUTING_MARK"', "allow only AWG-marked outer or selected bypass traffic"),
        ('-A WINSVPN_KS -d %s -m addrtype', "scope rejection to current tunneled destinations"),
        ('winsvpn-killswitch-empty-family', "reject an unprotected address family"),
        ("! --dst-type LOCAL", "preserve local destinations"),
        ("--comment winsvpn-killswitch", "make every lifecycle rule identifiable"),
        ("-j REJECT", "fail interface-bound escape closed"),
    ):
        require(helper, literal, f"Linux kill switch must {explanation}")

    configure = helper[helper.index("configure_kill_switch()") : helper.index("cleanup_split_rules()")]
    require_order(
        configure,
        'cleanup_kill_switch || return $?',
        'printf \'v1\\n\' > "$SPLIT_STATE_DIR/kill-switch-active"',
        'install_kill_switch_family iptables "$KS_IPV4"',
        'install_kill_switch_family ip6tables "$KS_IPV6"',
    )
    family = configure[configure.index("install_kill_switch_family()") :]
    require_order(
        family,
        '-A WINSVPN_KS -o "$NAME"',
        '-A WINSVPN_KS -m mark --mark "$ROUTING_MARK"',
        '-A WINSVPN_KS -d %s -m addrtype',
        '-I OUTPUT 1',
    )
    require_order(
        family,
        'done < "$CIDR_FILE"',
        'if [ ! -s "$CIDR_FILE" ]',
        '--comment winsvpn-killswitch-empty-family',
        '-j REJECT',
        '--comment winsvpn-killswitch -j RETURN',
    )

    start = helper[helper.index('case "${1:-}" in') :]
    require_order(
        start,
        '"$TOOL" up "$CONF_DST"',
        'configure_kill_switch "$CONF_DST"',
        "activate_xray_transport",
    )
    stop = start[start.index("  stop)") :]
    require_order(
        stop,
        "cleanup_split_rules",
        "cleanup_xray_transport",
        '"$TOOL" down "$CONF_DST"',
        "cleanup_kill_switch",
    )
    if start.count("cleanup_kill_switch") < 5:
        raise AssertionError("Every Linux startup/rollback/stop path must remove owned kill-switch state")

    routes = ("0.0.0.0/0", "::/0")
    cases = (
        ({"destination": "1.1.1.1", "output_interface": "winsvpn", "packet_mark": 0, "local_destination": False}, "allow_tunnel"),
        ({"destination": "1.1.1.1", "output_interface": "eth0", "packet_mark": 0, "local_destination": False}, "reject_bound_escape"),
        ({"destination": "1.1.1.1", "output_interface": "eth0", "packet_mark": 51820, "local_destination": False}, "allow_outer_or_explicit_bypass"),
        ({"destination": "127.0.0.1", "output_interface": "lo", "packet_mark": 0, "local_destination": True}, "allow_local"),
        ({"destination": "2606:4700:4700::1111", "output_interface": "eth0", "packet_mark": 0, "local_destination": False}, "reject_bound_escape"),
    )
    for values, expected in cases:
        actual = modeled_verdict(routing_mark=51820, allowed_ips=routes, **values)
        if actual != expected:
            raise AssertionError(f"Linux kill-switch model returned {actual}, expected {expected}")

    split_routes = ("0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/9", "192.128.0.0/10")
    excluded = modeled_verdict(
        destination="203.0.113.10",
        output_interface="eth0",
        packet_mark=0,
        routing_mark=51820,
        local_destination=False,
        allowed_ips=split_routes,
    )
    if excluded != "allow_destination_exclusion":
        raise AssertionError("Destination split exclusions must remain outside the kill switch")

    # ------------------------------------------------------------------
    # The /run marker must never again be able to lock a user out.
    #
    # /run is tmpfs. On a host running iptables-persistent the WINSVPN_KS chain
    # is restored at boot and the marker is not, and the old ownership test
    # refused to touch the chain without it -- so start AND stop both aborted
    # and the machine had no internet, no LAN, and no in-app way back. That
    # same test also never did its job: with the marker merely present, a
    # same-named chain belonging to somebody else was flushed and deleted
    # without being inspected. Ownership is now decided by chain contents.
    # ------------------------------------------------------------------
    cleanup = helper[helper.index("cleanup_kill_switch()") : helper.index("configure_kill_switch()")]
    for forbidden, explanation in (
        (
            '[ "$state" = v1 ] || {',
            "must not gate chain removal on a marker that every reboot destroys",
        ),
        (
            "rejected unknown Linux kill-switch state",
            "must not abort cleanup because a marker is unreadable",
        ),
    ):
        if forbidden in cleanup:
            raise AssertionError(
                f"Linux kill-switch cleanup {explanation}: found {forbidden!r}"
            )
    require(
        helper,
        "winsvpn_chain_is_ours()",
        "must identify its chains by durable content, not by a /run marker",
    )
    require(
        cleanup,
        'winsvpn_chain_is_ours "$IPT" "$KS_CHAIN" winsvpn-killswitch',
        "must prove ownership of the kill-switch chain before removing it",
    )
    # The predicate has to be consulted before anything destructive happens.
    require_order(
        cleanup,
        'winsvpn_chain_is_ours "$IPT" "$KS_CHAIN" winsvpn-killswitch',
        '"$IPT" -w 5 -F "$KS_CHAIN"',
        '"$IPT" -w 5 -X "$KS_CHAIN"',
    )

    # The reconnect guard REJECTs everything by itself and is restored by the
    # same persistent-firewall setups, so it gets the same ownership test.
    guard = helper[
        helper.index("reconnect_guard_teardown_slot()") : helper.index("cleanup_split_rules()")
    ]
    require(
        guard,
        'winsvpn_chain_is_ours "$IPT" "$RG_CHAIN" winsvpn-reconnect-guard',
        "must prove ownership of a reconnect-guard chain before removing it",
    )
    # Scoped to the teardown path only. begin_reconnect_guard still refuses to
    # proceed on an unrecognised marker, and must: there the marker selects
    # which of the two slots is live, so guessing could tear down the chain
    # that is currently protecting the host. That refusal happens on start,
    # before anything new is installed, and leaves stop able to clear
    # everything -- so it fails closed without stranding anyone.
    teardown = guard[: guard.index("begin_reconnect_guard()")]
    cleanup_guard = guard[guard.index("cleanup_reconnect_guard()") :]
    for section, name in ((teardown, "teardown"), (cleanup_guard, "cleanup")):
        if "rejected unknown Linux reconnect-guard state" in section:
            raise AssertionError(
                f"Linux reconnect-guard {name} must not abort on an unreadable marker"
            )

    # An explicit stop is the user's way back to a working network. A kill
    # switch this script declines to touch must not also prevent the reconnect
    # guard from being removed -- that combination left hosts fully offline
    # even after the kill-switch chain had been cleared by hand.
    if "cleanup_kill_switch || exit $?" in stop:
        raise AssertionError(
            "Linux stop must not abandon reconnect-guard teardown when "
            "kill-switch removal fails"
        )
    require_order(
        stop,
        "cleanup_kill_switch || STOP_RC=$?",
        "cleanup_reconnect_guard || STOP_RC=$?",
        '[ "$STOP_RC" -eq 0 ] || exit "$STOP_RC"',
    )

    # The unowned-chain exit status is a contract between the shell helper and
    # the C++ that turns it into the one message a user has to act on.
    require(
        source,
        "constexpr int kLinuxUnownedFirewallChainExit = 66;",
        "must give an unowned firewall chain its own exit status",
    )
    for literal, explanation in (
        ("kLinuxUnownedFirewallChainMessage", "name the recovery message once"),
        ("sudo iptables -S WINSVPN_KS", "show the user how to inspect the chain"),
        ("sudo iptables -X WINSVPN_KS", "give the user a removable command"),
        ("share/doc/wins-vpn/RECOVERY.md", "point at a copy readable with no internet"),
    ):
        require(source, literal, f"Linux unowned-chain recovery must {explanation}")
    if cleanup.count("return 66") != 1:
        raise AssertionError("cleanup_kill_switch must report unowned chains as 66")

    ours = "-A WINSVPN_KS -m addrtype ! --dst-type LOCAL -m comment --comment winsvpn-killswitch -j REJECT"
    empty_family = "-A WINSVPN_KS -m comment --comment winsvpn-killswitch-empty-family -j REJECT"
    foreign = "-A WINSVPN_KS -m comment --comment site-security-policy -j ACCEPT"
    for rules, tag, expected, description in (
        ((ours, empty_family), "winsvpn-killswitch", True, "our own chain, both rule shapes"),
        ((foreign,), "winsvpn-killswitch", False, "a chain that is entirely somebody else's"),
        ((ours, foreign), "winsvpn-killswitch", False, "one foreign rule taints the whole chain"),
        ((), "winsvpn-killswitch", True, "an empty chain encodes no policy"),
    ):
        if modeled_chain_is_ours(rules=rules, tag=tag) is not expected:
            raise AssertionError(
                f"Linux chain-ownership model disagrees on: {description}"
            )

    # ------------------------------------------------------------------
    # The offline recovery document, and the exact command shapes in it.
    #
    # Its reader has no internet and no LAN, so it has to ship on disk. The
    # commands were executed against a live chain before being written down:
    # `-F` restores connectivity on its own, and `-D` matches ONLY when the
    # comment match is repeated in full -- `-D OUTPUT -j WINSVPN_KS` fails with
    # "Bad rule" and leaves the user exactly as stuck as before.
    # ------------------------------------------------------------------
    recovery = ROOT / "linux/packaging/RECOVERY.md"
    if not recovery.is_file():
        raise AssertionError(f"Missing offline Linux recovery document: {recovery}")
    recovery_text = recovery.read_text(encoding="utf-8")
    build_script = (ROOT / "tools/build_linux_release.sh").read_text(encoding="utf-8")
    require(
        build_script,
        '"$BUNDLE_DIR/share/doc/wins-vpn/RECOVERY.md"',
        "Linux release must ship the recovery document on disk",
    )
    for chain in ("WINSVPN_KS", "WINSVPN_KS3", "WINSVPN_RGA", "WINSVPN_RGB"):
        for tool in ("iptables", "ip6tables"):
            require(
                recovery_text,
                f"sudo {tool} -F {chain}",
                f"recovery must flush {chain} on {tool} to restore connectivity",
            )
    for broken in (
        "sudo iptables -D OUTPUT -j WINSVPN_KS",
        "sudo ip6tables -D OUTPUT -j WINSVPN_KS",
    ):
        if broken in recovery_text:
            raise AssertionError(
                f"Recovery document contains a command that does not work: {broken!r} "
                "-- iptables -D requires the full rule spec including the comment match"
            )
    require(
        recovery_text,
        "-D OUTPUT -m comment --comment winsvpn-killswitch -j WINSVPN_KS",
        "recovery must delete the OUTPUT jump with the full rule spec",
    )
    require(
        recovery_text,
        "-D OUTPUT -m comment --comment winsvpn-killswitch3 -j WINSVPN_KS3",
        "recovery must delete the standalone v3 OUTPUT jump with its own tag",
    )

    print("Linux kill-switch regression tests passed.")


if __name__ == "__main__":
    main()
