"""The rulesets of the dominance predicate matrix (design 5.3, `winn3_latch_dominates` cases).

Each case is a real iptables-restore file. The Linux fixture loads it into a
fresh network namespace on the guest and runs the installer's own
`wins_latch_rules_inspect` against the guest's real iptables, so the
predicate reads the output format and exit statuses of the installed
iptables (the design marks the no-such-chain message and its status
UNVERIFIED-LIVE until a run on the guest).

`expect` is `pass` or the tag the predicate must print on failure: S1, S2, L1
or inspection. `mode` is `all`, or `structure` (the reassert step's S1 and S2
only).
"""
import collections

BUILTIN = {"ACCEPT", "DROP", "REJECT", "RETURN", "QUEUE", "LOG", "NFQUEUE"}
LATCH = [
    "-A WINVPN-LOCAL-SERVING -i lo -j RETURN",
    "-A WINVPN-LOCAL-SERVING -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j RETURN",
    "-A WINVPN-LOCAL-SERVING -j DROP",
]
R = "-A INPUT -j WINVPN-SSH-RECOVERY"
L = "-A INPUT -j WINVPN-LOCAL-SERVING"
WI = "-A INPUT -j WINVPN-INPUT"
WG = "-A INPUT -d 10.10.0.1/32 -i winn3gw0 -j WINN3GW-INPUT"
CF = "-A INPUT -p tcp -m multiport --dports 80,443 -j WINVPN-STEALTH-CF"
F2B = "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd"
RECOVERY_RULE = "-A WINVPN-SSH-RECOVERY -s 8.8.4.4/32 -p tcp -m tcp --dport 22 -j ACCEPT"
CF_BODY = [
    "-A WINVPN-STEALTH-CF -i lo -j RETURN",
    "-A WINVPN-STEALTH-CF -s 8.8.8.0/24 -j RETURN",
    "-A WINVPN-STEALTH-CF -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
    "-A WINVPN-STEALTH-CF -j DROP",
]
F2B_BODY = [
    "-A f2b-sshd -s 203.0.113.7/32 -j REJECT --reject-with icmp-port-unreachable",
    "-A f2b-sshd -j RETURN",
]
WI_BODY = ["-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY", "-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING",
           "-A WINVPN-INPUT -i lo -j ACCEPT", "-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT"]


def restore(input_rules, chains=None, latch=True):
    """An iptables-restore file for the filter table with every chain a rule jumps to declared."""
    chains = collections.OrderedDict(chains or {})
    if latch:
        chains.setdefault("WINVPN-LOCAL-SERVING", LATCH)
    rules = list(input_rules)
    for body in chains.values():
        rules.extend(body)
    declared = ["WINVPN-SSH-RECOVERY"] if any("WINVPN-SSH-RECOVERY" in r for r in rules) else []
    for name in chains:
        if name not in declared:
            declared.append(name)
    for rule in rules:
        words = rule.split()
        for flag in ("-j", "-g"):
            if flag in words:
                target = words[words.index(flag) + 1]
                if target not in BUILTIN and target not in declared:
                    declared.append(target)
    out = ["*filter", ":INPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]"]
    out += [":%s - [0:0]" % name for name in declared]
    out += input_rules
    for body in chains.values():
        out += body
    out.append("COMMIT")
    return "\n".join(out) + "\n"


def case(identifier, design, expect, input_rules, chains=None, mode="all", latch=True):
    return {"id": identifier, "design": design, "expect": expect, "mode": mode,
            "rules": restore(input_rules, chains, latch)}


def cases():
    out = []
    add = out.append
    pos = "5.3 winn3_latch_dominates passes on: "
    neg = "5.3 winn3_latch_dominates fails on: "
    body = "5.3 guard-body negatives (fix 2): "
    add(case("pass-latch-only-base", pos + "the base form", "pass", [L]))
    add(case("pass-chain-form-edge-output", pos + "the edge script's own output (DP 11122-11123)", "pass",
             [WI], {"WINVPN-INPUT": WI_BODY, "WINVPN-SSH-RECOVERY": []}))
    add(case("pass-base-form-after-2a", pos + "the base form after handler step 2a", "pass",
             [L, WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"]}))
    add(case("pass-base-R-L", pos + "the base form preceded by the recovery jump", "pass",
             [R, L, WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"], "WINVPN-SSH-RECOVERY": [RECOVERY_RULE]}))
    add(case("pass-base-two-recovery-jumps", pos + "v9 fix 1: two copies of the recovery jump", "pass",
             [R, R, L, WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"], "WINVPN-SSH-RECOVERY": []}))
    add(case("pass-R-WG-L-WI", pos + "v11 fix 1: [R, WG, L, ..., WI]", "pass",
             [R, WG, L, WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"], "WINN3GW-INPUT": ["-A WINN3GW-INPUT -j RETURN"],
                              "WINVPN-SSH-RECOVERY": []}))
    add(case("pass-CF-R-L-WI", pos + "v11 fix 1: [CF, R, L, ..., WI] with a checked body", "pass",
             [CF, R, L, WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"], "WINVPN-STEALTH-CF": CF_BODY,
                              "WINVPN-SSH-RECOVERY": []}))
    add(case("pass-chain-form-WG-in-S-order", pos + "v11 fix 1: chain form with WINN3GW-INPUT in the order iptables -S prints it", "pass",
             [WG, WI], {"WINVPN-INPUT": WI_BODY, "WINN3GW-INPUT": ["-A WINN3GW-INPUT -j RETURN"],
                        "WINVPN-SSH-RECOVERY": []}))
    add(case("pass-F2B-R-L-WI", pos + "v12 fix 4: [F2B, R, L, ..., WI] with a valid f2b-sshd body", "pass",
             [F2B, R, L, WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"], "f2b-sshd": F2B_BODY,
                               "WINVPN-SSH-RECOVERY": []}))
    add(case("pass-F2B-chain-form", pos + "v12 fix 4: the Fail2Ban jump ahead of -j WINVPN-INPUT", "pass",
             [F2B, WI], {"WINVPN-INPUT": WI_BODY, "f2b-sshd": F2B_BODY, "WINVPN-SSH-RECOVERY": []}))
    add(case("pass-recovery-body-pinned", "5.3 recovery body: the exact pinned /32 rule", "pass",
             [R, L], {"WINVPN-SSH-RECOVERY": [RECOVERY_RULE]}))
    add(case("structure-passes-with-no-latch-body", "5.3 reassert step: structure mode skips L1", "pass",
             [L], {"WINVPN-LOCAL-SERVING": ["-A WINVPN-LOCAL-SERVING -j RETURN"]}, mode="structure"))
    # chain-form and base-INPUT failures
    add(case("fail-france-ordering", neg + "the France ordering (evidence/france-mgmt.txt:21-24)", "S1",
             [WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT",
                                     "-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT"] + WI_BODY[:2],
                    "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-base-accept-ahead-of-wi", neg + "any base-INPUT ACCEPT ahead of -j WINVPN-INPUT", "S1",
             ["-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT", WI], {"WINVPN-INPUT": WI_BODY[:2], "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-unknown-jump-ahead", neg + "an unknown jump target ahead of it", "S1",
             ["-A INPUT -j SOMEWHERE", WI], {"WINVPN-INPUT": WI_BODY[:2], "SOMEWHERE": [], "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-missing-wi-jump", neg + "a missing INPUT -j WINVPN-INPUT", "S1",
             [], {"WINVPN-INPUT": WI_BODY[:2], "WINVPN-SSH-RECOVERY": []}))
    wrong = ["-A WINVPN-LOCAL-SERVING -i lo -j RETURN", "-A WINVPN-LOCAL-SERVING -j RETURN"]
    add(case("fail-wrong-latch-body", neg + "a wrong latch chain body", "L1", [L], {"WINVPN-LOCAL-SERVING": wrong}))
    add(case("fail-extra-latch-rule", neg + "a latch body with an extra rule", "L1", [L],
             {"WINVPN-LOCAL-SERVING": LATCH + ["-A WINVPN-LOCAL-SERVING -j DROP"]}))
    add(case("fail-latch-ctdir-original", neg + "a latch body whose ctdir is ORIGINAL", "L1", [L],
             {"WINVPN-LOCAL-SERVING": [LATCH[0], LATCH[1].replace("REPLY", "ORIGINAL"), LATCH[2]]}))
    add(case("fail-base-lo-accept-ahead", neg + "v11 fix 1: a base-INPUT rule outside the admitted set ahead of the first latch jump", "S1",
             ["-A INPUT -i lo -j ACCEPT", L]))
    add(case("fail-base-udp9111-accept-ahead", neg + "a UDP 9111 ACCEPT ahead of the latch jump", "S1",
             ["-A INPUT -p udp -m udp --dport 9111 -j ACCEPT", L]))
    add(case("fail-WG-negated", neg + "v11 fix 1: [R, WG!, L, ..., WI]", "S1",
             [R, "-A INPUT -d 10.10.0.1/32 ! -i winn3gw0 -j WINN3GW-INPUT", L, WI],
             {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"], "WINN3GW-INPUT": [], "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-WG-wrong-interface", neg + "a WINN3GW-INPUT jump on another interface", "S1",
             [R, "-A INPUT -d 10.10.0.1/32 -i eth0 -j WINN3GW-INPUT", L],
             {"WINN3GW-INPUT": [], "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-CF-accept-inside", neg + "v11 fix 1: [CF, R, L, ..., WI] with an ACCEPT added inside WINVPN-STEALTH-CF", "S2",
             [CF, R, L, WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -j ACCEPT"],
                              "WINVPN-STEALTH-CF": CF_BODY[:-1] + ["-A WINVPN-STEALTH-CF -p tcp -m tcp --dport 443 -j ACCEPT",
                                                                    CF_BODY[-1]], "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-F2B-accept-inside", neg + "v12 fix 4: an ACCEPT inside f2b-sshd", "S2",
             [F2B, R, L], {"f2b-sshd": [F2B_BODY[0], "-A f2b-sshd -p tcp -m tcp --dport 22 -j ACCEPT", F2B_BODY[1]],
                           "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-F2B-no-return", neg + "v12 fix 4: an f2b-sshd body that does not end in RETURN", "S2",
             [F2B, R, L], {"f2b-sshd": [F2B_BODY[0], "-A f2b-sshd -j DROP"], "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-F2B-ports-22-443", neg + "v12 fix 4: the Fail2Ban jump on --dports 22,443", "S1",
             ["-A INPUT -p tcp -m multiport --dports 22,443 -j f2b-sshd", R, L],
             {"f2b-sshd": F2B_BODY, "WINVPN-SSH-RECOVERY": []}))
    # guard-body negatives (fix 2)
    add(case("fail-recovery-443-accept", body + "a TCP 443 ACCEPT added inside WINVPN-SSH-RECOVERY", "S2",
             [R, L], {"WINVPN-SSH-RECOVERY": [RECOVERY_RULE, "-A WINVPN-SSH-RECOVERY -p tcp -m tcp --dport 443 -j ACCEPT"]}))
    add(case("fail-recovery-port-23", body + "a recovery rule for port 23", "S2",
             [R, L], {"WINVPN-SSH-RECOVERY": [RECOVERY_RULE.replace("--dport 22", "--dport 23")]}))
    add(case("fail-recovery-slash-24", body + "a recovery rule for a /24 source", "S2",
             [R, L], {"WINVPN-SSH-RECOVERY": [RECOVERY_RULE.replace("8.8.4.4/32", "8.8.4.0/24")]}))
    add(case("fail-recovery-second-rule", body + "a second recovery rule", "S2",
             [R, L], {"WINVPN-SSH-RECOVERY": [RECOVERY_RULE, RECOVERY_RULE.replace("8.8.4.4", "8.8.8.8")]}))
    add(case("fail-CF-jump-inside", body + "a jump to another chain inside WINVPN-STEALTH-CF", "S2",
             [CF, R, L], {"WINVPN-STEALTH-CF": ["-A WINVPN-STEALTH-CF -j OTHERCHAIN", CF_BODY[-1]], "OTHERCHAIN": [],
                          "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-CF-not-ending-in-drop", body + "a STEALTH-CF chain not ending in an unconditional DROP", "S2",
             [CF, R, L], {"WINVPN-STEALTH-CF": CF_BODY[:-1], "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-CF-conditional-final-drop", body + "a STEALTH-CF chain ending in a conditional DROP", "S2",
             [CF, R, L], {"WINVPN-STEALTH-CF": CF_BODY[:-1] + ["-A WINVPN-STEALTH-CF -s 1.2.3.4/32 -j DROP"],
                          "WINVPN-SSH-RECOVERY": []}))
    add(case("fail-not-lo-accept", body + "a base-INPUT ! -i lo -j ACCEPT ahead of the latch", "S1",
             ["-A INPUT ! -i lo -j ACCEPT", L]))
    add(case("fail-goto-ahead", body + "a -g goto ahead of the latch", "inspection",
             ["-A INPUT -g WINVPN-LOCAL-SERVING", L]))
    return out


# Wrapper-driven read failures: (chain, operation, exit status). The fixture builds an iptables
# wrapper that fails exactly that read and runs the predicate through IPTABLES_BIN.
READ_FAILURE_CHAINS = ("INPUT", "WINVPN-SSH-RECOVERY", "WINVPN-LOCAL-SERVING")
READ_FAILURE_STATUS = (1, 2, 4, 127)

# Absence of WINVPN-SSH-RECOVERY is only accepted as exit status 1 plus iptables' own message.
# (rc, stderr text, predicate must pass)
ABSENCE_WRAPPERS = (
    (1, "iptables: No chain/target/match by that name.", True),
    (4, "iptables: No chain/target/match by that name.", False),
    (4, "Another app is currently holding the xtables lock; Resource temporarily unavailable.", False),
    (1, "Another app is currently holding the xtables lock", False),
    (2, "iptables: Resource temporarily unavailable", False),
)


def states():
    """Whole-node pre-failure rulesets for the guard and exit-handler fixtures (5.3).

    open-serving is the permissive fresh-host snapshot with serving ports open and no guard chains.
    """
    open_rules = ["-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT", "-A INPUT -p tcp -m tcp --dport 9111 -j ACCEPT",
                  "-A INPUT -p udp -m udp --dport 9111 -j ACCEPT"]
    body = ["-A WINVPN-INPUT -j WINVPN-SSH-RECOVERY", "-A WINVPN-INPUT -j WINVPN-LOCAL-SERVING",
            "-A WINVPN-INPUT -i lo -j ACCEPT", "-A WINVPN-INPUT -p tcp -m tcp --dport 443 -j ACCEPT",
            "-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT", "-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT"]
    france_body = ["-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT", "-A WINVPN-INPUT -p udp -m udp --dport 9111 -j ACCEPT"] + body
    empty_latch = {"WINVPN-LOCAL-SERVING": [], "WINVPN-SSH-RECOVERY": []}
    out = {
        "permissive": restore([], {}, latch=False),
        "open-serving": restore(open_rules, {}, latch=False),
        "chain-open": restore([WI], {"WINVPN-INPUT": body, **empty_latch}, latch=False),
        "chain-open-3x9111": restore([WI], {"WINVPN-INPUT": ["-A WINVPN-INPUT -p tcp -m tcp --dport 9111 -j ACCEPT"] * 3 + body,
                                            **empty_latch}, latch=False),
        "chain-france": restore([WI], {"WINVPN-INPUT": france_body, **empty_latch}, latch=False),
        "base-443-ahead": restore(["-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT", WI], {"WINVPN-INPUT": body, **empty_latch}, latch=False),
        "jumps-only-base": restore([R, L, WI], {"WINVPN-INPUT": body[2:], **empty_latch}, latch=False),
        "chain-open-altered-latch": restore([WI], {"WINVPN-INPUT": body, "WINVPN-SSH-RECOVERY": [],
                                                   "WINVPN-LOCAL-SERVING": ["-A WINVPN-LOCAL-SERVING -i lo -j RETURN",
                                                                            "-A WINVPN-LOCAL-SERVING -j RETURN"]}, latch=False),
        "chain-f2b-ahead": restore([F2B, WI], {"WINVPN-INPUT": body, "f2b-sshd": F2B_BODY, **empty_latch}, latch=False),
        "chain-cf-ahead": restore([CF, WI], {"WINVPN-INPUT": body, "WINVPN-STEALTH-CF": CF_BODY, **empty_latch}, latch=False),
        "chain-f2b-accept-inside": restore([F2B, WI], {"WINVPN-INPUT": body, **empty_latch,
                                                       "f2b-sshd": [F2B_BODY[0], "-A f2b-sshd -p tcp -m tcp --dport 22 -j ACCEPT", F2B_BODY[1]]}, latch=False),
        "chain-open-recovery-443": restore([WI], {"WINVPN-INPUT": body, "WINVPN-LOCAL-SERVING": [],
                                                  "WINVPN-SSH-RECOVERY": ["-A WINVPN-SSH-RECOVERY -p tcp -m tcp --dport 443 -j ACCEPT"]}, latch=False),
    }
    return out
