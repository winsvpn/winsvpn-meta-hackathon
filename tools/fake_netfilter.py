#!/usr/bin/env python3
"""Stateful stand-in for iptables, iptables-save and iptables-restore.

Test-only. The state lives in the JSON file named by FAKE_IPT_STATE. The one
kernel behaviour the installer tests depend on is modelled explicitly, in the
restore path: a `:CHAIN - [0:0]` declaration of a user chain that already
exists FLUSHES that chain, with or without --noflush. That is what
iptables-restore does in both backends (legacy iptables-restore.c flushes an
existing user-defined chain on its declaration; xtables-restore calls
chain_user_flush under --noflush), and the data-plane installer records the
same behaviour in its own comment above the guard-chain block of
apply_firewall. A restore is atomic: any error leaves the state untouched.

Invocation: fake_netfilter.py {iptables|iptables-save|iptables-restore} ARGS...
"""
from __future__ import annotations

import copy
import json
import os
import sys

BUILTINS = {
    "filter": ["INPUT", "FORWARD", "OUTPUT"],
    "nat": ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"],
    "mangle": ["PREROUTING", "INPUT", "FORWARD", "OUTPUT", "POSTROUTING"],
}
TARGETS = {
    "ACCEPT", "DROP", "RETURN", "REJECT", "NFQUEUE", "LOG", "MASQUERADE",
    "REDIRECT", "TCPMSS", "DNAT", "SNAT", "MARK", "CONNMARK", "CT", "NOTRACK",
}


class Fail(Exception):
    pass


def empty_state() -> dict:
    return {
        table: {chain: {"policy": "ACCEPT", "rules": []} for chain in chains}
        for table, chains in BUILTINS.items()
    }


def load() -> dict:
    path = os.environ["FAKE_IPT_STATE"]
    if not os.path.exists(path):
        return empty_state()
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def save(state: dict) -> None:
    path = os.environ["FAKE_IPT_STATE"]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)


def log(line: str) -> None:
    path = os.environ.get("FAKE_IPT_LOG")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def chain_of(state: dict, table: str, chain: str) -> dict:
    try:
        return state[table][chain]
    except KeyError:
        raise Fail(f"iptables: No chain/target/match by that name ({table}/{chain})")


def check_jump(state: dict, table: str, spec: list[str]) -> None:
    for flag in ("-j", "-g"):
        if flag in spec:
            target = spec[spec.index(flag) + 1]
            if target not in TARGETS and target not in state[table]:
                raise Fail(f"Couldn't load target `{target}'")


def command(state: dict, table: str, args: list[str]) -> list[str]:
    """Apply one iptables command to state; return output lines."""
    if not args:
        raise Fail("no command")
    op, rest = args[0], args[1:]
    out: list[str] = []
    if table not in state:
        raise Fail(f"can't initialize iptables table `{table}'")
    tbl = state[table]
    if op == "-N":
        if rest[0] in tbl:
            raise Fail("iptables: Chain already exists.")
        tbl[rest[0]] = {"policy": "-", "rules": []}
    elif op == "-X":
        if rest[0] in BUILTINS[table]:
            raise Fail("cannot delete built-in chain")
        chain_of(state, table, rest[0])
        del tbl[rest[0]]
    elif op == "-F":
        chains = [rest[0]] if rest else list(tbl)
        for name in chains:
            chain_of(state, table, name)["rules"] = []
    elif op == "-P":
        chain_of(state, table, rest[0])["policy"] = rest[1]
    elif op in ("-A", "-I", "-C", "-D"):
        chain = chain_of(state, table, rest[0])
        spec = rest[1:]
        position = 1
        if op == "-I" and spec and spec[0].isdigit():
            position = int(spec[0])
            spec = spec[1:]
        rule = " ".join(spec)
        if op == "-A":
            check_jump(state, table, spec)
            chain["rules"].append(rule)
        elif op == "-I":
            check_jump(state, table, spec)
            chain["rules"].insert(position - 1, rule)
        elif op == "-C":
            if rule not in chain["rules"]:
                raise Fail("iptables: Bad rule (does a matching rule exist in that chain?).")
        else:
            if rule not in chain["rules"]:
                raise Fail("iptables: Bad rule (does a matching rule exist in that chain?).")
            chain["rules"].remove(rule)
    elif op in ("-L", "-S"):
        chains = [rest[0]] if rest else list(tbl)
        for name in chains:
            chain = chain_of(state, table, name)
            if op == "-S":
                if name in BUILTINS[table]:
                    out.append(f"-P {name} {chain['policy']}")
                else:
                    out.append(f"-N {name}")
                out.extend(f"-A {name} {rule}" for rule in chain["rules"])
            else:
                out.append(f"Chain {name}")
                out.extend(chain["rules"])
    else:
        raise Fail(f"unsupported fake iptables operation {op}")
    return out


def strip_common(args: list[str]) -> tuple[str, list[str]]:
    table = "filter"
    cleaned: list[str] = []
    index = 0
    while index < len(args):
        arg = args[index]
        if arg in ("-w", "--wait"):
            if index + 1 < len(args) and args[index + 1].isdigit():
                index += 1
        elif arg == "-t":
            table = args[index + 1]
            index += 1
        elif arg in ("-n", "-v", "--line-numbers"):
            pass
        else:
            cleaned.append(arg)
        index += 1
    return table, cleaned


def run_iptables(args: list[str]) -> int:
    state = load()
    table, cleaned = strip_common(args)
    log("iptables " + " ".join(args))
    try:
        out = command(state, table, cleaned)
    except Fail as exc:
        print(str(exc), file=sys.stderr)
        return 1
    save(state)
    if out:
        print("\n".join(out))
    return 0


def render_save(state: dict) -> str:
    lines: list[str] = []
    for table in ("filter", "nat", "mangle"):
        lines.append(f"*{table}")
        for name, chain in state[table].items():
            lines.append(f":{name} {chain['policy'] if name in BUILTINS[table] else '-'} [0:0]")
        for name, chain in state[table].items():
            lines.extend(f"-A {name} {rule}" for rule in chain["rules"])
        lines.append("COMMIT")
    return "\n".join(lines) + "\n"


def run_save(args: list[str]) -> int:
    print(render_save(load()), end="")
    return 0


def run_restore(args: list[str]) -> int:
    test_only = "--test" in args or "-t" in args
    noflush = "--noflush" in args or "-n" in args
    payload = sys.stdin.read()
    log(f"iptables-restore {' '.join(args)}")
    state = copy.deepcopy(load())
    table = None
    try:
        for raw in payload.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("*"):
                table = line[1:]
                if table not in state:
                    raise Fail(f"unknown table {table}")
                if not noflush:
                    state[table] = {
                        chain: {"policy": state[table][chain]["policy"], "rules": []}
                        for chain in BUILTINS[table]
                    }
                continue
            if line == "COMMIT":
                table = None
                continue
            if table is None:
                raise Fail("rule outside a table")
            if line.startswith(":"):
                name, policy = line[1:].split()[:2]
                if name in BUILTINS[table]:
                    if policy != "-":
                        state[table][name]["policy"] = policy
                elif name in state[table]:
                    # The modelled kernel behaviour: declaring an existing user
                    # chain flushes it, even under --noflush.
                    state[table][name]["rules"] = []
                else:
                    state[table][name] = {"policy": "-", "rules": []}
                continue
            command(state, table, line.split())
    except Fail as exc:
        print(f"iptables-restore: {exc}", file=sys.stderr)
        return 1
    if not test_only:
        save(state)
    return 0


def main() -> int:
    mode = os.path.basename(sys.argv[1])
    args = sys.argv[2:]
    if mode == "iptables":
        return run_iptables(args)
    if mode == "iptables-save":
        return run_save(args)
    if mode == "iptables-restore":
        return run_restore(args)
    print(f"unknown fake mode {mode}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
