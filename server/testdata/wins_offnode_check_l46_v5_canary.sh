#!/usr/bin/env bash
# L46 read-only node-side check for an operator-off node (F2 gate; argv parsing v4 after
# Round HV turn 4; literal registry path and inode checks v5 after Round HV turn 5).
# Prints what the node's runtime would accept, as digests only, plus the facts that tie the
# running winn3-gateway to its registry file. Runs no mutating command and writes nothing.
#
#   AWG   awg0 peers inside the AmneziaWG container via `awg show awg0 peers`,
#         `allowed-ips` and `latest-handshakes` (never the interface private key, preshared
#         keys or client endpoints). Per peer: key digest, address class (device_pool
#         10.8.0.0/16 outside 10.8.255.0/24, core_exit 10.8.255.0/24, other, none), and a
#         digest of its allowed-ips string (hub-assigned tunnel addresses, printed only as a
#         digest so the comparator can match an approved lab address exactly).
#   V3    /etc/winn/winn3-peers.json: SHA-256 of the exact bytes, size, mode, regularity,
#         validation against the gateway's own reload rules (peer_registry.go reloadLocked),
#         and per entry the static_public digest and not_after class. inner_v4 never printed.
#         The registry path must be absolute and normalized, EQUAL byte for byte to the
#         gateway's effective -peer-registry, and no component from / down may be a symlink
#         (every component is lstat'd); the file must be a regular file with st_nlink == 1,
#         owned by --expect-uid (default 0, root) with mode 0640, opened with O_NOFOLLOW, and
#         the (device, inode) of the open file must equal the lstat'd one before and after
#         the read (with the same size, mtime and ctime). The start-time check uses that inode.
#         Any failure sets registry_flag_matches=0 and is named by path_check=<reason>.
#   GW    winn3-gateway: unit state, whether the running process was started with
#         -forward and -peer-registry <that file> (its /proc/<pid>/cmdline is parsed exactly
#         as the gateway's Go flag.FlagSet parses it, with the gateway's 40 flags and their
#         types taken from cmd/winn3-gateway/main.go:183-285, and cross-checked token by token
#         against the unit's ExecStart; ANY ambiguity makes forward=0 and
#         registry_flag_matches=0, see argv_check), whether its uid/gids can read the file,
#         whether it STARTED AFTER the file last changed (max of mtime and ctime, against both
#         the process start time from /proc/<pid>/stat + btime and systemd's
#         ExecMainStartTimestampMonotonic, with a 1 s margin for btime rounding), and how many
#         "peer registry reload failed" journal lines it logged since the file was written.
#         The gateway exposes no loaded-digest endpoint, metric or success log line; see
#         l46_report.txt for what these facts prove and what they do not.
#
#   ssh <node> 'bash -s' < offnode_node_check.sh > node_check.txt
# Options (defaults are the production paths): --registry PATH --iface NAME --containers "a b"
#   --gateway-unit NAME --proc-root DIR --expect-uid N --canary-pubkey BASE64
# Exit: 0 every read completed, 2 some runtime state was unreadable or refused (the comparator
# and the hub fail it).
set -euo pipefail
export LC_ALL=C

REGISTRY=/etc/winn/winn3-peers.json
IFACE=awg0
CONTAINERS="amnezia-awg2 awg amnezia-awg"
GW_UNIT=winn3-gateway
PROC=/proc
EXPECT_UID=0
CANARY_PUBKEY=
while (($#)); do
  case "$1" in
    --canary-pubkey) CANARY_PUBKEY=${2:-}; shift 2 ;;
    --registry) REGISTRY=${2:-}; shift 2 ;;
    --iface) IFACE=${2:-}; shift 2 ;;
    --containers) CONTAINERS=${2:-}; shift 2 ;;
    --gateway-unit) GW_UNIT=${2:-}; shift 2 ;;
    --proc-root) PROC=${2:-}; shift 2 ;;
    --expect-uid) EXPECT_UID=${2:-}; shift 2 ;;
    *) printf '[l46_node_check] usage error: unknown argument %q\n' "$1" >&2; exit 2 ;;
  esac
done
[[ $IFACE =~ ^[a-z0-9]{1,15}$ ]] || { echo "[l46_node_check] usage error: bad interface name" >&2; exit 2; }
[[ $EXPECT_UID =~ ^[0-9]+$ ]] || { echo "[l46_node_check] usage error: bad --expect-uid" >&2; exit 2; }
[[ -z $CANARY_PUBKEY || $CANARY_PUBKEY =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "[l46_node_check] usage error: bad --canary-pubkey" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "READ_ERROR python3_missing"; exit 2; }

d16() { printf '%s' "$1" | sha256sum | cut -c1-16; }
rc=0

# ------------------------------------------------------------------ AWG
container=""
running=$(docker ps --format '{{.Names}}' </dev/null 2>/dev/null || true)
for c in $CONTAINERS; do
  if grep -qx -- "$c" <<<"$running"; then container=$c; break; fi
done
awg_ok=0
if [[ -z $container ]]; then
  echo "AWG_READ error=no_awg_container"
elif ! peers=$(docker exec "$container" awg show "$IFACE" peers </dev/null 2>/dev/null); then
  echo "AWG_READ error=awg_show_failed"
elif ! allowed=$(docker exec "$container" awg show "$IFACE" allowed-ips </dev/null 2>/dev/null); then
  echo "AWG_READ error=allowed_ips_failed"
elif ! handshakes=$(docker exec "$container" awg show "$IFACE" latest-handshakes </dev/null 2>/dev/null); then
  echo "AWG_READ error=handshakes_failed"
else
  awg_ok=1
fi
if [[ $awg_ok == 1 ]]; then
  now=$(date +%s)
  n=0
  for key in $peers; do
    n=$((n + 1))
    ips=$(awk -v k="$key" '$1 == k { $1 = ""; sub(/^ +/, ""); print; exit }' <<<"$allowed")
    ips_norm=$(tr ' ' '\n' <<<"$ips" | sed '/^$/d' | sort | paste -sd, -)
    class=none
    for ip in $(tr ',' ' ' <<<"$ips_norm"); do
      case "$ip" in
        "(none)") ;;
        10.8.255.*) class=core_exit ;;
        10.8.*) [[ $class == core_exit ]] || class=device_pool ;;
        *) [[ $class != none ]] || class=other ;;
      esac
    done
    ts=$(awk -v k="$key" '$1 == k { print $2; exit }' <<<"$handshakes")
    if [[ -z $ts || $ts == 0 ]]; then hs=never
    elif (( now - ts < 180 )); then hs=lt3m
    elif (( now - ts < 3600 )); then hs=lt1h
    elif (( now - ts < 86400 )); then hs=lt1d
    else hs=older; fi
    # Design 2.9: the one exemption. Only the exact canary key carrying exactly
    # 10.8.255.1/32 is a system peer. Without --canary-pubkey nothing is exempt.
    if [[ -n $CANARY_PUBKEY && $key == "$CANARY_PUBKEY" && $ips_norm == "10.8.255.1/32" ]]; then
      echo "AWGSYSPEER $(d16 "$key") canary $(d16 "$ips_norm") $hs"
    else
      echo "AWGPEER $(d16 "$key") $class $(d16 "$ips_norm") $hs"
    fi
  done
  echo "AWG_READ ok iface=$IFACE peers=$n"
else
  rc=2
fi

# ------------------------------------------------------------------ gateway process facts
gw_active=$(systemctl is-active "$GW_UNIT" </dev/null 2>/dev/null || true)
gw_pid=$(systemctl show -p MainPID --value "$GW_UNIT" </dev/null 2>/dev/null || echo 0)
[[ -n $gw_active ]] || gw_active=unknown
[[ $gw_pid =~ ^[0-9]+$ ]] || gw_pid=0
sd_mono=$(systemctl show -p ExecMainStartTimestampMonotonic --value "$GW_UNIT" </dev/null 2>/dev/null || echo "")
gw_exec=$(systemctl show -p ExecStart --value "$GW_UNIT" </dev/null 2>/dev/null || echo "")
[[ $sd_mono =~ ^[0-9]+$ ]] || sd_mono=""
gw_main=$(systemctl show -p ExecMainPID --value "$GW_UNIT" </dev/null 2>/dev/null || echo "")
[[ $gw_main =~ ^[0-9]+$ ]] || gw_main=""
reload_failed=unknown
if [[ -e $REGISTRY ]]; then
  mtime=$(python3 -c 'import os,sys; print(int(os.stat(sys.argv[1]).st_mtime))' "$REGISTRY" 2>/dev/null || echo "")
  if [[ -n $mtime ]] && out=$(journalctl -u "$GW_UNIT" --since "@$mtime" --no-pager -o cat </dev/null 2>/dev/null); then
    reload_failed=$(grep -c "peer registry reload failed" <<<"$out" || true)
  fi
fi

L46_EXPECT_UID=$EXPECT_UID L46_EXECSTART=$gw_exec L46_EXECMAINPID=$gw_main python3 - "$REGISTRY" "$PROC" "$gw_pid" "$gw_active" "$reload_failed" "$sd_mono" <<'L46_NODE_CHECK_PY' || rc=2
import hashlib, ipaddress, json, os, stat, sys, time, base64
path, proc, pid, active, reload_failed, sd_mono = (sys.argv[1], sys.argv[2], int(sys.argv[3]),
                                                   sys.argv[4], sys.argv[5], sys.argv[6])
d16 = lambda s: hashlib.sha256(s.encode()).hexdigest()[:16]
bad = False
import re
# ---- gateway argv. Nothing from it is printed except one reason word (argv_check).
# The registry path has exactly one source: the -peer-registry flag (main.go:234, copied into
# serveOptions at :317, read at :832 and :1027). No environment variable or config file sets
# it (the only os.Getenv reads in main.go are WINN3_GATEWAY_DEMUX, WINN3_GATEWAY_REPLAY_JOURNAL
# and WINN3_REPLAY_JOURNAL). main.go:183 builds flag.NewFlagSet(ContinueOnError) and :287 calls
# Parse(args); flags.Args() is never read, so tokens after the first non-flag are ignored.
GO_BOOL = {"forward", "accept-transit", "resolver", "insecure-cover-reuses-winn-leaf",
           "insecure-cover-is-not-a-real-origin", "insecure-cover-identifies-operator"}
GO_VALUE = {"mode", "out", "listen", "static", "admission", "dual-auth-ed-key", "dual-auth-ml-seed",
            "gateway-id", "inner-v4", "router-v4", "inner-v6", "router-v6", "plan", "path-mtu",
            "max-sessions", "for", "key", "cert", "suite", "cover-cert", "cover-key",
            "cover-server-name", "decoy-origin", "ech-keys", "demux", "forward-if", "forward-cidr",
            "peer-registry", "resolver-upstream", "resolver-timeout", "max-preauth-connections",
            "max-preauth-connections-per-ip", "speedtest-ingest-port", "status-json"}
GO_TRUE, GO_FALSE = {"1", "t", "T", "TRUE", "true", "True"}, {"0", "f", "F", "FALSE", "false", "False"}


def go_parse(args):
    """flag.FlagSet.Parse, step for step (Go src/flag/flag.go parseOne): stop at the first
    token that is not a flag or at "--"; "-x" and "--x" are the same flag; "-x=v" sets v;
    a non-bool flag without "=" takes the NEXT token whatever it is; a bool flag takes a
    value only as "-x=v"; a repeated flag overrides the earlier one."""
    eff, occ, i = {}, {}, 0
    while i < len(args):
        s = args[i]
        if len(s) < 2 or s[0] != "-":
            break
        minus = 2 if s[1] == "-" else 1
        if minus == 2 and len(s) == 2:
            break
        name = s[minus:]
        if not name or name[0] in "-=":
            raise ValueError("bad_flag_syntax")
        has_value = "=" in name
        value = None
        if has_value:
            name, value = name.split("=", 1)
        i += 1
        if name in ("h", "help"):
            raise ValueError("help_flag")
        if name in GO_BOOL:
            if not has_value:
                v, form = True, "bare"
            elif value in GO_TRUE:
                v, form = True, "="
            elif value in GO_FALSE:
                v, form = False, "="
            else:
                raise ValueError("bad_bool_value")
        elif name in GO_VALUE:
            if has_value:
                v, form = value, "="
            elif i < len(args):
                v, form = args[i], "sep"
                i += 1
            else:
                raise ValueError("flag_needs_argument")
        else:
            raise ValueError("flag_not_in_reviewed_gateway_source")
        occ.setdefault(name, []).append(form)
        eff[name] = v
    return eff, occ


def execstart_tokens(line):
    if line.count("{ path=") != 1:
        raise ValueError("execstart_not_exactly_one")
    m = re.search(r"argv\[\]=(.*?) ; ignore_errors=", line)
    if not m:
        raise ValueError("execstart_unparseable")
    body = m.group(1)
    if any(c in body for c in "\"'\\") or "  " in body:
        raise ValueError("execstart_quoted_or_spaced")
    pm = re.search(r" ; pid=(\d+) ", line)
    return body.split(" "), (int(pm.group(1)) if pm else None)


argv = None
argv_check = "no_process"
if pid > 0:
    try:
        raw_cmd = open(os.path.join(proc, str(pid), "cmdline"), "rb").read()
        argv = [a.decode("utf-8", "replace") for a in raw_cmd.split(b"\0")]
        if argv and argv[-1] == "":
            argv = argv[:-1]           # the terminator, not an argument
    except OSError:
        argv = None
        argv_check = "cmdline_unreadable"
eff, forward, reg_flag = {}, False, None
if argv:
    try:
        args = argv[1:]
        eff, occ = go_parse(args)
        raw_reg = sum(1 for a in args if re.fullmatch(r"--?peer-registry(=.*)?", a))
        raw_fwd = sum(1 for a in args if re.fullmatch(r"--?forward(=.*)?", a))
        if raw_reg != 1 or len(occ.get("peer-registry", [])) != 1:
            raise ValueError("peer_registry_not_exactly_once")
        if raw_fwd != 1 or len(occ.get("forward", [])) != 1:
            raise ValueError("forward_not_exactly_once")
        if eff.get("mode", "serve") != "serve":
            raise ValueError("mode_not_serve")
        want, _ = execstart_tokens(os.environ.get("L46_EXECSTART", ""))
        # The pid of the unit's main command is ExecMainPID, which a daemon-reload keeps.
        # The pid= field inside ExecStart is reset to 0 by one (the SSH recovery guard runs
        # one), so it cannot say whether MainPID is the process systemd started.
        main_pid = os.environ.get("L46_EXECMAINPID", "")
        if main_pid.isdigit() and int(main_pid) not in (0, pid):
            raise ValueError("execstart_pid_differs")
        if len(want) != len(argv) or os.path.basename(want[0]) != os.path.basename(argv[0]):
            raise ValueError("argv_differs_from_execstart")
        literal = set()          # positions that must be literal: the two relevant flags and the path
        for k, a in enumerate(args, start=1):
            if re.fullmatch(r"--?(peer-registry|forward)(=.*)?", a):
                literal.add(k)
                if a.lstrip("-") == "peer-registry":
                    literal.add(k + 1)
        for k in range(1, len(argv)):
            w, a = want[k], argv[k]
            if w == a:
                continue
            if k not in literal and re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", w):
                continue         # systemd expands ${VAR} to exactly one argument
            raise ValueError("argv_differs_from_execstart")
        forward = eff.get("forward") is True
        reg_flag = eff.get("peer-registry")
        argv_check = "ok"
    except ValueError as exc:
        argv_check = str(exc)
        eff, forward, reg_flag = {}, False, None
cidr, inner = eff.get("forward-cidr"), eff.get("inner-v4")
uid = gids = None
proc_start = sd_start = None
if pid > 0:
    try:
        for line in open(os.path.join(proc, str(pid), "status")):
            if line.startswith("Uid:"):
                uid = int(line.split()[1])
            elif line.startswith("Gid:"):
                gids = {int(line.split()[1])}
            elif line.startswith("Groups:"):
                gids = (gids or set()) | {int(g) for g in line.split()[1:]}
    except (OSError, ValueError):
        pass
    try:
        btime = next(int(l.split()[1]) for l in open(os.path.join(proc, "stat")) if l.startswith("btime "))
        fields = open(os.path.join(proc, str(pid), "stat")).read().rsplit(")", 1)[1].split()
        proc_start = btime + int(fields[19]) / os.sysconf("SC_CLK_TCK")   # field 22 of proc(5)
        if sd_mono:
            sd_start = btime + int(sd_mono) / 1e6
    except (OSError, ValueError, StopIteration, IndexError):
        pass
def path_problem(p):
    """'' when p is absolute, normalized, and no component from / down is a symlink."""
    if not p.startswith("/") or "//" in p or os.path.normpath(p) != p:
        return "path_not_absolute_normalized"
    parts = [c for c in p.split("/") if c]
    if any(c in (".", "..") for c in parts):
        return "path_not_absolute_normalized"
    cur = ""
    for i, part in enumerate(parts):
        cur += "/" + part
        try:
            st_c = os.lstat(cur)
        except OSError:
            return "path_component_missing"
        if stat.S_ISLNK(st_c.st_mode):
            return "symlink_in_path"
        if i < len(parts) - 1 and not stat.S_ISDIR(st_c.st_mode):
            return "parent_not_directory"
    return ""


expect_uid = int(os.environ.get("L46_EXPECT_UID", "0"))
if not os.path.lexists(path):
    print(f"V3_FILE absent")
else:
    problem = path_problem(path)
    if not problem and reg_flag is not None and reg_flag != path:
        problem = "flag_path_not_literally_equal"
    st = os.lstat(path)
    raw = b""
    if not problem:
        fd = -1
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
            fst = os.fstat(fd)
            if (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino):
                problem = "changed_during_check"
            elif not stat.S_ISREG(fst.st_mode):
                problem = "not_regular_file"
            elif fst.st_nlink != 1:
                problem = "hard_linked"
            elif fst.st_uid != expect_uid:
                problem = "wrong_owner"
            elif stat.S_IMODE(fst.st_mode) != 0o640:
                problem = "wrong_mode"
            else:
                chunks = []
                while True:
                    b = os.read(fd, 65536)
                    if not b or sum(len(c) for c in chunks) > 1024 * 1024:
                        break
                    chunks.append(b)
                raw = b"".join(chunks)
                after = os.lstat(path)
                if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                        != (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)):
                    problem = "changed_during_check"
                    raw = b""
        except OSError:
            problem = "open_failed"
        finally:
            if fd >= 0:
                os.close(fd)
    if problem:
        bad = True
    regular = stat.S_ISREG(st.st_mode) and not problem
    readable = None
    if uid is not None and gids is not None:
        m = st.st_mode
        readable = int((uid == st.st_uid and m & 0o400 != 0) or (st.st_gid in gids and m & 0o040 != 0)
                       or (m & 0o004 != 0) or uid == 0)
    print(f"V3_FILE present sha256={hashlib.sha256(raw).hexdigest()} size={len(raw)} "
          f"mode={oct(st.st_mode & 0o7777)} regular={int(regular)} age_s={int(time.time() - st.st_mtime)} "
          f"path_check={problem or 'ok'}")
    reason = "ok"
    entries = []
    try:
        if not regular or len(raw) > 1024 * 1024:
            raise ValueError("not_bounded_regular_file")
        doc = json.loads(raw.decode("utf-8"))
        if not isinstance(doc, dict) or set(doc) - {"version", "peers"}:
            raise ValueError("unknown_top_level_field")
        if doc.get("version") != 1:
            raise ValueError("version_not_1")
        peers = doc.get("peers")
        if peers is None:
            peers = []
        if not isinstance(peers, list):
            raise ValueError("peers_not_list")
        net = ipaddress.ip_network(cidr, strict=False) if cidr else None
        seen_k, seen_a = set(), set()
        for p in peers:
            if not isinstance(p, dict) or set(p) - {"static_public", "inner_v4", "not_after", "tier"}:
                raise ValueError("unknown_entry_field")
            # The optional tier word (cmd/winn3-gateway peer_registry.go): the
            # hub writes it only for a node whose binary reported
            # peer-registry-tier, omitted means premium, and it is never
            # anything but the two words. A service class, not an identity.
            if "tier" in p and p["tier"] not in ("free", "premium"):
                raise ValueError("invalid_traffic_tier")
            na = p.get("not_after")
            if not isinstance(na, int) or isinstance(na, bool) or na < 0:
                raise ValueError("invalid_not_after")
            key = str(p.get("static_public") or "")
            if len(base64.b64decode(key, validate=True)) != 32:
                raise ValueError("invalid_static_public")
            addr = ipaddress.IPv4Address(str(p.get("inner_v4")))
            if str(addr) != p.get("inner_v4"):
                raise ValueError("non_canonical_inner_v4")
            if net is not None and (addr not in net or addr in (net.network_address, net.broadcast_address)):
                raise ValueError("inner_v4_outside_pool")
            if inner and str(addr) == inner:
                raise ValueError("inner_v4_is_gateway_address")
            if key in seen_k or addr in seen_a:
                raise ValueError("duplicate_key_or_address")
            seen_k.add(key); seen_a.add(addr)
            entries.append((key, na))
    except Exception as exc:
        reason = str(exc) if isinstance(exc, ValueError) and str(exc).isidentifier() else "unparseable"
    now = int(time.time())
    for key, na in entries:
        print("V3PEER", d16(key), "0" if na == 0 else ("future" if na > now else "past"))
    print(f"V3_VALID gateway_rules={reason} pool_known={int(bool(cidr))}")
    if reason != "ok":
        bad = True
    changed = max(st.st_mtime, st.st_ctime)
    if proc_start is None or sd_start is None:
        started_after = "unknown"
    else:
        started_after = int(proc_start - changed > 1.0 and sd_start - changed > 1.0)
    print(f"GW unit={active} pid_known={int(pid > 0 and argv is not None and bool(argv))} forward={int(forward)} "
          f"argv_check={argv_check} "
          f"registry_flag_matches={int(reg_flag is not None and reg_flag == path and not problem)} "
          f"gateway_can_read={readable if readable is not None else 'unknown'} started_after_file={started_after} "
          f"reload_failed_since_file={reload_failed}")
    sys.exit(1 if bad else 0)
print(f"GW unit={active} pid_known={int(pid > 0 and bool(argv))} forward={int(forward)} argv_check={argv_check} "
      f"registry_flag_matches=0 gateway_can_read=unknown started_after_file=unknown "
      f"reload_failed_since_file={reload_failed}")
sys.exit(1 if bad else 0)
L46_NODE_CHECK_PY
exit $rc
