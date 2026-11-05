"""The deterministic fd 9 trace judgement for `rotate-serving` (design v17 5.5, v11 fix 5, v12 fix 7, v13).

The trace is `strace -f -o FILE -e trace=openat,dup2,dup3,close,close_range,fcntl,flock` of the guard command, one
line per syscall, each prefixed with its PID (strace's -f form with -o). The rules, in the design's words:

  * The observation boundary is the exit, with status 0, of the dispatcher's `flock -x 9` utility process: a child of
    the guard's shell whose `flock(9, LOCK_EX)` returned 0.
  * Exactly one `flock(9, LOCK_EX)` appears before the boundary, in that utility process, and none appears after it
    in any process of the command's tree.
  * After the boundary, in the guard's own shell (ROOT_PID), no `close`, `close_range`, `dup2`, `dup3` or
    `fcntl(F_DUPFD)` onto fd 9, and no `openat` of the lock file. Closes of inherited copies in child processes are
    not counted, and the dispatcher's own `exec 9<>` before the boundary is not counted.

usage: s7_fd9_trace.py TRACE ROOT_PID LOCK_FILE   (prints a JSON verdict; exit 0 on pass, 1 on fail, 2 unreadable)
"""
import json
import re
import sys

LINE = re.compile(r"^(\d+)\s+(.*)$")
CALL = re.compile(r"^([a-z_0-9]+)\((.*)$")
RESUMED = re.compile(r"^<\.\.\. ([a-z_0-9]+) resumed>(.*)$")
EXITED = re.compile(r"^\+\+\+ exited with (\d+) \+\+\+$")
RESULT = re.compile(r"\)\s*=\s*(-?\d+|\?)")


def parse(text):
    """[(index, pid, name, args, result)] with unfinished calls joined to their resumption; exits as name '+exit'."""
    events, pending = [], {}
    for index, raw in enumerate((text or "").splitlines()):
        match = LINE.match(raw.strip())
        if not match:
            continue
        pid, rest = int(match.group(1)), match.group(2).strip()
        exited = EXITED.match(rest)
        if exited:
            events.append((index, pid, "+exit", "", int(exited.group(1))))
            continue
        resumed = RESUMED.match(rest)
        if resumed:
            start = pending.pop((pid, resumed.group(1)), None)
            args = (start[1] if start else "") + resumed.group(2)
            result = RESULT.search(resumed.group(2))
            events.append((start[0] if start else index, pid, resumed.group(1), args,
                           None if not result or result.group(1) == "?" else int(result.group(1))))
            continue
        call = CALL.match(rest)
        if not call:
            continue
        name, args = call.group(1), call.group(2)
        if args.endswith("<unfinished ...>"):
            pending[(pid, name)] = (index, args[:-len("<unfinished ...>")])
            continue
        result = RESULT.search(args)
        events.append((index, pid, name, args, None if not result or result.group(1) == "?" else int(result.group(1))))
    for (pid, name), (index, args) in pending.items():
        events.append((index, pid, name, args, None))
    events.sort(key=lambda e: e[0])
    return events


def onto_fd9(name, args, result):
    if name == "close":
        return re.match(r"^\s*9\s*\)", args) is not None
    if name == "close_range":
        match = re.match(r"^\s*(\d+),\s*(\d+)", args)
        return bool(match and int(match.group(1)) <= 9 <= int(match.group(2)))
    if name in ("dup2", "dup3"):
        match = re.match(r"^\s*\d+,\s*(\d+)", args)
        return bool(match and int(match.group(1)) == 9)
    if name == "fcntl":
        return "F_DUPFD" in args and result == 9
    return False


def is_lock_ex_9(name, args):
    return name == "flock" and re.match(r"^\s*9,\s*LOCK_EX\b", args) is not None


def judge(text, root_pid, lock_file):
    events = parse(text)
    if not events:
        return {"pass": False, "reason": "empty or unreadable trace"}
    root_pid = int(root_pid)
    acquired = {}
    boundary = None
    for index, pid, name, args, result in events:
        if pid != root_pid and is_lock_ex_9(name, args) and result == 0:
            acquired[pid] = index
        if name == "+exit" and pid in acquired and result == 0 and boundary is None:
            boundary = (index, pid)
    if boundary is None:
        return {"pass": False, "reason": "no flock utility process acquired fd 9 and exited 0 (no boundary)"}
    b_index, utility = boundary
    problems = []
    before = [(i, p) for i, p, n, a, r in events if i < b_index and is_lock_ex_9(n, a)]
    if len(before) != 1 or before[0][1] != utility:
        problems.append("%d flock(9, LOCK_EX) before the boundary (want exactly one, in the utility process)" % len(before))
    if any(p == root_pid for _, p in before):
        problems.append("the guard's shell itself called flock(9, LOCK_EX)")
    after = [(i, p) for i, p, n, a, r in events if i > b_index and is_lock_ex_9(n, a)]
    if after:
        problems.append("a second flock(9, LOCK_EX) after the boundary, in pid %s" % sorted({p for _, p in after}))
    for index, pid, name, args, result in events:
        if index <= b_index or pid != root_pid:
            continue
        if onto_fd9(name, args, result):
            problems.append("the guard's shell ran %s onto fd 9 after the boundary: %s(%s" % (name, name, args[:80]))
        if name == "openat" and lock_file in args:
            problems.append("the guard's shell opened the lock file again after the boundary")
    return {"pass": not problems, "reason": "; ".join(problems) or "ok", "utility_pid": utility,
            "boundary_line": b_index, "acquisitions_before": len(before), "acquisitions_after": len(after)}


def main(argv):
    try:
        text = open(argv[1]).read()
    except OSError as exc:
        print(json.dumps({"pass": False, "reason": "unreadable trace: %s" % exc}))
        return 2
    verdict = judge(text, argv[2], argv[3])
    print(json.dumps(verdict, sort_keys=True))
    return 0 if verdict["pass"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
