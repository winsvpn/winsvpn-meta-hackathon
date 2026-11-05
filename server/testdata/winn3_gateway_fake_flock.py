#!/usr/bin/env python3
"""Test stand-in for util-linux flock(1), file-descriptor form only.

    flock [-x|-s] [-n | -w SECONDS] FD
    flock -u FD

Like flock(1) it locks the open file description behind FD, which the calling
shell keeps open, so the lock outlives this process exactly as the real one
does and is released when the caller closes FD or exits. Exit 1 when the lock
is not obtained in time, 64 on a usage error. The gateway suites install it as
`flock` because macOS ships no flock(1); on Linux it stands in for the real
one so every host runs the same code.
"""
import fcntl
import sys
import time

args = sys.argv[1:]
mode, wait, unlock = fcntl.LOCK_EX, None, False
while len(args) > 1:
    arg = args.pop(0)
    if arg in ("-x", "-e", "--exclusive"):
        mode = fcntl.LOCK_EX
    elif arg in ("-s", "--shared"):
        mode = fcntl.LOCK_SH
    elif arg in ("-u", "--unlock"):
        unlock = True
    elif arg in ("-n", "--nonblock"):
        wait = 0.0
    elif arg in ("-w", "--timeout") and args:
        wait = float(args.pop(0))
    else:
        sys.exit(64)
if len(args) != 1 or not args[0].isdigit():
    sys.exit(64)
fd = int(args[0])
if unlock:
    fcntl.flock(fd, fcntl.LOCK_UN)
    sys.exit(0)
deadline = None if wait is None else time.monotonic() + wait
while True:
    try:
        fcntl.flock(fd, mode | fcntl.LOCK_NB)
        sys.exit(0)
    except BlockingIOError:
        if deadline is not None and time.monotonic() >= deadline:
            sys.exit(1)
        time.sleep(0.05)
