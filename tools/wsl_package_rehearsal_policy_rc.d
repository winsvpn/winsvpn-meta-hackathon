#!/bin/sh
# Package-only WSL rehearsals share host ports with Windows services. Prevent
# maintainer scripts from starting/restarting daemons while dpkg is being
# exercised; production VPS deployments must not install this policy.
exit 101
