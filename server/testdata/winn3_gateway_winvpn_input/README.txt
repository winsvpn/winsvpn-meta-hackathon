`iptables -S WINVPN-INPUT` (the -A lines only) read on 2026-09-26 at 22:44 UTC
from uk-gb1, germany-de1, canada-ca1 and france-fr1 by lane L76, read-only.
The capture masked every IPv4 literal; these chains carry none. Every node
has the Round SU probe jump in slot 3; canada also has the Round EX2 TCP 443
ACCEPT at position 7. wins_winn3_gateway_install_su_probe_layout_test.sh runs
the gateway's boot helper against each of them.
