# If this computer has no internet after using Win's VPN

**Read this first: your account has not been blocked, and nobody has cut you
off.** What has almost certainly happened is that a firewall rule stayed behind
on *this computer* after the VPN stopped. It is a setting on your own machine.
Nothing was reported about you, and nothing was disabled from outside.

You can tell this is what happened if **all** of these are true:

- websites and apps fail instantly rather than slowly timing out;
- you also cannot reach your own Wi-Fi router's settings page;
- other people on the same Wi-Fi are fine.

This document is stored on your computer, so you can read it with no internet:

    /opt/wins-vpn/share/doc/wins-vpn/RECOVERY.md

---

## Step 1 — try the app first. This fixes it in almost every case.

1. Open Win's VPN.
2. Press **Disconnect** (even if it already looks disconnected).

That is the whole fix. The app is allowed to remove its own leftover rules and
will do so automatically, including rules left behind by a restart. Pressing
**Connect** works too — starting a new session clears the old rules first.

If your internet comes back, you are done. You do not need Step 2.

---

## Step 2 — only if Step 1 did not work

Open a terminal. You can usually do this by pressing **Ctrl+Alt+T**, or by
searching your applications menu for "Terminal".

Type these eight lines, one at a time, pressing Enter after each. If you are asked
for your password, type it and press Enter — the password will not appear on
screen as you type, which is normal.

    sudo iptables -F WINSVPN_KS
    sudo ip6tables -F WINSVPN_KS
    sudo iptables -F WINSVPN_KS3
    sudo ip6tables -F WINSVPN_KS3
    sudo iptables -F WINSVPN_RGA
    sudo ip6tables -F WINSVPN_RGA
    sudo iptables -F WINSVPN_RGB
    sudo ip6tables -F WINSVPN_RGB

**Most of these will print `No chain/target/match by that name`. That is
normal and it is not an error you need to fix** — it only means that particular
rule was not on your computer. Type all eight regardless of what the earlier ones
say.

Or run the single command `sudo systemctl start winsvpn-recover.service`.

Your internet should work again as soon as the eight lines are done. Check with:

    ping -c 3 1.1.1.1

If you see replies, your connection is back.

---

## Step 3 — tidy up (optional, but do it if you can)

Step 2 stops the rules from blocking anything, but leaves the empty shells
behind. To remove them completely, type these lines. Again, ignore any
`No chain/target/match by that name` or `Bad rule` messages.

    sudo iptables  -D OUTPUT -m comment --comment winsvpn-killswitch -j WINSVPN_KS
    sudo ip6tables -D OUTPUT -m comment --comment winsvpn-killswitch -j WINSVPN_KS
    sudo iptables  -X WINSVPN_KS
    sudo ip6tables -X WINSVPN_KS

    sudo iptables  -D OUTPUT -m comment --comment winsvpn-killswitch3 -j WINSVPN_KS3
    sudo ip6tables -D OUTPUT -m comment --comment winsvpn-killswitch3 -j WINSVPN_KS3
    sudo iptables  -X WINSVPN_KS3
    sudo ip6tables -X WINSVPN_KS3

    sudo iptables  -D OUTPUT -m comment --comment winsvpn-reconnect-guard -j WINSVPN_RGA
    sudo ip6tables -D OUTPUT -m comment --comment winsvpn-reconnect-guard -j WINSVPN_RGA
    sudo iptables  -X WINSVPN_RGA
    sudo ip6tables -X WINSVPN_RGA

    sudo iptables  -D OUTPUT -m comment --comment winsvpn-reconnect-guard -j WINSVPN_RGB
    sudo ip6tables -D OUTPUT -m comment --comment winsvpn-reconnect-guard -j WINSVPN_RGB
    sudo iptables  -X WINSVPN_RGB
    sudo ip6tables -X WINSVPN_RGB

The `-D` lines must be typed exactly as written, including the
`-m comment --comment ...` part. Without it they will say `Bad rule` and do
nothing.

---

## Step 4 — stop it coming back after a restart

Some computers save firewall rules and restore them at every startup. If yours
does, the rules could return the next time you restart. To save the cleaned-up
state, run:

    sudo netfilter-persistent save

If that command is not found, your computer does not save firewall rules and
there is nothing more to do.

---

## If none of this worked

The problem is something else, and none of these steps have made it worse.
Restart the computer and try again — on most systems the rules do not survive a
restart at all.

---

## What these rules are for

While the VPN is connected, Win's VPN installs a rule that blocks traffic trying
to leave your computer *outside* the tunnel. That is deliberate: it is what
stops your real location from leaking if the VPN drops. It is meant to be
removed the moment you disconnect. This document exists for the rare case where
it was not.

Standalone v3 uses WINSVPN_KS3 with the winsvpn-killswitch3 ownership tag. The recovery script removes only this owned chain.

Uninstall system files with `sudo /opt/wins-vpn/install.sh --uninstall-all`. User data is removed only with `--purge-user-data [USER...]`; residual paths and identities return a nonzero status. The release-signing key under /etc/winsvpn remains available to the bootstrap.
