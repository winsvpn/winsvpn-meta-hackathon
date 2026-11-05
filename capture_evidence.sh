#!/bin/bash
# Evidence capture for the XPRIZE demo. Run at each demo stage.
# Usage: ./capture_evidence.sh <stage-name>
STAGE="${1:-stage}"
DIR=$HOME/xprize/evidence/$STAGE
mkdir -p "$DIR"
adb exec-out screencap -p > "$DIR/screen.png" 2>/dev/null
adb shell dumpsys connectivity 2>/dev/null | grep -iE "active network|vpn" | head -5 > "$DIR/connectivity.txt"
curl -s -m 8 https://api.ipify.org > "$DIR/public_ip.txt" 2>/dev/null
curl -s -m 10 https://AI_ROUTER_HOST/decisions > "$DIR/router_decisions.json" 2>/dev/null
grep -iE "winn3|winn/3|descriptor|gate|handshake|carrying|promotion" $HOME/xprize/evidence/phone_logcat.txt | tail -30 > "$DIR/winn3_log_tail.txt" 2>/dev/null
echo "captured $STAGE: $(ls "$DIR" | wc -l) files, ip=$(cat "$DIR/public_ip.txt" 2>/dev/null)"
