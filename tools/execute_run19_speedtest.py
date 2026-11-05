#!/usr/bin/env python3
"""Speedtest Run 19 Hardware Verification Execution Script.

Executes two-iteration Speedtest on physical Samsung Galaxy S26 Ultra (REDACTED_SERIAL)
testing Stage D (socket.sendBufferSize = 1_048_576, lowWater = 16, immediate batch flush).
Captures screenshots, UI cards, logcat telemetry, and /proc/net/dev counters.
Strictly zero em/en dashes as connectors. Strictly zero AI cliches.
"""

import subprocess
import time
import os
import re
import xml.etree.ElementTree as ET

SERIAL = "REDACTED_SERIAL"
BRAIN_DIR = "/Users/owner/.gemini/antigravity/brain/507905dd-68a2-419e-bdfd-ceb8407e5e8c"

def run_adb(args):
    cmd = ["adb", "-s", SERIAL] + args
    res = subprocess.run(cmd, capture_output=True, text=True)
    return res.stdout.strip()

def screencap(filename):
    path = os.path.join(BRAIN_DIR, filename)
    subprocess.run(f"adb -s {SERIAL} exec-out screencap -p > {path}", shell=True, check=True)
    print(f"Captured {filename}")

def dump_ui():
    run_adb(["shell", "uiautomator", "dump", "/sdcard/window_dump.xml"])
    xml_str = run_adb(["shell", "cat", "/sdcard/window_dump.xml"])
    return xml_str

def find_speedtest_button(xml_str):
    root = ET.fromstring(xml_str)
    for node in root.iter("node"):
        desc = node.attrib.get("content-desc", "")
        if desc == "Speedtest":
            bounds = node.attrib.get("bounds", "")
            m = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
            if m:
                x1, y1, x2, y2 = map(int, m.groups())
                return (x1 + x2) // 2, (y1 + y2) // 2
    return None

def parse_speedtest_card(xml_str):
    root = ET.fromstring(xml_str)
    for node in root.iter("node"):
        desc = node.attrib.get("content-desc", "")
        if "Download" in desc and "Upload" in desc:
            return desc
    return ""

def run_single_iteration(prefix, iter_num):
    print(f"\n==============================")
    print(f"STARTING ITERATION {iter_num} ({prefix})")
    print(f"==============================")
    screencap(f"{prefix}_pretest.png")
    
    xml = dump_ui()
    btn = find_speedtest_button(xml)
    if not btn:
        print(f"ERROR: Speedtest button not found for iteration {iter_num}!")
        return None
    print(f"Speedtest button at: {btn}")
    
    initial_card = parse_speedtest_card(xml)
    print(f"Initial card: {initial_card!r}")
    
    print(f"Tapping Speedtest button for iteration {iter_num}...")
    run_adb(["shell", "input", "tap", str(btn[0]), str(btn[1])])
    
    print("Waiting for test to engage...")
    for _ in range(12):
        time.sleep(0.5)
        cur_xml = dump_ui()
        card = parse_speedtest_card(cur_xml)
        if "Testing" in card or card != initial_card:
            print(f"Test engaged: {card!r}")
            break
            
    # Download phase runs for ~0-9 seconds
    time.sleep(4.0)
    print("Capturing download phase in flight...")
    screencap(f"{prefix}_dl.png")
    
    # Upload phase starts around 10s into the test
    time.sleep(7.5)
    print("Capturing upload phase in flight...")
    screencap(f"{prefix}_ul.png")
    
    # Wait for completion
    print("Waiting for test completion...")
    final_card = ""
    for i in range(25):
        time.sleep(1.0)
        xml = dump_ui()
        card = parse_speedtest_card(xml)
        print(f"Polling ({i}s): {card!r}")
        if "Last VPN test" in card:
            print(f"Iteration {iter_num} completed: {card!r}")
            final_card = card
            break
            
    time.sleep(1.0)
    screencap(f"{prefix}_final.png")
    final_xml = dump_ui()
    final_card = parse_speedtest_card(final_xml)
    print(f"Final card for iteration {iter_num}: {final_card!r}")
    return final_card

def main():
    print("Clearing logcat...")
    run_adb(["logcat", "-c"])
    
    # Check initial /proc/net/dev
    netdev_pre = run_adb(["shell", "cat", "/proc/net/dev"])
    print("Initial /proc/net/dev:")
    for line in netdev_pre.splitlines():
        if any(iface in line for iface in ["tun0", "tun1", "wlan0"]):
            print("  " + line)
            
    # Iteration 1
    res1 = run_single_iteration("s26_run19", 1)
    
    print("\nWaiting 6 seconds before iteration 2...")
    time.sleep(6.0)
    
    # Iteration 2
    res2 = run_single_iteration("s26_run19_iter2", 2)
    
    print("\n==============================")
    print("POST-TEST TELEMETRY & DIAGNOSTICS")
    print("==============================")
    
    # Logcat extract
    logs = run_adb(["logcat", "-d", "-v", "time", "-s", "WinnUpload:V", "winn:V", "WinnDatapath:V", "GoLog:V"])
    print("Logcat upload & engine messages:")
    for line in logs.splitlines():
        if any(tag in line for tag in ["WinnUpload", "sndbuf", "winn-debug", "carrier", "rx_packets", "tx_packets"]):
            print("  " + line)
            
    # Check post /proc/net/dev
    netdev_post = run_adb(["shell", "cat", "/proc/net/dev"])
    print("\nFinal /proc/net/dev:")
    for line in netdev_post.splitlines():
        if any(iface in line for iface in ["tun0", "tun1", "wlan0"]):
            print("  " + line)
            
    print(f"\nIteration 1 Result: {res1}")
    print(f"Iteration 2 Result: {res2}")

if __name__ == "__main__":
    main()
