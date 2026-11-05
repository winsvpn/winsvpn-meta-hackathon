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

def main():
    print("Pre-test state check...")
    screencap("s26_run18_pretest.png")
    
    xml = dump_ui()
    btn = find_speedtest_button(xml)
    if not btn:
        print("ERROR: Speedtest button not found in UI dump!")
        return
    print(f"Speedtest button center at: {btn}")
    
    initial_card = parse_speedtest_card(xml)
    print(f"Initial card: {initial_card!r}")
    
    # Tap Speedtest button
    print("Tapping Speedtest button...")
    run_adb(["shell", "input", "tap", str(btn[0]), str(btn[1])])
    
    # Wait for test to start
    print("Waiting for test to engage...")
    for _ in range(10):
        time.sleep(0.5)
        cur_xml = dump_ui()
        card = parse_speedtest_card(cur_xml)
        if "Testing" in card or card != initial_card:
            print(f"Test engaged: {card!r}")
            break
            
    # Download phase runs for ~0-9 seconds
    time.sleep(4.0)
    print("Capturing download phase in flight...")
    screencap("s26_run18_dl.png")
    
    # Upload phase starts around 10s into the test
    time.sleep(7.5)
    print("Capturing upload phase in flight...")
    screencap("s26_run18_ul.png")
    
    # Wait for completion (total test ~20-25s)
    print("Waiting for test completion...")
    for i in range(25):
        time.sleep(1.0)
        xml = dump_ui()
        card = parse_speedtest_card(xml)
        print(f"Polling ({i}s): {card!r}")
        if "Last VPN test" in card:
            print(f"Speedtest completed: {card!r}")
            break
            
    time.sleep(1.0)
    screencap("s26_run18_final.png")
    final_xml = dump_ui()
    print("Final UI card:")
    print(parse_speedtest_card(final_xml))

if __name__ == "__main__":
    main()
