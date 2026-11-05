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

def parse_speedtest_results(xml_str):
    match = re.search(r'content-desc="Download&#10;Upload&#10;([0-9.]+ Mbps|-- Mbps)&#10;([0-9.]+ Mbps|-- Mbps)&#10;(Ready|Testing\.\.\.|Finished)"', xml_str)
    if match:
        return match.group(1), match.group(2), match.group(3)
    # Fallback broader search
    desc_match = re.findall(r'content-desc="([^"]*Mbps[^"]*)"', xml_str)
    return desc_match

def main():
    print("Pre-test state check...")
    screencap("s26_run17_pretest.png")
    
    # Tap Speedtest button at (390, 2205)
    print("Tapping Speedtest button...")
    run_adb(["shell", "input", "tap", "390", "2205"])
    
    # Download phase runs for ~0-9 seconds
    time.sleep(4.0)
    print("Capturing download phase...")
    screencap("s26_run17_iter2_dl.png")
    
    # Upload phase starts around 10s in
    time.sleep(7.5)
    print("Capturing upload phase in flight...")
    screencap("s26_run17_iter2_ul.png")
    
    # Wait for completion (total test ~18-20s)
    print("Waiting for test completion...")
    for i in range(15):
        time.sleep(1.0)
        xml = dump_ui()
        res = parse_speedtest_results(xml)
        print(f"Polling ({i}s): {res}")
        if isinstance(res, tuple) and len(res) == 3 and res[2] == "Ready" and res[0] != "-- Mbps":
            print(f"Speedtest finished! Results: DL {res[0]}, UL {res[1]}")
            break
        elif isinstance(res, list) and any("Ready" in x or "Last VPN test" in x for x in res):
            if any("Last VPN test" in x for x in res):
                print(f"Found completed state: {res}")
                break
            
    time.sleep(1.0)
    screencap("s26_run17_iter2_final.png")
    final_xml = dump_ui()
    print("Final UI dump result:")
    print(parse_speedtest_results(final_xml))

if __name__ == "__main__":
    main()
