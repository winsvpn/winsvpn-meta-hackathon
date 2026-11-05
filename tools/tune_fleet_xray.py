#!/usr/bin/env python3
import json
import subprocess
import sys

TARGET_HOSTS = [
    "chicago-mgmt",
    "germany-mgmt",
    "netherlands-mgmt",
    "france-mgmt",
    "singapore-mgmt",
    "uk-mgmt",
    "oregon-mgmt",
]

REMOTE_SCRIPT = r"""python3 - << 'EOF'
import json
import subprocess
import sys
import re

# 1. Determine bufferSize based on RAM
total_mem_kb = 8388608
try:
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith('MemTotal:'):
                total_mem_kb = int(line.split()[1])
                break
except Exception:
    pass

xray_buf = 4096
if total_mem_kb < 2000000:
    xray_buf = 1024
elif total_mem_kb < 4000000:
    xray_buf = 2048

print(f"Total Mem: {total_mem_kb} KB, XRay buffer size: {xray_buf} KiB")

# 2. Update /usr/local/etc/xray/config.json
xray_path = '/usr/local/etc/xray/config.json'
with open(xray_path, 'r', encoding='utf-8') as f:
    cfg = json.load(f)

# Policy tuning
policy = cfg.setdefault('policy', {})
levels = policy.setdefault('levels', {})
lvl0 = levels.setdefault('0', {})
lvl0['handshake'] = 4
lvl0['connIdle'] = 300
lvl0['uplinkOnly'] = 2
lvl0['downlinkOnly'] = 5
lvl0['bufferSize'] = xray_buf

policy['system'] = {
    'statsInboundUplink': False,
    'statsInboundDownlink': False,
    'statsOutboundUplink': False,
    'statsOutboundDownlink': False,
}

# Inbound sockopt
for ib in cfg.get('inbounds', []):
    stream = ib.setdefault('streamSettings', {})
    sockopt = stream.setdefault('sockopt', {})
    sockopt['tcpNoDelay'] = True
    sockopt['tcpCongestion'] = 'bbr'

# Outbound sockopt
for ob in cfg.get('outbounds', []):
    stream = ob.setdefault('streamSettings', {})
    sockopt = stream.setdefault('sockopt', {})
    sockopt['tcpNoDelay'] = True

test_file = '/tmp/xray_test_config.json'
with open(test_file, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2)

res = subprocess.run(['/usr/local/bin/xray', 'run', '-test', '-config', test_file], capture_output=True, text=True)
if res.returncode != 0:
    print(f"XRay test failed: {res.stderr or res.stdout}", file=sys.stderr)
    sys.exit(1)

# Write to live config and backup
subprocess.run(['cp', xray_path, xray_path + '.bak_speed'], check=True)
with open(xray_path, 'w', encoding='utf-8') as f:
    json.dump(cfg, f, indent=2)

# Restart XRay
subprocess.run(['systemctl', 'restart', 'xray'], check=True)
print("XRay updated and restarted successfully.")

# 3. Update Nginx configuration
nginx_conf = '/etc/nginx/sites-available/wins-node.conf'
try:
    with open(nginx_conf, 'r', encoding='utf-8') as f:
        content = f.read()

    if 'proxy_buffers 8 128k;' not in content:
        subprocess.run(['cp', nginx_conf, nginx_conf + '.bak_speed'], check=True)
        # Insert proxy_buffer_size 128k; proxy_buffers 8 128k; proxy_busy_buffers_size 256k;
        # after proxy_buffering off;
        if 'proxy_buffering off;' in content:
            new_content = content.replace(
                'proxy_buffering off;',
                'proxy_buffering off;\n        proxy_buffer_size 128k;\n        proxy_buffers 8 128k;\n        proxy_busy_buffers_size 256k;'
            )
        else:
            new_content = content.replace(
                'proxy_pass http://127.0.0.1:10085;',
                'proxy_buffer_size 128k;\n        proxy_buffers 8 128k;\n        proxy_busy_buffers_size 256k;\n        proxy_pass http://127.0.0.1:10085;'
            )
        
        with open(nginx_conf, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        res = subprocess.run(['nginx', '-t'], capture_output=True, text=True)
        if res.returncode != 0:
            print(f"Nginx test failed: {res.stderr or res.stdout}, rolling back...", file=sys.stderr)
            subprocess.run(['cp', nginx_conf + '.bak_speed', nginx_conf], check=True)
            sys.exit(1)
        
        subprocess.run(['systemctl', 'reload', 'nginx'], check=True)
        print("Nginx updated and reloaded successfully.")
    else:
        print("Nginx already has tuned proxy buffers.")
except FileNotFoundError:
    print(f"Nginx config {nginx_conf} not found; skipping Nginx update.")

print("NODE TUNING COMPLETE.")
EOF
"""

def main():
    hosts = sys.argv[1:] if len(sys.argv) > 1 else TARGET_HOSTS
    for host in hosts:
        print(f"\n==================== Tuning {host} ====================")
        try:
            res = subprocess.run(
                ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", host, REMOTE_SCRIPT],
                capture_output=True,
                text=True,
                timeout=30,
            )
            print(res.stdout)
            if res.stderr:
                print(f"STDERR:\n{res.stderr}", file=sys.stderr)
            if res.returncode != 0:
                print(f"FAILED on {host} with code {res.returncode}")
            else:
                print(f"SUCCESS on {host}")
        except Exception as exc:
            print(f"EXCEPTION connecting to {host}: {exc}")

if __name__ == "__main__":
    main()
