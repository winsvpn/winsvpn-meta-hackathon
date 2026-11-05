#!/bin/bash
set -euo pipefail

if [[ -d /sys/devices/system/cpu/cpu0/cpufreq ]]; then
  for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > "${g}" 2>/dev/null || true
  done
fi
if [[ -w /sys/devices/system/cpu/cpufreq/boost ]]; then
  echo 1 > /sys/devices/system/cpu/cpufreq/boost || true
fi

if [[ -w /sys/module/pcie_aspm/parameters/policy ]]; then
  echo performance > /sys/module/pcie_aspm/parameters/policy 2>/dev/null || true
fi

if command -v powerprofilesctl >/dev/null 2>&1; then
  powerprofilesctl set performance 2>/dev/null || true
fi

if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi -pm 1 >/dev/null 2>&1 || true
fi

/usr/local/sbin/nic-perf.sh enp3s0 || true
for w in /sys/class/net/wl* /sys/class/net/wlan*; do
  [[ -e "${w}" ]] || continue
  [[ -d "${w}" ]] || continue
  /usr/local/sbin/nic-perf.sh "$(basename "${w}")" || true
done
if command -v iw >/dev/null 2>&1; then
  iw reg set US 2>/dev/null || true
fi
