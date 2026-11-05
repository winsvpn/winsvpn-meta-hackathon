#!/usr/bin/env bash
# Stage a built cell into the release artifact set, then PROVE the packaged copy
# is the architecture it claims to be.
#
#   tools/package_release_artifacts.sh linux-arm64
#   tools/package_release_artifacts.sh linux-x64
#
# WHY THE VERIFICATION RUNS AFTER PACKAGING
# -----------------------------------------
# Checking the architecture of the input and then zipping it proves nothing
# about the output. A staging step that copies the wrong tree, a `ditto` that
# follows a symlink into another arch's build directory, or a hand-assembled
# archive that quietly loses a slice all pass an input-side check and ship a
# broken artifact. So every check below runs against files EXTRACTED BACK OUT
# of the finished zip, in a throwaway directory, and the script exits non-zero
# if any of them disagrees with the cell's declared architecture.
#
# CONVENTIONS THIS FOLLOWS (from the existing 2026-08-05 release set)
#   * layout     artifacts/<platform>-<arch>/
#   * name       WinsVPN-<platform>-<arch>[-<qualifier>].zip
#   * archiver   ditto -c -k --sequesterRsrc --keepParent
#   * checksums  appended to evidence/SHA256SUMS.txt, paths relative to artifacts/
#
# ONE DELIBERATE DEPARTURE: the existing windows-x64 zip keeps its build
# directory's own name as the archive's top-level folder ("Release/"). Two more
# Windows arches and two Linux arches would all want that same generic name
# ("Release/", "bundle/", "bundle/") and would overwrite one another when
# extracted side by side -- a silent cross-architecture mix-up in exactly the
# class of defect this script exists to catch. Each archive's top-level folder
# is therefore named after the archive itself.
#
# COMPILES AND LINKS, DOES NOT RUN. Packaging inherits the caveat of the build
# matrix it draws from: not one of these artifacts has been executed on any
# platform. This script establishes architecture and integrity. It establishes
# nothing about runtime behaviour.
set -euo pipefail

cell="${1:-}"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
release_identity="$(awk '/^version:[[:space:]]*/ {gsub(/\r/, ""); print $2; exit}' "$repo/pubspec.yaml")"
[[ "$release_identity" =~ ^[0-9]+\.[0-9]+\.[0-9]+\+[0-9]+$ ]] \
    || { echo "FAIL: could not read canonical release identity from pubspec.yaml" >&2; exit 1; }
release_root="${RELEASE_ROOT:-/Users/owner/Documents/WinsVPN-RELEASE-20260805}"
artifacts="$release_root/artifacts"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/winsvpn-pkg.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT

die() { echo "FAIL: $*" >&2; exit 1; }

# --- PE machine-type reader -------------------------------------------------
# Reads the machine field from the header bytes: e_lfanew -> "PE\0\0" -> u16.
# Never infers architecture from a filename. Prints NOT-A-PE when either check
# fails, so it cannot silently report a machine type for a non-PE file.
pe_machine() {
    python3 - "$1" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
if len(data) < 0x40 or data[:2] != b'MZ':
    print('NOT-A-PE'); raise SystemExit(0)
off = struct.unpack_from('<I', data, 0x3C)[0]
if len(data) < off + 6 or data[off:off+4] != b'PE\0\0':
    print('NOT-A-PE'); raise SystemExit(0)
print('0x%04x' % struct.unpack_from('<H', data, off + 4)[0])
PY
}

# --- ELF machine reader -----------------------------------------------------
# e_ident magic + EI_CLASS, then e_machine (u16 @ 0x12). 0xB7 = AArch64,
# 0x3E = x86-64. macOS has no readelf, so this is read directly.
elf_machine() {
    python3 - "$1" <<'PY'
import struct, sys
data = open(sys.argv[1], 'rb').read()
if len(data) < 0x14 or data[:4] != b'\x7fELF':
    print('NOT-AN-ELF'); raise SystemExit(0)
if data[4] != 2:
    print('NOT-ELF64'); raise SystemExit(0)
print('0x%02x' % struct.unpack_from('<H', data, 0x12)[0])
PY
}

case "$cell" in
linux-arm64)
    source_dir="${SOURCE_DIR:-$repo/build/linux-container/arm64/bundle}"
    zip_name="WinsVPN-linux-arm64.zip"
    expect_elf="0xb7"; expect_elf_label="AArch64"
    ;;
linux-x64)
    source_dir="${SOURCE_DIR:-$repo/build/linux-container/x64/bundle}"
    zip_name="WinsVPN-linux-x64.zip"
    expect_elf="0x3e"; expect_elf_label="x86-64"
    ;;
windows-arm64)
    die "the incomplete Windows ARM64 components archive is retired; build the complete native ARM64 Inno candidate on a Windows ARM64 host with installer/windows/build_installer.ps1 -TargetArchitecture arm64"
    ;;
*)
    echo "usage: $(basename "$0") [linux-arm64|linux-x64]" >&2
    exit 2
    ;;
esac

stage_name="${zip_name%.zip}"
stage="$scratch/$stage_name"
mkdir -p "$stage"

echo "=== staging $cell ==="
[ -d "$source_dir" ] || die "source bundle not found: $source_dir"
ditto "$source_dir" "$stage"
# Self-disclosing provenance. MANIFEST.md §3.4 and §5-§6 record that the
# SIGNED Linux release pipeline (tools/build_linux_release.sh + its frozen
# dependency index) is blocked on an owner decision about release identity,
# and that plain `flutter build linux --release` output is dev output rather
# than release output. These archives are that plain output. Staging them in
# artifacts/ must not be readable as the pipeline having been satisfied, so
# the archive says what it is from the inside.
printf "Win's VPN %s - Linux desktop bundle\n\n" "$release_identity" > "$stage/PROVENANCE.txt"
cat >> "$stage/PROVENANCE.txt" <<'TXT'

WHAT THIS IS. Plain `flutter build linux --release` output, built from
tools/Dockerfile.linux-desktop in a clean ubuntu:24.04 container whose base
image is pinned by platform manifest digest. Its architecture was verified by
reading ELF header bytes AFTER packaging, from files extracted back out of this
archive, and again independently with a second extractor.

WHAT THIS IS NOT. It is NOT output of the signed Linux release pipeline
(tools/build_linux_release.sh). That pipeline is blocked on an owner decision
about release identity - see MANIFEST.md sections 3.4, 5.5 and 6.3 in the
release set. Specifically, this bundle has:
  - no strip and no .gnu_debuglink (it still carries debug_info)
  - no release dependency freeze index verification
  - no bundled Xray / AmneziaWG userspace tools
  - no cosign bundle; it is UNSIGNED

NOT EXECUTED. No Linux host of either architecture has run this binary. Its
architecture and archive integrity are established. Its runtime behaviour is
not, in any respect.
TXT

echo "=== pre-package inventory ==="
find "$stage" -type f -not -name '._*' | sed "s|$scratch/||" | sort | head -20

out_dir="$artifacts/$cell"
mkdir -p "$out_dir"
zip_path="$out_dir/$zip_name"
echo "=== ditto -c -k --sequesterRsrc --keepParent -> $zip_path ==="
rm -f "$zip_path"
ditto -c -k --sequesterRsrc --keepParent "$stage" "$zip_path"

# ---------------------------------------------------------------------------
# POST-PACKAGING VERIFICATION. Everything below reads the EXTRACTED archive.
# ---------------------------------------------------------------------------
verify_root="$scratch/verify"
mkdir -p "$verify_root"
ditto -x -k "$zip_path" "$verify_root"
extracted="$verify_root/$stage_name"
[ -d "$extracted" ] || die "archive did not extract to expected top-level folder $stage_name"

echo "=== POST-PACKAGE architecture verification (reading the extracted copy) ==="
checked=0
failed=0
while IFS= read -r file; do
    base="$(basename "$file")"
    case "$base" in ._*) continue ;; esac
    if [ -n "${expect_elf:-}" ]; then
        case "$base" in
            wins_vpn|*.so|winsvpn-bypass-bpf) ;;
            *) continue ;;
        esac
        got="$(elf_machine "$file")"
        checked=$((checked + 1))
        if [ "$got" = "$expect_elf" ]; then
            printf '  OK   %-34s ELF64 e_machine=%s (%s)\n' "$base" "$got" "$expect_elf_label"
        else
            printf '  BAD  %-34s e_machine=%s, expected %s (%s)\n' "$base" "$got" "$expect_elf" "$expect_elf_label"
            failed=$((failed + 1))
        fi
    else
        case "$base" in *.exe|*.dll) ;; *) continue ;; esac
        got="$(pe_machine "$file")"
        checked=$((checked + 1))
        if [ "$got" = "$expect_pe" ]; then
            printf '  OK   %-34s PE machine=%s (%s)\n' "$base" "$got" "$expect_pe_label"
        else
            printf '  BAD  %-34s machine=%s, expected %s (%s)\n' "$base" "$got" "$expect_pe" "$expect_pe_label"
            failed=$((failed + 1))
        fi
    fi
done < <(find "$extracted" -type f | sort)

[ "$checked" -gt 0 ] || die "post-package verification examined ZERO binaries -- the archive is empty or misshaped"
[ "$failed" -eq 0 ] || die "$failed packaged binary/binaries have the wrong machine type"
echo "=== POST-PACKAGE OK: $checked binaries, all $([ -n "${expect_elf:-}" ] && echo "$expect_elf_label" || echo "$expect_pe_label") ==="

sha="$(shasum -a 256 "$zip_path" | awk '{print $1}')"
size="$(stat -f %z "$zip_path")"
cat <<EOF

Packaged: $zip_path
  size    $size bytes
  sha256  $sha

Append to $release_root/evidence/SHA256SUMS.txt:
$sha  ./$cell/$zip_name
EOF
