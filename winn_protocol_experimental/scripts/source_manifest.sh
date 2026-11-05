#!/bin/sh
#
# Produce a deterministic SHA-256 manifest of every main-module file selected
# by `go list` for one build target. The SHA-256 of the manifest is suitable
# for cmd/winn-acceptance's main.sourceTreeDigest build variable.
#
# Usage:
#   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
#     ./scripts/source_manifest.sh ./cmd/winn-acceptance OUTPUT

set -eu

if [ "$#" -ne 2 ]; then
	echo "usage: $0 GO_PACKAGE OUTPUT" >&2
	exit 64
fi

go_package=$1
output=$2
go_bin=${GO_BIN:-go}

go_mod=$("$go_bin" env GOMOD)
if [ -z "$go_mod" ] || [ "$go_mod" = /dev/null ]; then
	echo "source manifest requires a Go module" >&2
	exit 1
fi
module_root=$(dirname "$go_mod")

case "$output" in
/*) output_path=$output ;;
*) output_path=$PWD/$output ;;
esac

temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/winn-source-manifest.XXXXXX")
cleanup() {
	rm -rf "$temporary_directory"
}
trap cleanup EXIT HUP INT TERM

absolute_paths=$temporary_directory/absolute-paths.txt
relative_paths=$temporary_directory/relative-paths.txt
manifest_tmp=$temporary_directory/manifest.txt

{
	printf '%s\n' "$go_mod"
	if [ -f "$module_root/go.sum" ]; then
		printf '%s\n' "$module_root/go.sum"
	fi
	"$go_bin" list -deps -f \
		'{{if .Module}}{{if .Module.Main}}{{range .GoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .CgoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .CFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .CXXFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .MFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .HFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .FFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .SFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .SwigFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .SwigCXXFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .SysoFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{range .EmbedFiles}}{{$.Dir}}/{{.}}{{"\n"}}{{end}}{{end}}{{end}}' \
		"$go_package"
} >"$absolute_paths"
# Sort only after discovery succeeded: in a pipeline, sort's status would hide
# a failed `go list` from set -e and publish an incomplete manifest.
LC_ALL=C sort -u "$absolute_paths" -o "$absolute_paths"

: >"$relative_paths"
while IFS= read -r source_path; do
	[ -n "$source_path" ] || continue
	case "$source_path" in
	"$module_root"/*)
		relative_path=${source_path#"$module_root"/}
		;;
	*)
		echo "source input escapes module root: $source_path" >&2
		exit 1
		;;
	esac
	if [ ! -f "$source_path" ] || [ -L "$source_path" ]; then
		echo "source input is not a regular non-symlink file: $source_path" >&2
		exit 1
	fi
	printf '%s\n' "$relative_path" >>"$relative_paths"
done <"$absolute_paths"

LC_ALL=C sort -u "$relative_paths" -o "$relative_paths"

: >"$manifest_tmp"
while IFS= read -r relative_path; do
	[ -n "$relative_path" ] || continue
	if command -v sha256sum >/dev/null 2>&1; then
		digest=$(sha256sum "$module_root/$relative_path" | awk '{ print $1 }')
	else
		digest=$(shasum -a 256 "$module_root/$relative_path" | awk '{ print $1 }')
	fi
	printf '%s  %s\n' "$digest" "$relative_path" >>"$manifest_tmp"
done <"$relative_paths"

output_directory=$(dirname "$output_path")
if [ ! -d "$output_directory" ]; then
	echo "output directory does not exist: $output_directory" >&2
	exit 1
fi
mv "$manifest_tmp" "$output_path"

if command -v sha256sum >/dev/null 2>&1; then
	sha256sum "$output_path" | awk '{ print $1 }'
else
	shasum -a 256 "$output_path" | awk '{ print $1 }'
fi
