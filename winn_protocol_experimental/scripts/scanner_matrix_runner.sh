#!/bin/sh

WINN_SCANNER_TARGETS="darwin/arm64 linux/amd64 linux/arm64 windows/amd64 android/arm64"

winn_run_scanner_matrix() {
  staticcheck_bin=$1
  gosec_bin=$2
  govulncheck_bin=$3

  for target in $WINN_SCANNER_TARGETS; do
    target_os=${target%/*}
    target_arch=${target#*/}
    for scanner in staticcheck gosec govulncheck; do
      case "$scanner" in
        staticcheck)
          scanner_bin=$staticcheck_bin
          ;;
        gosec)
          scanner_bin=$gosec_bin
          ;;
        govulncheck)
          scanner_bin=$govulncheck_bin
          ;;
        *)
          echo "unknown release scanner: $scanner" >&2
          return 1
          ;;
      esac
      if [ ! -x "$scanner_bin" ]; then
        echo "release scanner is not executable: $scanner_bin" >&2
        return 1
      fi
      echo "SCANNER_START name=$scanner target=$target_os/$target_arch"
      case "$scanner" in
        staticcheck)
          if ! GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
            "$scanner_bin" ./...; then
            echo "SCANNER_FAIL name=$scanner target=$target_os/$target_arch" >&2
            return 1
          fi
          ;;
        gosec)
          if ! GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
            "$scanner_bin" -quiet ./...; then
            echo "SCANNER_FAIL name=$scanner target=$target_os/$target_arch" >&2
            return 1
          fi
          ;;
        govulncheck)
          if ! GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
            "$scanner_bin" ./...; then
            echo "SCANNER_FAIL name=$scanner target=$target_os/$target_arch" >&2
            return 1
          fi
          ;;
      esac
      echo "SCANNER_PASS name=$scanner target=$target_os/$target_arch"
    done
  done
  echo "PASS: pinned release scanners passed every shipping OS/architecture tuple"
}
