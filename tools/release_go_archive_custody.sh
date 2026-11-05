#!/bin/bash
# Sourceable wrapper for authenticated Go release archive custody.
# The Python controller is never executed by path. Isolated Python custody
# binds wrapper/controller/manifest/trust against an external owner issuance
# contract, then runs authenticated controller bytes on stdin.

_WINS_RG_ACTIVE_TOOL_SOURCE=""
_WINS_RG_ACTIVE_RUNTIME=""
_WINS_RG_ACTIVE_RUNTIME_ID=""
_WINS_RG_ACTIVE_ROOT=""
_WINS_RG_ACTIVE_TREE_SHA256=""
_WINS_RG_ACTIVE_BINARY=""
_WINS_RG_ACTIVE_BINARY_SHA256=""
_WINS_RG_ACTIVE_REPO=""
_WINS_RG_ACTIVE_MANIFEST=""

_wins_rg_error() {
  printf 'release-go custody: %s\n' "$*" >&2
  return 1
}

_wins_rg_python() {
  declare -F wins_release_python_run >/dev/null 2>&1 ||
    _wins_rg_error 'authenticated release Python custody is required' || return 1
  [[ -n "${_WINS_RG_ACTIVE_TOOL_SOURCE:-}" ]] ||
    _wins_rg_error 'Go custody controller snapshot is not bound' || return 1
  [[ "${WINS_GO_CUSTODY_ISSUANCE:-}" == /* ]] ||
    _wins_rg_error 'owner blocked: current reviewed Go custody issuance identity is unavailable' || return 1
  local -a forwarded_environment=()
  local name declaration
  for name in GOFLAGS GOWORK GOPROXY GOSUMDB GOEXPERIMENT; do
    declaration="$(declare -p "$name" 2>/dev/null)" || continue
    [[ "$declaration" != "declare -x "* ]] ||
      _wins_rg_error "inherited $name is refused" || return 1
  done
  for name in \
    GOOS GOARCH GOARM GOAMD64 CGO_ENABLED CC CXX \
    CGO_CFLAGS CGO_CPPFLAGS CGO_CXXFLAGS CGO_LDFLAGS \
    GOMODCACHE GOCACHE GOPRIVATE GONOPROXY GONOSUMDB GODEBUG GOTELEMETRY \
    SDKROOT MACOSX_DEPLOYMENT_TARGET IPHONEOS_DEPLOYMENT_TARGET \
    TVOS_DEPLOYMENT_TARGET WATCHOS_DEPLOYMENT_TARGET PKG_CONFIG_PATH; do
    declaration="$(declare -p "$name" 2>/dev/null)" || continue
    [[ "$declaration" == "declare -x "* ]] || continue
    forwarded_environment+=("$name=${!name}")
  done
  printf '%s' "$_WINS_RG_ACTIVE_TOOL_SOURCE" | wins_release_python_run -c '
import os, sys
issuance, count_text, *payload = sys.argv[1:]
if not count_text.isdigit():
    raise SystemExit("release-go custody: malformed forwarded environment count")
count = int(count_text)
if count < 0 or count > len(payload):
    raise SystemExit("release-go custody: malformed forwarded environment payload")
approved = {
    "GOOS", "GOARCH", "GOARM", "GOAMD64", "CGO_ENABLED", "CC", "CXX",
    "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS",
    "GOMODCACHE", "GOCACHE", "GOPRIVATE", "GONOPROXY", "GONOSUMDB",
    "GODEBUG", "GOTELEMETRY", "SDKROOT", "MACOSX_DEPLOYMENT_TARGET",
    "IPHONEOS_DEPLOYMENT_TARGET", "TVOS_DEPLOYMENT_TARGET",
    "WATCHOS_DEPLOYMENT_TARGET", "PKG_CONFIG_PATH",
}
refused = {"GOFLAGS", "GOWORK", "GOPROXY", "GOSUMDB", "GOEXPERIMENT"}
contaminated = sorted(refused.intersection(os.environ))
if contaminated:
    raise SystemExit("release-go custody: inherited " + contaminated[0] + " is refused")
for name in approved:
    os.environ.pop(name, None)
seen = set()
for assignment in payload[:count]:
    name, separator, value = assignment.partition("=")
    if not separator or name not in approved or name in seen:
        raise SystemExit("release-go custody: refused forwarded environment entry")
    seen.add(name)
    os.environ[name] = value
arguments = payload[count:]
os.environ["WINS_GO_CUSTODY_ISSUANCE"] = issuance
sys.argv = ["release_go_archive_custody.py", *arguments]
exec(compile(sys.stdin.read(), "release_go_archive_custody.py", "exec"), {"__name__": "__main__"})
' "$WINS_GO_CUSTODY_ISSUANCE" "${#forwarded_environment[@]}" \
    "${forwarded_environment[@]}" "$@"
}

_wins_rg_clear() {
  _WINS_RG_ACTIVE_TOOL_SOURCE=""
  _WINS_RG_ACTIVE_RUNTIME=""
  _WINS_RG_ACTIVE_RUNTIME_ID=""
  _WINS_RG_ACTIVE_ROOT=""
  _WINS_RG_ACTIVE_TREE_SHA256=""
  _WINS_RG_ACTIVE_BINARY=""
  _WINS_RG_ACTIVE_BINARY_SHA256=""
  _WINS_RG_ACTIVE_REPO=""
  _WINS_RG_ACTIVE_MANIFEST=""
  unset WINS_RELEASE_GO_RUNTIME WINS_RELEASE_GO_RUNTIME_ID
  unset WINS_RELEASE_GO_ROOT WINS_RELEASE_GO_TREE_SHA256
  unset WINS_RELEASE_GO WINS_RELEASE_GO_SHA256 WINS_GO_CUSTODY_TOOL
}

wins_release_go_cleanup() {
  if [[ -z "${_WINS_RG_ACTIVE_RUNTIME:-}" ]]; then
    _wins_rg_clear
    return 0
  fi
  _wins_rg_python cleanup \
    "$_WINS_RG_ACTIVE_RUNTIME" "$_WINS_RG_ACTIVE_RUNTIME_ID" || return 1
  _wins_rg_clear
}

wins_release_go_prepare() {
  [[ $# -eq 2 ]] ||
    _wins_rg_error 'usage: wins_release_go_prepare ABSOLUTE_TOOL ABSOLUTE_MANIFEST' || return 1
  [[ -z "${_WINS_RG_ACTIVE_RUNTIME:-}" ]] ||
    _wins_rg_error 'Go custody is already active' || return 1
  declare -F wins_release_python_run >/dev/null 2>&1 ||
    _wins_rg_error 'authenticated release Python custody is required' || return 1
  if [[ -n "${WINS_RELEASE_GO:-}" ]]; then
    _wins_rg_error 'WINS_RELEASE_GO executable path export is refused; use wins_release_go_run' || return 1
  fi
  local wrapper="${BASH_SOURCE[0]}"
  [[ "$wrapper" == /* ]] || wrapper="$(pwd)/$wrapper"
  local tools_dir
  tools_dir="$(cd "$(dirname "$wrapper")" && pwd)" ||
    _wins_rg_error 'Go custody wrapper directory could not be resolved' || return 1
  local expected_controller="$tools_dir/release_go_archive_custody.py"
  local expected_wrapper="$tools_dir/release_go_archive_custody.sh"
  local expected_provisioner="$tools_dir/provision_macos_release_go_runtime.sh"
  local expected_manifest="$tools_dir/toolchain-pins.json"
  local expected_trust="$tools_dir/release_go_archive_custody.trust.json"
  [[ "$1" == "$expected_controller" ]] ||
    _wins_rg_error 'malicious or substituted Go custody controller rejected' || return 1
  [[ "$2" == "$expected_manifest" ]] ||
    _wins_rg_error 'replacement Go pin manifest cannot self-authorize' || return 1
  [[ "$wrapper" == "$expected_wrapper" ]] ||
    _wins_rg_error 'malicious or substituted Go custody wrapper rejected' || return 1
  local repo
  repo="$(cd "$tools_dir/.." && pwd)" || return 1
  local bind_py
  bind_py='
import base64, datetime as dt, hashlib, json, os, pathlib, stat, subprocess, sys, tempfile

def fail(message):
    raise SystemExit(message)

def identity(info):
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )

def bind(path, limit, label):
    path = pathlib.Path(path)
    if not path.is_absolute():
        fail(label + " must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(label + " must be one regular non-hardlinked file")
    if before.st_size <= 0 or before.st_size > limit:
        fail(label + " size is outside the accepted range")
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if identity(before) != identity(opened):
            fail(label + " was replaced before it was opened")
        data = bytearray()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            data.extend(block)
        after = os.fstat(fd)
        if identity(opened) != identity(after):
            fail(label + " changed while it was read")
    finally:
        os.close(fd)
    latest = path.lstat()
    if identity(after) != identity(latest):
        fail(label + " was replaced after it was opened")
    if b"\0" in data or not data:
        fail("invalid " + label + " source")
    return bytes(data)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key rejected: " + key)
        result[key] = value
    return result

def canonical(document):
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")

controller, wrapper, provisioner, manifest, trust, repo = [pathlib.Path(item) for item in sys.argv[1:7]]
controller_data = bind(controller, 2 * 1024 * 1024, "Go custody controller")
wrapper_data = bind(wrapper, 2 * 1024 * 1024, "Go custody wrapper")
provisioner_data = bind(provisioner, 2 * 1024 * 1024, "Go runtime provisioner")
manifest_data = bind(manifest, 1024 * 1024, "Go pin manifest")
trust_data = bind(trust, 64 * 1024, "Go custody trust-anchor")
issuance_raw = sys.argv[7]
if type(issuance_raw) is not str or not issuance_raw:
    fail("owner blocked: current reviewed Go custody issuance identity is unavailable")
issuance_path = pathlib.Path(issuance_raw)
if not issuance_path.is_absolute():
    fail("owner blocked: current reviewed Go custody issuance identity is unavailable")
try:
    issuance_path.resolve(strict=False).relative_to(repo.resolve(strict=False))
except ValueError:
    pass
else:
    fail("owner blocked: Go custody issuance must be external to the candidate repository")
try:
    info = issuance_path.lstat()
except FileNotFoundError:
    fail("owner blocked: current reviewed Go custody issuance identity is unavailable")
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    fail("Go custody issuance must be one regular non-hardlinked file")
if stat.S_IMODE(info.st_mode) != 0o444:
    fail("owner blocked: current reviewed Go custody issuance identity is writable")
issuance_data = bind(issuance_path, 64 * 1024, "Go custody issuance")
issuance = json.loads(issuance_data, object_pairs_hook=object_pairs)
if type(issuance) is not dict or issuance_data != canonical(issuance):
    fail("Go custody issuance must be canonical JSON")
if issuance.get("contract") != "winsvpn-go-archive-custody-issuance-v2" or issuance.get("schema_version") != 2:
    fail("Go custody issuance contract mismatch")
authority_prefix = pathlib.Path("/Library/WinsVPN/ReleaseGoAuthority/v1")
authority_path = authority_prefix / "authority.json"
sf_immutable = getattr(stat, "SF_IMMUTABLE", 0x00020000)
for authority_component, directory, mode in (
    (authority_prefix.parent, True, 0o555),
    (authority_prefix, True, 0o555),
    (authority_path, False, 0o444),
):
    authority_info = authority_component.lstat()
    authority_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if stat.S_ISLNK(authority_info.st_mode) or not authority_kind(authority_info.st_mode) or authority_info.st_uid != 0 or authority_info.st_gid != 0 or stat.S_IMODE(authority_info.st_mode) != mode or not int(getattr(authority_info, "st_flags", 0)) & sf_immutable:
        fail("Go custody authority custody mismatch")
    if not directory and authority_info.st_nlink != 1:
        fail("Go custody authority hardlink rejected")
authority_data = bind(authority_path, 64 * 1024, "Go custody authority")
authority = json.loads(authority_data, object_pairs_hook=object_pairs)
if type(authority) is not dict or authority_data != canonical(authority):
    fail("Go custody authority must be canonical JSON")
public_key = base64.b64decode(authority.get("public_key_pem_base64", ""), validate=True)
if authority.get("contract") != "winsvpn-go-archive-custody-authority-v1" or authority.get("schema_version") != 1 or authority.get("signature_algorithm") != "ecdsa-p256-sha256-x962" or authority.get("key_id") != digest(public_key):
    fail("Go custody authority identity mismatch")
if issuance.get("authority_key_id") != authority.get("key_id") or issuance.get("signature_algorithm") != authority.get("signature_algorithm"):
    fail("Go custody issuance authority mismatch")
if issuance.get("issuance_id") != authority.get("active_issuance_id") or issuance.get("sequence") != authority.get("active_sequence"):
    fail("Go custody issuance is replayed or inactive")
created = dt.datetime.strptime(issuance.get("created_utc", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
expires = dt.datetime.strptime(issuance.get("expires_utc", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
not_before = dt.datetime.strptime(authority.get("not_before_utc", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
now = dt.datetime.now(dt.timezone.utc)
if created < not_before or created > now + dt.timedelta(minutes=5) or now - created > dt.timedelta(hours=72) or expires <= now or expires <= created or expires - created > dt.timedelta(hours=72):
    fail("Go custody issuance is stale or future-dated")
signature = base64.b64decode(issuance.get("signature_base64", ""), validate=True)
signed_issuance = dict(issuance)
signed_issuance.pop("signature_base64", None)
with tempfile.TemporaryFile(dir="/private/tmp") as key_file, tempfile.TemporaryFile(dir="/private/tmp") as signature_file:
    key_file.write(public_key)
    signature_file.write(signature)
    key_file.flush(); signature_file.flush()
    os.lseek(key_file.fileno(), 0, os.SEEK_SET)
    os.lseek(signature_file.fileno(), 0, os.SEEK_SET)
    verified = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-verify", f"/dev/fd/{key_file.fileno()}", "-signature", f"/dev/fd/{signature_file.fileno()}"],
        input=canonical(signed_issuance), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"HOME": "/private/tmp", "TMPDIR": "/private/tmp", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
        pass_fds=(key_file.fileno(), signature_file.fileno()), close_fds=True,
        timeout=10, check=False,
    )
if verified.returncode != 0 or verified.stdout.strip() != b"Verified OK":
    fail("Go custody issuance signature verification failed")
for key, data in (
    ("controller_sha256", controller_data),
    ("wrapper_sha256", wrapper_data),
    ("provisioner_sha256", provisioner_data),
    ("manifest_sha256", manifest_data),
    ("trust_anchor_sha256", trust_data),
):
    if issuance.get(key) != digest(data):
        fail("Go custody " + key.replace("_sha256", "") + " digest does not match the external issuance")
freeze = repo / "tools" / "release_source_freeze.py"
freeze_data = bind(freeze, 4 * 1024 * 1024, "source-freeze producer")
if issuance.get("source_freeze_producer") != "tools/release_source_freeze.py" or issuance.get("source_freeze_producer_sha256") != digest(freeze_data):
    fail("Go custody source-freeze producer digest does not match the external issuance")
manifest_document = json.loads(manifest_data, object_pairs_hook=object_pairs)
go = manifest_document.get("tools", {}).get("go", {})
version = go.get("version")
archive_sha = go.get("archive_sha256", {}).get("darwin_arm64")
tree_sha = go.get("install_tree_sha256", {}).get("darwin_arm64")
executable_sha = go.get("executable_sha256")
if not all(isinstance(value, str) and value for value in (version, archive_sha, tree_sha, executable_sha)):
    fail("Go pin manifest cannot locate the sealed controller")
materials = {
    "controller_sha256": digest(controller_data),
    "wrapper_sha256": digest(wrapper_data),
    "provisioner_sha256": digest(provisioner_data),
    "manifest_sha256": digest(manifest_data),
    "trust_anchor_sha256": digest(trust_data),
    "source_freeze_producer_sha256": digest(freeze_data),
}
identity_payload = "".join(f"{key}={materials[key]}\n" for key in sorted(materials))
identity_payload += "".join(
    f"{key}={value}\n" for key, value in (
        ("version", version), ("archive_sha", archive_sha),
        ("tree_sha", tree_sha), ("executable_sha", executable_sha),
    )
)
bootstrap_identity = hashlib.sha256(identity_payload.encode("ascii")).hexdigest()
bootstrap = pathlib.Path("/Library/WinsVPN/ReleaseGoBootstrap") / bootstrap_identity
sealed_controller = bootstrap / "release_go_archive_custody.py"
receipt_path = bootstrap / "bootstrap-receipt.json"
for path, directory, mode in (
    (bootstrap, True, 0o555),
    (sealed_controller, False, 0o444),
    (receipt_path, False, 0o444),
):
    info = path.lstat()
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if stat.S_ISLNK(info.st_mode) or not expected_kind(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != mode or not int(getattr(info, "st_flags", 0)) & sf_immutable:
        fail("sealed Go controller custody mismatch: " + str(path))
    if not directory and info.st_nlink != 1:
        fail("sealed Go controller hardlink rejected: " + str(path))
sealed_controller_data = bind(sealed_controller, 2 * 1024 * 1024, "sealed Go controller")
if digest(sealed_controller_data) != materials["controller_sha256"]:
    fail("sealed Go controller digest mismatch")
receipt_data = bind(receipt_path, 64 * 1024, "sealed Go bootstrap receipt")
receipt = json.loads(receipt_data, object_pairs_hook=object_pairs)
if receipt_data != canonical(receipt) or receipt.get("identity") != bootstrap_identity or receipt.get("path") != str(bootstrap):
    fail("sealed Go bootstrap receipt mismatch")
for key, value in materials.items():
    if receipt.get(key) != value:
        fail("sealed Go bootstrap material mismatch: " + key)
sys.stdout.buffer.write(sealed_controller_data)
'
  local tool_source
  tool_source="$(wins_release_python_run -c "$bind_py" \
    "$expected_controller" "$expected_wrapper" "$expected_provisioner" \
    "$expected_manifest" "$expected_trust" "$repo" \
    "${WINS_GO_CUSTODY_ISSUANCE:-}")" || return 1
  [[ -n "$tool_source" ]] ||
    _wins_rg_error 'Go custody controller snapshot is empty' || return 1
  _WINS_RG_ACTIVE_TOOL_SOURCE="$tool_source"
  local result key value runtime="" runtime_id="" root="" tree_sha="" binary="" binary_sha="" repo_result="" manifest_result=""
  result="$(_wins_rg_python prepare "$repo" "$expected_manifest")" || {
    _WINS_RG_ACTIVE_TOOL_SOURCE=""
    return 1
  }
  while IFS='|' read -r key value; do
    case "$key" in
      RUNTIME) runtime="$value" ;;
      RUNTIME_ID) runtime_id="$value" ;;
      ROOT) root="$value" ;;
      TREE_SHA256) tree_sha="$value" ;;
      BINARY) binary="$value" ;;
      BINARY_SHA256) binary_sha="$value" ;;
      REPO) repo_result="$value" ;;
      MANIFEST) manifest_result="$value" ;;
      *)
        if [[ -n "$runtime" && -n "$runtime_id" ]]; then
          _wins_rg_python cleanup "$runtime" "$runtime_id" || return 1
        fi
        _wins_rg_clear
        _wins_rg_error 'unexpected Go custody result field'
        return 1
        ;;
    esac
  done <<<"$result"
  [[ -n "$runtime" && -n "$runtime_id" && -n "$root" && "$tree_sha" =~ ^[0-9a-f]{64}$ &&
     -n "$binary" && "$binary_sha" =~ ^[0-9a-f]{64}$ &&
     "$repo_result" == "$repo" && "$manifest_result" == "$expected_manifest" ]] || {
    if [[ -n "$runtime" && -n "$runtime_id" ]]; then
      _wins_rg_python cleanup "$runtime" "$runtime_id" || return 1
    fi
    _wins_rg_clear
    _wins_rg_error 'incomplete Go custody result rejected'
    return 1
  }
  _WINS_RG_ACTIVE_RUNTIME="$runtime"
  _WINS_RG_ACTIVE_RUNTIME_ID="$runtime_id"
  _WINS_RG_ACTIVE_ROOT="$root"
  _WINS_RG_ACTIVE_TREE_SHA256="$tree_sha"
  _WINS_RG_ACTIVE_BINARY="$binary"
  _WINS_RG_ACTIVE_BINARY_SHA256="$binary_sha"
  _WINS_RG_ACTIVE_REPO="$repo_result"
  _WINS_RG_ACTIVE_MANIFEST="$manifest_result"
  WINS_RELEASE_GO_RUNTIME="$runtime"
  WINS_RELEASE_GO_RUNTIME_ID="$runtime_id"
  WINS_RELEASE_GO_ROOT="$root"
  WINS_RELEASE_GO_TREE_SHA256="$tree_sha"
  WINS_RELEASE_GO_SHA256="$binary_sha"
  export WINS_RELEASE_GO_RUNTIME WINS_RELEASE_GO_RUNTIME_ID
  export WINS_RELEASE_GO_ROOT WINS_RELEASE_GO_TREE_SHA256
  export WINS_RELEASE_GO_SHA256
  unset WINS_RELEASE_GO
}

wins_release_go_verify() {
  [[ $# -eq 0 ]] || _wins_rg_error 'usage: wins_release_go_verify' || return 1
  _wins_rg_python verify \
    "$_WINS_RG_ACTIVE_RUNTIME" "$_WINS_RG_ACTIVE_RUNTIME_ID" \
    "$_WINS_RG_ACTIVE_ROOT" "$_WINS_RG_ACTIVE_TREE_SHA256" \
    "$_WINS_RG_ACTIVE_BINARY" "$_WINS_RG_ACTIVE_BINARY_SHA256" \
    "$_WINS_RG_ACTIVE_REPO" "$_WINS_RG_ACTIVE_MANIFEST"
}

wins_release_go_run() {
  [[ -n "${_WINS_RG_ACTIVE_RUNTIME:-}" ]] ||
    _wins_rg_error 'Go custody is not prepared' || return 1
  if [[ -n "${WINS_RELEASE_GO:-}" ]]; then
    _wins_rg_error 'WINS_RELEASE_GO executable path export is refused; use wins_release_go_run' || return 1
  fi
  local timeout="${WINS_RELEASE_GO_TIMEOUT_SECONDS:-3600}"
  [[ "$timeout" =~ ^[0-9]+$ && "$timeout" -gt 300 && "$timeout" -le 21600 ]] ||
    _wins_rg_error 'WINS_RELEASE_GO_TIMEOUT_SECONDS must be an integer greater than 300 and at most 21600' || return 1
  _wins_rg_python run \
    "$_WINS_RG_ACTIVE_RUNTIME" "$_WINS_RG_ACTIVE_RUNTIME_ID" \
    "$_WINS_RG_ACTIVE_ROOT" "$_WINS_RG_ACTIVE_TREE_SHA256" \
    "$_WINS_RG_ACTIVE_BINARY" "$_WINS_RG_ACTIVE_BINARY_SHA256" \
    "$_WINS_RG_ACTIVE_REPO" "$_WINS_RG_ACTIVE_MANIFEST" \
    "$timeout" -- "$@"
}
