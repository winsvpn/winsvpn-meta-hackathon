#!/bin/bash
# Sourceable wrapper for authenticated Chrome for Testing archive custody.
# The Python controller is never executed by path. Isolated Python custody
# binds wrapper/controller/manifest/trust against an external owner issuance
# contract, then runs authenticated controller bytes on stdin. Adjacent trust
# hashes never self-authorize. Stale trust is refused and reported and is
# never rehashed. Snapshot directories and injected test runners cannot
# produce a production PASS. Official Chrome for Testing is ad-hoc signed.
# Trust is official archive/tree/executable digests. /usr/bin/codesign
# --verify --deep --strict checks frozen-bundle integrity, not Apple
# publisher identity.

_WINS_RB_ACTIVE_TOOL_SOURCE=""
_WINS_RB_ACTIVE_RUNTIME=""
_WINS_RB_ACTIVE_RUNTIME_ID=""
_WINS_RB_ACTIVE_ROOT=""
_WINS_RB_ACTIVE_TREE_SHA256=""
_WINS_RB_ACTIVE_BINARY=""
_WINS_RB_ACTIVE_BINARY_SHA256=""
_WINS_RB_ACTIVE_APP=""
_WINS_RB_ACTIVE_SIGNING_IDENTITY=""
_WINS_RB_ACTIVE_PRODUCT=""
_WINS_RB_ACTIVE_VERSION=""
_WINS_RB_ACTIVE_TARGET=""

_wins_rb_error() {
  printf 'release-browser custody: %s\n' "$*" >&2
  return 1
}

_wins_rb_python() {
  declare -F wins_release_python_run >/dev/null 2>&1 ||
    _wins_rb_error 'authenticated release Python custody is required' || return 1
  [[ -n "${_WINS_RB_ACTIVE_TOOL_SOURCE:-}" ]] ||
    _wins_rb_error 'Chrome custody controller snapshot is not bound' || return 1
  [[ "${WINS_BROWSER_CUSTODY_ISSUANCE:-}" == /* ]] ||
    _wins_rb_error 'owner blocked: current reviewed Chrome custody issuance identity is unavailable' || return 1
  printf '%s' "$_WINS_RB_ACTIVE_TOOL_SOURCE" | wins_release_python_run -c '
import base64, os, sys
issuance = sys.argv[1]
if not issuance or issuance[:1] != "/":
    raise SystemExit("release-browser custody: owner blocked: current reviewed Chrome custody issuance identity is unavailable")
os.environ["WINS_BROWSER_CUSTODY_ISSUANCE"] = issuance
sys.argv = ["release_browser_archive_custody.py", *sys.argv[2:]]
try:
    source = base64.b64decode(sys.stdin.read().encode("ascii"), validate=True)
except (UnicodeEncodeError, ValueError) as exc:
    raise SystemExit("release-browser custody: authenticated controller transport is invalid: " + str(exc))
exec(compile(source, "release_browser_archive_custody.py", "exec"), {"__name__": "__main__"})
' "${WINS_BROWSER_CUSTODY_ISSUANCE:-}" "$@"
}

_wins_rb_clear() {
  _WINS_RB_ACTIVE_TOOL_SOURCE=""
  _WINS_RB_ACTIVE_RUNTIME=""
  _WINS_RB_ACTIVE_RUNTIME_ID=""
  _WINS_RB_ACTIVE_ROOT=""
  _WINS_RB_ACTIVE_TREE_SHA256=""
  _WINS_RB_ACTIVE_BINARY=""
  _WINS_RB_ACTIVE_BINARY_SHA256=""
  _WINS_RB_ACTIVE_APP=""
  _WINS_RB_ACTIVE_SIGNING_IDENTITY=""
  _WINS_RB_ACTIVE_PRODUCT=""
  _WINS_RB_ACTIVE_VERSION=""
  _WINS_RB_ACTIVE_TARGET=""
  unset WINS_RELEASE_BROWSER_RUNTIME WINS_RELEASE_BROWSER_RUNTIME_ID
  unset WINS_RELEASE_BROWSER_ROOT WINS_RELEASE_BROWSER_TREE_SHA256
  unset WINS_RELEASE_BROWSER WINS_RELEASE_BROWSER_SHA256
  unset WINS_RELEASE_BROWSER_APP WINS_RELEASE_BROWSER_SIGNING_IDENTITY
  unset WINS_RELEASE_BROWSER_PRODUCT WINS_RELEASE_BROWSER_VERSION
  unset WINS_RELEASE_BROWSER_TARGET WINS_BROWSER_CUSTODY_TOOL
}

_wins_rb_cleanup_runtime() {
  local runtime="$1"
  local runtime_id="$2"
  [[ -n "$runtime" && -n "$runtime_id" ]] || return 1
  _wins_rb_python cleanup "$runtime" "$runtime_id" || {
    _wins_rb_error 'Chrome cleanup left residue'
    return 1
  }
  return 0
}

wins_release_browser_cleanup() {
  if [[ -z "${_WINS_RB_ACTIVE_RUNTIME:-}" ]]; then
    _wins_rb_clear
    return 0
  fi
  _wins_rb_cleanup_runtime \
    "$_WINS_RB_ACTIVE_RUNTIME" "$_WINS_RB_ACTIVE_RUNTIME_ID" || return 1
  _wins_rb_clear
}

wins_release_browser_prepare() {
  [[ $# -eq 2 ]] ||
    _wins_rb_error 'usage: wins_release_browser_prepare ABSOLUTE_TOOL ABSOLUTE_MANIFEST' || return 1
  [[ -z "${_WINS_RB_ACTIVE_RUNTIME:-}" ]] ||
    _wins_rb_error 'Chrome custody is already active' || return 1
  declare -F wins_release_python_run >/dev/null 2>&1 ||
    _wins_rb_error 'authenticated release Python custody is required' || return 1
  local wrapper="${BASH_SOURCE[0]}"
  [[ "$wrapper" == /* ]] || wrapper="$(pwd)/$wrapper"
  local tools_dir
  tools_dir="$(cd "$(dirname "$wrapper")" && pwd)" ||
    _wins_rb_error 'Chrome custody wrapper directory could not be resolved' || return 1
  local expected_controller="$tools_dir/release_browser_archive_custody.py"
  local expected_wrapper="$tools_dir/release_browser_archive_custody.sh"
  local expected_manifest="$tools_dir/toolchain-pins.json"
  local expected_trust="$tools_dir/release_browser_archive_custody.trust.json"
  [[ "$1" == "$expected_controller" ]] ||
    _wins_rb_error 'malicious or substituted Chrome custody controller rejected' || return 1
  [[ "$2" == "$expected_manifest" ]] ||
    _wins_rb_error 'replacement Chrome pin manifest cannot self-authorize' || return 1
  [[ "$wrapper" == "$expected_wrapper" ]] ||
    _wins_rb_error 'malicious or substituted Chrome custody wrapper rejected' || return 1
  local repo
  repo="$(cd "$tools_dir/.." && pwd)" || return 1
  local bind_py
  bind_py='
import base64, datetime, hashlib, json, os, pathlib, re, stat, subprocess, sys, tempfile

def fail(message):
    raise SystemExit(message)

def identity(info):
    return (
        info.st_dev, info.st_ino, info.st_uid, info.st_mode,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )

def bind(path, max_size, label):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    before = path.lstat()
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        fail(label + " must be one regular non-hardlinked file")
    if before.st_size <= 0 or before.st_size > max_size:
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
    payload = bytes(data)
    if not payload or b"\0" in payload:
        fail("invalid " + label)
    return payload

def digest(data):
    return hashlib.sha256(data).hexdigest()

def object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            fail("duplicate JSON key rejected: " + key)
        result[key] = value
    return result

def reject_constant(token):
    fail("non-finite JSON constant rejected: " + token)

def canonical(document):
    return (json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")

def stale(label, live, pinned):
    fail(
        "stale Chrome custody trust refused: "
        + label
        + " digest does not match the trust-anchor (live="
        + live
        + " trust="
        + pinned
        + ")"
    )

controller, wrapper, manifest, trust_path, repo = [pathlib.Path(item) for item in sys.argv[1:6]]
controller_data = bind(controller, 2 * 1024 * 1024, "Chrome custody controller")
wrapper_data = bind(wrapper, 2 * 1024 * 1024, "Chrome custody wrapper")
manifest_data = bind(manifest, 1024 * 1024, "Chrome pin manifest")
trust_data = bind(trust_path, 64 * 1024, "Chrome custody trust-anchor")
try:
    trust = json.loads(
        trust_data,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )
except ValueError as exc:
    fail("Chrome custody trust-anchor is not JSON: " + str(exc))
required = (
    "contract", "schema_version", "controller", "wrapper", "manifest",
    "trust_anchor", "issuance_env", "issuance_contract", "authority",
    "authority_contract", "signature_algorithm", "controller_sha256",
    "wrapper_sha256", "manifest_sha256",
)
if type(trust) is not dict or set(trust) != set(required):
    fail("Chrome custody trust-anchor schema mismatch")
if trust.get("contract") != "winsvpn-browser-archive-custody-trust-v1":
    fail("Chrome custody trust-anchor contract mismatch")
if trust.get("schema_version") != 1:
    fail("Chrome custody trust-anchor schema_version mismatch")
if trust.get("controller") != "tools/release_browser_archive_custody.py":
    fail("Chrome custody trust-anchor controller path mismatch")
if trust.get("wrapper") != "tools/release_browser_archive_custody.sh":
    fail("Chrome custody trust-anchor wrapper path mismatch")
if trust.get("manifest") != "tools/toolchain-pins.json":
    fail("Chrome custody trust-anchor manifest path mismatch")
if trust.get("trust_anchor") != "tools/release_browser_archive_custody.trust.json":
    fail("Chrome custody trust-anchor path mismatch")
if trust.get("issuance_env") != "WINS_BROWSER_CUSTODY_ISSUANCE":
    fail("Chrome custody trust-anchor issuance_env mismatch")
if trust.get("issuance_contract") != "winsvpn-browser-archive-custody-issuance-v2":
    fail("Chrome custody trust-anchor issuance_contract mismatch")
authority_path = pathlib.Path("/Library/WinsVPN/ReleaseBrowserAuthority/v1/authority.json")
if trust.get("authority") != str(authority_path):
    fail("Chrome custody trust-anchor authority path mismatch")
if trust.get("authority_contract") != "winsvpn-browser-archive-custody-authority-v1":
    fail("Chrome custody trust-anchor authority_contract mismatch")
if trust.get("signature_algorithm") != "ecdsa-p256-sha256-x962":
    fail("Chrome custody trust-anchor signature_algorithm mismatch")
live_controller = digest(controller_data)
live_wrapper = digest(wrapper_data)
live_manifest = digest(manifest_data)
if live_controller != trust.get("controller_sha256"):
    stale("controller", live_controller, str(trust.get("controller_sha256")))
if live_wrapper != trust.get("wrapper_sha256"):
    stale("wrapper", live_wrapper, str(trust.get("wrapper_sha256")))
if live_manifest != trust.get("manifest_sha256"):
    stale("manifest", live_manifest, str(trust.get("manifest_sha256")))
issuance_raw = sys.argv[6]
if type(issuance_raw) is not str or not issuance_raw:
    fail("owner blocked: current reviewed Chrome custody issuance identity is unavailable")
issuance_path = pathlib.Path(issuance_raw)
if not issuance_path.is_absolute():
    fail("owner blocked: current reviewed Chrome custody issuance identity is unavailable")
try:
    issuance_path.resolve(strict=False).relative_to(repo.resolve(strict=False))
except ValueError:
    pass
else:
    fail("owner blocked: Chrome custody issuance must be external to the candidate repository")
try:
    info = issuance_path.lstat()
except FileNotFoundError:
    fail("owner blocked: current reviewed Chrome custody issuance identity is unavailable")
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    fail("Chrome custody issuance must be one regular non-hardlinked file")
if stat.S_IMODE(info.st_mode) != 0o444:
    fail("owner blocked: current reviewed Chrome custody issuance identity is writable")
authority_prefix = authority_path.parent
authority_roots = {authority_prefix.parent, authority_prefix}
current = pathlib.Path(authority_path.anchor)
try:
    for part in authority_path.parts[1:-1]:
        current /= part
        ancestor = current.lstat()
        mode = stat.S_IMODE(ancestor.st_mode)
        if stat.S_ISLNK(ancestor.st_mode) or not stat.S_ISDIR(ancestor.st_mode):
            fail("unsafe Chrome custody authority ancestor: " + str(current))
        sticky_root = (
            ancestor.st_uid == 0 and ancestor.st_gid == 0
            and bool(mode & stat.S_ISVTX) and current not in authority_roots
        )
        if ancestor.st_uid != 0 or ancestor.st_gid != 0 or (mode & 0o022 and not sticky_root):
            fail("writable or foreign Chrome custody authority ancestor: " + str(current))
        if current in authority_roots and not ancestor.st_flags & getattr(stat, "SF_IMMUTABLE", 0x00020000):
            fail("owner blocked: immutable external Chrome custody authority is unavailable")
    authority_info = authority_path.lstat()
except FileNotFoundError:
    fail("owner blocked: immutable external Chrome custody authority is unavailable")
if (
    stat.S_ISLNK(authority_info.st_mode)
    or not stat.S_ISREG(authority_info.st_mode)
    or authority_info.st_nlink != 1
    or authority_info.st_uid != 0
    or authority_info.st_gid != 0
    or stat.S_IMODE(authority_info.st_mode) != 0o444
    or not authority_info.st_flags & getattr(stat, "SF_IMMUTABLE", 0x00020000)
):
    fail("owner blocked: immutable external Chrome custody authority is unavailable")
authority_data = bind(authority_path, 64 * 1024, "Chrome custody authority")
try:
    authority = json.loads(
        authority_data,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )
except ValueError as exc:
    fail("Chrome custody authority is not JSON: " + str(exc))
authority_required = {
    "contract", "schema_version", "key_id", "signature_algorithm",
    "public_key_pem_base64", "active_issuance_id", "active_sequence",
    "not_before_utc",
}
if type(authority) is not dict or set(authority) != authority_required or authority_data != canonical(authority):
    fail("Chrome custody authority schema or canonical JSON mismatch")
if authority.get("contract") != "winsvpn-browser-archive-custody-authority-v1" or authority.get("schema_version") != 1:
    fail("Chrome custody authority contract mismatch")
if authority.get("signature_algorithm") != "ecdsa-p256-sha256-x962":
    fail("Chrome custody authority signature_algorithm mismatch")
try:
    public_key = base64.b64decode(authority.get("public_key_pem_base64", ""), validate=True)
except (ValueError, TypeError):
    fail("Chrome custody authority public key is invalid")
if (
    not public_key.startswith(b"-----BEGIN PUBLIC KEY-----\n")
    or not public_key.endswith(b"-----END PUBLIC KEY-----\n")
    or b"PRIVATE KEY" in public_key
    or hashlib.sha256(public_key).hexdigest() != authority.get("key_id")
):
    fail("Chrome custody authority public key is invalid")
issuance_data = bind(issuance_path, 64 * 1024, "Chrome custody issuance")
try:
    issuance = json.loads(
        issuance_data,
        object_pairs_hook=object_pairs,
        parse_constant=reject_constant,
    )
except ValueError as exc:
    fail("Chrome custody issuance is not JSON: " + str(exc))
issuance_required = {
    "contract", "schema_version", "issuance_id", "created_utc", "sequence",
    "expires_utc", "issuer", "authority_key_id", "signature_algorithm",
    "target", "product", "version", "archive_sha256", "controller", "wrapper",
    "manifest", "trust_anchor", "source_freeze_producer", "controller_sha256",
    "wrapper_sha256", "manifest_sha256", "trust_anchor_sha256",
    "source_freeze_producer_sha256", "signature_base64",
}
if type(issuance) is not dict or set(issuance) != issuance_required or issuance_data != canonical(issuance):
    fail("Chrome custody issuance schema or canonical JSON mismatch")
if issuance.get("contract") != "winsvpn-browser-archive-custody-issuance-v2" or issuance.get("schema_version") != 2:
    fail("Chrome custody issuance contract mismatch")
hex32 = re.compile(r"[0-9a-f]{32}\Z")
hex64 = re.compile(r"[0-9a-f]{64}\Z")
version_re = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
timestamp_re = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
issuance_id = issuance.get("issuance_id")
if type(issuance_id) is not str or not hex32.fullmatch(issuance_id) or issuance_id == "0" * 32:
    fail("Chrome custody issuance identity is replayed or inactive")
if issuance_id != authority.get("active_issuance_id") or issuance.get("sequence") != authority.get("active_sequence"):
    fail("Chrome custody issuance identity is replayed or inactive")
if type(issuance.get("sequence")) is not int or issuance.get("sequence", 0) <= 0:
    fail("Chrome custody issuance sequence is invalid")
if issuance.get("authority_key_id") != authority.get("key_id"):
    fail("Chrome custody issuance authority key mismatch")
if issuance.get("signature_algorithm") != "ecdsa-p256-sha256-x962":
    fail("Chrome custody issuance signature_algorithm mismatch")
for timestamp_key in ("created_utc", "expires_utc"):
    timestamp = issuance.get(timestamp_key)
    if type(timestamp) is not str or not timestamp_re.fullmatch(timestamp):
        fail("Chrome custody issuance timestamps must be exact ISO UTC")
created = datetime.datetime.strptime(issuance["created_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
expires = datetime.datetime.strptime(issuance["expires_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
not_before = datetime.datetime.strptime(authority.get("not_before_utc", ""), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
now = datetime.datetime.now(datetime.timezone.utc)
if created < not_before or created < datetime.datetime(2026, 8, 23, tzinfo=datetime.timezone.utc):
    fail("Chrome custody issuance predates the active authority")
if created > now + datetime.timedelta(minutes=5) or now - created > datetime.timedelta(hours=72) or expires <= now:
    fail("Chrome custody issuance is stale or future-dated")
if expires <= created or expires - created > datetime.timedelta(hours=72):
    fail("Chrome custody issuance validity interval is invalid")
if issuance.get("issuer") != "winsvpn-browser-archive-custody":
    fail("Chrome custody issuance issuer mismatch")
if issuance.get("target") in {"edge-extension-package", "firefox-extension-package"}:
    fail("owner blocked: Chrome and Edge store IDs and store publication authority are unavailable")
if issuance.get("target") != "chrome-for-testing":
    fail("Chrome custody issuance target mismatch")
if issuance.get("product") != "Google Chrome for Testing":
    fail("Chrome custody issuance product mismatch")
if type(issuance.get("version")) is not str or not version_re.fullmatch(issuance["version"]):
    fail("Chrome custody issuance version mismatch")
if issuance.get("controller") != "tools/release_browser_archive_custody.py" or issuance.get("wrapper") != "tools/release_browser_archive_custody.sh":
    fail("Chrome custody issuance source identity mismatch")
if issuance.get("manifest") != "tools/toolchain-pins.json" or issuance.get("trust_anchor") != "tools/release_browser_archive_custody.trust.json":
    fail("Chrome custody issuance descriptor identity mismatch")
for key in (
    "archive_sha256", "controller_sha256", "wrapper_sha256", "manifest_sha256",
    "trust_anchor_sha256", "source_freeze_producer_sha256",
):
    value = issuance.get(key)
    if type(value) is not str or not hex64.fullmatch(value) or value == "0" * 64:
        fail("invalid Chrome custody issuance digest: " + key)
signed = dict(issuance)
try:
    signature = base64.b64decode(signed.pop("signature_base64"), validate=True)
except (ValueError, TypeError):
    fail("Chrome custody issuance signature is invalid")
if not signature or len(signature) > 1024:
    fail("Chrome custody issuance signature is invalid")
with tempfile.TemporaryFile(dir="/private/tmp") as key_file, tempfile.TemporaryFile(dir="/private/tmp") as signature_file:
    key_file.write(public_key)
    signature_file.write(signature)
    key_file.flush()
    signature_file.flush()
    os.lseek(key_file.fileno(), 0, os.SEEK_SET)
    os.lseek(signature_file.fileno(), 0, os.SEEK_SET)
    verified = subprocess.run(
        ["/usr/bin/openssl", "dgst", "-sha256", "-verify", f"/dev/fd/{key_file.fileno()}", "-signature", f"/dev/fd/{signature_file.fileno()}"],
        input=canonical(signed), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"HOME": "/private/tmp", "TMPDIR": "/private/tmp", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
        pass_fds=(key_file.fileno(), signature_file.fileno()), close_fds=True,
        timeout=10, check=False,
    )
if verified.returncode != 0 or verified.stdout.strip() != b"Verified OK":
    fail("Chrome custody issuance signature verification failed")
for key, data in (
    ("controller_sha256", controller_data),
    ("wrapper_sha256", wrapper_data),
    ("manifest_sha256", manifest_data),
    ("trust_anchor_sha256", trust_data),
):
    if issuance.get(key) != digest(data):
        fail("Chrome custody " + key.replace("_sha256", "") + " digest does not match the external issuance")
freeze = repo / "tools" / "release_source_freeze.py"
freeze_data = bind(freeze, 4 * 1024 * 1024, "source-freeze producer")
if issuance.get("source_freeze_producer") != "tools/release_source_freeze.py" or issuance.get("source_freeze_producer_sha256") != digest(freeze_data):
    fail("authenticated current source-freeze producer digest is required to bind Chrome controller, wrapper, manifest, and trust-anchor bytes")
sys.stdout.write(base64.b64encode(controller_data).decode("ascii"))
'
  local tool_source
  tool_source="$(wins_release_python_run -c "$bind_py" \
    "$expected_controller" "$expected_wrapper" "$expected_manifest" \
    "$expected_trust" "$repo" "${WINS_BROWSER_CUSTODY_ISSUANCE:-}")" || return 1
  [[ -n "$tool_source" ]] ||
    _wins_rb_error 'Chrome custody controller snapshot is empty' || return 1
  _WINS_RB_ACTIVE_TOOL_SOURCE="$tool_source"
  WINS_BROWSER_CUSTODY_TOOL="$expected_controller"
  local result key value seen='|'
  local runtime="" runtime_id="" root="" tree_sha="" binary="" binary_sha=""
  local app="" signing_identity="" product="" version="" target=""
  result="$(_wins_rb_python prepare "$repo" "$expected_manifest")" || {
    _WINS_RB_ACTIVE_TOOL_SOURCE=""
    return 1
  }
  while IFS='|' read -r key value; do
    if [[ "$seen" == *"|$key|"* ]]; then
      if [[ -n "$runtime" && -n "$runtime_id" ]]; then
        _wins_rb_cleanup_runtime "$runtime" "$runtime_id" || return 1
      fi
      _wins_rb_clear
      _wins_rb_error 'duplicate Chrome custody result field'
      return 1
    fi
    seen="${seen}${key}|"
    case "$key" in
      RUNTIME) runtime="$value" ;;
      RUNTIME_ID) runtime_id="$value" ;;
      ROOT) root="$value" ;;
      TREE_SHA256) tree_sha="$value" ;;
      BINARY) binary="$value" ;;
      BINARY_SHA256) binary_sha="$value" ;;
      APP) app="$value" ;;
      SIGNING_IDENTITY) signing_identity="$value" ;;
      PRODUCT) product="$value" ;;
      VERSION) version="$value" ;;
      TARGET) target="$value" ;;
      *)
        if [[ -n "$runtime" && -n "$runtime_id" ]]; then
          _wins_rb_cleanup_runtime "$runtime" "$runtime_id" || return 1
        fi
        _wins_rb_clear
        _wins_rb_error 'unexpected Chrome custody result field'
        return 1
        ;;
    esac
  done <<<"$result"
  [[ -n "$runtime" && -n "$runtime_id" && -n "$root" && "$tree_sha" =~ ^[0-9a-f]{64}$ &&
     -n "$binary" && "$binary_sha" =~ ^[0-9a-f]{64}$ && -n "$app" &&
     -n "$signing_identity" && "$product" == "Google Chrome for Testing" &&
     "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ &&
     "$target" == "chrome-for-testing" ]] || {
    if [[ -n "$runtime" && -n "$runtime_id" ]]; then
      _wins_rb_cleanup_runtime "$runtime" "$runtime_id" || return 1
    fi
    _wins_rb_clear
    _wins_rb_error 'incomplete Chrome custody result rejected'
    return 1
  }
  _WINS_RB_ACTIVE_RUNTIME="$runtime"
  _WINS_RB_ACTIVE_RUNTIME_ID="$runtime_id"
  _WINS_RB_ACTIVE_ROOT="$root"
  _WINS_RB_ACTIVE_TREE_SHA256="$tree_sha"
  _WINS_RB_ACTIVE_BINARY="$binary"
  _WINS_RB_ACTIVE_BINARY_SHA256="$binary_sha"
  _WINS_RB_ACTIVE_APP="$app"
  _WINS_RB_ACTIVE_SIGNING_IDENTITY="$signing_identity"
  _WINS_RB_ACTIVE_PRODUCT="$product"
  _WINS_RB_ACTIVE_VERSION="$version"
  _WINS_RB_ACTIVE_TARGET="$target"
  WINS_RELEASE_BROWSER_RUNTIME="$runtime"
  WINS_RELEASE_BROWSER_RUNTIME_ID="$runtime_id"
  WINS_RELEASE_BROWSER_ROOT="$root"
  WINS_RELEASE_BROWSER_TREE_SHA256="$tree_sha"
  WINS_RELEASE_BROWSER="$binary"
  WINS_RELEASE_BROWSER_SHA256="$binary_sha"
  WINS_RELEASE_BROWSER_APP="$app"
  WINS_RELEASE_BROWSER_SIGNING_IDENTITY="$signing_identity"
  WINS_RELEASE_BROWSER_PRODUCT="$product"
  WINS_RELEASE_BROWSER_VERSION="$version"
  WINS_RELEASE_BROWSER_TARGET="$target"
  export WINS_RELEASE_BROWSER_RUNTIME WINS_RELEASE_BROWSER_RUNTIME_ID
  export WINS_RELEASE_BROWSER_ROOT WINS_RELEASE_BROWSER_TREE_SHA256
  export WINS_RELEASE_BROWSER WINS_RELEASE_BROWSER_SHA256
  export WINS_RELEASE_BROWSER_APP WINS_RELEASE_BROWSER_SIGNING_IDENTITY
  export WINS_RELEASE_BROWSER_PRODUCT WINS_RELEASE_BROWSER_VERSION
  export WINS_RELEASE_BROWSER_TARGET
}

wins_release_browser_verify() {
  [[ $# -eq 0 ]] || _wins_rb_error 'usage: wins_release_browser_verify' || return 1
  _wins_rb_python verify \
    "$_WINS_RB_ACTIVE_RUNTIME" "$_WINS_RB_ACTIVE_RUNTIME_ID" \
    "$_WINS_RB_ACTIVE_ROOT" "$_WINS_RB_ACTIVE_TREE_SHA256" \
    "$_WINS_RB_ACTIVE_BINARY" "$_WINS_RB_ACTIVE_BINARY_SHA256" \
    "$_WINS_RB_ACTIVE_APP" "$_WINS_RB_ACTIVE_SIGNING_IDENTITY"
}

wins_release_browser_run() {
  [[ -n "${_WINS_RB_ACTIVE_RUNTIME:-}" ]] ||
    _wins_rb_error 'Chrome custody is not prepared' || return 1
  [[ "${_WINS_RB_ACTIVE_TARGET:-}" == "chrome-for-testing" ]] ||
    _wins_rb_error 'Chrome custody issuance target cannot be reused across Edge or Firefox/XPI' || return 1
  _wins_rb_python run \
    "$_WINS_RB_ACTIVE_RUNTIME" "$_WINS_RB_ACTIVE_RUNTIME_ID" \
    "$_WINS_RB_ACTIVE_ROOT" "$_WINS_RB_ACTIVE_TREE_SHA256" \
    "$_WINS_RB_ACTIVE_BINARY" "$_WINS_RB_ACTIVE_BINARY_SHA256" \
    "$_WINS_RB_ACTIVE_APP" "$_WINS_RB_ACTIVE_SIGNING_IDENTITY" -- "$@"
}
