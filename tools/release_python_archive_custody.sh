#!/bin/bash
# Sourceable macOS release-Python archive custody.
#
# Expected pin schema under tools.python.archive_custody.darwin_arm64:
#   package, Sigstore bundle/trusted-root/verifier/policy, framework_component,
#   python_executable, runtime_wheel_count, wheel_count, and wheels.<index>.
#   Production paths are
#   exact /Library/WinsVPN/ReleasePythonInputs/sha256/SHA256/LEAF locations.
#
# Paths and hashes are read only through the fixed system plutil. This file
# does not download, install, sign, elevate privilege, or mutate external state.
# Execution binds one owner-provisioned root-owned runtime derived from the
# exact reviewed python.org 3.14.7 package and wheels. Every ancestor, inode,
# mode, archive hash, complete tree hash, code signature, and receipt identity
# is rebound before exec. UF_IMMUTABLE is insufficient because the owner can
# clear it. User-writable copies plus pre-exec rehashing are not sufficient.
# If the owner runtime is absent, execution fails closed as an
# owner/environment blocker and never claims PASS. Provisioning is owned by the
# fixed external boundary at
# /Library/WinsVPN/ReleasePythonAuthority/v2/owner-provision.


readonly _WINS_RP_PLUTIL=/usr/bin/plutil
readonly _WINS_RP_STAT=/usr/bin/stat
readonly _WINS_RP_SHASUM=/usr/bin/shasum
readonly _WINS_RP_PKGUTIL=/usr/sbin/pkgutil
readonly _WINS_RP_MKTEMP=/usr/bin/mktemp
readonly _WINS_RP_UNZIP=/usr/bin/unzip
readonly _WINS_RP_ZIPINFO=/usr/bin/zipinfo
readonly _WINS_RP_DITTO=/usr/bin/ditto
readonly _WINS_RP_FIND=/usr/bin/find
readonly _WINS_RP_READLINK=/usr/bin/readlink
readonly _WINS_RP_UNAME=/usr/bin/uname
readonly _WINS_RP_ID=/usr/bin/id
readonly _WINS_RP_ENV=/usr/bin/env
readonly _WINS_RP_TR=/usr/bin/tr
readonly _WINS_RP_CP=/bin/cp
readonly _WINS_RP_CHMOD=/bin/chmod
readonly _WINS_RP_MKDIR=/bin/mkdir
readonly _WINS_RP_RM=/bin/rm
readonly _WINS_RP_BASENAME=/usr/bin/basename
readonly _WINS_RP_DIRNAME=/usr/bin/dirname
readonly _WINS_RP_SANDBOX_EXEC=/usr/bin/sandbox-exec
readonly _WINS_RP_SYSTEM_PYTHON=/usr/bin/python3
readonly _WINS_RP_OWNER_RUNTIME=/Library/WinsVPN/ReleasePython/3.14.7
readonly _WINS_RP_RECEIPT_MODULE_SHA256=5d29a5c0f7c8b01dc4bf7b94ae61d9379c7035916bc753ee08f020f36d26ea5e
readonly _WINS_RP_RECEIPT_TEST_SHA256=a8ace1a2c7fe890b2dbb65eb746f2a52ee15d493a07918e41f5223878461bd08
readonly _WINS_RP_GCP_COLLECTOR_SHA256=c6d2ee41697564dd8542e5022b62feef0e46c6707eaf77213c8b5c54f15ea00e
readonly _WINS_RP_GCP_PROBE_SHA256=ec03a251a383cef6b912365214103d94662f52e152b2c6c3d0c1fd1998ab6580
if [[ "$("$_WINS_RP_ID" -u)" == 0 ]]; then
  printf '%s\n' 'release-python custody: OWNER-BLOCKED: mutable repository ReleasePython helpers refuse euid 0' >&2
  return 1 2>/dev/null || exit 1
fi
if [[ "${BASH_SOURCE[0]}" == /dev/fd/8 ]]; then
  [[ -n "${_WINS_RP_HELD_HELPER_DIR:-}" && "$_WINS_RP_HELD_HELPER_DIR" == /* ]] || {
    printf '%s\n' 'release-python custody: held helper directory is unavailable' >&2
    return 1 2>/dev/null || exit 1
  }
  readonly _WINS_RP_HELPER_DIR="$_WINS_RP_HELD_HELPER_DIR"
else
  readonly _WINS_RP_HELPER_DIR="$(cd "$("$_WINS_RP_DIRNAME" "${BASH_SOURCE[0]}")" && pwd -P)"
fi
readonly _WINS_RP_RECEIPT_MODULE="${_WINS_RP_HELPER_DIR}/macos_release_python_runtime_receipt.py"
readonly _WINS_RP_GCP_COLLECTOR="${_WINS_RP_HELPER_DIR}/gcp_proof_evidence.py"
readonly _WINS_RP_GCP_PROBE="${_WINS_RP_HELPER_DIR}/gcp_proof_live_probe.py"

_WINS_RP_ACTIVE_RUNTIME=""
_WINS_RP_ACTIVE_RUNTIME_ID=""
_WINS_RP_ACTIVE_SCRATCH=""
_WINS_RP_ACTIVE_MANIFEST=""
_WINS_RP_ACTIVE_BIN=""
_WINS_RP_ACTIVE_BIN_SHA256=""
_WINS_RP_ACTIVE_LAUNCHER=""
_WINS_RP_ACTIVE_LAUNCHER_SHA256=""
_WINS_RP_ACTIVE_LAUNCHER_ID=""
_WINS_RP_ACTIVE_LAUNCHER_DIR_ID=""
_WINS_RP_ACTIVE_VENDOR=""
_WINS_RP_ACTIVE_VENDOR_SHA256=""
_WINS_RP_ACTIVE_VENDOR_ID=""
_WINS_RP_ACTIVE_VENDOR_DIR_ID=""
_WINS_RP_ACTIVE_FRAMEWORK=""
_WINS_RP_ACTIVE_FRAMEWORK_SHA256=""
_WINS_RP_ACTIVE_FRAMEWORK_ID=""
_WINS_RP_ACTIVE_FRAMEWORK_DIR_ID=""
readonly _WINS_RP_EXECUTION_BLOCKER='owner/environment blocker: this host cannot make the Python tree immutable against same-user path replacement through execution'

_wins_rp_error() {
  printf 'release-python custody: %s\n' "$*" >&2
  return 1
}

_wins_rp_refuse_root() {
  [[ "$("$_WINS_RP_ID" -u)" != 0 ]] ||
    _wins_rp_error "owner-blocked: mutable repository ReleasePython helpers refuse euid 0" || return 1
}

_wins_rp_require_macos_tools() {
  [[ "$($_WINS_RP_UNAME -s)" == Darwin ]] ||
    _wins_rp_error "macOS is required" || return 1
  local tool
  for tool in \
    "$_WINS_RP_PLUTIL" "$_WINS_RP_STAT" "$_WINS_RP_SHASUM" \
    "$_WINS_RP_PKGUTIL" "$_WINS_RP_MKTEMP" "$_WINS_RP_UNZIP" "$_WINS_RP_ZIPINFO" \
    "$_WINS_RP_DITTO" "$_WINS_RP_FIND" "$_WINS_RP_READLINK" \
    "$_WINS_RP_ENV" "$_WINS_RP_CP" "$_WINS_RP_CHMOD" \
    "$_WINS_RP_MKDIR" "$_WINS_RP_RM" "$_WINS_RP_BASENAME" \
    "$_WINS_RP_DIRNAME" "$_WINS_RP_SANDBOX_EXEC" \
    "$_WINS_RP_SYSTEM_PYTHON"; do
    [[ -x "$tool" && ! -L "$tool" ]] ||
      _wins_rp_error "required fixed system tool is unavailable: $tool" || return 1
  done
}

_wins_rp_pin() {
  local manifest="$1" key="$2"
  "$_WINS_RP_PLUTIL" -extract "$key" raw -o - "$manifest" 2>/dev/null
}

_wins_rp_mode() {
  "$_WINS_RP_STAT" -f '%Lp' "$1" 2>/dev/null
}

_wins_rp_identity() {
  "$_WINS_RP_STAT" -f '%d:%i:%l:%z:%m:%Su:%Lp' "$1" 2>/dev/null
}

_wins_rp_dir_identity() {
  "$_WINS_RP_STAT" -f '%d:%i:%u:%Lp' "$1" 2>/dev/null
}

_wins_rp_check_path_components() {
  local path="$1" current=/ component mode owner uid_owner symbolic_mode
  [[ "$path" == /* ]] || _wins_rp_error "path is not absolute: $path" || return 1
  path="${path%/}"
  IFS='/' read -r -a _wins_rp_parts <<< "${path#/}"
  for component in "${_wins_rp_parts[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] ||
      _wins_rp_error "unsafe path component in $path" || return 1
    if [[ "$current" == / ]]; then
      current="/$component"
    else
      current="$current/$component"
    fi
    [[ ! -L "$current" ]] ||
      _wins_rp_error "symlink path component rejected: $current" || return 1
    [[ -e "$current" ]] ||
      _wins_rp_error "missing path component: $current" || return 1
    owner="$_WINS_RP_STAT"
    uid_owner="$($owner -f '%u' "$current" 2>/dev/null)" || return 1
    # An external owner boundary may authenticate inputs owned by its invoking
    # release operator. The bytes remain SHA-256 pinned, the source identity is
    # checked before and after copying, and the leaf is single-link/read-only.
    [[ "$uid_owner" == 0 || "$uid_owner" == "$("$_WINS_RP_ID" -u)" ]] ||
      _wins_rp_error "untrusted path owner rejected: $current" || return 1
    mode="$(_wins_rp_mode "$current")" || return 1
    if (( (8#$mode & 0022) != 0 )); then
      symbolic_mode="$("$_WINS_RP_STAT" -f '%Sp' "$current" 2>/dev/null)" || return 1
      [[ "$uid_owner" == 0 &&
         ( "${symbolic_mode: -1}" == t || "${symbolic_mode: -1}" == T ) ]] ||
        _wins_rp_error "group/world-writable path component rejected: $current" || return 1
    fi
  done
}

_wins_rp_check_input_file() {
  local path="$1" mode links
  _wins_rp_check_path_components "$path" || return 1
  [[ -f "$path" && ! -L "$path" ]] ||
    _wins_rp_error "regular non-symlink file required: $path" || return 1
  links="$($_WINS_RP_STAT -f '%l' "$path")" || return 1
  [[ "$links" == 1 ]] || _wins_rp_error "hardlinked input rejected: $path" || return 1
  mode="$(_wins_rp_mode "$path")" || return 1
  (( (8#$mode & 0222) == 0 )) ||
    _wins_rp_error "writable input rejected: $path" || return 1
}

_wins_rp_sha256() {
  "$_WINS_RP_SHASUM" -a 256 "$1" | while IFS=' ' read -r digest _rest; do
    printf '%s\n' "$digest"
  done
}

_wins_rp_receipt_py() {
  _wins_rp_refuse_root || return 1
  if [[ "${1:-}" == plan-migration && $# -eq 3 ]]; then
    shift
    _wins_rp_plan_migration "$@"
    return
  fi
  [[ -f "$_WINS_RP_RECEIPT_MODULE" && ! -L "$_WINS_RP_RECEIPT_MODULE" ]] ||
    _wins_rp_error "Python runtime receipt schema is missing or symbolic" || return 1
  local bootstrap
  bootstrap='import hashlib,os,stat;path=os.environ["WINS_RECEIPT_SOURCE_PATH"];expected=os.environ["WINS_RECEIPT_EXPECTED_SOURCE_SHA256"];nofollow=getattr(os,"O_NOFOLLOW",0);assert nofollow;before=os.lstat(path);fd=os.open(path,os.O_RDONLY|nofollow|getattr(os,"O_CLOEXEC",0));opened=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns,getattr(s,"st_flags",0));assert stat.S_ISREG(opened.st_mode) and opened.st_nlink==1 and identity(before)==identity(opened);data=b"".join(iter(lambda:os.read(fd,1048576),b""));after=os.fstat(fd);latest=os.lstat(path);digest=hashlib.sha256(data).hexdigest();assert len(data)<=2097152 and identity(opened)==identity(after)==identity(latest) and digest==expected;os.environ["WINS_RECEIPT_EXECUTED_SOURCE_SHA256"]=digest;exec(compile(data,path,"exec"),{"__name__":"__main__","__file__":path})'
  if [[ -n "${WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT:-}" ]]; then
    "$_WINS_RP_ENV" -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      "WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT=${WINS_MACOS_RELEASE_PYTHON_RUNTIME_RECEIPT}" \
      "WINS_RECEIPT_EXPECTED_SOURCE_SHA256=$_WINS_RP_RECEIPT_MODULE_SHA256" \
      "WINS_RECEIPT_SOURCE_PATH=$_WINS_RP_RECEIPT_MODULE" \
      "$_WINS_RP_SYSTEM_PYTHON" -I -S -c "$bootstrap" "$@"
  else
    "$_WINS_RP_ENV" -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
      "WINS_RECEIPT_EXPECTED_SOURCE_SHA256=$_WINS_RP_RECEIPT_MODULE_SHA256" \
      "WINS_RECEIPT_SOURCE_PATH=$_WINS_RP_RECEIPT_MODULE" \
      "$_WINS_RP_SYSTEM_PYTHON" -I -S -c "$bootstrap" "$@"
  fi
  return $?
}

_wins_rp_plan_migration() (
  [[ $# -eq 2 ]] ||
    _wins_rp_error "usage: _wins_rp_plan_migration REPO PIN_MANIFEST" || return 1
  local repo="$1" manifest="$2"
  local receipt_test="${_WINS_RP_HELPER_DIR}/test_macos_release_python_runtime_receipt.py"
  local runtime="$_WINS_RP_OWNER_RUNTIME"
  local python_bin="$runtime/Python.framework/Versions/3.14/bin/python3.14"
  local launcher="$runtime/launcher/python3.14"
  local bootstrap
  [[ "$("$_WINS_RP_ID" -u)" != 0 ]] ||
    _wins_rp_error "owner-blocked: migration planning refuses root execution" || return 1
  [[ -f "$_WINS_RP_RECEIPT_MODULE" && ! -L "$_WINS_RP_RECEIPT_MODULE" &&
     -f "$receipt_test" && ! -L "$receipt_test" &&
     -x "$python_bin" && ! -L "$python_bin" &&
     -x "$launcher" && ! -L "$launcher" ]] ||
    _wins_rp_error "OWNER-BLOCKED: authenticated ReleasePython migration inputs are unavailable" || return 1
  bootstrap='import hashlib,os,stat;identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns,getattr(s,"st_flags",0));nofollow=getattr(os,"O_NOFOLLOW",0);assert nofollow
def read_held(path,expected):
 before=os.lstat(path);fd=os.open(path,os.O_RDONLY|nofollow|getattr(os,"O_CLOEXEC",0));opened=os.fstat(fd);assert stat.S_ISREG(opened.st_mode) and opened.st_nlink==1 and identity(before)==identity(opened);data=b"".join(iter(lambda:os.read(fd,1048576),b""));assert len(data)<=2097152 and identity(opened)==identity(os.fstat(fd))==identity(os.lstat(path)) and hashlib.sha256(data).hexdigest()==expected;os.lseek(fd,0,os.SEEK_SET);return fd,data
source_path=os.environ["WINS_RECEIPT_MIGRATION_SOURCE_PATH"];test_path=os.environ["WINS_RECEIPT_MIGRATION_TEST_PATH"];source_fd,data=read_held(source_path,os.environ["WINS_RECEIPT_EXPECTED_SOURCE_SHA256"]);test_fd,_=read_held(test_path,os.environ["WINS_RECEIPT_EXPECTED_TEST_SHA256"]);os.environ["WINS_RECEIPT_MIGRATION_HELD_SOURCE_FD"]=str(source_fd);os.environ["WINS_RECEIPT_MIGRATION_HELD_TEST_FD"]=str(test_fd);os.environ["WINS_RECEIPT_MIGRATION_EXECUTED_SOURCE_SHA256"]=hashlib.sha256(data).hexdigest();exec(compile(data,source_path,"exec"),{"__name__":"__main__","__file__":source_path})'
  "$_WINS_RP_ENV" -i PATH=/usr/bin:/bin:/usr/sbin:/sbin \
    DYLD_FRAMEWORK_PATH="$runtime" \
    DYLD_LIBRARY_PATH="$runtime/Python.framework/Versions/3.14/lib" \
    PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONEXECUTABLE="$launcher" \
    WINS_RELEASE_CHILD_PYTHON="$python_bin" \
    WINS_RECEIPT_EXPECTED_SOURCE_SHA256="$_WINS_RP_RECEIPT_MODULE_SHA256" \
    WINS_RECEIPT_EXPECTED_TEST_SHA256="$_WINS_RP_RECEIPT_TEST_SHA256" \
    WINS_RECEIPT_MIGRATION_SOURCE_PATH="$_WINS_RP_RECEIPT_MODULE" \
    WINS_RECEIPT_MIGRATION_TEST_PATH="$receipt_test" \
    "$python_bin" -I -S -c "$bootstrap" plan-migration "$repo" "$manifest"
)

_wins_rp_bind_tree() {
  if [[ "${1:-}" == --allow-in-tree-symlinks ]]; then
    _wins_rp_receipt_py bind-tree self --allow-in-tree-symlinks "$2"
  else
    _wins_rp_receipt_py bind-tree self "$1"
  fi
}

_wins_rp_copy_authenticated() {
  _wins_rp_refuse_root || return 1
  local source="$1" expected="$2" destination="$3"
  local before after source_digest copied_digest
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] ||
    _wins_rp_error "invalid SHA-256 pin for $source" || return 1
  _wins_rp_check_input_file "$source" || return 1
  before="$(_wins_rp_identity "$source")" || return 1
  source_digest="$(_wins_rp_sha256 "$source")" || return 1
  [[ "$source_digest" == "$expected" ]] ||
    _wins_rp_error "SHA-256 mismatch for $source" || return 1
  "$_WINS_RP_CP" -p "$source" "$destination" || return 1
  "$_WINS_RP_CHMOD" 0400 "$destination" || return 1
  copied_digest="$(_wins_rp_sha256 "$destination")" || return 1
  after="$(_wins_rp_identity "$source")" || return 1
  [[ "$before" == "$after" && "$copied_digest" == "$expected" ]] ||
    _wins_rp_error "input changed during authenticated copy: $source" || return 1
}

_wins_rp_validate_wheel_entries() {
  local wheel="$1" entry lowered permissions _rest saw_entry=0
  while IFS=' ' read -r permissions _rest; do
    case "$permissions" in
      l*) _wins_rp_error "wheel symlink metadata rejected: $wheel" || return 1 ;;
    esac
  done < <("$_WINS_RP_ZIPINFO" -l "$wheel")
  while IFS= read -r entry; do
    saw_entry=1
    [[ -n "$entry" && "$entry" != /* && "$entry" != *\\* ]] ||
      _wins_rp_error "unsafe wheel member in $wheel" || return 1
    case "/$entry/" in
      */../*|*/./*) _wins_rp_error "traversal wheel member rejected: $entry" || return 1 ;;
    esac
    lowered="$(printf '%s' "$entry" | "$_WINS_RP_TR" '[:upper:]' '[:lower:]')"
    case "$lowered" in
      *.pth|*/sitecustomize.py|sitecustomize.py|*/usercustomize.py|usercustomize.py)
        _wins_rp_error "Python startup hook rejected from wheel: $entry" || return 1 ;;
    esac
  done < <("$_WINS_RP_UNZIP" -Z1 "$wheel")
  [[ "$saw_entry" == 1 ]] || _wins_rp_error "empty or unreadable wheel: $wheel" || return 1
}

_wins_rp_reject_extracted_links() {
  local root="$1" link target target_dir target_base resolved_dir resolved
  while IFS= read -r link; do
    target="$($_WINS_RP_READLINK "$link")" || return 1
    [[ "$target" != /* ]] ||
      _wins_rp_error "absolute extracted symlink rejected: $link" || return 1
    target_dir="$($_WINS_RP_DIRNAME "$target")" || return 1
    target_base="$($_WINS_RP_BASENAME "$target")" || return 1
    resolved_dir="$(cd -P -- "$($_WINS_RP_DIRNAME "$link")/$target_dir" 2>/dev/null && pwd -P)" ||
      _wins_rp_error "broken extracted symlink rejected: $link" || return 1
    resolved="$resolved_dir/$target_base"
    case "$resolved" in
      "$root"|"$root"/*) ;;
      *) _wins_rp_error "escaping extracted symlink rejected: $link" || return 1 ;;
    esac
  done < <("$_WINS_RP_FIND" "$root" -type l -print)
}

_wins_rp_merge_wheel() {
  _wins_rp_refuse_root || return 1
  local wheel="$1" stage="$2" vendor="$3" entry relative destination
  "$_WINS_RP_MKDIR" -m 0700 "$stage" || return 1
  _wins_rp_validate_wheel_entries "$wheel" || return 1
  "$_WINS_RP_UNZIP" -qq "$wheel" -d "$stage" || return 1
  [[ -z "$("$_WINS_RP_FIND" "$stage" -type l -print -quit)" ]] ||
    _wins_rp_error "wheel symlink rejected: $wheel" || return 1
  while IFS= read -r entry; do
    relative="${entry#"$stage"/}"
    destination="$vendor/$relative"
    [[ ! -e "$destination" && ! -L "$destination" ]] ||
      _wins_rp_error "wheel file collision rejected: $relative" || return 1
  done < <("$_WINS_RP_FIND" "$stage" -type f -print)
  "$_WINS_RP_DITTO" "$stage" "$vendor" || return 1
}

wins_release_python_cleanup() {
  _wins_rp_refuse_root || return 1
  if [[ -n "${_WINS_RP_ACTIVE_SCRATCH:-}" ]]; then
    case "$_WINS_RP_ACTIVE_SCRATCH" in
      /private/tmp/wins-release-python-exec.*|/tmp/wins-release-python-exec.*)
        [[ ! -L "$_WINS_RP_ACTIVE_SCRATCH" ]] ||
          _wins_rp_error "refusing cleanup of substituted exec scratch" || return 1
        "$_WINS_RP_RM" -rf "$_WINS_RP_ACTIVE_SCRATCH"
        ;;
      *) _wins_rp_error "refusing cleanup outside private exec-scratch prefix"; return 1 ;;
    esac
  fi
  _WINS_RP_ACTIVE_SCRATCH=""
  _WINS_RP_ACTIVE_RUNTIME=""
  _WINS_RP_ACTIVE_RUNTIME_ID=""
  _WINS_RP_ACTIVE_MANIFEST=""
  _WINS_RP_ACTIVE_BIN=""
  _WINS_RP_ACTIVE_BIN_SHA256=""
  _WINS_RP_ACTIVE_LAUNCHER=""
  _WINS_RP_ACTIVE_LAUNCHER_SHA256=""
  _WINS_RP_ACTIVE_LAUNCHER_ID=""
  _WINS_RP_ACTIVE_LAUNCHER_DIR_ID=""
  _WINS_RP_ACTIVE_VENDOR=""
  _WINS_RP_ACTIVE_VENDOR_SHA256=""
  _WINS_RP_ACTIVE_VENDOR_ID=""
  _WINS_RP_ACTIVE_VENDOR_DIR_ID=""
  _WINS_RP_ACTIVE_FRAMEWORK=""
  _WINS_RP_ACTIVE_FRAMEWORK_SHA256=""
  _WINS_RP_ACTIVE_FRAMEWORK_ID=""
  _WINS_RP_ACTIVE_FRAMEWORK_DIR_ID=""
  _WINS_RP_EXEC_FRAMEWORK=""
  _WINS_RP_EXEC_BIN=""
  unset WINS_RELEASE_PYTHON_RUNTIME WINS_RELEASE_PYTHON_RUNTIME_ID
  unset WINS_RELEASE_PYTHON_BIN WINS_RELEASE_PYTHON_VENDOR
}

_wins_rp_validate_pinned_archives() {
  local manifest="$1" platform=darwin_arm64 prefix
  local package package_sha component executable runtime_wheel_count wheel_count
  local index wheel wheel_sha wheel_name
  prefix="tools.python.archive_custody.$platform"
  package="$(_wins_rp_pin "$manifest" "$prefix.package.path")" ||
    _wins_rp_error "missing package.path pin" || return 1
  package_sha="$(_wins_rp_pin "$manifest" "$prefix.package.sha256")" ||
    _wins_rp_error "missing package.sha256 pin" || return 1
  component="$(_wins_rp_pin "$manifest" "$prefix.framework_component")" ||
    _wins_rp_error "missing framework_component pin" || return 1
  executable="$(_wins_rp_pin "$manifest" "$prefix.python_executable")" ||
    _wins_rp_error "missing python_executable pin" || return 1
  wheel_count="$(_wins_rp_pin "$manifest" "$prefix.wheel_count")" ||
    _wins_rp_error "missing wheel_count pin" || return 1
  runtime_wheel_count="$(_wins_rp_pin "$manifest" "$prefix.runtime_wheel_count")" ||
    _wins_rp_error "missing runtime_wheel_count pin" || return 1
  [[ "$component" == Python_Framework.pkg &&
     "$executable" == Versions/3.14/bin/python3.14 ]] ||
    _wins_rp_error "unsafe framework component or executable pin" || return 1
  [[ "$wheel_count" =~ ^[1-9][0-9]*$ && "$wheel_count" -le 64 ]] ||
    _wins_rp_error "wheel_count must be between 1 and 64" || return 1
  [[ "$runtime_wheel_count" =~ ^[1-9][0-9]*$ &&
     "$runtime_wheel_count" -le "$wheel_count" ]] ||
    _wins_rp_error "runtime_wheel_count must select a nonempty prefix" || return 1
  _wins_rp_check_input_file "$package" || return 1
  [[ "$(_wins_rp_sha256 "$package")" == "$package_sha" ]] ||
    _wins_rp_error "SHA-256 mismatch for $package" || return 1
  for ((index=0; index<wheel_count; index++)); do
    wheel="$(_wins_rp_pin "$manifest" "$prefix.wheels.$index.path")" ||
      _wins_rp_error "missing wheel path pin $index" || return 1
    wheel_sha="$(_wins_rp_pin "$manifest" "$prefix.wheels.$index.sha256")" ||
      _wins_rp_error "missing wheel SHA-256 pin $index" || return 1
    wheel_name="$($_WINS_RP_BASENAME "$wheel")"
    [[ "$wheel_name" == *.whl && "$wheel_name" != */* ]] ||
      _wins_rp_error "invalid wheel basename: $wheel_name" || return 1
    _wins_rp_check_input_file "$wheel" || return 1
    [[ "$(_wins_rp_sha256 "$wheel")" == "$wheel_sha" ]] ||
      _wins_rp_error "SHA-256 mismatch for $wheel" || return 1
  done
}

wins_release_python_materialize_unsealed() {
  _wins_rp_refuse_root || return 1
  local dest="$1" manifest="$2" platform=darwin_arm64 prefix
  local package package_sha component executable runtime_wheel_count wheel_count
  local incoming expanded framework vendor wheel_stage
  local index wheel wheel_sha wheel_copy wheel_name
  local launcher_dir launcher launcher_source
  [[ $# -eq 2 ]] ||
    _wins_rp_error "usage: wins_release_python_materialize_unsealed DEST MANIFEST" || return 1
  [[ "$dest" == /* && -d "$dest" && ! -L "$dest" ]] ||
    _wins_rp_error "materialize destination must be one absolute directory" || return 1
  _wins_rp_check_path_components "$manifest" || return 1
  [[ -f "$manifest" && ! -L "$manifest" ]] ||
    _wins_rp_error "regular pin manifest required" || return 1
  prefix="tools.python.archive_custody.$platform"
  package="$(_wins_rp_pin "$manifest" "$prefix.package.path")" ||
    _wins_rp_error "missing package.path pin" || return 1
  package_sha="$(_wins_rp_pin "$manifest" "$prefix.package.sha256")" ||
    _wins_rp_error "missing package.sha256 pin" || return 1
  component="$(_wins_rp_pin "$manifest" "$prefix.framework_component")" ||
    _wins_rp_error "missing framework_component pin" || return 1
  executable="$(_wins_rp_pin "$manifest" "$prefix.python_executable")" ||
    _wins_rp_error "missing python_executable pin" || return 1
  wheel_count="$(_wins_rp_pin "$manifest" "$prefix.wheel_count")" ||
    _wins_rp_error "missing wheel_count pin" || return 1
  runtime_wheel_count="$(_wins_rp_pin "$manifest" "$prefix.runtime_wheel_count")" ||
    _wins_rp_error "missing runtime_wheel_count pin" || return 1
  [[ "$wheel_count" =~ ^[1-9][0-9]*$ && "$wheel_count" -le 64 &&
     "$runtime_wheel_count" =~ ^[1-9][0-9]*$ &&
     "$runtime_wheel_count" -le "$wheel_count" ]] ||
    _wins_rp_error "runtime and custody wheel counts are invalid" || return 1
  incoming="$dest/incoming"
  expanded="$dest/expanded"
  framework="$dest/Python.framework"
  vendor="$dest/vendor"
  wheel_stage="$dest/wheel-stage"
  launcher_dir="$dest/launcher"
  "$_WINS_RP_MKDIR" -m 0700 "$incoming" "$vendor" "$wheel_stage" "$launcher_dir" || return 1
  _wins_rp_copy_authenticated "$package" "$package_sha" "$incoming/python.pkg" || return 1
  "$_WINS_RP_PKGUTIL" --expand-full "$incoming/python.pkg" "$expanded" || return 1
  [[ -d "$expanded/$component/Payload" && ! -L "$expanded/$component/Payload" ]] ||
    _wins_rp_error "Python_Framework.pkg payload is absent" || return 1
  _wins_rp_reject_extracted_links "$expanded/$component/Payload" || return 1
  "$_WINS_RP_DITTO" "$expanded/$component/Payload" "$framework" || return 1
  for ((index=0; index<runtime_wheel_count; index++)); do
    wheel="$(_wins_rp_pin "$manifest" "$prefix.wheels.$index.path")" ||
      _wins_rp_error "missing wheel path pin $index" || return 1
    wheel_sha="$(_wins_rp_pin "$manifest" "$prefix.wheels.$index.sha256")" ||
      _wins_rp_error "missing wheel SHA-256 pin $index" || return 1
    wheel_name="$($_WINS_RP_BASENAME "$wheel")"
    [[ "$wheel_name" == *.whl && "$wheel_name" != */* ]] ||
      _wins_rp_error "invalid wheel basename: $wheel_name" || return 1
    wheel_copy="$incoming/$index-$wheel_name"
    _wins_rp_copy_authenticated "$wheel" "$wheel_sha" "$wheel_copy" || return 1
    _wins_rp_merge_wheel "$wheel_copy" "$wheel_stage/$index" "$vendor" || return 1
  done
  [[ -f "$framework/$executable" && -x "$framework/$executable" && ! -L "$framework/$executable" ]] ||
    _wins_rp_error "pinned Python executable is absent or unsafe" || return 1
  launcher="$launcher_dir/python3.14"
  launcher_source="#!/bin/sh
exec /usr/bin/env -i \"HOME=\${HOME}\" \"TMPDIR=\${TMPDIR}\" DYLD_FRAMEWORK_PATH='${_WINS_RP_OWNER_RUNTIME}' DYLD_LIBRARY_PATH='${_WINS_RP_OWNER_RUNTIME}/Python.framework/Versions/3.14/lib' PYTHONPATH='${_WINS_RP_OWNER_RUNTIME}/vendor' PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONEXECUTABLE='${_WINS_RP_OWNER_RUNTIME}/Python.framework/Versions/3.14/bin/python3.14' PATH='${_WINS_RP_OWNER_RUNTIME}/launcher:/usr/bin:/bin:/usr/sbin:/sbin' '${_WINS_RP_OWNER_RUNTIME}/Python.framework/Versions/3.14/bin/python3.14' -S \"\$@\"
"
  printf '%s' "$launcher_source" >"$launcher" || return 1
  "$_WINS_RP_CHMOD" 0500 "$launcher" || return 1
  "$_WINS_RP_CP" -p "$launcher" "$launcher_dir/python3" || return 1
  "$_WINS_RP_CHMOD" 0500 "$launcher_dir/python3" || return 1
  "$_WINS_RP_CHMOD" 0500 "$launcher_dir" || return 1
  "$_WINS_RP_CHMOD" -R a-w "$framework" "$vendor" || return 1
  "$_WINS_RP_RM" -rf "$incoming" "$expanded" "$wheel_stage"
}

wins_release_python_prepare() {
  _wins_rp_refuse_root || return 1
  local manifest="$1" repo bindings line key value scratch
  [[ $# -eq 1 ]] || _wins_rp_error "usage: wins_release_python_prepare PIN_MANIFEST" || return 1
  [[ -z "${WINS_RELEASE_PYTHON_RUNTIME:-}" ]] ||
    _wins_rp_error "release Python custody is already active" || return 1
  _wins_rp_require_macos_tools || return 1
  [[ "$("$_WINS_RP_UNAME" -m)" == arm64 ]] ||
    _wins_rp_error "darwin_arm64 custody requires an arm64 host" || return 1
  [[ "$("$_WINS_RP_ID" -u)" != 0 ]] ||
    _wins_rp_error "owner-blocked: release Python custody must execute as a non-root user against a previously root-provisioned runtime" || return 1
  _wins_rp_check_path_components "$manifest" || return 1
  [[ -f "$manifest" && ! -L "$manifest" ]] ||
    _wins_rp_error "regular pin manifest required" || return 1
  repo="$(cd "$("$_WINS_RP_DIRNAME" "$manifest")/.." && pwd -P)" || return 1
  bindings="$(_wins_rp_receipt_py authenticate "$repo" "$manifest")" || return 1
  while IFS= read -r line; do
    key="${line%%=*}"
    value="${line#*=}"
    case "$key" in
      RUNTIME) _WINS_RP_ACTIVE_RUNTIME="$value" ;;
      BIN) _WINS_RP_ACTIVE_BIN="$value" ;;
      BIN_SHA256) _WINS_RP_ACTIVE_BIN_SHA256="$value" ;;
      VENDOR) _WINS_RP_ACTIVE_VENDOR="$value" ;;
      VENDOR_SHA256) _WINS_RP_ACTIVE_VENDOR_SHA256="$value" ;;
      VENDOR_ID) _WINS_RP_ACTIVE_VENDOR_ID="$value" ;;
      VENDOR_DIR_ID) _WINS_RP_ACTIVE_VENDOR_DIR_ID="$value" ;;
      LAUNCHER) _WINS_RP_ACTIVE_LAUNCHER="$value" ;;
      LAUNCHER_SHA256) _WINS_RP_ACTIVE_LAUNCHER_SHA256="$value" ;;
      LAUNCHER_ID) _WINS_RP_ACTIVE_LAUNCHER_ID="$value" ;;
      LAUNCHER_DIR_ID) _WINS_RP_ACTIVE_LAUNCHER_DIR_ID="$value" ;;
      FRAMEWORK) _WINS_RP_ACTIVE_FRAMEWORK="$value" ;;
      FRAMEWORK_SHA256) _WINS_RP_ACTIVE_FRAMEWORK_SHA256="$value" ;;
      FRAMEWORK_ID) _WINS_RP_ACTIVE_FRAMEWORK_ID="$value" ;;
      FRAMEWORK_DIR_ID) _WINS_RP_ACTIVE_FRAMEWORK_DIR_ID="$value" ;;
    esac
  done <<<"$bindings"
  [[ "$_WINS_RP_ACTIVE_RUNTIME" == "$_WINS_RP_OWNER_RUNTIME" &&
     "$_WINS_RP_ACTIVE_BIN" == "$_WINS_RP_OWNER_RUNTIME/Python.framework/Versions/3.14/bin/python3.14" &&
     "$_WINS_RP_ACTIVE_VENDOR" == "$_WINS_RP_OWNER_RUNTIME/vendor" &&
     "$_WINS_RP_ACTIVE_LAUNCHER" == "$_WINS_RP_OWNER_RUNTIME/launcher/python3.14" &&
     "$_WINS_RP_ACTIVE_FRAMEWORK" == "$_WINS_RP_OWNER_RUNTIME/Python.framework" ]] ||
    _wins_rp_error "authenticated Python runtime is not the owner prefix" || return 1
  scratch="$($_WINS_RP_MKTEMP -d /private/tmp/wins-release-python-exec.XXXXXX 2>/dev/null || \
    "$_WINS_RP_MKTEMP" -d /tmp/wins-release-python-exec.XXXXXX)" || return 1
  "$_WINS_RP_CHMOD" 0700 "$scratch" || { "$_WINS_RP_RM" -rf "$scratch"; return 1; }
  "$_WINS_RP_MKDIR" -m 0700 "$scratch/home" "$scratch/tmp" || {
    "$_WINS_RP_RM" -rf "$scratch"
    return 1
  }
  _WINS_RP_ACTIVE_SCRATCH="$scratch"
  _WINS_RP_ACTIVE_MANIFEST="$manifest"
  _WINS_RP_ACTIVE_RUNTIME_ID="$(_wins_rp_dir_identity "$_WINS_RP_ACTIVE_RUNTIME")" || {
    wins_release_python_cleanup
    return 1
  }
  WINS_RELEASE_PYTHON_RUNTIME="$_WINS_RP_ACTIVE_RUNTIME"
  WINS_RELEASE_PYTHON_RUNTIME_ID="$_WINS_RP_ACTIVE_RUNTIME_ID"
  WINS_RELEASE_PYTHON_BIN="$_WINS_RP_ACTIVE_BIN"
  WINS_RELEASE_PYTHON_VENDOR="$_WINS_RP_ACTIVE_VENDOR"
  export WINS_RELEASE_PYTHON_RUNTIME WINS_RELEASE_PYTHON_RUNTIME_ID
  export WINS_RELEASE_PYTHON_BIN WINS_RELEASE_PYTHON_VENDOR
}

_wins_rp_revalidate_prepared() {
  local runtime="${_WINS_RP_ACTIVE_RUNTIME:-}"
  local runtime_id="${_WINS_RP_ACTIVE_RUNTIME_ID:-}"
  local manifest="${_WINS_RP_ACTIVE_MANIFEST:-}"
  local python_bin="${_WINS_RP_ACTIVE_BIN:-}"
  local launcher="${_WINS_RP_ACTIVE_LAUNCHER:-}"
  local vendor="${_WINS_RP_ACTIVE_VENDOR:-}"
  local framework="${_WINS_RP_ACTIVE_FRAMEWORK:-}"
  local repo bindings
  [[ -n "$runtime" && -n "$runtime_id" && -n "$manifest" && -n "$python_bin" &&
     -n "$launcher" && -n "$vendor" && -n "$framework" &&
     -n "${_WINS_RP_ACTIVE_SCRATCH:-}" ]] ||
    _wins_rp_error "release Python custody is not prepared" || return 1
  [[ "$runtime" == "$_WINS_RP_OWNER_RUNTIME" ]] ||
    _wins_rp_error "release Python runtime is not the owner prefix" || return 1
  [[ "$(_wins_rp_dir_identity "$runtime")" == "$runtime_id" ]] ||
    _wins_rp_error "release Python runtime identity changed" || return 1
  [[ "$framework" == "$runtime/Python.framework" &&
     "$python_bin" == "$framework/Versions/3.14/bin/python3.14" &&
     "$launcher" == "$runtime/launcher/python3.14" &&
     "$vendor" == "$runtime/vendor" &&
     -x "$python_bin" && ! -L "$python_bin" ]] ||
    _wins_rp_error "release Python executable custody failed" || return 1
  repo="$(cd "$("$_WINS_RP_DIRNAME" "$manifest")/.." && pwd -P)" || return 1
  bindings="$(_wins_rp_receipt_py authenticate "$repo" "$manifest")" || return 1
  [[ "$bindings" == *"RUNTIME=$runtime"* ]] ||
    _wins_rp_error "release Python runtime identity changed" || return 1
}

_wins_rp_bind_execution() {
  _wins_rp_revalidate_prepared || return 1
  _WINS_RP_EXEC_FRAMEWORK="${_WINS_RP_ACTIVE_FRAMEWORK}"
  _WINS_RP_EXEC_BIN="${_WINS_RP_ACTIVE_BIN}"
  [[ -f "$_WINS_RP_EXEC_BIN" && -x "$_WINS_RP_EXEC_BIN" && ! -L "$_WINS_RP_EXEC_BIN" ]] ||
    _wins_rp_error "owner-provisioned Python executable is absent or unsafe" || return 1
}

_wins_rp_select_python_startup_flags() {
  python_startup_flags=(-S)
  case "${1:-}" in
    tools/verify_android_aab_signers.py|./tools/verify_android_aab_signers.py|/*/tools/verify_android_aab_signers.py)
      python_startup_flags=(-I -S)
      ;;
  esac
}

_wins_release_python_run_impl() (
  _wins_rp_refuse_root || return 1
  local mode="${1:-}"
  local release_keytool="" release_jarsigner="" release_node="" node_profile=""
  local release_browser="" browser_profile=""
  local release_browser_sha="" release_browser_tree="" release_browser_app=""
  local release_browser_root="" release_browser_runtime="" release_browser_identity=""
  local release_browser_product="" release_browser_version=""
  local gcp_credential_kind="${WINS_GCP_PROOF_CREDENTIAL_KIND:-}"
  local gcp_credential_path="${WINS_GCP_PROOF_CREDENTIAL_PATH:-}"
  local gcp_credential_account="${WINS_GCP_PROOF_CREDENTIAL_ACCOUNT:-}"
  local gcp_credential_project="${WINS_GCP_PROOF_CREDENTIAL_PROJECT:-}"
  local gcp_python_receipt="${WINS_GCP_PYTHON_RUNTIME_RECEIPT:-}"
  local gcp_remote_python_receipt="${WINS_GCP_REMOTE_PYTHON_RUNTIME_RECEIPT:-}"
  shift || return 1
  case "$mode" in
    clean) ;;
    openssl)
      [[ -n "${WINS_RELEASE_OPENSSL_RUNTIME:-}" &&
         -n "${WINS_RELEASE_OPENSSL_ROOT:-}" &&
         -n "${WINS_RELEASE_OPENSSL:-}" &&
         "$WINS_RELEASE_OPENSSL_ROOT" == "$WINS_RELEASE_OPENSSL_RUNTIME/extracted/openssl" &&
         "$WINS_RELEASE_OPENSSL" == "$WINS_RELEASE_OPENSSL_ROOT/bin/openssl" &&
         -x "$WINS_RELEASE_OPENSSL" && ! -L "$WINS_RELEASE_OPENSSL" ]] ||
        _wins_rp_error "authenticated OpenSSL custody is required" || return 1
      ;;
    release-tools|release-tools-browser)
      [[ -n "${WINS_RELEASE_OPENSSL_RUNTIME:-}" &&
         -n "${WINS_RELEASE_OPENSSL_ROOT:-}" &&
         -n "${WINS_RELEASE_OPENSSL:-}" &&
         "$WINS_RELEASE_OPENSSL_ROOT" == "$WINS_RELEASE_OPENSSL_RUNTIME/extracted/openssl" &&
         "$WINS_RELEASE_OPENSSL" == "$WINS_RELEASE_OPENSSL_ROOT/bin/openssl" &&
         -x "$WINS_RELEASE_OPENSSL" && ! -L "$WINS_RELEASE_OPENSSL" ]] ||
        _wins_rp_error "authenticated OpenSSL custody is required" || return 1
      [[ -n "${WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME:-}" &&
         -n "${WINS_RELEASE_JAVA_HOME:-}" &&
         "$WINS_RELEASE_JAVA_HOME" == "$WINS_RELEASE_ANDROID_TOOLCHAIN_RUNTIME/extracted/java-archive/"*/Contents/Home &&
         -d "$WINS_RELEASE_JAVA_HOME" && ! -L "$WINS_RELEASE_JAVA_HOME" ]] ||
        _wins_rp_error "authenticated Java custody is required" || return 1
      release_keytool="$WINS_RELEASE_JAVA_HOME/bin/keytool"
      release_jarsigner="$WINS_RELEASE_JAVA_HOME/bin/jarsigner"
      [[ -f "$release_keytool" && ! -L "$release_keytool" && -x "$release_keytool" &&
         -f "$release_jarsigner" && ! -L "$release_jarsigner" && -x "$release_jarsigner" ]] ||
        _wins_rp_error "authenticated Java signing tools are required" || return 1
      if [[ -n "${WINS_RELEASE_NODE:-}" ]]; then
        [[ -n "${WINS_RELEASE_NODE_RUNTIME:-}" &&
           "$WINS_RELEASE_NODE_RUNTIME" == /private/tmp/wins-release-node.* &&
           -d "$WINS_RELEASE_NODE_RUNTIME" && ! -L "$WINS_RELEASE_NODE_RUNTIME" &&
           "$WINS_RELEASE_NODE" == "$WINS_RELEASE_NODE_RUNTIME/extracted/"*/bin/node &&
           -f "$WINS_RELEASE_NODE" && ! -L "$WINS_RELEASE_NODE" &&
           -x "$WINS_RELEASE_NODE" ]] ||
          _wins_rp_error "authenticated Node custody is invalid" || return 1
        release_node="$WINS_RELEASE_NODE"
        node_profile=" (subpath \"$WINS_RELEASE_NODE_RUNTIME\")"
      fi
      if [[ -n "${WINS_RELEASE_BROWSER:-}" ]]; then
        [[ -n "${WINS_RELEASE_BROWSER_RUNTIME:-}" &&
           "$WINS_RELEASE_BROWSER_RUNTIME" == /private/tmp/wins-release-browser.* &&
           -d "$WINS_RELEASE_BROWSER_RUNTIME" && ! -L "$WINS_RELEASE_BROWSER_RUNTIME" &&
           "${WINS_RELEASE_BROWSER_ROOT:-}" == "$WINS_RELEASE_BROWSER_RUNTIME/extracted/chrome-mac-arm64" &&
           "${WINS_RELEASE_BROWSER_APP:-}" == "$WINS_RELEASE_BROWSER_ROOT/Google Chrome for Testing.app" &&
           -d "$WINS_RELEASE_BROWSER_APP" && ! -L "$WINS_RELEASE_BROWSER_APP" &&
           "$WINS_RELEASE_BROWSER" == "$WINS_RELEASE_BROWSER_APP/Contents/MacOS/Google Chrome for Testing" &&
           -f "$WINS_RELEASE_BROWSER" && ! -L "$WINS_RELEASE_BROWSER" &&
           -x "$WINS_RELEASE_BROWSER" &&
           "${WINS_RELEASE_BROWSER_SHA256:-}" =~ ^[0-9a-f]{64}$ &&
           "${WINS_RELEASE_BROWSER_TREE_SHA256:-}" =~ ^[0-9a-f]{64}$ &&
           -n "${WINS_RELEASE_BROWSER_SIGNING_IDENTITY:-}" &&
           "${WINS_RELEASE_BROWSER_PRODUCT:-Google Chrome for Testing}" == "Google Chrome for Testing" ]] ||
          _wins_rp_error "authenticated browser custody is invalid" || return 1
        local measured_browser_sha
        measured_browser_sha="$(_wins_rp_sha256 "$WINS_RELEASE_BROWSER")" || return 1
        [[ "$measured_browser_sha" == "$WINS_RELEASE_BROWSER_SHA256" ]] ||
          _wins_rp_error "authenticated browser executable digest is not the receipt digest" || return 1
        release_browser="$WINS_RELEASE_BROWSER"
        release_browser_sha="$WINS_RELEASE_BROWSER_SHA256"
        release_browser_tree="$WINS_RELEASE_BROWSER_TREE_SHA256"
        release_browser_app="$WINS_RELEASE_BROWSER_APP"
        release_browser_root="$WINS_RELEASE_BROWSER_ROOT"
        release_browser_runtime="$WINS_RELEASE_BROWSER_RUNTIME"
        release_browser_identity="$WINS_RELEASE_BROWSER_SIGNING_IDENTITY"
        release_browser_product="${WINS_RELEASE_BROWSER_PRODUCT:-Google Chrome for Testing}"
        release_browser_version="${WINS_RELEASE_BROWSER_VERSION:-}"
        browser_profile=" (subpath \"$release_browser_runtime\")"
      fi
      if [[ "$mode" == release-tools-browser && -z "$release_browser" ]]; then
        _wins_rp_error "authenticated browser custody is required" || return 1
      fi
      ;;
    android-privacy)
      [[ -n "${WINS_ANDROID_KEY_PASSWORD:-}" && -n "${WINS_ANDROID_STORE_PASSWORD:-}" ]] ||
        _wins_rp_error "Android privacy scan requires both signing passwords" || return 1
      ;;
    *) _wins_rp_error "unknown release Python environment mode"; return 1 ;;
  esac
  local runtime="${_WINS_RP_ACTIVE_RUNTIME:-}"
  local python_bin="${_WINS_RP_ACTIVE_BIN:-}"
  local launcher="${_WINS_RP_ACTIVE_LAUNCHER:-}"
  local vendor="${_WINS_RP_ACTIVE_VENDOR:-}"
  local scratch="${_WINS_RP_ACTIVE_SCRATCH:-}"
  local -a python_startup_flags
  _wins_rp_select_python_startup_flags "$@"
  _WINS_RP_EXEC_FRAMEWORK=""
  _WINS_RP_EXEC_BIN=""
  _wins_rp_bind_execution || return 1
  runtime="${_WINS_RP_ACTIVE_RUNTIME}"
  python_bin="${_WINS_RP_EXEC_BIN}"
  launcher="${_WINS_RP_ACTIVE_LAUNCHER}"
  vendor="${_WINS_RP_ACTIVE_VENDOR}"
  scratch="${_WINS_RP_ACTIVE_SCRATCH}"
  local variable
  while IFS='=' read -r variable _value; do
    case "$variable" in
      PYTHON*|DYLD*) unset "$variable" ;;
    esac
  done < <("$_WINS_RP_ENV")
  export HOME="$scratch/home"
  export TMPDIR="$scratch/tmp"
  # Python.org's relocatable framework retains absolute install names. Bind
  # them only to the owner-provisioned runtime; caller DYLD controls were
  # removed above.
  export DYLD_FRAMEWORK_PATH="$runtime"
  export DYLD_LIBRARY_PATH="$runtime/Python.framework/Versions/3.14/lib"
  export PYTHONPATH="$vendor"
  export PYTHONDONTWRITEBYTECODE=1
  export PYTHONNOUSERSITE=1
  # The authenticated env -i below remains the sole caller-environment
  # boundary. Report the authenticated raw leaf as sys.executable so an
  # isolated consumer can hand its own child only capabilities created after
  # that boundary. In particular, GCP runtime-receipt and release-dependency
  # build-attempt fields must not be copied from the caller into env -i.
  export PYTHONEXECUTABLE="$python_bin"
  export PATH="${launcher%/*}:/usr/bin:/bin:/usr/sbin:/sbin"
  local profile
  profile="(version 1) (allow default) (deny file-write* (literal \"$runtime\") (subpath \"$runtime/Python.framework\") (subpath \"$vendor\"))"
  if [[ "$mode" == clean && "${1:-}" == "$_WINS_RP_GCP_COLLECTOR" ]]; then
    local gcp_bootstrap
    [[ -n "$gcp_credential_kind" && -n "$gcp_credential_path" &&
       -n "$gcp_credential_account" && -n "$gcp_credential_project" &&
       -n "$gcp_python_receipt" && -n "$gcp_remote_python_receipt" ]] ||
      _wins_rp_error "authenticated GCP collector handoff is incomplete" || return 1
    shift
    gcp_bootstrap='import hashlib,os,stat,sys,types
collector_path,collector_sha,probe_path,probe_sha,vendor=sys.argv[1:6]
credential_names=("WINS_GCP_PROOF_CREDENTIAL_KIND","WINS_GCP_PROOF_CREDENTIAL_PATH","WINS_GCP_PROOF_CREDENTIAL_ACCOUNT","WINS_GCP_PROOF_CREDENTIAL_PROJECT","WINS_GCP_PYTHON_RUNTIME_RECEIPT","WINS_GCP_REMOTE_PYTHON_RUNTIME_RECEIPT")
credential_values=sys.argv[6:12]
collector_argv=sys.argv[12:]
sys.argv=["authenticated-gcp-bootstrap"]
for name in credential_names: os.environ.pop(name,None)
identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def hold(path,expected):
 flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0);dflags=flags|getattr(os,"O_DIRECTORY",0);parts=os.path.abspath(path).split("/")[1:];fds=[];current="/";parent=os.open(current,dflags);fds.append(parent)
 for part in parts[:-1]:
  before=os.stat(part,dir_fd=parent,follow_symlinks=False);fd=os.open(part,dflags,dir_fd=parent);opened=os.fstat(fd);after=os.stat(part,dir_fd=parent,follow_symlinks=False);assert stat.S_ISDIR(opened.st_mode) and identity(before)==identity(opened)==identity(after);parent=fd;fds.append(fd);current=os.path.join(current,part)
 before=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False);fd=os.open(parts[-1],flags,dir_fd=parent);opened=os.fstat(fd);data=b"".join(iter(lambda:os.read(fd,1048576),b""));after=os.fstat(fd);latest=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False);assert stat.S_ISREG(opened.st_mode) and opened.st_nlink==1 and len(data)<=4194304 and identity(before)==identity(opened)==identity(after)==identity(latest) and hashlib.sha256(data).hexdigest()==expected;os.lseek(fd,0,os.SEEK_SET);fds.append(fd);return data,fds
collector_data,collector_fds=hold(collector_path,collector_sha)
probe_data,probe_fds=hold(probe_path,probe_sha)
sys.path[:0]=[os.path.dirname(collector_path),vendor]
probe_module=types.ModuleType("gcp_proof_live_probe");probe_module.__file__=probe_path;sys.modules["gcp_proof_live_probe"]=probe_module;exec(compile(probe_data,probe_path,"exec"),probe_module.__dict__)
collector_module=types.ModuleType("gcp_proof_evidence");collector_module.__file__=collector_path;collector_module.__dict__["__wins_gcp_authenticated_collector_sha256__"]=collector_sha;collector_module.__dict__["__wins_gcp_authenticated_probe_sha256__"]=probe_sha;sys.modules["gcp_proof_evidence"]=collector_module;exec(compile(collector_data,collector_path,"exec"),collector_module.__dict__)
for name,value in zip(credential_names,credential_values): os.environ[name]=value
raise SystemExit(collector_module.main(collector_argv))'
    exec "$_WINS_RP_SANDBOX_EXEC" -p "$profile" "$_WINS_RP_ENV" -i \
      "HOME=$HOME" "TMPDIR=$TMPDIR" \
      "DYLD_FRAMEWORK_PATH=$DYLD_FRAMEWORK_PATH" \
      "DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH" \
      "PYTHONDONTWRITEBYTECODE=1" "PYTHONNOUSERSITE=1" \
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin" \
      "$python_bin" -I -S -c "$gcp_bootstrap" \
      "$_WINS_RP_GCP_COLLECTOR" "$_WINS_RP_GCP_COLLECTOR_SHA256" \
      "$_WINS_RP_GCP_PROBE" "$_WINS_RP_GCP_PROBE_SHA256" "$vendor" \
      "$gcp_credential_kind" "$gcp_credential_path" \
      "$gcp_credential_account" "$gcp_credential_project" \
      "$gcp_python_receipt" "$gcp_remote_python_receipt" "$@"
  fi
  if [[ "$mode" == openssl ]]; then
    profile="(version 1) (allow default) (deny file-write* (literal \"$runtime\") (subpath \"$runtime/Python.framework\") (subpath \"$vendor\") (subpath \"$WINS_RELEASE_OPENSSL_ROOT\"))"
    exec "$_WINS_RP_SANDBOX_EXEC" -p "$profile" "$_WINS_RP_ENV" -i \
      "HOME=$HOME" "TMPDIR=$TMPDIR" \
      "DYLD_FRAMEWORK_PATH=$DYLD_FRAMEWORK_PATH" \
      "DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH" \
      "PYTHONPATH=$PYTHONPATH" "PYTHONDONTWRITEBYTECODE=1" \
      "PYTHONNOUSERSITE=1" "PYTHONEXECUTABLE=$PYTHONEXECUTABLE" \
      "WINS_RELEASE_CHILD_PYTHON=$python_bin" \
      "PATH=${WINS_RELEASE_OPENSSL%/*}:$PATH" \
      "OPENSSL_CONF=/dev/null" "WINS_RELEASE_OPENSSL=$WINS_RELEASE_OPENSSL" \
      "$python_bin" "${python_startup_flags[@]}" "$@"
  fi
  if [[ "$mode" == release-tools-browser ]]; then
    # Chrome terminates DevTools targets under any inherited macOS
    # sandbox-exec profile, including allow-default. Keep this one browser
    # suite outside Seatbelt but preserve the same authenticated runtimes,
    # fail-closed path checks, and empty inherited environment.
    #
    # Only extension/tools/core_tests.py is executed through this unsandboxed
    # path. Java, OpenSSL, Node, and secrets stay out of the environment so a
    # browser child cannot inherit them even if a suite forgets to replace
    # os.environ. Python DYLD/PYTHONPATH remain only so the authenticated
    # interpreter can start; the suite must omit them from the browser child.
    exec "$_WINS_RP_ENV" -i \
      "HOME=$HOME" "TMPDIR=$TMPDIR" \
      "DYLD_FRAMEWORK_PATH=$DYLD_FRAMEWORK_PATH" \
      "DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH" \
      "PYTHONPATH=$PYTHONPATH" "PYTHONDONTWRITEBYTECODE=1" \
      "PYTHONNOUSERSITE=1" "PYTHONEXECUTABLE=$PYTHONEXECUTABLE" \
      "WINS_RELEASE_CHILD_PYTHON=$python_bin" \
      "PATH=$PATH" \
      "BROWSER_BIN=$release_browser" \
      "WINS_RELEASE_BROWSER=$release_browser" \
      "WINS_RELEASE_BROWSER_SHA256=$release_browser_sha" \
      "WINS_RELEASE_BROWSER_TREE_SHA256=$release_browser_tree" \
      "WINS_RELEASE_BROWSER_APP=$release_browser_app" \
      "WINS_RELEASE_BROWSER_ROOT=$release_browser_root" \
      "WINS_RELEASE_BROWSER_RUNTIME=$release_browser_runtime" \
      "WINS_RELEASE_BROWSER_SIGNING_IDENTITY=$release_browser_identity" \
      "WINS_RELEASE_BROWSER_PRODUCT=$release_browser_product" \
      "WINS_RELEASE_BROWSER_VERSION=$release_browser_version" \
      "$python_bin" "${python_startup_flags[@]}" "$@"
  fi
  if [[ "$mode" == release-tools ]]; then
    profile="(version 1) (allow default) (deny file-write* (literal \"$runtime\") (subpath \"$runtime/Python.framework\") (subpath \"$vendor\") (subpath \"$WINS_RELEASE_OPENSSL_ROOT\") (subpath \"$WINS_RELEASE_JAVA_HOME\")${node_profile}${browser_profile})"
    exec "$_WINS_RP_SANDBOX_EXEC" -p "$profile" "$_WINS_RP_ENV" -i \
      "HOME=$HOME" "TMPDIR=$TMPDIR" \
      "DYLD_FRAMEWORK_PATH=$DYLD_FRAMEWORK_PATH" \
      "DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH" \
      "PYTHONPATH=$PYTHONPATH" "PYTHONDONTWRITEBYTECODE=1" \
      "PYTHONNOUSERSITE=1" "PYTHONEXECUTABLE=$PYTHONEXECUTABLE" \
      "WINS_RELEASE_CHILD_PYTHON=$python_bin" \
      "PATH=${WINS_RELEASE_OPENSSL%/*}:${WINS_RELEASE_JAVA_HOME}/bin:$PATH" \
      "OPENSSL_CONF=/dev/null" "WINS_RELEASE_OPENSSL=$WINS_RELEASE_OPENSSL" \
      "WINS_RELEASE_KEYTOOL=$release_keytool" \
      "WINS_RELEASE_JARSIGNER=$release_jarsigner" \
      "WINS_RELEASE_NODE=$release_node" \
      "BROWSER_BIN=$release_browser" \
      "WINS_RELEASE_BROWSER=$release_browser" \
      "WINS_RELEASE_BROWSER_SHA256=$release_browser_sha" \
      "WINS_RELEASE_BROWSER_TREE_SHA256=$release_browser_tree" \
      "WINS_RELEASE_BROWSER_APP=$release_browser_app" \
      "WINS_RELEASE_BROWSER_ROOT=$release_browser_root" \
      "WINS_RELEASE_BROWSER_RUNTIME=$release_browser_runtime" \
      "WINS_RELEASE_BROWSER_SIGNING_IDENTITY=$release_browser_identity" \
      "WINS_RELEASE_BROWSER_PRODUCT=$release_browser_product" \
      "WINS_RELEASE_BROWSER_VERSION=$release_browser_version" \
      "$python_bin" "${python_startup_flags[@]}" "$@"
  fi
  if [[ "$mode" == android-privacy ]]; then
    exec "$_WINS_RP_SANDBOX_EXEC" -p "$profile" "$_WINS_RP_ENV" -i \
      "HOME=$HOME" "TMPDIR=$TMPDIR" \
      "DYLD_FRAMEWORK_PATH=$DYLD_FRAMEWORK_PATH" \
      "DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH" \
      "PYTHONPATH=$PYTHONPATH" "PYTHONDONTWRITEBYTECODE=1" \
      "PYTHONNOUSERSITE=1" "PYTHONEXECUTABLE=$PYTHONEXECUTABLE" \
      "WINS_RELEASE_CHILD_PYTHON=$python_bin" "PATH=$PATH" \
      "WINS_ANDROID_KEY_PASSWORD=$WINS_ANDROID_KEY_PASSWORD" \
      "WINS_ANDROID_STORE_PASSWORD=$WINS_ANDROID_STORE_PASSWORD" \
      "$python_bin" "${python_startup_flags[@]}" "$@"
  fi
  exec "$_WINS_RP_SANDBOX_EXEC" -p "$profile" "$_WINS_RP_ENV" -i \
    "HOME=$HOME" "TMPDIR=$TMPDIR" \
    "DYLD_FRAMEWORK_PATH=$DYLD_FRAMEWORK_PATH" \
    "DYLD_LIBRARY_PATH=$DYLD_LIBRARY_PATH" \
    "PYTHONPATH=$PYTHONPATH" "PYTHONDONTWRITEBYTECODE=1" \
    "PYTHONNOUSERSITE=1" "PYTHONEXECUTABLE=$PYTHONEXECUTABLE" \
    "WINS_RELEASE_CHILD_PYTHON=$python_bin" "PATH=$PATH" \
    "$python_bin" "${python_startup_flags[@]}" "$@"
)

wins_release_python_run() {
  _wins_release_python_run_impl clean "$@"
}

wins_release_python_run_with_android_privacy_secrets() {
  _wins_release_python_run_impl android-privacy "$@"
}

wins_release_python_run_with_openssl() {
  _wins_release_python_run_impl openssl "$@"
}

wins_release_python_run_with_release_tools() {
  _wins_release_python_run_impl release-tools "$@"
}

wins_release_python_run_with_release_browser() {
  _wins_release_python_run_impl release-tools-browser "$@"
}

wins_release_python_run_bootstrap_test() (
  _wins_rp_refuse_root || return 1
  [[ $# -eq 1 ]] || _wins_rp_error "usage: wins_release_python_run_bootstrap_test ABSOLUTE_TEST_PATH" || return 1
  local test_path="$1"
    case "$test_path" in
    */tools/test_release_python_archive_custody.py|*/tools/test_release_gate_determinism.py) ;;
    *) _wins_rp_error "unapproved unsandboxed bootstrap test rejected"; return 1 ;;
  esac
  # Browser runtime execution is not a bootstrap exception. Only
  # extension/tools/core_tests.py is launched unsandboxed, and only through
  # wins_release_python_run_with_release_browser.
  [[ "$test_path" == /* && -f "$test_path" && ! -L "$test_path" ]] ||
    _wins_rp_error "bootstrap test must be one absolute regular file" || return 1
  _wins_rp_check_path_components "$test_path" || return 1
  _WINS_RP_EXEC_FRAMEWORK=""
  _WINS_RP_EXEC_BIN=""
  _wins_rp_bind_execution || return 1
  local runtime="${_WINS_RP_ACTIVE_RUNTIME}"
  local python_bin="${_WINS_RP_EXEC_BIN}"
  local vendor="${_WINS_RP_ACTIVE_VENDOR}"
  local scratch="${_WINS_RP_ACTIVE_SCRATCH}"
  exec "$_WINS_RP_ENV" -i \
    HOME="$scratch/home" TMPDIR="$scratch/tmp" \
    DYLD_FRAMEWORK_PATH="$runtime" \
    DYLD_LIBRARY_PATH="$runtime/Python.framework/Versions/3.14/lib" \
    PYTHONPATH="$vendor" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 \
    PATH="/usr/bin:/bin:/usr/sbin:/sbin" \
    "$python_bin" -S "$test_path"
)
