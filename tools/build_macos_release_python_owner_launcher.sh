#!/bin/bash
# Deterministically build the fixed ReleasePython owner native launcher.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)" || {
  printf 'ReleasePython native-launcher build: cannot resolve source directory\n' >&2
  exit 1
}
readonly SCRIPT_DIR
readonly SOURCE="$SCRIPT_DIR/macos_release_python_owner_launcher.c"
readonly CONTROLLER="$SCRIPT_DIR/macos_release_python_owner_provision.py"
readonly RUNTIME_LAUNCHER=/Library/WinsVPN/ReleasePython/3.14.7/launcher/python3.14
readonly RUNTIME_PYTHON=/Library/WinsVPN/ReleasePython/3.14.7/Python.framework/Versions/3.14/bin/python3.14
readonly DEVELOPER=/Applications/Xcode.app/Contents/Developer
readonly EXPECTED_CLANG=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
readonly EXPECTED_LINKER=/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld
readonly SHASUM=/usr/bin/shasum
readonly STAT=/usr/bin/stat
readonly XCRUN=/usr/bin/xcrun
readonly CODESIGN=/usr/bin/codesign

fail() {
  printf 'ReleasePython native-launcher build: %s\n' "$*" >&2
  exit 1
}

sha256() {
  "$SHASUM" -a 256 "$1" | while IFS=' ' read -r digest _rest; do
    printf '%s\n' "$digest"
  done
}

identity() {
  "$STAT" -f '%i:%u:%g:%l:%z:%Fm:%Fc:%Sf' "$1"
}

main() {
  [[ $# -eq 1 ]] || fail "usage: $0 ABSOLUTE_OUTPUT"
  local output="$1" output_parent output_leaf clang linker sdk
  local source_hash build_hash compiler_hash linker_hash sdk_closure_hash controller_hash
  local runtime_launcher_hash runtime_python_hash launcher_hash
  local scratch source_snapshot temporary first second probe
  local source_before source_fd_before compiler_before compiler_fd_before
  local linker_before linker_fd_before build_before sdk_manifest sdk_custody holder_manifest holder_complete
  local holder_ready holder_release holder_pid
  [[ "$output" == /* && "$output" != / ]] || fail 'output must be an absolute file path'
  output_parent="$(dirname "$output")"
  output_leaf="$(basename "$output")"
  [[ -d "$output_parent" && ! -L "$output_parent" ]] || fail 'output parent must be an existing real directory'
  [[ "$output_leaf" != . && "$output_leaf" != .. && "$output_leaf" != */* ]] ||
    fail 'output leaf is unsafe'
  [[ ! "$output_leaf" =~ ^[.]winsvpn-owner-launcher-stage-[0-9a-f]{48}$ ]] ||
    fail 'output leaf uses the reserved launcher transaction namespace'
  [[ ! -L "$output" ]] || fail 'output path is symbolic'
  [[ -f "$SOURCE" && ! -L "$SOURCE" ]] || fail 'reviewed C source is absent or symbolic'
  [[ -f "$CONTROLLER" && ! -L "$CONTROLLER" ]] || fail 'reviewed controller source is absent or symbolic'
  [[ -f "$RUNTIME_LAUNCHER" && ! -L "$RUNTIME_LAUNCHER" ]] || fail 'reviewed runtime launcher is absent or symbolic'
  [[ -f "$RUNTIME_PYTHON" && ! -L "$RUNTIME_PYTHON" ]] || fail 'reviewed runtime Mach-O is absent or symbolic'
  clang="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --find clang)" || fail 'reviewed Apple clang is unavailable'
  linker="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --find ld)" || fail 'reviewed Apple linker is unavailable'
  sdk="$(DEVELOPER_DIR="$DEVELOPER" "$XCRUN" --sdk macosx --show-sdk-path)" || fail 'reviewed macOS SDK is unavailable'
  [[ "$clang" == "$EXPECTED_CLANG" && -f "$clang" && ! -L "$clang" ]] ||
    fail 'clang path is not the reviewed Xcode toolchain'
  [[ "$linker" == "$EXPECTED_LINKER" && -f "$linker" && ! -L "$linker" ]] ||
    fail 'linker path is not the reviewed Xcode toolchain'
  [[ "$($STAT -f '%u:%Lp:%l:%HT' "$clang")" == '0:755:1:Regular File' ]] ||
    fail 'reviewed clang custody is invalid'
  [[ "$($STAT -f '%u:%Lp:%l:%HT' "$linker")" == '0:755:1:Regular File' ]] ||
    fail 'reviewed linker custody is invalid'

  exec 7<"$linker"
  exec 8<"$clang"
  exec 9<"$SOURCE"
  source_before="$(identity "$SOURCE")" || fail 'cannot bind reviewed source identity'
  source_fd_before="$(identity /dev/fd/9)" || fail 'cannot bind reviewed source descriptor'
  compiler_before="$(identity "$clang")" || fail 'cannot bind reviewed compiler identity'
  compiler_fd_before="$(identity /dev/fd/8)" || fail 'cannot bind reviewed compiler descriptor'
  linker_before="$(identity "$linker")" || fail 'cannot bind reviewed linker identity'
  linker_fd_before="$(identity /dev/fd/7)" || fail 'cannot bind reviewed linker descriptor'
  [[ "$source_before" == "$source_fd_before" && "$compiler_before" == "$compiler_fd_before" &&
     "$linker_before" == "$linker_fd_before" ]] ||
    fail 'source, compiler, or linker changed before descriptor custody'
  build_before="$(identity "${BASH_SOURCE[0]}")" || fail 'cannot bind build script identity'

  scratch="$(/usr/bin/mktemp -d /private/tmp/winsvpn-releasepython-owner-launcher-build.XXXXXX)" ||
    fail 'cannot create exclusive deterministic build scratch'
  [[ -d "$scratch" && ! -L "$scratch" ]] || fail 'build scratch custody is invalid'
  /bin/chmod 0700 "$scratch"
  source_snapshot="$scratch/owner-launcher.c"
  temporary="$scratch/owner-launcher"
  first="$scratch/owner-launcher.one"
  second="$scratch/owner-launcher.two"
  probe="$scratch/owner-launcher.probe"
  sdk_manifest="$scratch/sdk-inputs"
  sdk_custody="$scratch/sdk-inputs.sha256"
  holder_manifest="$scratch/retained-build-inputs"
  holder_complete="$scratch/retained-build-inputs.complete"
  holder_ready="$scratch/sdk-holder.ready"
  holder_release="$scratch/sdk-holder.release"
  trap 'if [[ -n "${holder_pid:-}" ]]; then /bin/kill "$holder_pid" 2>/dev/null || true; fi; /bin/rm -rf -- "$scratch"' EXIT HUP INT TERM
  (umask 077; /bin/cp /dev/fd/9 "$source_snapshot")
  /bin/chmod 0400 "$source_snapshot"
  source_hash="$(sha256 "$source_snapshot")"
  build_hash="$(sha256 "${BASH_SOURCE[0]}")"
  compiler_hash="$(sha256 /dev/fd/8)"
  linker_hash="$(sha256 /dev/fd/7)"
  controller_hash="$(sha256 "$CONTROLLER")"
  runtime_launcher_hash="$(sha256 "$RUNTIME_LAUNCHER")"
  runtime_python_hash="$(sha256 "$RUNTIME_PYTHON")"
  [[ "$source_hash" == "$(sha256 "$SOURCE")" ]] || fail 'retained source snapshot digest mismatch'

  validate_inputs() {
    [[ "$(identity "$SOURCE")" == "$source_before" &&
       "$(identity /dev/fd/9)" == "$source_fd_before" &&
       "$(sha256 "$SOURCE")" == "$source_hash" ]] ||
      fail 'reviewed source changed during deterministic build'
    [[ "$(identity "$clang")" == "$compiler_before" &&
       "$(identity /dev/fd/8)" == "$compiler_fd_before" &&
       "$(sha256 "$clang")" == "$compiler_hash" ]] ||
      fail 'executed compiler changed during deterministic build'
    [[ "$(identity "$linker")" == "$linker_before" &&
       "$(identity /dev/fd/7)" == "$linker_fd_before" &&
       "$(sha256 "$linker")" == "$linker_hash" ]] ||
      fail 'executed linker changed during deterministic build'
    [[ "$(identity "${BASH_SOURCE[0]}")" == "$build_before" &&
       "$(sha256 "${BASH_SOURCE[0]}")" == "$build_hash" ]] ||
      fail 'reviewed build script changed during deterministic build'
    [[ "$(sha256 "$source_snapshot")" == "$source_hash" ]] ||
      fail 'retained source snapshot changed during deterministic build'
  }

  build_once() {
    local destination="$1" tag="$2" closure_hash="$3"
    local dependencies="$scratch/dependencies.$tag" trace="$scratch/linker.$tag"
    local diagnostics="$scratch/diagnostics.$tag" manifest="$scratch/sdk-inputs.$tag"
    if ! /usr/bin/env -i PATH=/usr/bin:/bin TMPDIR=/private/tmp \
      DEVELOPER_DIR="$DEVELOPER" SOURCE_DATE_EPOCH=0 ZERO_AR_DATE=1 \
      "$clang" -std=c17 -Os -Wall -Wextra -Wpedantic -Werror \
        -isysroot "$sdk" -mmacosx-version-min=13.0 -fno-ident -fvisibility=hidden \
        "--ld-path=$linker" -MD -MF "$dependencies" -Wl,-t \
        -Wl,-dead_strip -Wl,-no_adhoc_codesign -Wl,-fatal_warnings -lproc \
        "-DWINS_BUILD_SOURCE_SHA256=\"$source_hash\"" \
        "-DWINS_BUILD_SCRIPT_SHA256=\"$build_hash\"" \
        "-DWINS_BUILD_COMPILER_SHA256=\"$compiler_hash\"" \
        "-DWINS_BUILD_LINKER_SHA256=\"$linker_hash\"" \
        "-DWINS_BUILD_SDK_CLOSURE_SHA256=\"$closure_hash\"" \
        "-DWINS_CONTROLLER_SHA256=\"$controller_hash\"" \
        "-DWINS_RUNTIME_LAUNCHER_SHA256=\"$runtime_launcher_hash\"" \
        "-DWINS_RUNTIME_PYTHON_SHA256=\"$runtime_python_hash\"" \
        "$source_snapshot" -o "$temporary" >"$trace" 2>"$diagnostics"; then
      /bin/cat "$diagnostics" >&2
      fail 'warning-clean compiler/linker invocation failed'
    fi
    [[ ! -s "$diagnostics" ]] || fail 'compiler or linker emitted diagnostics'
    {
      /usr/bin/awk '{ sub(/\\\\$/, ""); for (i = 1; i <= NF; ++i) print $i }' "$dependencies"
      /bin/cat "$trace"
    } | while IFS= read -r input; do
      input="${input%:}"
      input="${input%%(*}"
      case "$input" in
        "$sdk"/*|"$DEVELOPER"/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/*)
          [[ -f "$input" || -L "$input" ]] ||
            fail "compiler/linker SDK input is not a file: $input"
          printf '%s\n' "$input"
          if [[ -L "$input" ]]; then
            /bin/realpath "$input"
          fi
          ;;
      esac
    done | /usr/bin/sort -u >"$manifest"
    [[ -s "$manifest" ]] || fail 'compiler/linker SDK input closure is empty'
    "$CODESIGN" --force --sign - --timestamp=none \
      --identifier org.winsvpn.releasepython.owner-launcher "$temporary"
    /bin/chmod 0555 "$temporary"
    /bin/cp -p "$temporary" "$destination"
    /bin/rm -f -- "$temporary"
    validate_inputs
  }

  build_once "$probe" probe "$(printf '0%.0s' {1..64})"
  /bin/mv "$scratch/sdk-inputs.probe" "$sdk_manifest"
  while IFS= read -r input; do
    if [[ -L "$input" ]]; then
      printf 'L %s  %s\n' "$(/usr/bin/readlink "$input")" "$input"
    else
      printf 'F %s  %s\n' "$(sha256 "$input")" "$input"
    fi
  done <"$sdk_manifest" >"$sdk_custody"
  sdk_closure_hash="$(sha256 "$sdk_custody")"
  /bin/rm -f -- "$probe"

  {
    /bin/cat "$sdk_manifest"
    printf '%s\n' "$SOURCE" "${BASH_SOURCE[0]}" "$clang" "$linker" \
      "$CONTROLLER" "$RUNTIME_LAUNCHER" "$RUNTIME_PYTHON"
  } | /usr/bin/sort -u >"$holder_manifest"
  while IFS= read -r input; do
    [[ "$input" == /* ]] || fail 'retained build input path is not absolute'
    printf '%s\n' "$input"
    while [[ "$input" != / ]]; do
      input="$(dirname "$input")"
      printf '%s\n' "$input"
    done
  done <"$holder_manifest" | /usr/bin/sort -u >"$holder_complete"
  /bin/mv "$holder_complete" "$holder_manifest"
  /usr/bin/env -i HOME=/private/var/empty PATH=/usr/bin:/bin TMPDIR=/private/tmp /usr/bin/python3 -I -S -c $'import hashlib,os,select,stat,sys,time\nmanifest,ready,release=sys.argv[1:]\npaths=[line.rstrip("\\n") for line in open(manifest,encoding="utf-8") if line.rstrip("\\n")]\nheld=[]\ndef identity(value): return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)\nkqueue=select.kqueue(); by_fd={}\nnotes=select.KQ_NOTE_DELETE|select.KQ_NOTE_WRITE|select.KQ_NOTE_EXTEND|select.KQ_NOTE_LINK|select.KQ_NOTE_RENAME|select.KQ_NOTE_REVOKE\ndef watch(fd,path):\n by_fd[fd]=path; kqueue.control([select.kevent(fd,filter=select.KQ_FILTER_VNODE,flags=select.KQ_EV_ADD|select.KQ_EV_CLEAR,fflags=notes)],0,0)\ndef check_events(timeout):\n events=kqueue.control(None,256,timeout)\n if events: raise RuntimeError("retained input vnode event: "+by_fd.get(events[0].ident,"unknown"))\nfor path in paths:\n named=os.lstat(path)\n if stat.S_ISLNK(named.st_mode): held.append((path,None,"L",identity(named),os.readlink(path)))\n elif stat.S_ISDIR(named.st_mode):\n  fd=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)); info=os.fstat(fd); assert stat.S_ISDIR(info.st_mode) and identity(info)==identity(named); held.append((path,fd,"D",identity(info),None)); watch(fd,path)\n elif stat.S_ISREG(named.st_mode):\n  fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)); info=os.fstat(fd); assert stat.S_ISREG(info.st_mode) and info.st_nlink>=1 and identity(info)==identity(named); data=b"".join(iter(lambda:os.read(fd,1048576),b"")); held.append((path,fd,"F",identity(info),hashlib.sha256(data).digest())); watch(fd,path)\n else: raise RuntimeError("unsupported retained build input: "+path)\nmarker=os.open(ready,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400); os.write(marker,b"ready\\n"); os.fsync(marker); os.close(marker)\nwhile not os.path.exists(release):\n check_events(0.05); time.sleep(0.01)\ncheck_events(0)\nfor path,fd,kind,expected,digest in held:\n named=os.lstat(path); assert identity(named)==expected\n if kind=="L": assert os.readlink(path)==digest\n elif kind=="D": assert identity(os.fstat(fd))==expected and stat.S_ISDIR(os.fstat(fd).st_mode)\n else:\n  info=os.fstat(fd); os.lseek(fd,0,0); data=b"".join(iter(lambda:os.read(fd,1048576),b"")); assert identity(info)==expected and stat.S_ISREG(info.st_mode) and hashlib.sha256(data).digest()==digest\n' "$holder_manifest" "$holder_ready" "$holder_release" &
  holder_pid=$!
  while [[ ! -f "$holder_ready" ]] && /bin/kill -0 "$holder_pid" 2>/dev/null; do /bin/sleep 0.01; done
  [[ -f "$holder_ready" ]] || { wait "$holder_pid"; fail 'SDK descriptor holder failed before build'; }

  build_once "$first" one "$sdk_closure_hash"
  build_once "$second" two "$sdk_closure_hash"
  /usr/bin/cmp -s "$sdk_manifest" "$scratch/sdk-inputs.one" ||
    fail 'compiler SDK input closure changed in first derivation build'
  /usr/bin/cmp -s "$sdk_manifest" "$scratch/sdk-inputs.two" ||
    fail 'compiler SDK input closure changed in second derivation build'
  (umask 077; printf 'release\n' >"$holder_release")
  wait "$holder_pid" || fail 'retained compiler, linker, or SDK input changed during deterministic build'
  holder_pid=''
  [[ "$(sha256 "$first")" == "$(sha256 "$second")" ]] ||
    fail 'two clean builds are not deterministic'
  launcher_hash="$(sha256 "$first")"
  /usr/bin/env -i HOME=/private/var/empty PATH=/usr/bin:/bin TMPDIR=/private/tmp \
    /usr/bin/python3 -I -S -c $'import hashlib,os,re,stat,sys\nparent_path,expected=sys.argv[1:]\npattern=re.compile(r"\\A[.]winsvpn-owner-launcher-stage-[0-9a-f]{48}\\Z")\ndef stable(value): return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid)\ndef digest(fd):\n info=os.fstat(fd); value=hashlib.sha256(); offset=0\n while offset<info.st_size:\n  block=os.pread(fd,min(1048576,info.st_size-offset),offset)\n  if not block: raise RuntimeError("short abandoned-stage read")\n  value.update(block); offset+=len(block)\n if os.pread(fd,1,offset): raise RuntimeError("abandoned stage grew")\n return value.hexdigest()\nflags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)\ncomponents=[item for item in parent_path.split("/") if item]\ntree=[]; root=os.open("/",flags); tree.append((root,None,None,stable(os.fstat(root)))); current=root\nfor component in components:\n child=os.open(component,flags,dir_fd=current); info=os.fstat(child)\n if not stat.S_ISDIR(info.st_mode): raise RuntimeError("publication recovery ancestor is not a directory")\n tree.append((child,current,component,stable(info))); current=child\nparent=current\ndef validate_tree():\n for descriptor,parent_fd,name,wanted in tree:\n  current_info=os.fstat(descriptor); named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False) if parent_fd is not None else current_info\n  if stable(current_info)!=wanted or stable(named)!=wanted: raise RuntimeError("publication recovery ancestor identity changed")\nentries=[]\nwith os.scandir(parent) as scan:\n for entry in scan:\n  if len(entries)>=4096: raise RuntimeError("publication recovery directory exceeds entry ceiling")\n  entries.append(entry.name)\nstages=sorted(name for name in entries if pattern.fullmatch(name))\nif len(stages)>16: raise RuntimeError("abandoned launcher stage count exceeds ceiling")\nfor name in stages:\n validate_tree(); named=os.stat(name,dir_fd=parent,follow_symlinks=False); stage=os.open(name,flags,dir_fd=parent)\n try:\n  held=os.fstat(stage)\n  if stable(held)!=stable(named) or stat.S_IMODE(held.st_mode)!=0o700 or held.st_uid!=os.getuid() or held.st_gid!=os.getgid(): raise RuntimeError("abandoned launcher stage custody is invalid")\n  children=os.listdir(stage)\n  if children not in ([],["launcher"]): raise RuntimeError("abandoned launcher stage shape is invalid")\n  if children:\n   launcher=os.open("launcher",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=stage)\n   try:\n    info=os.fstat(launcher)\n    if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() or info.st_gid!=os.getgid() or stat.S_IMODE(info.st_mode) not in (0o500,0o555) or digest(launcher)!=expected: raise RuntimeError("abandoned launcher bytes are not authenticated")\n   finally: os.close(launcher)\n   os.unlink("launcher",dir_fd=stage)\n  if stable(os.fstat(stage))[:5]!=stable(named)[:5]: raise RuntimeError("abandoned launcher stage changed during cleanup")\n finally: os.close(stage)\n os.rmdir(name,dir_fd=parent); os.fsync(parent)\nvalidate_tree()\nfor descriptor,_parent,_name,_wanted in reversed(tree): os.close(descriptor)\n' "$output_parent" "$launcher_hash" >/dev/null
  /usr/bin/env -i HOME=/private/var/empty PATH=/usr/bin:/bin TMPDIR=/private/tmp \
    /usr/bin/python3 -I -S -c $'import ctypes,errno,hashlib,os,secrets,select,stat,sys\nparent_path,leaf,source_path,expected=sys.argv[1:]\nif not parent_path.startswith("/") or not leaf or leaf in {".",".."} or "/" in leaf or "\\0" in leaf: raise RuntimeError("unsafe publication path")\ndef identity(value): return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)\ndef stable_directory_identity(value): return (value.st_dev,value.st_ino,value.st_mode,value.st_uid,value.st_gid)\ndef stable_directory_identity_from_tuple(value): return value[:5]\ndef digest(fd):\n info=os.fstat(fd); value=hashlib.sha256(); offset=0\n while offset<info.st_size:\n  block=os.pread(fd,min(1048576,info.st_size-offset),offset)\n  if not block: raise RuntimeError("short retained publication read")\n  value.update(block); offset+=len(block)\n if os.pread(fd,1,offset): raise RuntimeError("retained publication input grew")\n return value.hexdigest()\nflags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)\ncomponents=[item for item in parent_path.split("/") if item]\ntree=[]; root=os.open("/",flags); tree.append((root,None,None,identity(os.fstat(root)))); current=root\nfor component in components:\n child=os.open(component,flags,dir_fd=current); info=os.fstat(child)\n if not stat.S_ISDIR(info.st_mode): raise RuntimeError("publication ancestor is not a directory")\n tree.append((child,current,component,identity(info))); current=child\nparent=current\nkqueue=select.kqueue(); notes=select.KQ_NOTE_DELETE|select.KQ_NOTE_ATTRIB|select.KQ_NOTE_LINK|select.KQ_NOTE_RENAME|select.KQ_NOTE_REVOKE\nfor index,(descriptor,_parent,_name,_expected) in enumerate(tree):\n watched=notes if index+1<len(tree) else select.KQ_NOTE_DELETE|select.KQ_NOTE_RENAME|select.KQ_NOTE_REVOKE\n kqueue.control([select.kevent(descriptor,filter=select.KQ_FILTER_VNODE,flags=select.KQ_EV_ADD|select.KQ_EV_CLEAR,fflags=watched)],0,0)\ndef validate_tree():\n if kqueue.control(None,256,0): raise RuntimeError("publication ancestor changed while retained")\n for index,(descriptor,parent_fd,name,wanted) in enumerate(tree):\n  current=os.fstat(descriptor); named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False) if parent_fd is not None else current\n  if index+1==len(tree):\n   if stable_directory_identity(current)!=stable_directory_identity(named) or stable_directory_identity(current)!=stable_directory_identity_from_tuple(wanted): raise RuntimeError("retained publication directory identity changed")\n  elif identity(current)!=wanted or identity(named)!=wanted: raise RuntimeError("publication ancestor pathname changed")\nsource=os.open(source_path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)); source_info=os.fstat(source)\nif not stat.S_ISREG(source_info.st_mode) or source_info.st_nlink!=1 or digest(source)!=expected: raise RuntimeError("publication source is not exact")\ntry:\n existing=os.open(leaf,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=parent)\nexcept FileNotFoundError: existing=None\nif existing is not None:\n info=os.fstat(existing)\n if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o555 or info.st_uid!=os.getuid() or info.st_gid!=os.getgid() or digest(existing)!=expected: raise RuntimeError("existing publication is not an exact retry")\n validate_tree(); os.close(existing); os.close(source); kqueue.close()\n for descriptor,_parent,_name,_expected in reversed(tree): os.close(descriptor)\n print("already-present"); raise SystemExit(0)\nstage_name=".winsvpn-owner-launcher-stage-"+secrets.token_hex(24); os.mkdir(stage_name,0o700,dir_fd=parent); stage_dir=os.open(stage_name,flags,dir_fd=parent); stage_fd=None; published_fd=None; committed=False\ntry:\n stage_fd=os.open("launcher",os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),0o500,dir_fd=stage_dir)\n offset=0\n while offset<source_info.st_size:\n  block=os.pread(source,min(1048576,source_info.st_size-offset),offset)\n  if not block: raise RuntimeError("publication source ended early")\n  cursor=0\n  while cursor<len(block):\n   written=os.write(stage_fd,block[cursor:])\n   if written<=0: raise RuntimeError("short publication write")\n   cursor+=written\n  offset+=len(block)\n os.fchmod(stage_fd,0o555); os.fsync(stage_fd); os.close(stage_fd); stage_fd=None\n retained=os.open("launcher",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=stage_dir); retained_info=os.fstat(retained)\n if not stat.S_ISREG(retained_info.st_mode) or retained_info.st_nlink!=1 or stat.S_IMODE(retained_info.st_mode)!=0o555 or digest(retained)!=expected: raise RuntimeError("private publication stage is invalid")\n validate_tree(); libc=ctypes.CDLL(None,use_errno=True); rename=libc.renameatx_np; rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]; rename.restype=ctypes.c_int\n if rename(stage_dir,b"launcher",parent,os.fsencode(leaf),4)!=0: raise OSError(ctypes.get_errno(),os.strerror(ctypes.get_errno()))\n committed=True; os.fsync(parent); published_fd=os.open(leaf,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=parent); published_info=os.fstat(published_fd)\n if identity(published_info)[:8]!=identity(retained_info)[:8] or stat.S_IMODE(published_info.st_mode)!=0o555 or published_info.st_nlink!=1 or digest(published_fd)!=expected: raise RuntimeError("published launcher readback is not exact")\n validate_tree(); os.close(retained); retained=None; os.rmdir(stage_name,dir_fd=parent); os.fsync(parent); validate_tree(); print("published")\nexcept BaseException:\n if stage_fd is not None: os.close(stage_fd)\n if committed:\n  try:\n   named=os.stat(leaf,dir_fd=parent,follow_symlinks=False)\n   rollback_fd=published_fd if published_fd is not None else retained\n   if rollback_fd is not None and identity(named)==identity(os.fstat(rollback_fd)): os.unlink(leaf,dir_fd=parent); os.fsync(parent)\n  except OSError: pass\n try: os.unlink("launcher",dir_fd=stage_dir)\n except FileNotFoundError: pass\n try: os.rmdir(stage_name,dir_fd=parent); os.fsync(parent)\n except OSError: pass\n raise\nfinally:\n if published_fd is not None: os.close(published_fd)\n try:\n  if retained is not None: os.close(retained)\n except NameError: pass\n os.close(stage_dir); os.close(source); kqueue.close()\n for descriptor,_parent,_name,_expected in reversed(tree): os.close(descriptor)\n' "$output_parent" "$output_leaf" "$first" "$launcher_hash" >/dev/null
  [[ "$(sha256 "$output")" == "$launcher_hash" ]] || fail 'bound output digest drifted'
  validate_inputs
  /bin/rm -rf -- "$scratch"
  trap - EXIT HUP INT TERM
  exec 8<&-
  exec 9<&-
  exec 7<&-
  printf 'source_sha256=%s\n' "$source_hash"
  printf 'build_script_sha256=%s\n' "$build_hash"
  printf 'compiler_sha256=%s\n' "$compiler_hash"
  printf 'linker_sha256=%s\n' "$linker_hash"
  printf 'sdk_closure_sha256=%s\n' "$sdk_closure_hash"
  printf 'controller_sha256=%s\n' "$controller_hash"
  printf 'runtime_launcher_sha256=%s\n' "$runtime_launcher_hash"
  printf 'runtime_python_sha256=%s\n' "$runtime_python_hash"
  printf 'launcher_sha256=%s\n' "$launcher_hash"
}

main "$@"
