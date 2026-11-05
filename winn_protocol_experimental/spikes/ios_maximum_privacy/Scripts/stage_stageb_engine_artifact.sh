#!/usr/bin/env bash
set -euo pipefail

readonly RECEIPT_SCHEMA="winn-stageb-engine-artifact-receipt/4"
readonly EXPECTED_INSTALL_NAME="@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine"
readonly DEVICE_SHA256="e0e810039d0ed43b1a599bb64320b0ee4ab4903cbdfd33e048bf0fb5e7f116cd"
readonly SIMULATOR_SHA256="00a17dfd702dc0490efd4f39bc2259fcc38fa4eed8311885499b5f1611713fa3"
readonly PINNED_DEPENDENCIES=$'@rpath/WinsAmneziaWGPacketEngine.framework/WinsAmneziaWGPacketEngine\n/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation\n/System/Library/Frameworks/Foundation.framework/Foundation\n/System/Library/Frameworks/Security.framework/Security\n/usr/lib/libSystem.B.dylib\n/usr/lib/libobjc.A.dylib\n/usr/lib/libresolv.9.dylib'

die() {
  printf 'stage_stageb_engine_artifact: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'usage: %s <iphoneos|iphonesimulator> <absolute-existing-output-root>\n' \
    "${0##*/}" >&2
  exit 64
}

require_tool() {
  [ -x "$1" ] || die "required tool is unavailable: $1"
}

contains_ascii_control_character() {
  LC_ALL=C printf '%s' "$1" |
    /usr/bin/od -An -tu1 |
    /usr/bin/awk '{
      for (i = 1; i <= NF; i += 1) {
        if ($i < 32 || $i == 127) bad = 1
      }
    } END { exit bad ? 0 : 1 }'
}

configure_platform() {
  case "$PLATFORM" in
    iphoneos)
      SOURCE_ARTIFACT="$SOURCE_CUSTODY_ROOT/ios/iphoneos/libWinsAmneziaWGPacketEngine.dylib"
      EXPECTED_SHA256="$DEVICE_SHA256"
      EXPECTED_BUILD_PLATFORM="IOS"
      EXPECTED_ARCHES="arm64"
      RECEIPT_ARCHES='"arm64"'
      EXPECTED_SUPPORTED_PLATFORM="iPhoneOS"
      ;;
    iphonesimulator)
      SOURCE_ARTIFACT="$SOURCE_CUSTODY_ROOT/ios/iphonesimulator/libWinsAmneziaWGPacketEngine.dylib"
      EXPECTED_SHA256="$SIMULATOR_SHA256"
      EXPECTED_BUILD_PLATFORM="IOSSIMULATOR"
      EXPECTED_ARCHES="arm64 x86_64"
      RECEIPT_ARCHES='"arm64","x86_64"'
      EXPECTED_SUPPORTED_PLATFORM="iPhoneSimulator"
      ;;
    *)
      # PLATFORM is deliberately not interpolated: command-line strings can
      # contain control characters and must never become diagnostic output.
      die "unsupported platform; expected iphoneos or iphonesimulator"
      ;;
  esac
}

expected_minos_for_arch() {
  case "$PLATFORM:$1" in
    iphoneos:arm64) printf '13.0\n' ;;
    iphonesimulator:arm64) printf '14.0\n' ;;
    iphonesimulator:x86_64) printf '13.0\n' ;;
    *) die "architecture is not pinned for the selected platform" ;;
  esac
}

validate_dependency_syntax() {
  local dependency="$1"
  local component
  local remainder

  [ -n "$dependency" ] || die "dependency path is empty"
  if contains_ascii_control_character "$dependency"; then
    die "dependency path contains a control character"
  fi
  case "$dependency" in
    *//*)
      die "dependency path contains a repeated separator"
      ;;
    */)
      die "dependency path contains an empty trailing component"
      ;;
    "$EXPECTED_INSTALL_NAME"|/*)
      ;;
    *)
      die "dependency path is neither the pinned install name nor absolute"
      ;;
  esac

  remainder="$dependency"
  case "$remainder" in
    /*) remainder="${remainder#/}" ;;
  esac
  while :; do
    case "$remainder" in
      */*)
        component="${remainder%%/*}"
        remainder="${remainder#*/}"
        ;;
      *)
        component="$remainder"
        remainder=""
        ;;
    esac
    case "$component" in
      ""|"."|"..")
        die "dependency path contains an empty, dot, or dot-dot component"
        ;;
    esac
    [ -n "$remainder" ] || break
  done
}

validate_pinned_dependency() {
  local architecture="$1"
  local dependency="$2"

  case " $EXPECTED_ARCHES " in
    *" $architecture "*) ;;
    *) die "architecture is not pinned for the selected platform" ;;
  esac
  validate_dependency_syntax "$dependency"
  if ! printf '%s\n' "$PINNED_DEPENDENCIES" |
    /usr/bin/grep -Fqx -- "$dependency"; then
    die "dependency is not in the exact pinned allowlist"
  fi
}

parse_otool_dependency_line() {
  local line="$1"
  local payload
  local dependency
  local versions

  case "$line" in
    $'\t'*) payload="${line#$'\t'}" ;;
    *) die "Mach-O dependency line is not tab-prefixed" ;;
  esac
  if contains_ascii_control_character "$payload"; then
    die "Mach-O dependency line contains a control character"
  fi
  case "$payload" in
    *" (compatibility version "*" current version "*")") ;;
    *) die "Mach-O dependency line has an invalid load-command rendering" ;;
  esac
  dependency="${payload%% (compatibility version *}"
  versions="${payload#"$dependency (compatibility version "}"
  if ! printf '%s\n' "$versions" |
    /usr/bin/grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+, current version [0-9]+\.[0-9]+\.[0-9]+\)$'; then
    die "Mach-O dependency line has invalid version fields"
  fi
  [ "$payload" = "$dependency (compatibility version $versions" ] ||
    die "Mach-O dependency line is ambiguous"
  validate_dependency_syntax "$dependency"
  printf '%s\n' "$dependency"
}

parse_otool_dependencies() {
  local output="$1"
  local expected_header="$2"
  local header
  local remainder
  local line

  case "$output" in
    *$'\n'*)
      header="${output%%$'\n'*}"
      remainder="${output#*$'\n'}"
      ;;
    *)
      die "Mach-O dependency output has no load-command lines"
      ;;
  esac
  [ "$header" = "$expected_header:" ] ||
    die "Mach-O dependency output header is not exact"
  [ -n "$remainder" ] ||
    die "Mach-O dependency output has no dependencies"
  while :; do
    case "$remainder" in
      *$'\n'*)
        line="${remainder%%$'\n'*}"
        remainder="${remainder#*$'\n'}"
        ;;
      *)
        line="$remainder"
        remainder=""
        ;;
    esac
    [ -n "$line" ] || die "Mach-O dependency output contains an empty line"
    parse_otool_dependency_line "$line"
    [ -n "$remainder" ] || break
  done
}

reject_symlink_components() {
  local candidate="$1"
  local cursor="$candidate"

  case "$candidate" in
    /*) ;;
    *) die "internal error: symlink custody check requires an absolute path" ;;
  esac

  while [ "$cursor" != "/" ]; do
    [ ! -L "$cursor" ] || die "symlink path component is forbidden: $cursor"
    cursor=$(/usr/bin/dirname -- "$cursor")
  done
}

sha256_file() {
  local path="$1"
  local result
  result=$(/usr/bin/shasum -a 256 -- "$path") ||
    die "could not hash artifact"
  printf '%s\n' "${result%% *}"
}

write_publisher_source() {
  /usr/bin/tee "$1" >/dev/null <<'WINN_STAGEB_PUBLISHER_C'
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define FRAMEWORK_NAME "WinsAmneziaWGPacketEngine.framework"
#define BINARY_NAME "WinsAmneziaWGPacketEngine"
#define STAGING_PREFIX ".winn-stageb-engine."

typedef struct {
  uint8_t data[64];
  uint32_t datalen;
  uint64_t bitlen;
  uint32_t state[8];
} sha256_ctx;

static const uint32_t sha256_k[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};

#define ROTR(a,b) (((a) >> (b)) | ((a) << (32U-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR((x),2U) ^ ROTR((x),13U) ^ ROTR((x),22U))
#define EP1(x) (ROTR((x),6U) ^ ROTR((x),11U) ^ ROTR((x),25U))
#define SIG0(x) (ROTR((x),7U) ^ ROTR((x),18U) ^ ((x) >> 3U))
#define SIG1(x) (ROTR((x),17U) ^ ROTR((x),19U) ^ ((x) >> 10U))

static void sha256_transform(sha256_ctx *ctx, const uint8_t block[64]) {
  uint32_t m[64], a, b, c, d, e, f, g, h, t1, t2;
  unsigned i;
  for (i = 0; i < 16; i++) {
    m[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
           ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
  }
  for (; i < 64; i++) m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
  a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
  e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
  for (i = 0; i < 64; i++) {
    t1=h+EP1(e)+CH(e,f,g)+sha256_k[i]+m[i];
    t2=EP0(a)+MAJ(a,b,c);
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
  ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
  ctx->datalen=0; ctx->bitlen=0;
  ctx->state[0]=0x6a09e667U; ctx->state[1]=0xbb67ae85U;
  ctx->state[2]=0x3c6ef372U; ctx->state[3]=0xa54ff53aU;
  ctx->state[4]=0x510e527fU; ctx->state[5]=0x9b05688cU;
  ctx->state[6]=0x1f83d9abU; ctx->state[7]=0x5be0cd19U;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
  size_t i;
  for (i=0; i<len; i++) {
    ctx->data[ctx->datalen++]=data[i];
    if (ctx->datalen==64) {
      sha256_transform(ctx,ctx->data);
      ctx->bitlen+=512;
      ctx->datalen=0;
    }
  }
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
  uint32_t i=ctx->datalen;
  ctx->data[i++]=0x80;
  if (i>56) {
    while (i<64) ctx->data[i++]=0;
    sha256_transform(ctx,ctx->data);
    i=0;
  }
  while (i<56) ctx->data[i++]=0;
  ctx->bitlen += (uint64_t)ctx->datalen*8U;
  for (i=0; i<8; i++) ctx->data[63-i]=(uint8_t)(ctx->bitlen>>(i*8U));
  sha256_transform(ctx,ctx->data);
  for (i=0; i<4; i++) {
    out[i]=(uint8_t)(ctx->state[0]>>(24U-i*8U));
    out[i+4]=(uint8_t)(ctx->state[1]>>(24U-i*8U));
    out[i+8]=(uint8_t)(ctx->state[2]>>(24U-i*8U));
    out[i+12]=(uint8_t)(ctx->state[3]>>(24U-i*8U));
    out[i+16]=(uint8_t)(ctx->state[4]>>(24U-i*8U));
    out[i+20]=(uint8_t)(ctx->state[5]>>(24U-i*8U));
    out[i+24]=(uint8_t)(ctx->state[6]>>(24U-i*8U));
    out[i+28]=(uint8_t)(ctx->state[7]>>(24U-i*8U));
  }
}

static int hash_fd(int fd, char hex[65]) {
  uint8_t buffer[16384], digest[32];
  sha256_ctx ctx;
  ssize_t n;
  unsigned i;
  if (lseek(fd,0,SEEK_SET)<0) return -1;
  sha256_init(&ctx);
  while ((n=read(fd,buffer,sizeof(buffer)))>0) sha256_update(&ctx,buffer,(size_t)n);
  if (n<0) return -1;
  sha256_final(&ctx,digest);
  for (i=0; i<32; i++) (void)snprintf(hex+i*2,3,"%02x",digest[i]);
  hex[64]='\0';
  return 0;
}

static void hash_bytes(const uint8_t *bytes, size_t length, char hex[65]) {
  uint8_t digest[32];
  sha256_ctx ctx;
  unsigned i;
  sha256_init(&ctx);
  sha256_update(&ctx,bytes,length);
  sha256_final(&ctx,digest);
  for (i=0; i<32; i++) (void)snprintf(hex+i*2,3,"%02x",digest[i]);
  hex[64]='\0';
}

static int write_all(int fd, const uint8_t *bytes, size_t length) {
  while (length) {
    ssize_t written=write(fd,bytes,length);
    if (written<=0) return -1;
    bytes+=(size_t)written;
    length-=(size_t)written;
  }
  return 0;
}

static int parse_fd(const char *text) {
  char *end=NULL;
  long value;
  errno=0;
  value=strtol(text,&end,10);
  if (errno || !end || *end || value<0 || value>1024) return -1;
  return (int)value;
}

static int parse_u64(const char *text, uint64_t *value) {
  char *end=NULL;
  unsigned long long parsed;
  errno=0;
  parsed=strtoull(text,&end,10);
  if (errno || !end || *end) return -1;
  *value=(uint64_t)parsed;
  return 0;
}

static int verify_directory_identity(int fd, uint64_t dev, uint64_t ino) {
  struct stat st;
  if (fstat(fd,&st)<0 || !S_ISDIR(st.st_mode)) return -1;
  return (uint64_t)st.st_dev==dev && (uint64_t)st.st_ino==ino ? 0 : -1;
}

static int valid_staging_name(const char *name) {
  size_t prefix=strlen(STAGING_PREFIX), i, length=strlen(name);
  if (length!=prefix+24 || strncmp(name,STAGING_PREFIX,prefix)!=0) return 0;
  for (i=prefix; i<length; i++) {
    if (!((name[i]>='0' && name[i]<='9') || (name[i]>='a' && name[i]<='f'))) return 0;
  }
  return 1;
}

static int verify_staging_binding(int rootfd, int stagingfd, const char *name,
                                  uint64_t rootdev, uint64_t rootino) {
  struct stat expected, actual;
  int opened;
  if (verify_directory_identity(rootfd,rootdev,rootino)<0 || !valid_staging_name(name)) return -1;
  if (fstat(stagingfd,&expected)<0 || !S_ISDIR(expected.st_mode)) return -1;
  opened=openat(rootfd,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
  if (opened<0) return -1;
  if (fstat(opened,&actual)<0) { close(opened); return -1; }
  close(opened);
  return expected.st_dev==actual.st_dev && expected.st_ino==actual.st_ino ? 0 : -1;
}

static int exact_entries(int fd, const char *first, const char *second) {
  int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
  int seen_first=0, seen_second=(second==NULL);
  DIR *dir;
  struct dirent *entry;
  if (copy<0) return -1;
  dir=fdopendir(copy);
  if (!dir) { close(copy); return -1; }
  errno=0;
  while ((entry=readdir(dir))!=NULL) {
    if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
    if (!strcmp(entry->d_name,first) && !seen_first) seen_first=1;
    else if (second && !strcmp(entry->d_name,second) && !seen_second) seen_second=1;
    else { closedir(dir); return -1; }
  }
  if (errno) { closedir(dir); return -1; }
  closedir(dir);
  return seen_first && seen_second ? 0 : -1;
}

static int directory_empty(int fd) {
  int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
  DIR *dir;
  struct dirent *entry;
  if (copy<0) return -1;
  dir=fdopendir(copy);
  if (!dir) { close(copy); return -1; }
  errno=0;
  while ((entry=readdir(dir))!=NULL) {
    if (strcmp(entry->d_name,".") && strcmp(entry->d_name,"..")) {
      closedir(dir);
      return 0;
    }
  }
  if (errno) { closedir(dir); return -1; }
  closedir(dir);
  return 1;
}

static int verify_regular_file(int dirfd, const char *name, mode_t mode,
                               uint64_t source_dev, uint64_t source_ino,
                               int check_source, const char *expected_hash) {
  struct stat st;
  char actual_hash[65];
  int fd=openat(dirfd,name,O_RDONLY|O_NOFOLLOW);
  if (fd<0) return -1;
  if (fstat(fd,&st)<0 || !S_ISREG(st.st_mode) || st.st_nlink!=1 ||
      (st.st_mode&07777)!=mode ||
      (check_source && (uint64_t)st.st_dev==source_dev && (uint64_t)st.st_ino==source_ino) ||
      hash_fd(fd,actual_hash)<0 || strcmp(actual_hash,expected_hash)!=0) {
    close(fd);
    return -1;
  }
  close(fd);
  return 0;
}

static int recursive_remove_contents(int dirfd) {
  int copy=openat(dirfd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
  DIR *dir;
  struct dirent *entry;
  if (copy<0) return -1;
  dir=fdopendir(copy);
  if (!dir) { close(copy); return -1; }
  errno=0;
  while ((entry=readdir(dir))!=NULL) {
    struct stat st;
    if (!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
    if (fstatat(dirfd,entry->d_name,&st,AT_SYMLINK_NOFOLLOW)<0) { closedir(dir); return -1; }
    if (S_ISDIR(st.st_mode)) {
      int child=openat(dirfd,entry->d_name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
      if (child<0 || fchmod(child,0700)<0 || recursive_remove_contents(child)<0) {
        if (child>=0) close(child);
        closedir(dir);
        return -1;
      }
      close(child);
      if (unlinkat(dirfd,entry->d_name,AT_REMOVEDIR)<0) { closedir(dir); return -1; }
    } else if (unlinkat(dirfd,entry->d_name,0)<0) {
      closedir(dir);
      return -1;
    }
    errno=0;
  }
  if (errno) { closedir(dir); return -1; }
  closedir(dir);
  return 0;
}

static int command_identity(int argc, char **argv) {
  struct stat st;
  int fd;
  if (argc!=3 || (fd=parse_fd(argv[2]))<0 || fstat(fd,&st)<0 || !S_ISDIR(st.st_mode)) return 1;
  printf("%llu %llu %u %o\n",
         (unsigned long long)st.st_dev,
         (unsigned long long)st.st_ino,
         (unsigned)st.st_uid,
         (unsigned)(st.st_mode&07777));
  return 0;
}

static int command_stage_publish(int argc, char **argv) {
  static const char hex_digits[]="0123456789abcdef";
  static const char plist_format[]=
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
    "<plist version=\"1.0\">\n"
    "<dict>\n"
    "  <key>CFBundleExecutable</key>\n"
    "  <string>WinsAmneziaWGPacketEngine</string>\n"
    "  <key>CFBundleIdentifier</key>\n"
    "  <string>org.winsvpn.experimental.WinsAmneziaWGPacketEngine</string>\n"
    "  <key>CFBundleInfoDictionaryVersion</key>\n"
    "  <string>6.0</string>\n"
    "  <key>CFBundleName</key>\n"
    "  <string>WinsAmneziaWGPacketEngine</string>\n"
    "  <key>CFBundlePackageType</key>\n"
    "  <string>FMWK</string>\n"
    "  <key>CFBundleShortVersionString</key>\n"
    "  <string>1.0</string>\n"
    "  <key>CFBundleSupportedPlatforms</key>\n"
    "  <array>\n"
    "    <string>%s</string>\n"
    "  </array>\n"
    "  <key>CFBundleVersion</key>\n"
    "  <string>1</string>\n"
    "  <key>MinimumOSVersion</key>\n"
    "  <string>%s</string>\n"
    "</dict>\n"
    "</plist>\n";
  uint64_t rootdev, rootino;
  uint8_t random_bytes[12], copy_buffer[16384];
  char name[sizeof(STAGING_PREFIX)+24], source_hash[65], binary_hash[65];
  char plist_hash[65], tree_hash[65], manifest[256];
  char *plist=NULL;
  struct stat source_st;
  int inheritedrootfd, rootfd=-1, sourcefd, stagingfd=-1, frameworkfd=-1, binaryfd=-1, plistfd=-1;
  int attempt, checkpoint=0, published=0, result=1, plist_length, manifest_length;
  int post_publication_cleanup_failed=0;
  size_t i, prefix;
  ssize_t count;
  const char *barrier;

  if (argc!=9 || (inheritedrootfd=parse_fd(argv[2]))<0 || (sourcefd=parse_fd(argv[5]))<0 ||
      parse_u64(argv[3],&rootdev)<0 || parse_u64(argv[4],&rootino)<0 ||
      (rootfd=openat(inheritedrootfd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW))<0 ||
      verify_directory_identity(rootfd,rootdev,rootino)<0 ||
      fstat(sourcefd,&source_st)<0 || !S_ISREG(source_st.st_mode) || source_st.st_nlink!=1 ||
      hash_fd(sourcefd,source_hash)<0 || strcmp(source_hash,argv[6])!=0) return 1;
  if (!((!strcmp(argv[7],"iPhoneOS") && !strcmp(argv[8],"13.0")) ||
        (!strcmp(argv[7],"iPhoneSimulator") && !strcmp(argv[8],"14.0")))) return 1;

  prefix=strlen(STAGING_PREFIX);
  memcpy(name,STAGING_PREFIX,prefix);
  for (attempt=0; attempt<32; attempt++) {
    arc4random_buf(random_bytes,sizeof(random_bytes));
    for (i=0; i<sizeof(random_bytes); i++) {
      name[prefix+i*2]=hex_digits[random_bytes[i]>>4];
      name[prefix+i*2+1]=hex_digits[random_bytes[i]&15U];
    }
    name[prefix+24]='\0';
    if (mkdirat(rootfd,name,0700)==0) break;
    if (errno!=EEXIST) return 1;
  }
  if (attempt==32) return 1;
  checkpoint=10;
  stagingfd=openat(rootfd,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
  if (stagingfd<0 || fchmod(stagingfd,0700)<0 ||
      mkdirat(stagingfd,FRAMEWORK_NAME,0755)<0) goto cleanup;
  frameworkfd=openat(stagingfd,FRAMEWORK_NAME,O_RDONLY|O_DIRECTORY|O_NOFOLLOW);
  if (frameworkfd<0 || fchmod(frameworkfd,0755)<0) goto cleanup;

  checkpoint=20;
  binaryfd=openat(frameworkfd,BINARY_NAME,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
  if (binaryfd<0 || lseek(sourcefd,0,SEEK_SET)<0) goto cleanup;
  while ((count=read(sourcefd,copy_buffer,sizeof(copy_buffer)))>0) {
    if (write_all(binaryfd,copy_buffer,(size_t)count)<0) goto cleanup;
  }
  if (count<0 || fchmod(binaryfd,0555)<0 || hash_fd(binaryfd,binary_hash)<0 ||
      strcmp(binary_hash,argv[6])!=0) goto cleanup;
  close(binaryfd);
  binaryfd=-1;

  checkpoint=30;
  plist_length=snprintf(NULL,0,plist_format,argv[7],argv[8]);
  if (plist_length<=0) goto cleanup;
  plist=malloc((size_t)plist_length+1U);
  if (!plist || snprintf(plist,(size_t)plist_length+1U,plist_format,argv[7],argv[8])!=plist_length)
    goto cleanup;
  plistfd=openat(frameworkfd,"Info.plist",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
  if (plistfd<0 || write_all(plistfd,(const uint8_t *)plist,(size_t)plist_length)<0 ||
      fchmod(plistfd,0444)<0 || hash_fd(plistfd,plist_hash)<0) goto cleanup;
  close(plistfd);
  plistfd=-1;
  free(plist);
  plist=NULL;

  checkpoint=40;
  manifest_length=snprintf(manifest,sizeof(manifest),
                           "0444\t%s\tInfo.plist\n0555\t%s\t%s\n",
                           plist_hash,binary_hash,BINARY_NAME);
  if (manifest_length<=0 || (size_t)manifest_length>=sizeof(manifest)) goto cleanup;
  hash_bytes((const uint8_t *)manifest,(size_t)manifest_length,tree_hash);
  if (fchmod(frameworkfd,0555)<0 || fchmod(stagingfd,0500)<0) goto cleanup;

  checkpoint=50;
  barrier=getenv("WINN_STAGEB_TEST_BARRIER");
  if (barrier && !strcmp(barrier,"1")) {
    char command[3];
    size_t received=0;
    if (dprintf(5,"%s\n",name)<0) goto cleanup;
    while (received<sizeof(command)) {
      count=read(6,command+received,sizeof(command)-received);
      if (count<=0) goto cleanup;
      received+=(size_t)count;
    }
    if (memcmp(command,"GO\n",3)!=0) goto cleanup;
  } else if (barrier && strcmp(barrier,"0")) {
    goto cleanup;
  }

  checkpoint=60;
  if (verify_staging_binding(rootfd,stagingfd,name,rootdev,rootino)<0 ||
      exact_entries(stagingfd,FRAMEWORK_NAME,NULL)<0 ||
      exact_entries(frameworkfd,"Info.plist",BINARY_NAME)<0 ||
      verify_regular_file(frameworkfd,"Info.plist",0444,0,0,0,plist_hash)<0 ||
      verify_regular_file(frameworkfd,BINARY_NAME,0555,
                          (uint64_t)source_st.st_dev,(uint64_t)source_st.st_ino,1,binary_hash)<0)
    goto cleanup;
  {
    struct stat framework_st;
    checkpoint=70;
    if (fstat(frameworkfd,&framework_st)<0 || !S_ISDIR(framework_st.st_mode) ||
        (framework_st.st_mode&07777)!=0555) goto cleanup;
  }
  /*
   * Darwin requires owner write permission on a directory moved between
   * parents. Restore the declared published mode only inside this non-yielding
   * publisher, then repeat the closed-world checks immediately before rename.
   */
  if (fchmod(frameworkfd,0755)<0 ||
      exact_entries(frameworkfd,"Info.plist",BINARY_NAME)<0 ||
      verify_regular_file(frameworkfd,"Info.plist",0444,0,0,0,plist_hash)<0 ||
      verify_regular_file(frameworkfd,BINARY_NAME,0555,
                          (uint64_t)source_st.st_dev,(uint64_t)source_st.st_ino,1,binary_hash)<0)
    goto cleanup;
  {
    struct stat framework_st;
    if (fstat(frameworkfd,&framework_st)<0 || (framework_st.st_mode&07777)!=0755)
      goto cleanup;
  }
  close(frameworkfd);
  frameworkfd=-1;
  checkpoint=80;
  if (fchmod(stagingfd,0700)<0) goto cleanup;
  if (renameatx_np(stagingfd,FRAMEWORK_NAME,rootfd,FRAMEWORK_NAME,RENAME_EXCL)<0) {
    struct stat rs, ss;
    int saved=errno;
    (void)fstat(rootfd,&rs);
    (void)fstat(stagingfd,&ss);
    fprintf(stderr,"descriptor-relative rename failed (errno=%d rootmode=%o stagemode=%o)\n",
            saved,(unsigned)(rs.st_mode&07777),(unsigned)(ss.st_mode&07777));
    goto cleanup;
  }
  published=1;
  checkpoint=90;
  barrier=getenv("WINN_STAGEB_TEST_POST_RENAME_CLEANUP_FAILURE");
  if (barrier && !strcmp(barrier,"1")) {
    post_publication_cleanup_failed=1;
  } else if (barrier && strcmp(barrier,"0")) {
    post_publication_cleanup_failed=1;
  } else if (verify_staging_binding(rootfd,stagingfd,name,rootdev,rootino)<0 ||
             directory_empty(stagingfd)!=1 ||
             unlinkat(rootfd,name,AT_REMOVEDIR)<0) {
    post_publication_cleanup_failed=1;
  }
  if (post_publication_cleanup_failed) {
    fprintf(stderr,
            "publisher warning: framework publication committed; "
            "post-publication staging cleanup failed at checkpoint 90\n");
  }
  printf("%s %s\n",plist_hash,tree_hash);
  result=0;

cleanup:
  if (plist) free(plist);
  if (plistfd>=0) close(plistfd);
  if (binaryfd>=0) close(binaryfd);
  if (frameworkfd>=0) close(frameworkfd);
  if (stagingfd>=0) {
    if (!published) {
      (void)fchmod(stagingfd,0700);
      (void)recursive_remove_contents(stagingfd);
      (void)unlinkat(rootfd,name,AT_REMOVEDIR);
    }
    close(stagingfd);
  }
  if (rootfd>=0) close(rootfd);
  if (result!=0) fprintf(stderr,"publisher rejected staged tree at checkpoint %d (errno=%d)\n",checkpoint,errno);
  return result;
}

int main(int argc, char **argv) {
  if (argc<2) return 64;
  if (!strcmp(argv[1],"identity")) return command_identity(argc,argv);
  if (!strcmp(argv[1],"stage-publish")) return command_stage_publish(argc,argv);
  return 64;
}
WINN_STAGEB_PUBLISHER_C
}

SCRIPT_DIR="$(cd -- "$(/usr/bin/dirname -- "$0")" && /bin/pwd -P)"
readonly SCRIPT_DIR
SPIKE_ROOT="$(cd -- "$SCRIPT_DIR/.." && /bin/pwd -P)"
readonly SPIKE_ROOT
REPOSITORY_ROOT="$(cd -- "$SPIKE_ROOT/../../.." && /bin/pwd -P)"
readonly REPOSITORY_ROOT
SOURCE_CUSTODY_ROOT="$REPOSITORY_ROOT/apple/EngineArtifacts"
readonly SOURCE_CUSTODY_ROOT

# A narrow unit seam lets tests exercise rejection of malformed load-command
# strings without rewriting the hash-pinned Mach-O inputs.
if [ "${1:-}" = "--validate-dependency" ]; then
  [ "$#" -eq 4 ] || usage
  PLATFORM="$2"
  readonly PLATFORM
  configure_platform
  validate_pinned_dependency "$3" "$4"
  printf 'WINN_STAGEB_DEPENDENCY_VALID\n'
  exit 0
fi

if [ "${1:-}" = "--parse-otool-dependency-line" ]; then
  [ "$#" -eq 5 ] || usage
  PLATFORM="$2"
  readonly PLATFORM
  configure_platform
  parsed_dependency="$(parse_otool_dependency_line "$4")"
  [ "$parsed_dependency" = "$5" ] ||
    die "parsed dependency differs from the expected test value"
  validate_pinned_dependency "$3" "$parsed_dependency"
  printf 'WINN_STAGEB_OTOOL_LINE_VALID\n'
  exit 0
fi

[ "$#" -eq 2 ] || usage
PLATFORM="$1"
readonly PLATFORM
OUTPUT_ROOT_INPUT="$2"
readonly OUTPUT_ROOT_INPUT
configure_platform
readonly SOURCE_ARTIFACT EXPECTED_SHA256 EXPECTED_BUILD_PLATFORM EXPECTED_ARCHES
readonly RECEIPT_ARCHES EXPECTED_SUPPORTED_PLATFORM

require_tool /usr/bin/awk
require_tool /usr/bin/dirname
require_tool /usr/bin/file
require_tool /usr/bin/grep
require_tool /usr/bin/mktemp
require_tool /usr/bin/nm
require_tool /usr/bin/od
require_tool /usr/bin/otool
require_tool /usr/bin/shasum
require_tool /usr/bin/sort
require_tool /usr/bin/stat
require_tool /usr/bin/tee
require_tool /usr/bin/vtool
require_tool /usr/bin/xcode-select
require_tool /usr/bin/xcrun
require_tool /bin/chmod
require_tool /bin/pwd
require_tool /bin/rmdir
require_tool /bin/rm

STAGER_SCRIPT_PATH="$SCRIPT_DIR/${0##*/}"
readonly STAGER_SCRIPT_PATH
reject_symlink_components "$STAGER_SCRIPT_PATH"
[ -f "$STAGER_SCRIPT_PATH" ] ||
  die "stager script identity path is not a regular file"
[ ! -L "$STAGER_SCRIPT_PATH" ] ||
  die "stager script identity path must not be a symlink"
STAGER_SCRIPT_SHA256="$(sha256_file "$STAGER_SCRIPT_PATH")"
readonly STAGER_SCRIPT_SHA256

HELPER_TMP_ROOT_INPUT="${TMPDIR:-/private/tmp}"
[ -d "$HELPER_TMP_ROOT_INPUT" ] ||
  die "helper temporary root is unavailable"
HELPER_TMP_ROOT="$(cd -- "$HELPER_TMP_ROOT_INPUT" && /bin/pwd -P)"
readonly HELPER_TMP_ROOT
HELPER_DIRECTORY=$(
  /usr/bin/mktemp -d "$HELPER_TMP_ROOT/winn-stageb-publisher.XXXXXX"
) || die "could not create publisher build directory"
/bin/chmod 0700 "$HELPER_DIRECTORY"

cleanup_helper_build() {
  if [ -n "${HELPER_DIRECTORY:-}" ] && [ -d "$HELPER_DIRECTORY" ]; then
    case "$HELPER_DIRECTORY" in
      "$HELPER_TMP_ROOT"/winn-stageb-publisher.*)
        /bin/chmod 0700 "$HELPER_DIRECTORY" 2>/dev/null || true
        /bin/chmod 0600 "$HELPER_DIRECTORY/publisher.c" "$HELPER_DIRECTORY/publisher" 2>/dev/null || true
        /bin/rm -f -- "$HELPER_DIRECTORY/publisher.c" "$HELPER_DIRECTORY/publisher" 2>/dev/null || true
        /bin/rmdir -- "$HELPER_DIRECTORY" 2>/dev/null || true
        ;;
    esac
  fi
  return 0
}
trap cleanup_helper_build EXIT HUP INT TERM

PUBLISHER_SOURCE="$HELPER_DIRECTORY/publisher.c"
PUBLISHER_BINARY="$HELPER_DIRECTORY/publisher"
write_publisher_source "$PUBLISHER_SOURCE"
PUBLISHER_SOURCE_SHA256="$(sha256_file "$PUBLISHER_SOURCE")"
readonly PUBLISHER_SOURCE_SHA256
DEVELOPER_DIRECTORY="$(/usr/bin/xcode-select -p)"
CLANG_PATH="$(/usr/bin/xcrun --sdk macosx --find clang)"
MACOS_SDK_PATH="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
CLANG_VERSION="$("$CLANG_PATH" --version)"
DEVELOPER_TOOLCHAIN_SELECTOR_SHA256="$(
  /usr/bin/printf \
    'developer_directory=%s\nclang_path=%s\nsdk_path=%s\nclang_version=%s\n' \
    "$DEVELOPER_DIRECTORY" "$CLANG_PATH" "$MACOS_SDK_PATH" "$CLANG_VERSION" |
    /usr/bin/shasum -a 256 |
    /usr/bin/awk '{ print $1 }'
)"
readonly DEVELOPER_TOOLCHAIN_SELECTOR_SHA256
"$CLANG_PATH" \
  -isysroot "$MACOS_SDK_PATH" \
  -std=c11 -Wall -Wextra -Werror -mmacosx-version-min=10.12 \
  "$PUBLISHER_SOURCE" -o "$PUBLISHER_BINARY"
/bin/chmod 0555 "$PUBLISHER_BINARY"
/bin/chmod 0444 "$PUBLISHER_SOURCE"
PUBLISHER_BINARY_SHA256="$(sha256_file "$PUBLISHER_BINARY")"
readonly PUBLISHER_BINARY_SHA256
/bin/chmod 0500 "$HELPER_DIRECTORY"

verify_publisher_identity() {
  [ "$(sha256_file "$PUBLISHER_BINARY")" = "$PUBLISHER_BINARY_SHA256" ] ||
    die "publisher binary identity changed after compilation"
}

case "$OUTPUT_ROOT_INPUT" in
  /*) ;;
  *) die "output root must be an explicit absolute path" ;;
esac

if contains_ascii_control_character "$OUTPUT_ROOT_INPUT"; then
  die "output root must not contain control characters"
fi

[ -d "$OUTPUT_ROOT_INPUT" ] || die "output root must already exist as a directory"
reject_symlink_components "$OUTPUT_ROOT_INPUT"
OUTPUT_ROOT="$(cd -- "$OUTPUT_ROOT_INPUT" && /bin/pwd -P)"
readonly OUTPUT_ROOT
[ "$OUTPUT_ROOT" = "$OUTPUT_ROOT_INPUT" ] ||
  die "output root must use its canonical absolute spelling"
[ "$OUTPUT_ROOT" != "/" ] || die "filesystem root is not a safe staging output"
[ "$OUTPUT_ROOT" != "$REPOSITORY_ROOT" ] || die "repository root is not a safe staging output"
case "$OUTPUT_ROOT" in
  "$SOURCE_CUSTODY_ROOT"|"$SOURCE_CUSTODY_ROOT"/*)
    die "engine source-custody tree is not a safe staging output"
    ;;
esac

exec 8<"$OUTPUT_ROOT"
verify_publisher_identity
OUTPUT_ROOT_IDENTITY="$("$PUBLISHER_BINARY" identity 8)" ||
  die "could not inspect opened output-root descriptor"
read -r OUTPUT_ROOT_DEVICE OUTPUT_ROOT_INODE OUTPUT_OWNER OUTPUT_MODE \
  <<< "$OUTPUT_ROOT_IDENTITY"
readonly OUTPUT_ROOT_DEVICE OUTPUT_ROOT_INODE OUTPUT_OWNER OUTPUT_MODE
[ "$(/usr/bin/stat -f '%d' -- "$OUTPUT_ROOT")" = "$OUTPUT_ROOT_DEVICE" ] &&
  [ "$(/usr/bin/stat -f '%i' -- "$OUTPUT_ROOT")" = "$OUTPUT_ROOT_INODE" ] ||
  die "output root changed while its custody descriptor was opened"

[ "$OUTPUT_OWNER" = "$(/usr/bin/id -u)" ] ||
  die "output root is not owned by the current caller"
case "$OUTPUT_MODE" in
  [0-7][0-7][0-7]) ;;
  *) die "output root has an unexpected permission mode" ;;
esac
case "${OUTPUT_MODE:1:1}${OUTPUT_MODE:2:1}" in
  [2367]?|?[2367])
    die "output root must not be group- or world-writable"
    ;;
esac

reject_symlink_components "$SOURCE_ARTIFACT"
[ -f "$SOURCE_ARTIFACT" ] || die "pinned source artifact is not a regular file"
[ ! -L "$SOURCE_ARTIFACT" ] || die "pinned source artifact must not be a symlink"
SOURCE_LINK_COUNT="$(/usr/bin/stat -f '%l' -- "$SOURCE_ARTIFACT")"
readonly SOURCE_LINK_COUNT
[ "$SOURCE_LINK_COUNT" = "1" ] ||
  die "pinned source artifact must have exactly one hard link"

SOURCE_SHA256="$(sha256_file "$SOURCE_ARTIFACT")"
readonly SOURCE_SHA256
[ "$SOURCE_SHA256" = "$EXPECTED_SHA256" ] ||
  die "pinned source SHA-256 mismatch for the selected platform"

MACHO_DESCRIPTION="$(/usr/bin/file -b -- "$SOURCE_ARTIFACT")"
readonly MACHO_DESCRIPTION
case "$MACHO_DESCRIPTION" in
  *Mach-O*) ;;
  *) die "pinned source is not a Mach-O artifact" ;;
esac

ACTUAL_ARCHES="$(
  /usr/bin/xcrun lipo -archs "$SOURCE_ARTIFACT" |
    /usr/bin/awk '{ for (i = 1; i <= NF; i += 1) print $i }' |
    LC_ALL=C /usr/bin/sort |
    /usr/bin/awk 'BEGIN { separator = "" } { printf "%s%s", separator, $0; separator = " " } END { print "" }'
)"
readonly ACTUAL_ARCHES
[ "$ACTUAL_ARCHES" = "$EXPECTED_ARCHES" ] ||
  die "Mach-O architectures do not match the pinned platform contract"

MINIMUM_OS_VERSIONS=""
for architecture in $EXPECTED_ARCHES; do
  SLICE_BUILD="$(
    /usr/bin/vtool -arch "$architecture" -show-build "$SOURCE_ARTIFACT"
  )"
  SLICE_BUILD_PLATFORM="$(
    printf '%s\n' "$SLICE_BUILD" |
      /usr/bin/awk '$1 == "platform" { print $2 }'
  )"
  [ "$SLICE_BUILD_PLATFORM" = "$EXPECTED_BUILD_PLATFORM" ] ||
    die "Mach-O slice build platform does not match the selected platform"
  SLICE_MIN_OS="$(
    printf '%s\n' "$SLICE_BUILD" |
      /usr/bin/awk '$1 == "minos" { print $2 }'
  )"
  case "$SLICE_MIN_OS" in
    *$'\n'*|"") die "Mach-O slice has an invalid minimum-OS record count" ;;
  esac
  if ! printf '%s\n' "$SLICE_MIN_OS" |
    /usr/bin/grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
    die "Mach-O slice has a non-canonical minimum OS version"
  fi
  [ "$SLICE_MIN_OS" = "$(expected_minos_for_arch "$architecture")" ] ||
    die "Mach-O slice minimum OS differs from the pinned contract"
  MINIMUM_OS_VERSIONS="${MINIMUM_OS_VERSIONS}${SLICE_MIN_OS}"$'\n'

  RAW_SLICE_INSTALL_NAME="$(
    /usr/bin/otool -arch "$architecture" -D "$SOURCE_ARTIFACT"
  )"
  [ "$RAW_SLICE_INSTALL_NAME" = "$SOURCE_ARTIFACT:"$'\n'"$EXPECTED_INSTALL_NAME" ] ||
    die "Mach-O slice install name does not match the framework contract"

  SLICE_EXPORTED_SYMBOLS="$(
    /usr/bin/nm -arch "$architecture" -gUj "$SOURCE_ARTIFACT"
  )"
  for required_symbol in \
    _wgTurnOn \
    _wgTurnOff \
    _wgGetConfig \
    _wgSetConfig \
    _wgBumpSockets \
    _wins_amneziawg_packet_engine_contract_version; do
    printf '%s\n' "$SLICE_EXPORTED_SYMBOLS" |
      /usr/bin/grep -Fqx -- "$required_symbol" ||
      die "required defined exported symbol is missing from a Mach-O slice"
  done

  RAW_SLICE_DEPENDENCIES="$(
    /usr/bin/otool -arch "$architecture" -L "$SOURCE_ARTIFACT"
  )"
  SLICE_DEPENDENCIES="$(
    parse_otool_dependencies "$RAW_SLICE_DEPENDENCIES" "$SOURCE_ARTIFACT"
  )"
  while IFS= read -r dependency; do
    [ -n "$dependency" ] || continue
    validate_pinned_dependency "$architecture" "$dependency"
  done <<< "$SLICE_DEPENDENCIES"
  SORTED_SLICE_DEPENDENCIES="$(
    printf '%s\n' "$SLICE_DEPENDENCIES" | LC_ALL=C /usr/bin/sort
  )"
  SORTED_PINNED_DEPENDENCIES="$(
    printf '%s\n' "$PINNED_DEPENDENCIES" | LC_ALL=C /usr/bin/sort
  )"
  [ "$SORTED_SLICE_DEPENDENCIES" = "$SORTED_PINNED_DEPENDENCIES" ] ||
    die "Mach-O slice dependencies differ from the exact pinned set"
done

MINIMUM_OS_VERSION="$(
  printf '%s' "$MINIMUM_OS_VERSIONS" |
    /usr/bin/awk -F. '
      NF {
        major = $1 + 0
        minor = $2 + 0
        patch = (NF >= 3 ? $3 + 0 : 0)
        if (!seen || major > best_major ||
            (major == best_major && minor > best_minor) ||
            (major == best_major && minor == best_minor && patch > best_patch)) {
          best = $0
          best_major = major
          best_minor = minor
          best_patch = patch
          seen = 1
        }
      }
      END {
        if (!seen) exit 1
        print best
      }
    '
)"
readonly MINIMUM_OS_VERSION

exec 10<"$SOURCE_ARTIFACT"
verify_publisher_identity
[ "$(sha256_file "$STAGER_SCRIPT_PATH")" = "$STAGER_SCRIPT_SHA256" ] ||
  die "stager script identity changed before publication"
PUBLISH_RESULT="$(
  "$PUBLISHER_BINARY" stage-publish \
    8 "$OUTPUT_ROOT_DEVICE" "$OUTPUT_ROOT_INODE" \
    10 "$SOURCE_SHA256" "$EXPECTED_SUPPORTED_PLATFORM" "$MINIMUM_OS_VERSION"
)" || {
  exec 10<&- 8<&-
  die "anchored closed-world framework publication failed"
}
exec 10<&-
read -r INFO_PLIST_SHA256 REGULAR_FILE_TREE_MANIFEST_SHA256 <<< "$PUBLISH_RESULT"
case "$INFO_PLIST_SHA256:$REGULAR_FILE_TREE_MANIFEST_SHA256" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
  *) die "publisher returned malformed attestation hashes" ;;
esac
[ "${#INFO_PLIST_SHA256}" -eq 64 ] &&
  [ "${#REGULAR_FILE_TREE_MANIFEST_SHA256}" -eq 64 ] ||
  die "publisher returned malformed attestation hash lengths"
readonly INFO_PLIST_SHA256 REGULAR_FILE_TREE_MANIFEST_SHA256
BINARY_SHA256="$SOURCE_SHA256"
readonly BINARY_SHA256

cleanup_helper_build
HELPER_DIRECTORY=""
trap - EXIT HUP INT TERM
exec 8<&-

/usr/bin/printf \
  '{"schema":"%s","platform":"%s","supported_platform":"%s","minimum_os_version":"%s","architectures":[%s],"install_name":"%s","source_binary_sha256":"%s","binary_sha256":"%s","info_plist_sha256":"%s","regular_file_tree_manifest_sha256":"%s","stager_script_sha256":"%s","publisher_source_sha256":"%s","publisher_binary_sha256":"%s","developer_toolchain_selector_sha256":"%s","publication":"atomic-no-replace-non-durable"}\n' \
  "$RECEIPT_SCHEMA" \
  "$PLATFORM" \
  "$EXPECTED_SUPPORTED_PLATFORM" \
  "$MINIMUM_OS_VERSION" \
  "$RECEIPT_ARCHES" \
  "$EXPECTED_INSTALL_NAME" \
  "$SOURCE_SHA256" \
  "$BINARY_SHA256" \
  "$INFO_PLIST_SHA256" \
  "$REGULAR_FILE_TREE_MANIFEST_SHA256" \
  "$STAGER_SCRIPT_SHA256" \
  "$PUBLISHER_SOURCE_SHA256" \
  "$PUBLISHER_BINARY_SHA256" \
  "$DEVELOPER_TOOLCHAIN_SELECTOR_SHA256"
