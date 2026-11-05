# Standalone Windows-native custody verifier for official Inno Setup 7.1.0.
# Never executes a setup candidate, never executes ISSigTool.exe, never
# searches PATH, and never uploads an artifact.
[CmdletBinding()]
param(
    [switch]$VerifyPins,
    [switch]$VerifyInstaller,
    [switch]$VerifyCompiler,
    [switch]$Measure,
    [switch]$CustodySelfTest,
    [ValidateSet('sibling-churn', 'parent-swap', 'parent-swap-restore')]
    [string]$CustodySelfTestKind = 'sibling-churn',
    [ValidateSet('x64', 'x86', 'arm64')]
    [string]$Architecture,
    [string]$Path,
    [string]$PinPath
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:WinsInnoContract = 'winsvpn-inno-toolchain-custody-v1'
$script:WinsInnoVersion = '7.1.0'
$script:WinsInnoSha256Pattern = '^[0-9a-f]{64}$'
$script:WinsInnoPublisherName = 'Pyrsys B.V.'
$script:WinsInnoMaxPinBytes = 262144
$script:WinsInnoMaxInstallerBytes = 33554432
$script:WinsInnoMaxCompilerBytes = 16777216
$script:WinsInnoMaxIssigBytes = 4096
$script:WinsInnoMaxPkcs7 = 262144
$script:WinsInnoMaxPkcs7Certs = 8
$script:WinsInnoMaxTreeFiles = 4096
$script:WinsInnoMaxTreeBytes = 67108864

$script:WinsInnoOfficialPublisher = [ordered]@{
    authenticode_publisher_name = 'Pyrsys B.V.'
    authenticode_subject_rfc4514 = 'CN=Pyrsys B.V.,O=Pyrsys B.V.,ST=Noord-Holland,C=NL'
    authenticode_issuer_rfc4514 = 'CN=Sectigo Public Code Signing CA R36,O=Sectigo Limited,C=GB'
    authenticode_leaf_serial_hex = 'b208315c09c02ef1550e0c8d127cf499'
    authenticode_leaf_sha256 = '4efd84e6f1091b19321231743b9aa86482effd6d0bea9f7a44db6211154616f3'
}

$script:WinsInnoOfficialKeys = @{
    def02 = [ordered]@{
        filename = 'def02.ispublickey'
        key_id = 'def020edee3c4835fd54d85eff8b66d4d899b22a777353ca4a114b652e5e7a28'
        public_x = '515dc7d6c16d4a46272ceb3d158c5630a96466ab4d948e72c2029d737c823097'
        public_y = 'f3c21f6b5156c52a35f6f28016ee3e31a3ded60c325b81fb7b1f88c221081a61'
        sha256 = '32bea6bceb4ac7c4e6b3becdf3fb38de77378c5e76d494ab907d87cfab9e597b'
        size = 248
    }
    def01 = [ordered]@{
        filename = 'def01.ispublickey'
        key_id = 'def0147c3bbc17ab99bf7b7a9c2de1390283f38972152418d7c2a4a7d7131a38'
        public_x = 'e3e943066aff8f28d2219fd71c9ffff4c8d1aa26bc4225434be67180ab5e242d'
        public_y = 'e419041c3f54551e86a1c47f387005cd535dfc9d64339b30d37f9a4f7866b650'
        sha256 = '3b0b7e1e478c9ab327746a990512e2b245c9231e88a7fdd60d7874dd439db562'
        size = 248
    }
}

if (-not ('WinsVpn.InnoCustodyNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;
#pragma warning disable SYSLIB0057

namespace WinsVpn {
    public sealed class InnoCustodyException : Exception {
        public InnoCustodyException(string message) : base(message) {}
    }

    public static class InnoCustodyNative {
        public sealed class FileIdentity {
            public ulong Device;
            public ulong Inode;
            public uint FileType;
            public uint Owner;
            public uint Group;
            public uint VolumeSerialNumber;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
            public ulong FileSize;
            public ulong LastWriteFileTime;
            public uint FileAttributes;
        }

        public sealed class BoundParent {
            public string Path;
            public FileIdentity Identity;
            public SafeFileHandle WinHandle;
            public int UnixFd = -1;
            public string ChildName;
            public FileIdentity ChildIdentity;
        }

        public sealed class BoundFile {
            public string Path;
            public byte[] Data;
            public string Sha256;
            public FileIdentity Identity;
            public FileStream Stream;
            public List<BoundParent> Parents = new List<BoundParent>();
            public List<string> ParentPaths = new List<string>();
            public List<FileIdentity> ParentIdentities = new List<FileIdentity>();
        }

        public sealed class BoundTree {
            public string Root;
            public FileIdentity RootIdentity;
            public List<BoundFile> Files = new List<BoundFile>();
            public List<string> DirectoryPaths = new List<string>();
            public List<FileIdentity> DirectoryIdentities = new List<FileIdentity>();
            public string Digest;
        }

        public sealed class AuthenticodeLeaf {
            public string PublisherName;
            public string Subject;
            public string Issuer;
            public string Serial;
            public string Sha256;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME { public uint Low; public uint High; }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION information);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("libc", SetLastError = true, EntryPoint = "open")]
        private static extern int UnixOpen(string path, int flags);

        [DllImport("libc", SetLastError = true, EntryPoint = "openat")]
        private static extern int UnixOpenat(int dirfd, string path, int flags);

        [DllImport("libc", SetLastError = true, EntryPoint = "close")]
        private static extern int UnixClose(int fd);

        [DllImport("libc", SetLastError = true, EntryPoint = "fstat")]
        private static extern int UnixFstat(int fd, byte[] buf);

        [DllImport("libc", SetLastError = true, EntryPoint = "fstatat")]
        private static extern int UnixFstatat(int dirfd, string path, byte[] buf, int flags);

        [DllImport("libc", SetLastError = true, EntryPoint = "lstat")]
        private static extern int UnixLstat(string path, byte[] buf);

        [StructLayout(LayoutKind.Sequential)]
        private struct GUID {
            public uint Data1; public ushort Data2; public ushort Data3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Data4;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WINTRUST_FILE_INFO {
            public uint cbStruct;
            public string pcwszFilePath;
            public IntPtr hFile;
            public IntPtr pgKnownSubject;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WINTRUST_DATA {
            public uint cbStruct;
            public IntPtr pPolicyCallbackData;
            public IntPtr pSIPClientData;
            public uint dwUIChoice;
            public uint fdwRevocationChecks;
            public uint dwUnionChoice;
            public IntPtr pFile;
            public uint dwStateAction;
            public IntPtr hWVTStateData;
            public IntPtr pwszURLReference;
            public uint dwProvFlags;
            public uint dwUIContext;
            public IntPtr pSignatureSettings;
        }

        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern int WinVerifyTrust(IntPtr hwnd, ref GUID pgActionID, IntPtr pWVTData);

        private const uint GENERIC_READ = 0x80000000;
        private const uint FILE_SHARE_READ = 1;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x400;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x10;
        private const int MAX_PKCS7 = 262144;
        private const int MAX_CERTS = 8;
        private const int MAX_DER_DEPTH = 12;

        public static Hashtable ParseJson(string text) {
            var parser = new JsonParser(text);
            object value = parser.ParseValue();
            parser.SkipWs();
            if (!parser.Done) throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
            Hashtable root = ToTable(value);
            if (root == null) throw new InnoCustodyException("type coercion refused: pin must be an object");
            return root;
        }

        public static byte[] IssigHashToSign(string filename, string tag, long size, string fileHashHex) {
            using (var sha = SHA256.Create()) {
                Prefix(sha, filename);
                Prefix(sha, tag);
                byte[] sizeBytes = BitConverter.GetBytes(size);
                sha.TransformBlock(sizeBytes, 0, sizeBytes.Length, null, 0);
                byte[] fileHash = FromHex(fileHashHex);
                sha.TransformFinalBlock(fileHash, 0, fileHash.Length);
                return sha.Hash;
            }
        }

        public static void VerifyEcdsaP256(string publicX, string publicY, byte[] digest, string sigR, string sigS) {
            byte[] x = Pad32(FromHex(publicX));
            byte[] y = Pad32(FromHex(publicY));
            byte[] r = FromHex(sigR);
            byte[] s = FromHex(sigS);
            if (r.Length > 32 || s.Length > 32) {
                throw new InnoCustodyException("ISSig ECDSA-P256 signature verification failed");
            }
            var signature = new byte[64];
            Buffer.BlockCopy(r, 0, signature, 32 - r.Length, r.Length);
            Buffer.BlockCopy(s, 0, signature, 64 - s.Length, s.Length);
            var parameters = new ECParameters {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = x, Y = y }
            };
            try {
                using (ECDsa ecdsa = ECDsa.Create(parameters)) {
                    if (!ecdsa.VerifyHash(digest, signature)) {
                        throw new InnoCustodyException("ISSig ECDSA-P256 signature verification failed");
                    }
                }
            } catch (InnoCustodyException) {
                throw;
            } catch (Exception) {
                throw new InnoCustodyException("ISSig ECDSA-P256 signature verification failed");
            }
        }

        public static string Sha256Hex(byte[] data) {
            using (var sha = SHA256.Create()) {
                return ToHex(sha.ComputeHash(data));
            }
        }

        public static BoundFile BindRegularFile(string path, string description, long maximumBytes) {
            if (string.IsNullOrEmpty(Path.GetDirectoryName(path))) {
                throw new InnoCustodyException("PATH substitution refused: candidate must be an explicit path");
            }
            string full = Path.GetFullPath(path);
            if (!Path.IsPathRooted(full)) {
                throw new InnoCustodyException("PATH substitution refused: path is not absolute");
            }
            var bound = new BoundFile();
            bound.Path = full;
            FileStream stream = null;
            int unixFileFd = -1;
            try {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                    SafeFileHandle fileHandle = BindWindowsParents(full, description, bound);
                    stream = new FileStream(fileHandle, FileAccess.Read);
                } else {
                    unixFileFd = BindUnixParents(full, description, bound);
                    var handle = new SafeFileHandle(new IntPtr(unixFileFd), true);
                    unixFileFd = -1;
                    stream = new FileStream(handle, FileAccess.Read);
                }
                bound.Stream = stream;
                bound.Identity = IdentityFromStream(stream);
                if (bound.Identity.NumberOfLinks != 1) {
                    throw new InnoCustodyException("hardlink refused: " + description + " must be a single-link file");
                }
                if ((bound.Identity.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || bound.Identity.FileType == 0xA000) {
                    throw new InnoCustodyException("reparse point rejected: " + full);
                }
                if (bound.Identity.FileType != 0 && bound.Identity.FileType != 0x8000) {
                    throw new InnoCustodyException(description + " must be one regular non-reparse file: " + full);
                }
                if (bound.Identity.FileSize < 1 || bound.Identity.FileSize > (ulong)maximumBytes) {
                    throw new InnoCustodyException(description + " size is outside the accepted range: " + full);
                }
                bound.Data = new byte[bound.Identity.FileSize];
                int read = 0;
                while (read < bound.Data.Length) {
                    int n = stream.Read(bound.Data, read, bound.Data.Length - read);
                    if (n <= 0) throw new InnoCustodyException(description + " mutated while it was read: " + full);
                    read += n;
                }
                FileIdentity after = IdentityFromStream(stream);
                if (!IdentityEqual(bound.Identity, after)) {
                    throw new InnoCustodyException(description + " mutated while it was hashed: " + full);
                }
                bound.Sha256 = Sha256Hex(bound.Data);
                AssertUnchanged(bound, description);
                return bound;
            } catch {
                if (stream != null) {
                    stream.Dispose();
                    bound.Stream = null;
                }
                if (unixFileFd >= 0) UnixClose(unixFileFd);
                CloseParents(bound);
                throw;
            }
        }

        public static void AssertUnchanged(BoundFile bound, string description) {
            if (bound.Stream == null) {
                throw new InnoCustodyException(description + " snapshot descriptor is closed");
            }
            FileIdentity opened = IdentityFromStream(bound.Stream);
            if (!IdentityEqual(opened, bound.Identity)) {
                throw new InnoCustodyException(description + " mutated while it was inspected: " + bound.Path);
            }
            ConfirmBoundParents(bound, description);
        }

        public static void CloseBound(BoundFile bound) {
            if (bound == null) return;
            if (bound.Stream != null) {
                bound.Stream.Dispose();
                bound.Stream = null;
            }
            CloseParents(bound);
        }

        public static void WinVerifyTrustHandle(BoundFile bound) {
            AssertUnchanged(bound, "Authenticode candidate");
            var action = new GUID {
                Data1 = 0x00AAC56B, Data2 = 0xCD44, Data3 = 0x11D0,
                Data4 = new byte[] { 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE }
            };
            var fileInfo = new WINTRUST_FILE_INFO {
                cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)),
                pcwszFilePath = bound.Path,
                hFile = bound.Stream.SafeFileHandle.DangerousGetHandle(),
                pgKnownSubject = IntPtr.Zero
            };
            IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf(fileInfo));
            var data = new WINTRUST_DATA();
            IntPtr pData = IntPtr.Zero;
            try {
                Marshal.StructureToPtr(fileInfo, pFile, false);
                data.cbStruct = (uint)Marshal.SizeOf(typeof(WINTRUST_DATA));
                data.dwUIChoice = 2;
                data.fdwRevocationChecks = 0;
                data.dwUnionChoice = 1;
                data.pFile = pFile;
                data.dwStateAction = 1;
                data.dwProvFlags = 0x1000 | 0x2000;
                pData = Marshal.AllocHGlobal(Marshal.SizeOf(data));
                Marshal.StructureToPtr(data, pData, false);
                int status = WinVerifyTrust(IntPtr.Zero, ref action, pData);
                if (status != 0) {
                    throw new InnoCustodyException(
                        "Authenticode chain verification failed with 0x" + ((uint)status).ToString("x8"));
                }
                AssertUnchanged(bound, "Authenticode candidate");
            } finally {
                if (pData != IntPtr.Zero) {
                    data.dwStateAction = 2;
                    Marshal.StructureToPtr(data, pData, false);
                    WinVerifyTrust(IntPtr.Zero, ref action, pData);
                    Marshal.FreeHGlobal(pData);
                }
                Marshal.FreeHGlobal(pFile);
            }
        }

        public static Hashtable ParsePe(byte[] data) {
            if (data.Length < 64 || data[0] != 0x4D || data[1] != 0x5A) {
                throw new InnoCustodyException("candidate is not a PE image");
            }
            int pe = BitConverter.ToInt32(data, 60);
            if (pe + 24 > data.Length || data[pe] != 0x50 || data[pe + 1] != 0x45 || data[pe + 2] != 0 || data[pe + 3] != 0) {
                throw new InnoCustodyException("candidate has an invalid PE header");
            }
            int machine = BitConverter.ToUInt16(data, pe + 4);
            int sectionCount = BitConverter.ToUInt16(data, pe + 6);
            int optionalSize = BitConverter.ToUInt16(data, pe + 20);
            int optional = pe + 24;
            if (optional + optionalSize > data.Length || sectionCount > 96) {
                throw new InnoCustodyException("candidate has a truncated optional header");
            }
            int magic = BitConverter.ToUInt16(data, optional);
            int directoryBase = optional + (magic == 0x20B ? 112 : 96);
            int numberOffset = optional + (magic == 0x20B ? 108 : 92);
            uint directories = BitConverter.ToUInt32(data, numberOffset);
            if (directories < 5 || directoryBase + 40 > optional + optionalSize) {
                throw new InnoCustodyException("candidate has no Authenticode directory");
            }
            uint resourceRva = BitConverter.ToUInt32(data, directoryBase + 16);
            uint resourceSize = BitConverter.ToUInt32(data, directoryBase + 20);
            uint certOffset = BitConverter.ToUInt32(data, directoryBase + 32);
            uint certSize = BitConverter.ToUInt32(data, directoryBase + 36);
            if (certOffset == 0 || certSize < 8 || certOffset + certSize > data.Length) {
                throw new InnoCustodyException("candidate has no embedded Authenticode signature");
            }
            if (certSize > MAX_PKCS7 + 16) {
                throw new InnoCustodyException("Authenticode PKCS#7 size bound exceeded");
            }
            var table = new Hashtable();
            table["machine"] = machine;
            table["magic"] = magic;
            table["certOffset"] = (int)certOffset;
            table["certSize"] = (int)certSize;
            table["resourceRva"] = (int)resourceRva;
            table["resourceSize"] = (int)resourceSize;
            table["sectionCount"] = sectionCount;
            table["optionalSize"] = optionalSize;
            table["optional"] = optional;
            return table;
        }

        public static Hashtable VersionStrings(byte[] data) {
            Hashtable pe = ParsePe(data);
            int resourceRva = (int)pe["resourceRva"];
            int resourceSize = (int)pe["resourceSize"];
            if (resourceRva == 0 || resourceSize < 16) {
                throw new InnoCustodyException("candidate has no VERSIONINFO resource");
            }
            int peOff = BitConverter.ToInt32(data, 60);
            int optional = (int)pe["optional"];
            int optionalSize = (int)pe["optionalSize"];
            int sectionCount = (int)pe["sectionCount"];
            int sectionTable = optional + optionalSize;
            int root = RvaToOffset(data, resourceRva, sectionTable, sectionCount);
            int limit = Math.Min(data.Length, root + resourceSize);
            int versionDir = FindResourceDir(data, root, limit, 16);
            if (versionDir < 0) throw new InnoCustodyException("candidate has no VERSIONINFO resource");
            int languageDir = FirstSubdirectory(data, versionDir, limit, root);
            if (languageDir < 0) throw new InnoCustodyException("candidate has no VERSIONINFO resource");
            int dataEntry = FirstDataEntry(data, languageDir, limit, root);
            if (dataEntry < 0 || dataEntry + 16 > limit) {
                throw new InnoCustodyException("candidate VERSIONINFO resource is truncated");
            }
            int rva = (int)BitConverter.ToUInt32(data, dataEntry);
            int size = (int)BitConverter.ToUInt32(data, dataEntry + 4);
            int fileOffset = RvaToOffset(data, rva, sectionTable, sectionCount);
            if (size < 92 || fileOffset + size > data.Length) {
                throw new InnoCustodyException("candidate VERSIONINFO resource is truncated");
            }
            var found = new Hashtable();
            CollectVersionStrings(data, fileOffset, fileOffset + size, found);
            string[] wanted = { "CompanyName", "FileDescription", "ProductName", "ProductVersion" };
            foreach (string key in wanted) {
                if (!found.ContainsKey(key)) {
                    throw new InnoCustodyException("candidate VERSIONINFO is missing " + key);
                }
            }
            return found;
        }

        public static AuthenticodeLeaf AuthenticodeLeafFromPe(byte[] data) {
            Hashtable pe = ParsePe(data);
            int certOffset = (int)pe["certOffset"];
            int certSize = (int)pe["certSize"];
            int length = BitConverter.ToInt32(data, certOffset);
            int revision = BitConverter.ToUInt16(data, certOffset + 4);
            int certType = BitConverter.ToUInt16(data, certOffset + 6);
            if (length < 8 || length > certSize || revision != 0x0200 || certType != 0x0002) {
                throw new InnoCustodyException("candidate has an invalid WIN_CERTIFICATE record");
            }
            if (length - 8 > MAX_PKCS7) {
                throw new InnoCustodyException("Authenticode PKCS#7 size bound exceeded");
            }
            byte[] pkcs7 = new byte[length - 8];
            Buffer.BlockCopy(data, certOffset + 8, pkcs7, 0, pkcs7.Length);
            return AuthenticodeLeafFromPkcs7(pkcs7);
        }

        public static AuthenticodeLeaf AuthenticodeLeafFromPkcs7(byte[] pkcs7) {
            if (pkcs7.Length > MAX_PKCS7) {
                throw new InnoCustodyException("Authenticode PKCS#7 size bound exceeded");
            }
            int offset = 0;
            byte[] seq = ReadTlv(pkcs7, ref offset, 0x30, 0);
            if (offset < pkcs7.Length) {
                for (int i = offset; i < pkcs7.Length; i++) {
                    if (pkcs7[i] != 0 || i - offset > 8) {
                        if (pkcs7[i] != 0) throw new InnoCustodyException("Authenticode PKCS#7 has trailing data");
                    }
                }
            }
            int inner = 0;
            byte[] oid = ReadTlv(seq, ref inner, 0x06, 1);
            if (DecodeOid(oid) != "1.2.840.113549.1.7.2") {
                throw new InnoCustodyException("Authenticode PKCS#7 is not signedData");
            }
            byte[] wrapper = ReadTlv(seq, ref inner, 0xA0, 1);
            int wrapOff = 0;
            byte[] signed = ReadTlv(wrapper, ref wrapOff, 0x30, 2);
            int cursor = 0;
            ReadTlv(signed, ref cursor, 0x02, 3);
            ReadTlv(signed, ref cursor, 0x31, 3);
            ReadTlv(signed, ref cursor, 0x30, 3);
            var certs = new List<byte[]>();
            if (cursor < signed.Length && signed[cursor] == 0xA0) {
                byte[] certContent = ReadTlv(signed, ref cursor, 0xA0, 3);
                int certOff = 0;
                while (certOff < certContent.Length) {
                    if (certs.Count >= MAX_CERTS) {
                        throw new InnoCustodyException("Authenticode PKCS#7 certificate count bound exceeded");
                    }
                    int mark = certOff;
                    ReadTlv(certContent, ref certOff, 0x30, 4);
                    byte[] der = new byte[certOff - mark];
                    Buffer.BlockCopy(certContent, mark, der, 0, der.Length);
                    certs.Add(der);
                }
            }
            if (cursor < signed.Length && signed[cursor] == 0xA1) {
                ReadTlv(signed, ref cursor, 0xA1, 3);
            }
            byte[] signerSet = ReadTlv(signed, ref cursor, 0x31, 3);
            if (cursor != signed.Length) {
                throw new InnoCustodyException("Authenticode PKCS#7 SignedData has trailing fields");
            }
            int signerOff = 0;
            byte[] signerInfo = ReadTlv(signerSet, ref signerOff, 0x30, 4);
            if (signerOff != signerSet.Length) {
                throw new InnoCustodyException("Authenticode PKCS#7 must contain exactly one SignerInfo");
            }
            int infoOff = 0;
            ReadTlv(signerInfo, ref infoOff, 0x02, 5);
            byte[] issuerSerial = ReadTlv(signerInfo, ref infoOff, 0x30, 5);
            int ias = 0;
            int issuerMark = ias;
            ReadTlv(issuerSerial, ref ias, 0x30, 6);
            byte[] issuerDer = new byte[ias - issuerMark];
            Buffer.BlockCopy(issuerSerial, issuerMark, issuerDer, 0, issuerDer.Length);
            byte[] serialContent = ReadTlv(issuerSerial, ref ias, 0x02, 6);
            if (ias != issuerSerial.Length) {
                throw new InnoCustodyException("Authenticode SignerInfo issuer/serial is malformed");
            }
            byte[] matchDer = null;
            foreach (byte[] der in certs) {
                byte[] certIssuer;
                byte[] certSerial;
                byte[] certSubject;
                CertificateTbsNames(der, out certIssuer, out certSerial, out certSubject);
                if (BytesEqual(certIssuer, issuerDer) && DerInteger(certSerial).Equals(DerInteger(serialContent))) {
                    if (matchDer != null) {
                        throw new InnoCustodyException("Authenticode SignerInfo does not resolve to one signing certificate");
                    }
                    matchDer = der;
                }
            }
            if (matchDer == null) {
                throw new InnoCustodyException("Authenticode SignerInfo does not resolve to one signing certificate");
            }
            byte[] matchIssuer;
            byte[] matchSerial;
            byte[] matchSubject;
            CertificateTbsNames(matchDer, out matchIssuer, out matchSerial, out matchSubject);
            string cn = RdnValue(matchSubject, "2.5.4.3");
            string org = RdnValue(matchSubject, "2.5.4.10");
            if (cn != "Pyrsys B.V." || org != "Pyrsys B.V.") {
                throw new InnoCustodyException("Authenticode publisher mismatch: expected one Pyrsys B.V. leaf");
            }
            var leaf = new AuthenticodeLeaf();
            leaf.PublisherName = "Pyrsys B.V.";
            leaf.Subject = Rfc4514(matchSubject);
            leaf.Issuer = Rfc4514(matchIssuer);
            leaf.Serial = UnsignedSerialHex(serialContent);
            leaf.Sha256 = Sha256Hex(matchDer);
            return leaf;
        }

        public static string InstallTreeDigest(string rootPath, long maxFileBytes) {
            BoundTree tree = SnapshotInstallTree(rootPath, maxFileBytes);
            try {
                AssertTreeUnchanged(tree);
                return tree.Digest;
            } finally {
                CloseTree(tree);
            }
        }

        public static BoundTree SnapshotInstallTree(string rootPath, long maxFileBytes) {
            string full = Path.GetFullPath(rootPath);
            var tree = new BoundTree();
            tree.Root = full;
            tree.RootIdentity = IdentityFromPath(full, false);
            if ((tree.RootIdentity.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                throw new InnoCustodyException("reparse point rejected: " + full);
            }
            var digest = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            int files = 0;
            long total = 0;
            try {
                WalkTreeHeld(new DirectoryInfo(full), new DirectoryInfo(full), tree, digest, ref files, ref total, maxFileBytes);
                if (files < 1) throw new InnoCustodyException("ISCC install tree contains no regular files");
                tree.Digest = ToHex(digest.GetHashAndReset());
                AssertTreeUnchanged(tree);
                return tree;
            } catch {
                CloseTree(tree);
                throw;
            }
        }

        public static void AssertTreeUnchanged(BoundTree tree) {
            FileIdentity rootNow = IdentityFromPath(tree.Root, false);
            if (!PathnameIdentityEqual(rootNow, tree.RootIdentity)) {
                throw new InnoCustodyException("ISCC install tree mutated while it was inspected: " + tree.Root);
            }
            var held = new Dictionary<string, BoundFile>(StringComparer.Ordinal);
            foreach (BoundFile bound in tree.Files) {
                AssertUnchanged(bound, "ISCC install tree file");
                string relative = RelativeTreePath(tree.Root, bound.Path);
                if (held.ContainsKey(relative)) {
                    throw new InnoCustodyException("ISCC install tree mixed old/new tree membership: " + tree.Root);
                }
                held[relative] = bound;
                FileIdentity pathIdentity = IdentityFromPath(bound.Path, true);
                if (!IdentityEqual(pathIdentity, bound.Identity)) {
                    throw new InnoCustodyException("ISCC install tree pathname identity changed: " + bound.Path);
                }
            }
            var currentFiles = new HashSet<string>(StringComparer.Ordinal);
            var currentDirs = new HashSet<string>(StringComparer.Ordinal);
            CollectTreeMembership(new DirectoryInfo(tree.Root), new DirectoryInfo(tree.Root), currentFiles, currentDirs);
            if (currentFiles.Count != held.Count) {
                throw new InnoCustodyException("ISCC install tree mixed old/new tree membership: " + tree.Root);
            }
            foreach (string relative in currentFiles) {
                if (!held.ContainsKey(relative)) {
                    throw new InnoCustodyException("ISCC install tree mixed old/new tree membership: " + tree.Root);
                }
            }
            if (currentDirs.Count != tree.DirectoryPaths.Count) {
                throw new InnoCustodyException("ISCC install tree mixed old/new tree membership: " + tree.Root);
            }
            for (int i = 0; i < tree.DirectoryPaths.Count; i++) {
                FileIdentity current = IdentityFromPath(tree.DirectoryPaths[i], false);
                if (!PathnameIdentityEqual(current, tree.DirectoryIdentities[i])) {
                    throw new InnoCustodyException("ISCC install tree directory mutated: " + tree.DirectoryPaths[i]);
                }
            }
        }

        public static void CloseTree(BoundTree tree) {
            if (tree == null) return;
            foreach (BoundFile bound in tree.Files) CloseBound(bound);
            tree.Files.Clear();
        }

        private static void WalkTreeHeld(DirectoryInfo root, DirectoryInfo directory, BoundTree tree, IncrementalHash digest, ref int files, ref long total, long maxFileBytes) {
            tree.DirectoryPaths.Add(directory.FullName);
            tree.DirectoryIdentities.Add(IdentityFromPath(directory.FullName, false));
            FileSystemInfo[] entries = directory.GetFileSystemInfos();
            Array.Sort(entries, (a, b) => string.CompareOrdinal(a.Name, b.Name));
            foreach (FileSystemInfo entry in entries) {
                string relative = RelativeTreePath(root.FullName, entry.FullName);
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) {
                    throw new InnoCustodyException("reparse point rejected: " + entry.FullName);
                }
                if ((entry.Attributes & FileAttributes.Directory) != 0) {
                    Feed(digest, "D", relative, "dir", PosixMode(entry, true).ToString());
                    WalkTreeHeld(root, (DirectoryInfo)entry, tree, digest, ref files, ref total, maxFileBytes);
                    continue;
                }
                if (IsPerInstallFile(relative)) {
                    continue;
                }
                var file = new FileInfo(entry.FullName);
                files++;
                total += file.Length;
                if (files > 4096 || total > 67108864) {
                    throw new InnoCustodyException("ISCC install tree size bound exceeded");
                }
                BoundFile bound = BindRegularFile(file.FullName, "ISCC install tree file " + relative, maxFileBytes);
                tree.Files.Add(bound);
                Feed(digest, "F", relative, "reg", PosixMode(file, false).ToString(), bound.Data.Length.ToString(), bound.Sha256);
            }
        }

        private static void CollectTreeMembership(DirectoryInfo root, DirectoryInfo directory, HashSet<string> files, HashSet<string> dirs) {
            dirs.Add(directory.FullName);
            foreach (FileSystemInfo entry in directory.GetFileSystemInfos()) {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0) {
                    throw new InnoCustodyException("reparse point rejected: " + entry.FullName);
                }
                if ((entry.Attributes & FileAttributes.Directory) != 0) {
                    CollectTreeMembership(root, (DirectoryInfo)entry, files, dirs);
                    continue;
                }
                string relative = RelativeTreePath(root.FullName, entry.FullName);
                if (IsPerInstallFile(relative)) {
                    continue;
                }
                files.Add(relative);
            }
        }

        // Setup writes its uninstall log (unins000.dat) per installation and
        // ISCC never reads it, so a root-level unins###.dat stays out of the
        // install-tree digest (same rule as release_inno_toolchain_custody.py).
        private static bool IsPerInstallFile(string relative) {
            return relative.IndexOf('/') < 0 &&
                System.Text.RegularExpressions.Regex.IsMatch(relative, @"\Aunins[0-9]{3}\.dat\z");
        }

        private static string RelativeTreePath(string rootPath, string fullPath) {
            string root = rootPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            return fullPath.Substring(root.Length).TrimStart('\\', '/').Replace('\\', '/');
        }

        private static void Feed(IncrementalHash digest, params string[] parts) {
            foreach (string part in parts) {
                byte[] encoded = Encoding.UTF8.GetBytes(part);
                byte[] len = BitConverter.GetBytes(encoded.LongLength);
                if (BitConverter.IsLittleEndian) Array.Reverse(len);
                digest.AppendData(len);
                digest.AppendData(encoded);
            }
        }

        private static int PosixMode(FileSystemInfo entry, bool directory) {
            bool readOnly = (entry.Attributes & FileAttributes.ReadOnly) != 0;
            if (directory) return readOnly ? Convert.ToInt32("555", 8) : Convert.ToInt32("777", 8);
            return readOnly ? Convert.ToInt32("444", 8) : Convert.ToInt32("666", 8);
        }

        private static void CollectVersionStrings(byte[] data, int offset, int limit, Hashtable found) {
            if (offset + 6 > limit) throw new InnoCustodyException("candidate VERSIONINFO resource is truncated");
            int length = BitConverter.ToUInt16(data, offset);
            int valueLength = BitConverter.ToUInt16(data, offset + 2);
            int wtype = BitConverter.ToUInt16(data, offset + 4);
            int end = offset + length;
            if (length < 6 || end > limit) throw new InnoCustodyException("candidate VERSIONINFO resource is truncated");
            int cursor;
            string key = ReadUtf16Z(data, offset + 6, end, out cursor);
            cursor = (cursor + 3) & ~3;
            byte[] value = new byte[0];
            if (valueLength > 0) {
                int valueBytes = wtype == 0 ? valueLength : valueLength * 2;
                if (cursor + valueBytes > end) throw new InnoCustodyException("candidate VERSIONINFO resource is truncated");
                value = new byte[valueBytes];
                Buffer.BlockCopy(data, cursor, value, 0, valueBytes);
                cursor = (cursor + valueBytes + 3) & ~3;
            }
            if (key == "CompanyName" || key == "FileDescription" || key == "ProductName" || key == "ProductVersion") {
                int unused;
                byte[] padded = new byte[value.Length + 2];
                Buffer.BlockCopy(value, 0, padded, 0, value.Length);
                string text = ReadUtf16Z(padded, 0, padded.Length, out unused).TrimEnd();
                if (string.IsNullOrEmpty(text)) throw new InnoCustodyException("candidate VERSIONINFO " + key + " is empty");
                if (found.ContainsKey(key) && (string)found[key] != text) {
                    throw new InnoCustodyException("candidate VERSIONINFO " + key + " is ambiguous");
                }
                found[key] = text;
            } else if (key == "OriginalFileName" || key == "InternalName") {
                if (value.Length >= 2) {
                    int unused;
                    byte[] padded = new byte[value.Length + 2];
                    Buffer.BlockCopy(value, 0, padded, 0, value.Length);
                    string text = ReadUtf16Z(padded, 0, padded.Length, out unused).TrimEnd();
                    if (!string.IsNullOrEmpty(text)) found[key] = text;
                }
            }
            if (key == "VS_VERSION_INFO") {
                if (value.Length < 52 || BitConverter.ToUInt32(value, 0) != 0xFEEF04BD) {
                    throw new InnoCustodyException("candidate VERSIONINFO resource is truncated");
                }
            }
            while (cursor + 6 <= end) {
                int childLength = BitConverter.ToUInt16(data, cursor);
                if (childLength < 6) break;
                CollectVersionStrings(data, cursor, end, found);
                cursor = (cursor + childLength + 3) & ~3;
            }
        }

        private static string ReadUtf16Z(byte[] data, int offset, int limit, out int cursor) {
            var chars = new StringBuilder();
            cursor = offset;
            while (cursor + 1 < limit) {
                int code = data[cursor] | (data[cursor + 1] << 8);
                cursor += 2;
                if (code == 0) return chars.ToString();
                if (code < 32 || (code >= 0xD800 && code <= 0xDFFF)) {
                    throw new InnoCustodyException("candidate VERSIONINFO string is malformed");
                }
                chars.Append((char)code);
                if (chars.Length > 256) throw new InnoCustodyException("candidate VERSIONINFO string is malformed");
            }
            throw new InnoCustodyException("candidate VERSIONINFO string is truncated");
        }

        private static int FindResourceDir(byte[] data, int root, int limit, int wanted) {
            foreach (var entry in ResourceEntries(data, root, limit)) {
                if (entry.Item1 == wanted && entry.Item2) return root + entry.Item3;
            }
            return -1;
        }

        private static int FirstSubdirectory(byte[] data, int dir, int limit, int root) {
            foreach (var entry in ResourceEntries(data, dir, limit)) {
                if (entry.Item2) return root + entry.Item3;
            }
            return -1;
        }

        private static int FirstDataEntry(byte[] data, int dir, int limit, int root) {
            foreach (var entry in ResourceEntries(data, dir, limit)) {
                if (!entry.Item2) return root + entry.Item3;
            }
            return -1;
        }

        private static List<Tuple<int, bool, int>> ResourceEntries(byte[] data, int offset, int limit) {
            if (offset + 16 > limit) throw new InnoCustodyException("candidate VERSIONINFO resource directory is truncated");
            int named = BitConverter.ToUInt16(data, offset + 12);
            int ids = BitConverter.ToUInt16(data, offset + 14);
            int total = named + ids;
            if (total < 1 || total > 64 || offset + 16 + total * 8 > limit) {
                throw new InnoCustodyException("candidate VERSIONINFO resource directory is truncated");
            }
            var entries = new List<Tuple<int, bool, int>>();
            int cursor = offset + 16;
            for (int i = 0; i < total; i++) {
                int name = BitConverter.ToInt32(data, cursor);
                uint dataOffset = BitConverter.ToUInt32(data, cursor + 4);
                cursor += 8;
                entries.Add(Tuple.Create(name & 0x7FFFFFFF, (dataOffset & 0x80000000u) != 0, (int)(dataOffset & 0x7FFFFFFF)));
            }
            return entries;
        }

        private static int RvaToOffset(byte[] data, int rva, int sectionTable, int sectionCount) {
            for (int i = 0; i < sectionCount; i++) {
                int start = sectionTable + i * 40;
                if (start + 40 > data.Length) throw new InnoCustodyException("candidate has a truncated section table");
                int virtualSize = BitConverter.ToInt32(data, start + 8);
                int virtualAddress = BitConverter.ToInt32(data, start + 12);
                int rawSize = BitConverter.ToInt32(data, start + 16);
                int rawPtr = BitConverter.ToInt32(data, start + 20);
                int span = Math.Max(virtualSize, rawSize);
                if (rva >= virtualAddress && rva < virtualAddress + span) {
                    int offset = rawPtr + (rva - virtualAddress);
                    if (offset < 0 || offset > data.Length) throw new InnoCustodyException("PE RVA is outside the image");
                    return offset;
                }
            }
            throw new InnoCustodyException("PE RVA is not inside a section");
        }

        private static byte[] ReadTlv(byte[] blob, ref int offset, int expected, int depth) {
            if (depth > MAX_DER_DEPTH) throw new InnoCustodyException("Authenticode PKCS#7 DER nesting is too deep");
            if (offset < 0 || offset >= blob.Length) throw new InnoCustodyException("Authenticode PKCS#7 is truncated");
            int tag = blob[offset];
            if (tag != expected) throw new InnoCustodyException("Authenticode PKCS#7 DER tag mismatch");
            if ((tag & 0x1F) == 0x1F) throw new InnoCustodyException("Authenticode PKCS#7 DER tag is malformed");
            int cursor = offset + 1;
            if (cursor >= blob.Length) throw new InnoCustodyException("Authenticode PKCS#7 is truncated");
            int lengthByte = blob[cursor++];
            int length;
            if (lengthByte == 0x80) throw new InnoCustodyException("Authenticode PKCS#7 indefinite length is refused");
            if (lengthByte < 0x80) {
                length = lengthByte;
            } else {
                int count = lengthByte & 0x7F;
                if (count < 1 || count > 4 || cursor + count > blob.Length) {
                    throw new InnoCustodyException("Authenticode PKCS#7 DER length is malformed");
                }
                if (blob[cursor] == 0) throw new InnoCustodyException("Authenticode PKCS#7 DER length is malformed");
                length = 0;
                for (int i = 0; i < count; i++) length = (length << 8) | blob[cursor++];
            }
            if (length < 0 || length > MAX_PKCS7 || cursor + length > blob.Length) {
                throw new InnoCustodyException("Authenticode PKCS#7 DER length is malformed");
            }
            byte[] content = new byte[length];
            Buffer.BlockCopy(blob, cursor, content, 0, length);
            offset = cursor + length;
            return content;
        }

        private static string DecodeOid(byte[] content) {
            if (content.Length < 1) throw new InnoCustodyException("Authenticode PKCS#7 OID is malformed");
            var parts = new List<string>();
            parts.Add((content[0] / 40).ToString());
            parts.Add((content[0] % 40).ToString());
            int value = 0;
            for (int i = 1; i < content.Length; i++) {
                value = (value << 7) | (content[i] & 0x7F);
                if ((content[i] & 0x80) == 0) {
                    parts.Add(value.ToString());
                    value = 0;
                } else if (value > (1 << 28)) {
                    throw new InnoCustodyException("Authenticode PKCS#7 OID is malformed");
                }
            }
            if ((content[content.Length - 1] & 0x80) != 0) {
                throw new InnoCustodyException("Authenticode PKCS#7 OID is malformed");
            }
            return string.Join(".", parts);
        }

        private static void CertificateTbsNames(byte[] der, out byte[] issuerTlv, out byte[] serialContent, out byte[] subjectTlv) {
            int offset = 0;
            byte[] cert = ReadTlv(der, ref offset, 0x30, 0);
            int cursor = 0;
            byte[] tbs = ReadTlv(cert, ref cursor, 0x30, 1);
            int t = 0;
            if (tbs.Length > 0 && tbs[0] == 0xA0) {
                ReadTlv(tbs, ref t, 0xA0, 2);
            }
            serialContent = ReadTlv(tbs, ref t, 0x02, 2);
            ReadTlv(tbs, ref t, 0x30, 2);
            int issuerMark = t;
            ReadTlv(tbs, ref t, 0x30, 2);
            issuerTlv = new byte[t - issuerMark];
            Buffer.BlockCopy(tbs, issuerMark, issuerTlv, 0, issuerTlv.Length);
            ReadTlv(tbs, ref t, 0x30, 2);
            int subjectMark = t;
            ReadTlv(tbs, ref t, 0x30, 2);
            subjectTlv = new byte[t - subjectMark];
            Buffer.BlockCopy(tbs, subjectMark, subjectTlv, 0, subjectTlv.Length);
        }

        private static void CertificateIssuerSerial(byte[] der, out byte[] issuerTlv, out byte[] serialContent) {
            byte[] unused;
            CertificateTbsNames(der, out issuerTlv, out serialContent, out unused);
        }

        private static string UnsignedSerialHex(byte[] content) {
            int start = 0;
            while (start < content.Length - 1 && content[start] == 0) {
                start++;
            }
            var trimmed = new byte[content.Length - start];
            Buffer.BlockCopy(content, start, trimmed, 0, trimmed.Length);
            return ToHex(trimmed);
        }

        private static BigInteger DerInteger(byte[] content) {
            if (content == null || content.Length < 1 || content.Length > 21) {
                throw new InnoCustodyException("Authenticode PKCS#7 INTEGER is malformed");
            }
            if ((content[0] & 0x80) != 0) {
                throw new InnoCustodyException("Authenticode PKCS#7 INTEGER is malformed");
            }
            if (content.Length > 1 && content[0] == 0 && content[1] < 0x80) {
                throw new InnoCustodyException("Authenticode PKCS#7 INTEGER is malformed");
            }
            var padded = new byte[content.Length + 1];
            Buffer.BlockCopy(content, 0, padded, 1, content.Length);
            Array.Reverse(padded);
            return new BigInteger(padded);
        }

        private static string Rfc4514(byte[] nameDer) {
            var parts = new List<string>();
            int offset = 0;
            byte[] content;
            if (nameDer.Length > 0 && nameDer[0] == 0x30) {
                content = ReadTlv(nameDer, ref offset, 0x30, 0);
            } else {
                content = nameDer;
            }
            int cursor = 0;
            while (cursor < content.Length) {
                byte[] set = ReadTlv(content, ref cursor, 0x31, 1);
                int setOff = 0;
                byte[] ava = ReadTlv(set, ref setOff, 0x30, 2);
                int avaOff = 0;
                byte[] oid = ReadTlv(ava, ref avaOff, 0x06, 3);
                if (avaOff >= ava.Length) throw new InnoCustodyException("Authenticode PKCS#7 DER tag mismatch");
                int valueTag = ava[avaOff];
                byte[] value = ReadTlv(ava, ref avaOff, valueTag, 3);
                string type = AttrType(DecodeOid(oid));
                string text = DirectoryString(valueTag, value);
                parts.Add(type + "=" + text);
            }
            parts.Reverse();
            return string.Join(",", parts);
        }

        private static string RdnValue(byte[] nameDer, string dottedOid) {
            int offset = 0;
            byte[] content;
            if (nameDer.Length > 0 && nameDer[0] == 0x30) {
                content = ReadTlv(nameDer, ref offset, 0x30, 0);
            } else {
                content = nameDer;
            }
            int cursor = 0;
            string found = null;
            while (cursor < content.Length) {
                byte[] set = ReadTlv(content, ref cursor, 0x31, 1);
                int setOff = 0;
                byte[] ava = ReadTlv(set, ref setOff, 0x30, 2);
                int avaOff = 0;
                byte[] oid = ReadTlv(ava, ref avaOff, 0x06, 3);
                int valueTag = ava[avaOff];
                byte[] value = ReadTlv(ava, ref avaOff, valueTag, 3);
                if (DecodeOid(oid) == dottedOid) {
                    found = DirectoryString(valueTag, value);
                }
            }
            return found;
        }

        private static string AttrType(string oid) {
            if (oid == "2.5.4.3") return "CN";
            if (oid == "2.5.4.10") return "O";
            if (oid == "2.5.4.8") return "ST";
            if (oid == "2.5.4.6") return "C";
            if (oid == "2.5.4.7") return "L";
            if (oid == "2.5.4.4") return "SN";
            if (oid == "2.5.4.11") return "OU";
            return oid;
        }

        private static string DirectoryString(int tag, byte[] value) {
            if (tag == 0x13 || tag == 0x16 || tag == 0x0C) return Encoding.UTF8.GetString(value);
            if (tag == 0x1E) return Encoding.BigEndianUnicode.GetString(value);
            throw new InnoCustodyException("Authenticode PKCS#7 DER tag mismatch");
        }

        private static bool BytesEqual(byte[] a, byte[] b) {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private static void ConfirmBoundParents(BoundFile bound, string description) {
            List<BoundParent> parents = bound.Parents;
            if (parents.Count == 0) {
                parents = LegacyParents(bound);
            }
            foreach (BoundParent parent in parents) {
                FileIdentity current = IdentityFromPath(parent.Path, false);
                if (!PathnameIdentityEqual(current, parent.Identity)) {
                    throw new InnoCustodyException("parent path component mutated: " + parent.Path);
                }
                if ((current.FileType != 0x4000) && (current.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
                    throw new InnoCustodyException("parent path component mutated: " + parent.Path);
                }
                if (parent.WinHandle != null && !parent.WinHandle.IsInvalid) {
                    FileIdentity held = Inspect(parent.WinHandle);
                    if (!PathnameIdentityEqual(held, parent.Identity)) {
                        throw new InnoCustodyException("parent path component mutated: " + parent.Path);
                    }
                } else if (parent.UnixFd >= 0) {
                    FileIdentity held = UnixIdentityFromFd(parent.UnixFd);
                    if (!PathnameIdentityEqual(held, parent.Identity)) {
                        throw new InnoCustodyException("parent path component mutated: " + parent.Path);
                    }
                }
                if (string.IsNullOrEmpty(parent.ChildName) || parent.ChildIdentity == null) continue;
                string childPath = Path.Combine(parent.Path, parent.ChildName);
                FileIdentity child;
                if (parent.UnixFd >= 0) {
                    child = UnixIdentityFromAt(parent.UnixFd, parent.ChildName, "parent path component mutated: " + parent.Path);
                } else {
                    bool isFile = string.Equals(childPath, bound.Path, StringComparison.OrdinalIgnoreCase);
                    child = IdentityFromPath(childPath, isFile);
                }
                if (!PathnameIdentityEqual(child, parent.ChildIdentity)) {
                    if (string.Equals(childPath, bound.Path, StringComparison.OrdinalIgnoreCase)) {
                        throw new InnoCustodyException(description + " mutated while it was inspected: " + bound.Path);
                    }
                    throw new InnoCustodyException("parent path component mutated: " + parent.Path);
                }
                if ((child.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || child.FileType == 0xA000) {
                    throw new InnoCustodyException("reparse point rejected: " + childPath);
                }
            }
        }

        private static List<BoundParent> LegacyParents(BoundFile bound) {
            var parents = new List<BoundParent>();
            for (int i = 0; i < bound.ParentPaths.Count; i++) {
                bool isFile = i == bound.ParentPaths.Count - 1;
                if (isFile) continue;
                parents.Add(new BoundParent {
                    Path = bound.ParentPaths[i],
                    Identity = bound.ParentIdentities[i],
                    UnixFd = -1
                });
            }
            return parents;
        }

        private static void CloseParents(BoundFile bound) {
            if (bound == null || bound.Parents == null) return;
            foreach (BoundParent parent in bound.Parents) {
                if (parent.WinHandle != null) {
                    parent.WinHandle.Dispose();
                    parent.WinHandle = null;
                }
                if (parent.UnixFd >= 0) {
                    UnixClose(parent.UnixFd);
                    parent.UnixFd = -1;
                }
            }
            bound.Parents.Clear();
            bound.ParentPaths.Clear();
            bound.ParentIdentities.Clear();
        }

        private static SafeFileHandle BindWindowsParents(string full, string description, BoundFile bound) {
            if (string.IsNullOrEmpty(description)) {
                throw new InnoCustodyException("PATH substitution refused: candidate must be an explicit path");
            }
            string root = Path.GetPathRoot(full);
            SafeFileHandle current = OpenWindows(root, false);
            FileIdentity rootIdent = Inspect(current);
            RefuseReparse(rootIdent, root);
            BoundParent parent = AddParent(bound, root, rootIdent, current, -1);
            string currentPath = root;
            string rest = full.Substring(root.Length);
            string[] parts = rest.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++) {
                string part = parts[i];
                if (part == ".." || part == ".") {
                    throw new InnoCustodyException("unsafe path component rejected: " + full);
                }
                currentPath = Path.Combine(currentPath, part);
                bool last = i == parts.Length - 1;
                SafeFileHandle next = OpenWindows(currentPath, last);
                FileIdentity ident = Inspect(next);
                RefuseReparse(ident, currentPath);
                parent.ChildName = part;
                parent.ChildIdentity = ident;
                if (last) return next;
                parent = AddParent(bound, currentPath, ident, next, -1);
            }
            throw new InnoCustodyException("PATH substitution refused: path is not absolute");
        }

        private static int BindUnixParents(string full, string description, BoundFile bound) {
            int dirFlags = UnixORdonly() | UnixOCloexec() | UnixODirectory() | UnixONofollow();
            int rootFlags = UnixORdonly() | UnixOCloexec() | UnixODirectory();
            int fileFlags = UnixORdonly() | UnixOCloexec() | UnixONofollow();
            string root = Path.GetPathRoot(full);
            int current = UnixOpen(root, rootFlags);
            if (current < 0) throw new InnoCustodyException("path component is unreadable: " + root);
            FileIdentity rootIdent = UnixIdentityFromFd(current);
            RefuseReparse(rootIdent, root);
            BoundParent parent = AddParent(bound, root, rootIdent, null, current);
            string currentPath = root;
            string rest = full.Substring(root.Length);
            string[] parts = rest.Split(new char[] { '\\', '/' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < parts.Length; i++) {
                string part = parts[i];
                if (part == ".." || part == ".") {
                    throw new InnoCustodyException("unsafe path component rejected: " + full);
                }
                currentPath = Path.Combine(currentPath, part);
                bool last = i == parts.Length - 1;
                FileIdentity peeked = UnixIdentityFromAt(current, part, description + " is unreadable: " + currentPath);
                RefuseReparse(peeked, currentPath);
                parent.ChildName = part;
                parent.ChildIdentity = peeked;
                int flags = last ? fileFlags : dirFlags;
                int next = UnixOpenat(current, part, flags);
                if (next < 0) {
                    throw new InnoCustodyException(description + " could not be opened without following links: " + full);
                }
                FileIdentity opened = UnixIdentityFromFd(next);
                if (last) {
                    if (!IdentityEqual(peeked, opened)) {
                        UnixClose(next);
                        throw new InnoCustodyException(description + " mutated while it was inspected: " + full);
                    }
                    return next;
                }
                if (!PathnameIdentityEqual(peeked, opened)) {
                    UnixClose(next);
                    throw new InnoCustodyException(description + " mutated while it was inspected: " + full);
                }
                parent = AddParent(bound, currentPath, opened, null, next);
                current = next;
            }
            throw new InnoCustodyException("PATH substitution refused: path is not absolute");
        }

        private static BoundParent AddParent(BoundFile bound, string path, FileIdentity identity, SafeFileHandle winHandle, int unixFd) {
            var parent = new BoundParent {
                Path = path,
                Identity = identity,
                WinHandle = winHandle,
                UnixFd = unixFd
            };
            bound.Parents.Add(parent);
            bound.ParentPaths.Add(path);
            bound.ParentIdentities.Add(identity);
            return parent;
        }

        private static SafeFileHandle OpenWindows(string path, bool fileExpected) {
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT;
            if (!fileExpected) flags |= FILE_FLAG_BACKUP_SEMANTICS;
            SafeFileHandle handle = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
            if (handle.IsInvalid) throw new InnoCustodyException("path component is unreadable: " + path);
            return handle;
        }

        private static void RefuseReparse(FileIdentity ident, string path) {
            if ((ident.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || ident.FileType == 0xA000) {
                throw new InnoCustodyException("reparse point rejected: " + path);
            }
        }

        private static FileIdentity IdentityFromPath(string path, bool fileExpected) {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                SafeFileHandle handle = OpenWindows(path, fileExpected);
                try {
                    return Inspect(handle);
                } finally {
                    handle.Dispose();
                }
            }
            byte[] buf = new byte[256];
            if (UnixLstat(path, buf) != 0) {
                throw new InnoCustodyException("path component is unreadable: " + path);
            }
            FileIdentity ident = IdentityFromUnixBuffer(buf);
            if ((ident.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || ident.FileType == 0xA000) {
                throw new InnoCustodyException("reparse point rejected: " + path);
            }
            return ident;
        }

        private static FileIdentity IdentityFromStream(FileStream stream) {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                return Inspect(stream.SafeFileHandle);
            }
            int fd = stream.SafeFileHandle.DangerousGetHandle().ToInt32();
            return UnixIdentityFromFd(fd);
        }

        private static FileIdentity Inspect(SafeFileHandle handle) {
            BY_HANDLE_FILE_INFORMATION information;
            if (!GetFileInformationByHandle(handle, out information)) {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            uint fileType = 0x8000;
            if ((information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) fileType = 0x4000;
            else if ((information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) fileType = 0xA000;
            return new FileIdentity {
                VolumeSerialNumber = information.VolumeSerialNumber,
                NumberOfLinks = information.NumberOfLinks,
                FileIndexHigh = information.FileIndexHigh,
                FileIndexLow = information.FileIndexLow,
                Device = information.VolumeSerialNumber,
                Inode = ((ulong)information.FileIndexHigh << 32) | information.FileIndexLow,
                FileType = fileType,
                FileSize = ((ulong)information.FileSizeHigh << 32) | information.FileSizeLow,
                LastWriteFileTime = ((ulong)information.LastWriteTime.High << 32) | information.LastWriteTime.Low,
                FileAttributes = information.FileAttributes
            };
        }

        private static FileIdentity UnixIdentityFromFd(int fd) {
            byte[] buf = new byte[256];
            if (UnixFstat(fd, buf) != 0) {
                throw new InnoCustodyException("parent descriptor became unreadable");
            }
            return IdentityFromUnixBuffer(buf);
        }

        private static FileIdentity UnixIdentityFromAt(int dirfd, string name, string missing) {
            byte[] buf = new byte[256];
            if (UnixFstatat(dirfd, name, buf, UnixAtNofollow()) != 0) {
                throw new InnoCustodyException(missing);
            }
            return IdentityFromUnixBuffer(buf);
        }

        private static FileIdentity IdentityFromUnixBuffer(byte[] buf) {
            var ident = new FileIdentity();
            if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) {
                ident.Device = (ulong)(uint)BitConverter.ToInt32(buf, 0);
                ushort mode = BitConverter.ToUInt16(buf, 4);
                ident.FileType = (uint)(mode & 0xF000);
                ident.NumberOfLinks = BitConverter.ToUInt16(buf, 6);
                ident.Inode = BitConverter.ToUInt64(buf, 8);
                ident.Owner = BitConverter.ToUInt32(buf, 16);
                ident.Group = BitConverter.ToUInt32(buf, 20);
                ident.FileSize = (ulong)BitConverter.ToInt64(buf, 96);
                long msec = BitConverter.ToInt64(buf, 48);
                long nsec = BitConverter.ToInt64(buf, 56);
                ident.LastWriteFileTime = (ulong)msec * 1000000000UL + (ulong)nsec;
            } else {
                ident.Device = BitConverter.ToUInt64(buf, 0);
                ident.Inode = BitConverter.ToUInt64(buf, 8);
                ident.NumberOfLinks = (uint)BitConverter.ToUInt64(buf, 16);
                ident.FileType = BitConverter.ToUInt32(buf, 24) & 0xF000;
                ident.Owner = BitConverter.ToUInt32(buf, 28);
                ident.Group = BitConverter.ToUInt32(buf, 32);
                ident.FileSize = (ulong)BitConverter.ToInt64(buf, 48);
                long msec = BitConverter.ToInt64(buf, 88);
                long nsec = BitConverter.ToInt64(buf, 96);
                ident.LastWriteFileTime = (ulong)msec * 1000000000UL + (ulong)nsec;
            }
            if (ident.FileType == 0x4000) ident.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY;
            if (ident.FileType == 0xA000) ident.FileAttributes |= FILE_ATTRIBUTE_REPARSE_POINT;
            return ident;
        }

        private static int UnixORdonly() { return 0; }
        private static int UnixOCloexec() {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? 0x01000000 : 0x80000;
        }
        private static int UnixODirectory() {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? 0x00100000 : 0x10000;
        }
        private static int UnixONofollow() {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? 0x00000100 : 0x20000;
        }
        private static int UnixAtNofollow() {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? 0x0020 : 0x100;
        }

        private static bool IdentityEqual(FileIdentity a, FileIdentity b) {
            return PathnameIdentityEqual(a, b) &&
                a.NumberOfLinks == b.NumberOfLinks &&
                a.FileSize == b.FileSize &&
                a.LastWriteFileTime == b.LastWriteFileTime &&
                a.FileAttributes == b.FileAttributes;
        }

        private static bool PathnameIdentityEqual(FileIdentity a, FileIdentity b) {
            return a.Device == b.Device &&
                a.Inode == b.Inode &&
                a.FileType == b.FileType &&
                a.Owner == b.Owner &&
                a.Group == b.Group;
        }

        private static Hashtable ToTable(object value) {
            var dict = value as Dictionary<string, object>;
            if (dict == null) return null;
            var table = new Hashtable();
            foreach (var kv in dict) table[kv.Key] = ToPs(kv.Value);
            return table;
        }

        private static object ToPs(object value) {
            var dict = value as Dictionary<string, object>;
            if (dict != null) return ToTable(dict);
            var list = value as List<object>;
            if (list != null) {
                object[] array = new object[list.Count];
                for (int i = 0; i < list.Count; i++) array[i] = ToPs(list[i]);
                return array;
            }
            return value;
        }

        private static void Prefix(SHA256 sha, string value) {
            byte[] encoded = Encoding.UTF8.GetBytes(value);
            byte[] len = BitConverter.GetBytes((uint)encoded.Length);
            sha.TransformBlock(len, 0, 4, null, 0);
            if (encoded.Length > 0) sha.TransformBlock(encoded, 0, encoded.Length, null, 0);
        }

        private static byte[] FromHex(string hex) {
            if (hex == null || (hex.Length % 2) != 0) {
                throw new InnoCustodyException("pin SHA-256 is not an exact lowercase non-zero digest: hex");
            }
            var data = new byte[hex.Length / 2];
            for (int i = 0; i < data.Length; i++) {
                data[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return data;
        }

        private static byte[] Pad32(byte[] value) {
            if (value.Length > 32) throw new InnoCustodyException("ISSig ECDSA-P256 signature verification failed");
            if (value.Length == 32) return value;
            var padded = new byte[32];
            Buffer.BlockCopy(value, 0, padded, 32 - value.Length, value.Length);
            return padded;
        }

        private static string ToHex(byte[] data) {
            var sb = new StringBuilder(data.Length * 2);
            foreach (byte b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        private sealed class JsonParser {
            private readonly string text;
            private int i;
            public JsonParser(string text) { this.text = text; i = 0; }
            public bool Done { get { return i >= text.Length; } }
            public void SkipWs() {
                while (i < text.Length) {
                    char c = text[i];
                    if (c == ' ' || c == '\n' || c == '\r' || c == '\t') i++;
                    else break;
                }
            }
            public object ParseValue() {
                SkipWs();
                if (i >= text.Length) throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                char c = text[i];
                if (c == '{') return ParseObject();
                if (c == '[') return ParseArray();
                if (c == '"') return ParseString();
                if (c == 't' || c == 'f') return ParseBool();
                if (c == 'n') return ParseNull();
                if (c == '-' || (c >= '0' && c <= '9')) return ParseNumber();
                throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
            }
            private Dictionary<string, object> ParseObject() {
                i++;
                var result = new Dictionary<string, object>();
                SkipWs();
                if (i < text.Length && text[i] == '}') { i++; return result; }
                while (true) {
                    SkipWs();
                    if (i >= text.Length || text[i] != '"') throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                    string key = ParseString();
                    if (result.ContainsKey(key)) throw new InnoCustodyException("duplicate JSON key rejected: " + key);
                    SkipWs();
                    if (i >= text.Length || text[i] != ':') throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                    i++;
                    result[key] = ParseValue();
                    SkipWs();
                    if (i >= text.Length) throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                    if (text[i] == ',') { i++; continue; }
                    if (text[i] == '}') { i++; return result; }
                    throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                }
            }
            private List<object> ParseArray() {
                i++;
                var result = new List<object>();
                SkipWs();
                if (i < text.Length && text[i] == ']') { i++; return result; }
                while (true) {
                    result.Add(ParseValue());
                    SkipWs();
                    if (i >= text.Length) throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                    if (text[i] == ',') { i++; continue; }
                    if (text[i] == ']') { i++; return result; }
                    throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                }
            }
            private string ParseString() {
                i++;
                var sb = new StringBuilder();
                while (i < text.Length) {
                    char c = text[i++];
                    if (c == '"') return sb.ToString();
                    if (c == '\\') {
                        if (i >= text.Length) throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                        char e = text[i++];
                        if (e == '"' || e == '\\' || e == '/') sb.Append(e);
                        else if (e == 'b') sb.Append('\b');
                        else if (e == 'f') sb.Append('\f');
                        else if (e == 'n') sb.Append('\n');
                        else if (e == 'r') sb.Append('\r');
                        else if (e == 't') sb.Append('\t');
                        else if (e == 'u') {
                            if (i + 4 > text.Length) throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                            sb.Append((char)Convert.ToInt32(text.Substring(i, 4), 16));
                            i += 4;
                        } else throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                    } else if (c < 32) {
                        throw new InnoCustodyException("pin field contains a control character: json");
                    } else sb.Append(c);
                }
                throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
            }
            private object ParseBool() {
                if (text.Substring(i).StartsWith("true")) { i += 4; return true; }
                if (text.Substring(i).StartsWith("false")) { i += 5; return false; }
                throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
            }
            private object ParseNull() {
                if (text.Substring(i).StartsWith("null")) { i += 4; return null; }
                throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
            }
            private object ParseNumber() {
                int start = i;
                if (text[i] == '-') i++;
                if (i >= text.Length || text[i] < '0' || text[i] > '9') throw new InnoCustodyException("Inno toolchain pin is not strict JSON");
                if (text[i] == '0') i++;
                else while (i < text.Length && text[i] >= '0' && text[i] <= '9') i++;
                if (i < text.Length && (text[i] == '.' || text[i] == 'e' || text[i] == 'E')) {
                    throw new InnoCustodyException("type coercion refused: schema_version must be an integer");
                }
                long value;
                if (!long.TryParse(text.Substring(start, i - start), out value)) {
                    throw new InnoCustodyException("type coercion refused: pin integer is outside the accepted range");
                }
                return value;
            }
        }
    }
}
'@
}

function Fail-WinsInno {
    param([Parameter(Mandatory)][string]$Message)
    throw $Message
}

function Assert-WinsInnoExactKeys {
    param(
        $Object,
        [Parameter(Mandatory)][string[]]$Keys,
        [Parameter(Mandatory)][string]$Label
    )
    if ($null -eq $Object -or $Object -isnot [hashtable]) {
        Fail-WinsInno "type coercion refused: $Label must be an object"
    }
    foreach ($key in $Keys) {
        if (-not $Object.ContainsKey($key)) {
            Fail-WinsInno "pin field is absent: $Label.$key"
        }
    }
    foreach ($key in @($Object.Keys)) {
        if ($Keys -notcontains $key) {
            Fail-WinsInno "unexpected pin field rejected: $Label.$key"
        }
    }
}

function Assert-WinsInnoExactString {
    param(
        $Value,
        [Parameter(Mandatory)][string]$Expected,
        [Parameter(Mandatory)][string]$Label
    )
    if ($Value -isnot [string]) {
        Fail-WinsInno "type coercion refused: $Label must be a string"
    }
    if ($Value -cne $Expected) {
        Fail-WinsInno "$Label mismatch"
    }
}

function Get-WinsInnoText {
    param($Object, [string]$Key, [string]$Label, [switch]$AllowEmpty)
    $value = $Object[$Key]
    if ($value -isnot [string]) {
        Fail-WinsInno "type coercion refused: $Key must be a string"
    }
    foreach ($character in $value.ToCharArray()) {
        if ([int]$character -lt 32) {
            Fail-WinsInno "pin field contains a control character: $Key"
        }
    }
    if ($value.Trim() -cne $value) {
        Fail-WinsInno "pin field has surrounding whitespace: $Key"
    }
    if (-not $AllowEmpty -and [string]::IsNullOrEmpty($value)) {
        Fail-WinsInno "pin field must be one non-empty string: $Key"
    }
    return $value
}

function Get-WinsInnoBool {
    param($Object, [string]$Key)
    $value = $Object[$Key]
    if ($value -isnot [bool]) {
        Fail-WinsInno "type coercion refused: $Key must be a boolean"
    }
    return [bool]$value
}

function Get-WinsInnoInt {
    param($Object, [string]$Key, [long]$Minimum, [long]$Maximum)
    $value = $Object[$Key]
    if ($value -is [bool] -or ($value -isnot [int] -and $value -isnot [long])) {
        Fail-WinsInno "type coercion refused: $Key must be an integer"
    }
    $number = [int64]$value
    if ($number -lt $Minimum -or $number -gt $Maximum) {
        Fail-WinsInno "pin integer is outside the accepted range: $Key"
    }
    return $number
}

function Get-WinsInnoHex64 {
    param($Object, [string]$Key)
    $value = Get-WinsInnoText -Object $Object -Key $Key -Label $Key
    if ($value -cnotmatch $script:WinsInnoSha256Pattern -or $value -ceq ('0' * 64)) {
        Fail-WinsInno "pin SHA-256 is not an exact lowercase non-zero digest: $Key"
    }
    return $value
}

function Assert-WinsInnoNull {
    param($Value, [Parameter(Mandatory)][string]$Label)
    if ($null -ne $Value) {
        Fail-WinsInno "unmeasured or unpublished field must be JSON null: $Label"
    }
}

function Get-WinsInnoHttps {
    param($Object, [string]$Key)
    $value = Get-WinsInnoText -Object $Object -Key $Key -Label $Key
    if (-not $value.StartsWith('https://')) {
        Fail-WinsInno "official URL must be https: $Key"
    }
    return $value
}

function Assert-WinsInnoKeyAnchor {
    param($Record, [Parameter(Mandatory)][string]$Name)
    Assert-WinsInnoExactKeys -Object $Record -Keys @('filename', 'key_id', 'public_x', 'public_y', 'sha256', 'size') -Label "issig_keys.$Name"
    $anchor = $script:WinsInnoOfficialKeys[$Name]
    foreach ($field in @('filename', 'key_id', 'public_x', 'public_y', 'sha256')) {
        Assert-WinsInnoExactString -Value $Record[$field] -Expected ([string]$anchor[$field]) -Label "issig_keys.$Name.$field"
    }
    if ([int64]$Record['size'] -ne [int64]$anchor['size']) {
        Fail-WinsInno "ISSig trust-root key does not match immutable code anchor: $Name"
    }
}

function Invoke-WinsInnoEcdsa {
    param(
        [Parameter(Mandatory)][string]$Filename,
        [Parameter(Mandatory)][int64]$Size,
        [Parameter(Mandatory)][string]$FileHash,
        [AllowEmptyString()][string]$Tag,
        [Parameter(Mandatory)][string]$PublicX,
        [Parameter(Mandatory)][string]$PublicY,
        [Parameter(Mandatory)][string]$KeyId,
        [Parameter(Mandatory)][string]$SigR,
        [Parameter(Mandatory)][string]$SigS
    )
    $xy = $PublicX + $PublicY
    $bytes = for ($i = 0; $i -lt 64; $i += 1) { [Convert]::ToByte($xy.Substring($i * 2, 2), 16) }
    $computed = [WinsVpn.InnoCustodyNative]::Sha256Hex([byte[]]$bytes)
    if ($computed -cne $KeyId) {
        Fail-WinsInno 'ISSig public key id does not match public-x||public-y'
    }
    $digest = [WinsVpn.InnoCustodyNative]::IssigHashToSign($Filename, $Tag, $Size, $FileHash)
    [WinsVpn.InnoCustodyNative]::VerifyEcdsaP256($PublicX, $PublicY, $digest, $SigR, $SigS)
}

function Get-WinsInnoUtc {
    param($Object, [string]$Key)
    $value = Get-WinsInnoText -Object $Object -Key $Key -Label $Key
    if ($value -cnotmatch '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$') {
        Fail-WinsInno "retrieved timestamp must be exact ISO UTC: $Key"
    }
    try {
        $parsed = [datetime]::ParseExact(
            $value,
            'yyyy-MM-ddTHH:mm:ssZ',
            [globalization.CultureInfo]::InvariantCulture,
            [globalization.DateTimeStyles]::AssumeUniversal -bor [globalization.DateTimeStyles]::AdjustToUniversal
        )
    } catch {
        Fail-WinsInno "retrieved timestamp must be exact ISO UTC: $Key"
    }
    $issuance = [datetime]::ParseExact(
        '2026-08-01T00:00:00Z',
        'yyyy-MM-ddTHH:mm:ssZ',
        [globalization.CultureInfo]::InvariantCulture,
        [globalization.DateTimeStyles]::AssumeUniversal -bor [globalization.DateTimeStyles]::AdjustToUniversal
    )
    $now = [datetime]::UtcNow
    if ($parsed -lt $issuance) {
        Fail-WinsInno "retrieved timestamp is before the reviewed issuance bound: $Key"
    }
    if ($parsed -gt $now) {
        Fail-WinsInno "retrieved timestamp is after the reviewed issuance bound: $Key"
    }
    return $parsed
}

function ConvertFrom-WinsInnoCustodyPin {
    param([Parameter(Mandatory)][string]$ManifestPath)

    if ([IO.Path]::GetDirectoryName($ManifestPath) -eq [string]::Empty) {
        Fail-WinsInno 'PATH substitution refused: candidate must be an explicit path'
    }
    $full = [IO.Path]::GetFullPath($ManifestPath)
    if (-not [IO.Path]::IsPathRooted($full)) {
        Fail-WinsInno 'PATH substitution refused: path is not absolute'
    }
    $bound = [WinsVpn.InnoCustodyNative]::BindRegularFile($full, 'Inno toolchain pin', $script:WinsInnoMaxPinBytes)
    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bound.Data)
        $manifest = [WinsVpn.InnoCustodyNative]::ParseJson($text)
        Assert-WinsInnoExactKeys -Object $manifest -Keys @(
            'schema_version', 'contract', 'product', 'vendor', 'version', 'channel', 'status',
            'retrieved_utc', 'official_sources', 'verification_methods', 'publisher', 'issig_keys',
            'installers', 'compilers', 'verification_tool', 'compiler_archive'
        ) -Label 'pin'
        $schema = $manifest['schema_version']
        if ($schema -is [bool] -or ($schema -isnot [int] -and $schema -isnot [long])) {
            Fail-WinsInno 'type coercion refused: schema_version must be an integer'
        }
        if ([int64]$schema -ne 1) {
            Fail-WinsInno 'Inno toolchain pin schema_version mismatch'
        }
        Assert-WinsInnoExactString -Value $manifest['contract'] -Expected $script:WinsInnoContract -Label 'contract'
        Assert-WinsInnoExactString -Value $manifest['product'] -Expected 'Inno Setup' -Label 'product'
        Assert-WinsInnoExactString -Value $manifest['vendor'] -Expected 'JRSoftware' -Label 'vendor'
        Assert-WinsInnoExactString -Value $manifest['version'] -Expected $script:WinsInnoVersion -Label 'version'
        Assert-WinsInnoExactString -Value $manifest['channel'] -Expected 'latest-stable' -Label 'channel'
        $documentStatus = Get-WinsInnoText -Object $manifest -Key 'status' -Label 'status'
        $pinRetrieved = Get-WinsInnoUtc -Object $manifest -Key 'retrieved_utc'
        $sourceNames = @(
            'downloads', 'verify', 'product', 'whatsnew', 'files_readme', 'x64_issig', 'x86_issig',
            'def02_key', 'def01_key', 'issigtool', 'issigtool_issig', 'immutable_x64', 'immutable_x86',
            'immutable_tag', 'issig_help', 'issigfunc'
        )
        $sources = $manifest['official_sources']
        Assert-WinsInnoExactKeys -Object $sources -Keys $sourceNames -Label 'official_sources'
        $times = @($pinRetrieved)
        foreach ($name in $sourceNames) {
            $item = $sources[$name]
            Assert-WinsInnoExactKeys -Object $item -Keys @('url', 'retrieved_utc', 'role') -Label "official_sources.$name"
            $sourceRetrieved = Get-WinsInnoUtc -Object $item -Key 'retrieved_utc'
            if ($sourceRetrieved -gt $pinRetrieved) {
                Fail-WinsInno "retrieved timestamp is after the reviewed issuance bound: official_sources.$name"
            }
            $times += $sourceRetrieved
        }
        $sortedTimes = @($times | Sort-Object)
        if (($sortedTimes[-1] - $sortedTimes[0]) -gt [timespan]::FromHours(24)) {
            Fail-WinsInno 'retrieved timestamps exceed the reviewed freshness bound'
        }
    $methods = $manifest['verification_methods']
    Assert-WinsInnoExactKeys -Object $methods -Keys @('authenticode', 'issig_ecdsa_p256', 'github_release_attestation') -Label 'verification_methods'
    $authenticode = $methods['authenticode']
    Assert-WinsInnoExactKeys -Object $authenticode -Keys @('required', 'publisher_name', 'signer_binding', 'source_url', 'windows_api') -Label 'verification_methods.authenticode'
    if (-not (Get-WinsInnoBool -Object $authenticode -Key 'required')) {
        Fail-WinsInno 'Authenticode verification must be required'
    }
    Assert-WinsInnoExactString -Value $authenticode['publisher_name'] -Expected $script:WinsInnoPublisherName -Label 'publisher'
    Assert-WinsInnoExactString -Value $authenticode['signer_binding'] -Expected 'pkcs7_signerinfo_issuer_serial' -Label 'signer_binding'
    Assert-WinsInnoExactString -Value $authenticode['windows_api'] -Expected 'WinVerifyTrust' -Label 'windows_api'
    $issig = $methods['issig_ecdsa_p256']
    Assert-WinsInnoExactKeys -Object $issig -Keys @('required', 'installer_key', 'tool_key', 'trust_anchor', 'source_url', 'execute_issigtool') -Label 'verification_methods.issig_ecdsa_p256'
    if (-not (Get-WinsInnoBool -Object $issig -Key 'required')) {
        Fail-WinsInno 'ISSig verification must be required'
    }
    if (Get-WinsInnoBool -Object $issig -Key 'execute_issigtool') {
        Fail-WinsInno 'refusing to execute ISSigTool.exe'
    }
    Assert-WinsInnoExactString -Value $issig['trust_anchor'] -Expected 'immutable_code_constants' -Label 'trust_anchor'
    Assert-WinsInnoExactString -Value $issig['installer_key'] -Expected 'def02' -Label 'installer_key'
    Assert-WinsInnoExactString -Value $issig['tool_key'] -Expected 'def01' -Label 'tool_key'
    $github = $methods['github_release_attestation']
    Assert-WinsInnoExactKeys -Object $github -Keys @('required', 'source_url', 'reason') -Label 'verification_methods.github_release_attestation'
    if (Get-WinsInnoBool -Object $github -Key 'required') {
        Fail-WinsInno 'GitHub attestation must not be a custody gate'
    }
    $publisher = $manifest['publisher']
    Assert-WinsInnoExactKeys -Object $publisher -Keys @(
        'authenticode_publisher_name', 'authenticode_subject_rfc4514', 'authenticode_issuer_rfc4514',
        'authenticode_leaf_serial_hex', 'authenticode_leaf_sha256'
    ) -Label 'publisher'
    foreach ($field in $script:WinsInnoOfficialPublisher.Keys) {
        Assert-WinsInnoExactString -Value $publisher[$field] -Expected ([string]$script:WinsInnoOfficialPublisher[$field]) -Label $field
    }
    $keys = $manifest['issig_keys']
    Assert-WinsInnoExactKeys -Object $keys -Keys @('def02', 'def01') -Label 'issig_keys'
    Assert-WinsInnoKeyAnchor -Record $keys['def02'] -Name 'def02'
    Assert-WinsInnoKeyAnchor -Record $keys['def01'] -Name 'def01'
    $installers = $manifest['installers']
    Assert-WinsInnoExactKeys -Object $installers -Keys @('windows_x64', 'windows_x86') -Label 'installers'
    foreach ($name in @('windows_x64', 'windows_x86')) {
        $record = $installers[$name]
        Assert-WinsInnoExactKeys -Object $record -Keys @(
            'status', 'filename', 'edition', 'pe_machine', 'recommended_compiler_host', 'size', 'sha256',
            'product_name', 'product_version_string', 'company_name', 'file_description', 'download_url',
            'issig_url', 'issig_sha256', 'issig_size', 'issig_key', 'issig_file_tag', 'issig_sig_r', 'issig_sig_s'
        ) -Label "installers.$name"
        Assert-WinsInnoExactString -Value $record['status'] -Expected 'pinned' -Label "$name.status"
        $null = Get-WinsInnoHex64 -Object $record -Key 'sha256'
        $size = Get-WinsInnoInt -Object $record -Key 'size' -Minimum 1 -Maximum $script:WinsInnoMaxInstallerBytes
        $keyName = [string]$record['issig_key']
        if ($keyName -cne 'def02') {
            Fail-WinsInno "installer ISSig key is unknown: $name"
        }
        $anchor = $script:WinsInnoOfficialKeys[$keyName]
        Invoke-WinsInnoEcdsa -Filename ([string]$record['filename']) -Size $size -FileHash ([string]$record['sha256']) -Tag ([string]$record['issig_file_tag']) -PublicX ([string]$anchor['public_x']) -PublicY ([string]$anchor['public_y']) -KeyId ([string]$anchor['key_id']) -SigR ([string]$record['issig_sig_r']) -SigS ([string]$record['issig_sig_s'])
    }
    if (-not (Get-WinsInnoBool -Object $installers['windows_x64'] -Key 'recommended_compiler_host')) {
        Fail-WinsInno '64-bit Inno Setup 7 is the required compiler host'
    }
    if (Get-WinsInnoBool -Object $installers['windows_x86'] -Key 'recommended_compiler_host') {
        Fail-WinsInno '32-bit Inno Setup 7 is not the required compiler host'
    }
    $tool = $manifest['verification_tool']
    Assert-WinsInnoExactKeys -Object $tool -Keys @(
        'status', 'filename', 'execute', 'pe_machine', 'size', 'sha256', 'download_url', 'issig_url',
        'issig_sha256', 'issig_size', 'issig_key', 'issig_file_tag', 'issig_sig_r', 'issig_sig_s', 'note'
    ) -Label 'verification_tool'
    if (Get-WinsInnoBool -Object $tool -Key 'execute') {
        Fail-WinsInno 'refusing to execute ISSigTool.exe'
    }
    Assert-WinsInnoExactString -Value $tool['filename'] -Expected 'ISSigTool.exe' -Label 'verification_tool.filename'
    Assert-WinsInnoExactString -Value $tool['issig_key'] -Expected 'def01' -Label 'verification_tool.issig_key'
    $toolAnchor = $script:WinsInnoOfficialKeys['def01']
    Invoke-WinsInnoEcdsa -Filename 'ISSigTool.exe' -Size (Get-WinsInnoInt -Object $tool -Key 'size' -Minimum 1 -Maximum $script:WinsInnoMaxCompilerBytes) -FileHash (Get-WinsInnoHex64 -Object $tool -Key 'sha256') -Tag ([string]$tool['issig_file_tag']) -PublicX ([string]$toolAnchor['public_x']) -PublicY ([string]$toolAnchor['public_y']) -KeyId ([string]$toolAnchor['key_id']) -SigR ([string]$tool['issig_sig_r']) -SigS ([string]$tool['issig_sig_s'])
    $archive = $manifest['compiler_archive']
    Assert-WinsInnoExactKeys -Object $archive -Keys @('status', 'filename', 'sha256', 'size', 'owner_action') -Label 'compiler_archive'
    Assert-WinsInnoExactString -Value $archive['status'] -Expected 'not_published' -Label 'compiler_archive.status'
    Assert-WinsInnoNull -Value $archive['filename'] -Label 'compiler_archive.filename'
    Assert-WinsInnoNull -Value $archive['sha256'] -Label 'compiler_archive.sha256'
    Assert-WinsInnoNull -Value $archive['size'] -Label 'compiler_archive.size'
    $compilers = $manifest['compilers']
    Assert-WinsInnoExactKeys -Object $compilers -Keys @('windows_x64', 'windows_arm64') -Label 'compilers'
    $compilersPinned = $true
    foreach ($name in @('windows_x64', 'windows_arm64')) {
        $record = $compilers[$name]
        $required = @(
            'status', 'filename', 'pe_machine', 'output_architectures', 'trusted_root_leaf',
            'trusted_root_kind', 'publisher_name', 'expected_version', 'sha256', 'size',
            'install_tree_sha256', 'product_version_string', 'owner_action'
        )
        if ($name -eq 'windows_arm64') {
            $required += 'native_arm64_compiler'
        }
        Assert-WinsInnoExactKeys -Object $record -Keys $required -Label "compilers.$name"
        Assert-WinsInnoExactString -Value $record['filename'] -Expected 'ISCC.exe' -Label "$name.compiler.filename"
        if ([string]$record['status'] -ceq 'unmeasured') {
            $compilersPinned = $false
            Assert-WinsInnoNull -Value $record['sha256'] -Label "$name.compiler.sha256"
            Assert-WinsInnoNull -Value $record['size'] -Label "$name.compiler.size"
            Assert-WinsInnoNull -Value $record['install_tree_sha256'] -Label "$name.compiler.install_tree_sha256"
            Assert-WinsInnoNull -Value $record['product_version_string'] -Label "$name.compiler.product_version_string"
        } elseif ([string]$record['status'] -ceq 'pinned') {
            $null = Get-WinsInnoHex64 -Object $record -Key 'sha256'
            $null = Get-WinsInnoHex64 -Object $record -Key 'install_tree_sha256'
            $null = Get-WinsInnoInt -Object $record -Key 'size' -Minimum 1 -Maximum $script:WinsInnoMaxCompilerBytes
            $null = Get-WinsInnoText -Object $record -Key 'product_version_string' -Label 'product_version_string'
        } else {
            Fail-WinsInno "compiler status is unsupported: $name"
        }
    }
    $expectedStatus = if ($compilersPinned) { 'pinned' } else { 'unmeasured' }
    if ($documentStatus -cne $expectedStatus) {
        Fail-WinsInno "pin status must be pinned when both compilers carry complete pins, otherwise unmeasured: expected $expectedStatus"
    }
        [WinsVpn.InnoCustodyNative]::AssertUnchanged($bound, 'Inno toolchain pin')
        return @{ Manifest = $manifest; Bound = $bound }
    } catch {
        [WinsVpn.InnoCustodyNative]::CloseBound($bound)
        throw
    }
}

function Assert-WinsInnoPublisherLeaf {
    param($Leaf)
    if ([string]$Leaf.PublisherName -cne $script:WinsInnoOfficialPublisher.authenticode_publisher_name) {
        Fail-WinsInno 'Authenticode publisher mismatch'
    }
    if ([string]$Leaf.Serial -cne $script:WinsInnoOfficialPublisher.authenticode_leaf_serial_hex) {
        Fail-WinsInno 'Authenticode publisher mismatch'
    }
    if ([string]$Leaf.Sha256 -cne $script:WinsInnoOfficialPublisher.authenticode_leaf_sha256) {
        Fail-WinsInno 'Authenticode publisher mismatch'
    }
    if ([string]$Leaf.Subject -cne $script:WinsInnoOfficialPublisher.authenticode_subject_rfc4514) {
        Fail-WinsInno 'Authenticode publisher mismatch'
    }
    if ([string]$Leaf.Issuer -cne $script:WinsInnoOfficialPublisher.authenticode_issuer_rfc4514) {
        Fail-WinsInno 'Authenticode chain publisher mismatch'
    }
}

function Assert-WinsInnoPeMachine {
    param(
        [Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][ValidateSet('x86', 'x64', 'arm64')][string]$Expected
    )
    $parsed = [WinsVpn.InnoCustodyNative]::ParsePe($Bytes)
    $expectedMachine = @{ x86 = 0x014C; x64 = 0x8664; arm64 = 0xAA64 }[$Expected]
    $expectedMagic = @{ x86 = 0x010B; x64 = 0x020B; arm64 = 0x020B }[$Expected]
    if ([int]$parsed['machine'] -ne $expectedMachine -or [int]$parsed['magic'] -ne $expectedMagic) {
        Fail-WinsInno "architecture mismatch: expected $Expected"
    }
}

function Assert-WinsInnoTrustedCompilerRoot {
    param([Parameter(Mandatory)][string]$Path)

    $full = [IO.Path]::GetFullPath($Path)
    $name = [IO.Path]::GetFileName($full)
    $leaf = [IO.Path]::GetFileName([IO.Path]::GetDirectoryName($full))
    if ($name -cne 'ISCC.exe' -or $leaf -cne 'Inno Setup 7') {
        Fail-WinsInno 'untrusted installation root'
    }
    if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
        $programFiles = [Environment]::GetFolderPath('ProgramFiles')
        $expected = [IO.Path]::GetFullPath((Join-Path $programFiles 'Inno Setup 7\ISCC.exe'))
        if (-not $full.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
            Fail-WinsInno 'untrusted installation root'
        }
        $wow = [Environment]::GetFolderPath('ProgramFilesX86')
        if (-not [string]::IsNullOrWhiteSpace($wow)) {
            $wowPrefix = ([IO.Path]::GetFullPath($wow)).TrimEnd('\') + '\'
            if ($full.StartsWith($wowPrefix, [StringComparison]::OrdinalIgnoreCase)) {
                Fail-WinsInno 'untrusted installation root'
            }
        }
    }
}

function Test-WinsInnoIssigSidecar {
    param(
        $Bound,
        $Record,
        $Anchor
    )
    $sidecarPath = $Bound.Path + '.issig'
    if (-not (Test-Path -LiteralPath $sidecarPath)) {
        Fail-WinsInno 'issig sidecar is required'
    }
    $sidecar = [WinsVpn.InnoCustodyNative]::BindRegularFile($sidecarPath, 'Inno Setup installer issig', $script:WinsInnoMaxIssigBytes)
    try {
        if ($sidecar.Sha256 -cne [string]$Record['issig_sha256'] -or [int64]$sidecar.Data.Length -ne [int64]$Record['issig_size']) {
            Fail-WinsInno 'installer issig sidecar SHA-256 mismatch'
        }
        Invoke-WinsInnoEcdsa -Filename ([string]$Record['filename']) -Size ([int64]$Record['size']) -FileHash $Bound.Sha256 -Tag ([string]$Record['issig_file_tag']) -PublicX ([string]$Anchor['public_x']) -PublicY ([string]$Anchor['public_y']) -KeyId ([string]$Anchor['key_id']) -SigR ([string]$Record['issig_sig_r']) -SigS ([string]$Record['issig_sig_s'])
        [WinsVpn.InnoCustodyNative]::AssertUnchanged($sidecar, 'Inno Setup installer issig')
        return $sidecar
    } catch {
        [WinsVpn.InnoCustodyNative]::CloseBound($sidecar)
        throw
    }
}

function Invoke-WinsInnoVerifyPins {
    param([Parameter(Mandatory)][string]$ManifestPath)

    $loaded = ConvertFrom-WinsInnoCustodyPin -ManifestPath $ManifestPath
    try {
        $manifest = $loaded.Manifest
        [WinsVpn.InnoCustodyNative]::AssertUnchanged($loaded.Bound, 'Inno toolchain pin')
        $compilersPinned = $true
        foreach ($name in @('windows_x64', 'windows_arm64')) {
            if ([string]$manifest['compilers'][$name]['status'] -cne 'pinned') {
                $compilersPinned = $false
            }
        }
        Write-Output 'contract|winsvpn-inno-toolchain-custody-v1'
        Write-Output 'version|7.1.0'
        Write-Output ('status|' + $(if ($compilersPinned) { 'pinned' } else { 'unmeasured' }))
        Write-Output 'installers_pinned|True'
        Write-Output ('compilers_pinned|' + $(if ($compilersPinned) { 'True' } else { 'False' }))
        [WinsVpn.InnoCustodyNative]::AssertUnchanged($loaded.Bound, 'Inno toolchain pin')
    } finally {
        [WinsVpn.InnoCustodyNative]::CloseBound($loaded.Bound)
    }
}

function Invoke-WinsInnoVerifyInstaller {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][ValidateSet('x64', 'x86')][string]$Architecture,
        [Parameter(Mandatory)][string]$CandidatePath
    )

    $loaded = ConvertFrom-WinsInnoCustodyPin -ManifestPath $ManifestPath
    $bound = $null
    $sidecar = $null
    try {
        $manifest = $loaded.Manifest
        $record = $manifest['installers']["windows_$Architecture"]
        if (-not $record) {
            Fail-WinsInno 'installer architecture is unsupported'
        }
        $bound = [WinsVpn.InnoCustodyNative]::BindRegularFile($CandidatePath, 'Inno Setup installer', $script:WinsInnoMaxInstallerBytes)
        if ([IO.Path]::GetFileName($bound.Path) -cne [string]$record['filename']) {
            Fail-WinsInno 'installer filename mismatch'
        }
        if ([int64]$record['size'] -ne [int64]$bound.Data.Length -or $bound.Sha256 -cne [string]$record['sha256']) {
            Fail-WinsInno 'installer SHA-256 mismatch'
        }
        $anchor = $script:WinsInnoOfficialKeys[[string]$record['issig_key']]
        $sidecar = Test-WinsInnoIssigSidecar -Bound $bound -Record $record -Anchor $anchor
        Assert-WinsInnoPeMachine -Bytes $bound.Data -Expected $Architecture
        $versions = [WinsVpn.InnoCustodyNative]::VersionStrings($bound.Data)
        if ([string]$versions['ProductVersion'] -cne [string]$record['product_version_string']) {
            Fail-WinsInno 'version mismatch'
        }
        $leaf = [WinsVpn.InnoCustodyNative]::AuthenticodeLeafFromPe($bound.Data)
        Assert-WinsInnoPublisherLeaf -Leaf $leaf
        [WinsVpn.InnoCustodyNative]::AssertUnchanged($bound, 'Inno Setup installer')
        [WinsVpn.InnoCustodyNative]::AssertUnchanged($loaded.Bound, 'Inno toolchain pin')
        if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
            [WinsVpn.InnoCustodyNative]::WinVerifyTrustHandle($bound)
        } else {
            Fail-WinsInno 'Authenticode chain verification requires Windows'
        }
        [WinsVpn.InnoCustodyNative]::AssertUnchanged($bound, 'Inno Setup installer')
        Write-Output "architecture|$Architecture"
        Write-Output ("filename|" + $record['filename'])
        Write-Output ("sha256|" + $bound.Sha256)
        Write-Output ("publisher|" + $script:WinsInnoPublisherName)
    } finally {
        if ($null -ne $sidecar) { [WinsVpn.InnoCustodyNative]::CloseBound($sidecar) }
        if ($null -ne $bound) { [WinsVpn.InnoCustodyNative]::CloseBound($bound) }
        [WinsVpn.InnoCustodyNative]::CloseBound($loaded.Bound)
    }
}

function Assert-WinsInnoCompilerNotInstaller {
    param($Bound, $Manifest)
    foreach ($name in @('windows_x64', 'windows_x86')) {
        $installer = $Manifest['installers'][$name]
        if ($Bound.Sha256 -ceq [string]$installer['sha256']) {
            Fail-WinsInno 'compiler identity must be ISCC.exe, not the Pyrsys installer'
        }
    }
    try {
        $versions = [WinsVpn.InnoCustodyNative]::VersionStrings($Bound.Data)
    } catch {
        return
    }
    if ([string]$versions['FileDescription'] -ceq 'Inno Setup Setup') {
        Fail-WinsInno 'compiler identity must be ISCC.exe, not the Pyrsys installer'
    }
    foreach ($name in @('windows_x64', 'windows_x86')) {
        $installer = $Manifest['installers'][$name]
        if ([string]$versions['FileDescription'] -ceq [string]$installer['file_description']) {
            Fail-WinsInno 'compiler identity must be ISCC.exe, not the Pyrsys installer'
        }
        if ($versions.ContainsKey('OriginalFileName') -and [string]$versions['OriginalFileName'] -ceq [string]$installer['filename']) {
            Fail-WinsInno 'compiler identity must be ISCC.exe, not the Pyrsys installer'
        }
    }
    if ($versions.ContainsKey('OriginalFileName') -and [string]$versions['OriginalFileName'] -cne 'ISCC.exe') {
        Fail-WinsInno 'compiler filename mismatch'
    }
}

function Invoke-WinsInnoVerifyCompiler {
    param(
        [Parameter(Mandatory)][string]$ManifestPath,
        [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
        [Parameter(Mandatory)][string]$CandidatePath,
        [switch]$Measure
    )

    $loaded = ConvertFrom-WinsInnoCustodyPin -ManifestPath $ManifestPath
    $bound = $null
    try {
        $manifest = $loaded.Manifest
        $record = $manifest['compilers']["windows_$Architecture"]
        if (-not $record) {
            Fail-WinsInno 'compiler architecture is unsupported'
        }
        Assert-WinsInnoTrustedCompilerRoot -Path $CandidatePath
        $bound = [WinsVpn.InnoCustodyNative]::BindRegularFile($CandidatePath, 'ISCC compiler', $script:WinsInnoMaxCompilerBytes)
        if ([IO.Path]::GetFileName($bound.Path) -cne 'ISCC.exe') {
            Fail-WinsInno 'compiler filename mismatch'
        }
        Assert-WinsInnoCompilerNotInstaller -Bound $bound -Manifest $manifest
        if ($Measure) {
            # The official 7.1.0 ISCC.exe carries VERSIONINFO ProductVersion
            # 0.0.0.0; measure mode reports it and checks FileDescription.
            $expectedProductVersion = $null
        } else {
            if ([string]$record['status'] -cne 'pinned' -or $null -eq $record['sha256'] -or $null -eq $record['size'] -or
                $null -eq $record['install_tree_sha256'] -or $null -eq $record['product_version_string']) {
                Fail-WinsInno "ISCC $Architecture pin not measured; run verify-compiler --measure on a Windows host and record the printed values in tools/inno-toolchain-pins.json"
            }
            if ([int64]$record['size'] -ne [int64]$bound.Data.Length -or $bound.Sha256 -cne [string]$record['sha256']) {
                Fail-WinsInno 'compiler SHA-256 mismatch'
            }
            $expectedProductVersion = [string]$record['product_version_string']
        }
        Assert-WinsInnoPeMachine -Bytes $bound.Data -Expected 'x64'
        $parsed = [WinsVpn.InnoCustodyNative]::ParsePe($bound.Data)
        if ($Architecture -eq 'arm64' -and [int]$parsed['machine'] -eq 0xAA64) {
            Fail-WinsInno 'architecture mismatch: native ARM64 ISCC is not published for 7.1.0'
        }
        $versions = [WinsVpn.InnoCustodyNative]::VersionStrings($bound.Data)
        if ($null -eq $expectedProductVersion) {
            if ([string]$versions['FileDescription'] -cne 'Inno Setup Command-Line Compiler') {
                Fail-WinsInno 'compiler identity must be the Inno Setup command-line compiler'
            }
        } elseif ([string]$versions['ProductVersion'] -cne $expectedProductVersion) {
            Fail-WinsInno 'version mismatch'
        }
        if ([string]$versions['FileDescription'] -ceq 'Inno Setup Setup') {
            Fail-WinsInno 'compiler identity must be ISCC.exe, not the Pyrsys installer'
        }
        $tree = [WinsVpn.InnoCustodyNative]::SnapshotInstallTree(([IO.Path]::GetDirectoryName($bound.Path)), $script:WinsInnoMaxCompilerBytes)
        try {
            [WinsVpn.InnoCustodyNative]::AssertTreeUnchanged($tree)
            if (-not $Measure -and $tree.Digest -cne [string]$record['install_tree_sha256']) {
                Fail-WinsInno 'compiler install-tree SHA-256 mismatch'
            }
            $leaf = [WinsVpn.InnoCustodyNative]::AuthenticodeLeafFromPe($bound.Data)
            Assert-WinsInnoPublisherLeaf -Leaf $leaf
            [WinsVpn.InnoCustodyNative]::AssertUnchanged($bound, 'ISCC compiler')
            [WinsVpn.InnoCustodyNative]::AssertUnchanged($loaded.Bound, 'Inno toolchain pin')
            if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
                [WinsVpn.InnoCustodyNative]::WinVerifyTrustHandle($bound)
            } else {
                Fail-WinsInno 'Authenticode chain verification requires Windows'
            }
            [WinsVpn.InnoCustodyNative]::AssertTreeUnchanged($tree)
            if ($Measure) {
                if ($tree.Digest -ceq $bound.Sha256) {
                    Fail-WinsInno 'compiler file and install-tree hashes must be independently derived'
                }
                Write-Output 'mode|measure'
                Write-Output "pin_record|compilers.windows_$Architecture"
                Write-Output "architecture|$Architecture"
                Write-Output ("sha256|" + $bound.Sha256)
                Write-Output ("size|" + [int64]$bound.Data.Length)
                Write-Output ("install_tree_sha256|" + $tree.Digest)
                Write-Output ("product_version_string|" + [string]$versions['ProductVersion'])
                return
            }
            $outputArchitectures = @($record['output_architectures'] | ForEach-Object { [string]$_ })
            Write-Output "architecture|$Architecture"
            Write-Output 'filename|ISCC.exe'
            Write-Output ("sha256|" + $bound.Sha256)
            Write-Output ("size|" + [int64]$bound.Data.Length)
            Write-Output 'pe_machine|x64'
            Write-Output ("output_architectures|" + ($outputArchitectures -join ','))
            Write-Output ("version|" + [string]$record['expected_version'])
            Write-Output ("product_version_string|" + [string]$versions['ProductVersion'])
            Write-Output ("publisher_name|" + [string]$leaf.PublisherName)
            Write-Output ("authenticode_leaf_sha256|" + [string]$leaf.Sha256)
            Write-Output ("authenticode_leaf_serial_hex|" + [string]$leaf.Serial)
            Write-Output ("install_tree_sha256|" + $tree.Digest)
            Write-Output ("trusted_root_leaf|" + [string]$record['trusted_root_leaf'])
        } finally {
            [WinsVpn.InnoCustodyNative]::CloseTree($tree)
        }
    } finally {
        if ($null -ne $bound) { [WinsVpn.InnoCustodyNative]::CloseBound($bound) }
        [WinsVpn.InnoCustodyNative]::CloseBound($loaded.Bound)
    }
}

function Invoke-WinsInnoCustodySelfTest {
    param(
        [Parameter(Mandatory)][string]$CandidatePath,
        [Parameter(Mandatory)][string]$Kind
    )

    $full = [IO.Path]::GetFullPath($CandidatePath)
    $parent = [IO.Path]::GetDirectoryName($full)
    $name = [IO.Path]::GetFileName($full)
    if ([string]::IsNullOrWhiteSpace($parent) -or -not [IO.Path]::IsPathRooted($full)) {
        Fail-WinsInno 'PATH substitution refused: candidate must be an explicit path'
    }
    $bound = [WinsVpn.InnoCustodyNative]::BindRegularFile($full, 'custody self-test', $script:WinsInnoMaxInstallerBytes)
    try {
        if ($Kind -eq 'sibling-churn') {
            $roots = New-Object System.Collections.Generic.List[string]
            [void]$roots.Add($parent)
            foreach ($extra in @([IO.Path]::GetTempPath().TrimEnd('\', '/'), '/private/tmp', '/tmp')) {
                if (-not [string]::IsNullOrWhiteSpace($extra) -and [IO.Directory]::Exists($extra) -and -not $roots.Contains($extra)) {
                    [void]$roots.Add($extra)
                }
            }
            foreach ($root in $roots) {
                for ($i = 0; $i -lt 8; $i++) {
                    $sib = Join-Path $root ('wins-inno-churn-' + [guid]::NewGuid().ToString('N'))
                    [void][IO.Directory]::CreateDirectory($sib)
                    [void][IO.Directory]::CreateDirectory((Join-Path $sib 'nlink'))
                    try { [IO.Directory]::SetLastWriteTimeUtc($root, [datetime]::UtcNow) } catch { }
                    [IO.Directory]::Delete($sib, $true)
                }
            }
            [WinsVpn.InnoCustodyNative]::AssertUnchanged($bound, 'custody self-test')
            Write-Output 'CUSTODY_SELFTEST|sibling-churn|ok'
            return
        }
        $old = $parent + '.old'
        $decoy = $parent + '.decoy'
        if (Test-Path -LiteralPath $old) { Fail-WinsInno 'parent swap self-test collision' }
        [IO.Directory]::Move($parent, $old)
        try {
            [void][IO.Directory]::CreateDirectory($parent)
            [IO.File]::WriteAllBytes((Join-Path $parent $name), [Text.Encoding]::ASCII.GetBytes('replacement-bytes'))
            if ($Kind -eq 'parent-swap-restore') {
                [IO.Directory]::Move($parent, $decoy)
                [void][IO.Directory]::CreateDirectory($parent)
                [IO.File]::WriteAllBytes((Join-Path $parent $name), [Text.Encoding]::ASCII.GetBytes('restored-decoy-bytes'))
            }
            $detected = $false
            try {
                [WinsVpn.InnoCustodyNative]::AssertUnchanged($bound, 'custody self-test')
            } catch {
                $detected = $true
                if ($_.Exception.Message -notmatch 'parent path component mutated|mutated while it was inspected') {
                    throw
                }
            }
            if (-not $detected) {
                Fail-WinsInno 'parent swap was not detected'
            }
            Write-Output ('CUSTODY_SELFTEST|' + $Kind + '|ok')
        } finally {
            if (Test-Path -LiteralPath $parent) {
                try { [IO.Directory]::Delete($parent, $true) } catch { }
            }
            if (Test-Path -LiteralPath $decoy) {
                try { [IO.Directory]::Delete($decoy, $true) } catch { }
            }
            if (Test-Path -LiteralPath $old) {
                try { [IO.Directory]::Move($old, $parent) } catch { }
            }
        }
    } finally {
        [WinsVpn.InnoCustodyNative]::CloseBound($bound)
    }
}
$commandCount = @($VerifyPins, $VerifyInstaller, $VerifyCompiler, $CustodySelfTest | Where-Object { $_ }).Count
if ($commandCount -ne 1) {
    throw 'Specify exactly one of -VerifyPins, -VerifyInstaller, -VerifyCompiler, or -CustodySelfTest.'
}

$resolvedPin = if ([string]::IsNullOrWhiteSpace($PinPath)) {
    Join-Path $PSScriptRoot 'inno-toolchain-pins.json'
} else {
    $PinPath
}

if ($VerifyInstaller -or $VerifyCompiler) {
    if ([string]::IsNullOrWhiteSpace($Architecture) -or [string]::IsNullOrWhiteSpace($Path)) {
        throw '-Architecture and -Path are required for installer or compiler verification.'
    }
    if ($Path -ieq 'ISCC.exe' -or $Path -ieq 'innosetup-7.1.0-x64.exe') {
        throw 'PATH substitution refused: candidate must be an explicit path'
    }
}

if ($Measure -and -not $VerifyCompiler) {
    throw '-Measure is only valid with -VerifyCompiler.'
}

if ($CustodySelfTest -and [string]::IsNullOrWhiteSpace($Path)) {
    throw '-Path is required for -CustodySelfTest.'
}

try {
    if ($CustodySelfTest) {
        Invoke-WinsInnoCustodySelfTest -CandidatePath $Path -Kind $CustodySelfTestKind
    } elseif ($VerifyPins) {
        Invoke-WinsInnoVerifyPins -ManifestPath $resolvedPin
    } elseif ($VerifyInstaller) {
        if ($Architecture -notin @('x64', 'x86')) {
            throw 'installer architecture is unsupported'
        }
        Invoke-WinsInnoVerifyInstaller -ManifestPath $resolvedPin -Architecture $Architecture -CandidatePath $Path
    } else {
        if ($Architecture -notin @('x64', 'arm64')) {
            throw 'compiler architecture is unsupported'
        }
        Invoke-WinsInnoVerifyCompiler -ManifestPath $resolvedPin -Architecture $Architecture -CandidatePath $Path -Measure:$Measure
    }
} catch {
    $message = $_.Exception.Message
    Write-Error "INNO CUSTODY REFUSED: $message"
    exit 1
}
