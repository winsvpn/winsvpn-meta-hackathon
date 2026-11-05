//go:build linux && winn_incomplete_e8

package main

import (
	"context"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	e8AndroidPackageBindingSchema = "winn-e8-android-package-binding/v1"
	e8AndroidPackageBindingDomain = "winn-e8-android-package-binding-object/v1"
	e8AndroidWorkerFilename       = "libwinn_e8_worker.so"
)

var e8AndroidPackageNamePattern = regexp.MustCompile(
	`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`,
)

// e8AndroidPackageBinding is the closed handoff from the Android application
// host. The host must populate it from PackageManager/ApplicationInfo, never
// from an intent, shell argument, writable preference, or downloaded file.
//
// The production resolver independently reopens and measures BaseAPKPath and
// the exact worker beneath NativeLibraryDir. PackageUID must be the current app
// UID. SigningCertificateSHA256 is the SHA-256 of the sole current APK signing
// certificate returned by PackageManager. WorkerBuildID is a release-generated
// 32-byte value embedded into the worker with the other package fields.
type e8AndroidPackageBinding struct {
	Schema                       string `json:"schema"`
	PackageName                  string `json:"package_name"`
	PackageUID                   uint32 `json:"package_uid"`
	VersionCode                  uint64 `json:"version_code"`
	SigningCertificateSHA256     string `json:"signing_certificate_sha256"`
	BaseAPKPath                  string `json:"base_apk_path"`
	BaseAPKSHA256                string `json:"base_apk_sha256"`
	NativeLibraryDir             string `json:"native_library_dir"`
	WorkerFilename               string `json:"worker_filename"`
	WorkerSHA256                 string `json:"worker_sha256"`
	WorkerBuildID                string `json:"worker_build_id"`
	PackageManagerProofVersion   string `json:"package_manager_proof_version"`
	PackageManagerProofValidated bool   `json:"package_manager_proof_validated"`
	ObjectDigest                 string `json:"object_digest"`
}

// e8AndroidPackageManagerProof is the only production input surface expected
// from the APK/JNI host. It intentionally has no caller-controlled schema,
// worker filename, validation boolean, or object digest. The Go boundary fixes
// and authenticates those fields before it opens either package artifact.
type e8AndroidPackageManagerProof struct {
	PackageName              string `json:"package_name"`
	PackageUID               uint32 `json:"package_uid"`
	VersionCode              uint64 `json:"version_code"`
	SigningCertificateSHA256 string `json:"signing_certificate_sha256"`
	BaseAPKPath              string `json:"base_apk_path"`
	BaseAPKSHA256            string `json:"base_apk_sha256"`
	NativeLibraryDir         string `json:"native_library_dir"`
	WorkerSHA256             string `json:"worker_sha256"`
	WorkerBuildID            string `json:"worker_build_id"`
}

func bindE8AndroidPackageManagerProof(
	proof e8AndroidPackageManagerProof,
) (e8AndroidPackageBinding, error) {
	return encodeE8AndroidPackageBinding(
		e8AndroidPackageBinding{
			PackageName: proof.PackageName, PackageUID: proof.PackageUID,
			VersionCode:                  proof.VersionCode,
			SigningCertificateSHA256:     proof.SigningCertificateSHA256,
			BaseAPKPath:                  proof.BaseAPKPath,
			BaseAPKSHA256:                proof.BaseAPKSHA256,
			NativeLibraryDir:             proof.NativeLibraryDir,
			WorkerSHA256:                 proof.WorkerSHA256,
			WorkerBuildID:                proof.WorkerBuildID,
			PackageManagerProofVersion:   "android-package-manager/v1",
			PackageManagerProofValidated: true,
		},
	)
}

func encodeE8AndroidPackageBinding(
	value e8AndroidPackageBinding,
) (e8AndroidPackageBinding, error) {
	value.Schema = e8AndroidPackageBindingSchema
	value.WorkerFilename = e8AndroidWorkerFilename
	value.ObjectDigest = ""
	digest, err := admittedDigest(e8AndroidPackageBindingDomain, value)
	if err != nil {
		return e8AndroidPackageBinding{}, err
	}
	value.ObjectDigest = digest
	if err := validateE8AndroidPackageBinding(value); err != nil {
		return e8AndroidPackageBinding{}, err
	}
	return value, nil
}

func validateE8AndroidPackageBinding(
	value e8AndroidPackageBinding,
) error {
	digest := value.ObjectDigest
	value.ObjectDigest = ""
	expected, err := admittedDigest(e8AndroidPackageBindingDomain, value)
	if err != nil || digest != expected {
		return errors.New("E8 Android package binding digest mismatch")
	}
	if value.Schema != e8AndroidPackageBindingSchema ||
		!e8AndroidPackageNamePattern.MatchString(value.PackageName) ||
		value.PackageUID == 0 || value.VersionCode == 0 ||
		!digestPattern.MatchString(value.SigningCertificateSHA256) ||
		!digestPattern.MatchString(value.BaseAPKSHA256) ||
		!digestPattern.MatchString(value.WorkerSHA256) ||
		!digestPattern.MatchString(value.WorkerBuildID) ||
		value.WorkerFilename != e8AndroidWorkerFilename ||
		value.PackageManagerProofVersion != "android-package-manager/v1" ||
		!value.PackageManagerProofValidated {
		return errors.New("E8 Android package binding fields are invalid")
	}
	for label, path := range map[string]string{
		"base APK":           value.BaseAPKPath,
		"native library dir": value.NativeLibraryDir,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf(
				"E8 Android %s path is not absolute and canonical", label,
			)
		}
	}
	if filepath.Base(value.BaseAPKPath) != "base.apk" ||
		filepath.Base(value.NativeLibraryDir) == "." ||
		filepath.Dir(value.NativeLibraryDir) == value.NativeLibraryDir {
		return errors.New("E8 Android package paths are not exact")
	}
	workerPath := filepath.Join(
		value.NativeLibraryDir, value.WorkerFilename,
	)
	if filepath.Dir(workerPath) != value.NativeLibraryDir {
		return errors.New("E8 Android worker escaped nativeLibraryDir")
	}
	return nil
}

func prepareAndroidPackagedLocalFourNode(
	ctx context.Context,
	proof e8AndroidPackageManagerProof,
) (*e8PreparedWorkerSet, error) {
	if runtime.GOOS != "android" {
		return nil, errors.New(
			"E8 Android packaged worker resolver is Android-only",
		)
	}
	binding, err := bindE8AndroidPackageManagerProof(proof)
	if err != nil {
		return nil, err
	}
	worker, err := openE8AndroidPackagedWorker(binding, true)
	if err != nil {
		return nil, err
	}
	return prepareLocalFourNodeWithWorker(
		ctx,
		filepath.Join(binding.NativeLibraryDir, binding.WorkerFilename),
		binding.WorkerSHA256,
		worker,
		unix.O_RDONLY,
		&binding,
	)
}

func openE8AndroidPackagedWorker(
	binding e8AndroidPackageBinding,
	enforceAndroidPlatform bool,
) (*os.File, error) {
	if err := validateE8AndroidPackageBinding(binding); err != nil {
		return nil, err
	}
	if enforceAndroidPlatform {
		if runtime.GOOS != "android" {
			return nil, errors.New("E8 packaged worker is not on Android")
		}
		// #nosec G115 -- Android application UIDs are positive 32-bit values.
		if uint32(os.Geteuid()) != binding.PackageUID {
			return nil, errors.New("E8 Android package UID changed")
		}
		if !strings.HasPrefix(binding.BaseAPKPath, "/data/app/") ||
			!strings.HasPrefix(binding.NativeLibraryDir, "/data/app/") {
			return nil, errors.New(
				"E8 Android package is outside PackageManager custody",
			)
		}
		installRoot := filepath.Dir(binding.BaseAPKPath)
		if !strings.HasPrefix(
			binding.NativeLibraryDir, installRoot+string(filepath.Separator),
		) {
			return nil, errors.New(
				"E8 Android nativeLibraryDir is outside the installed package",
			)
		}
	}
	if err := verifyE8AndroidDirectory(
		binding.NativeLibraryDir, enforceAndroidPlatform,
	); err != nil {
		return nil, err
	}
	if enforceAndroidPlatform {
		if err := verifyE8AndroidNotWritable(
			filepath.Dir(binding.BaseAPKPath),
			binding.NativeLibraryDir,
		); err != nil {
			return nil, err
		}
	}
	baseAPK, err := openE8AndroidPinnedFile(
		binding.BaseAPKPath, binding.BaseAPKSHA256, false,
	)
	if err != nil {
		return nil, fmt.Errorf("open E8 Android base APK: %w", err)
	}
	if enforceAndroidPlatform {
		if err := verifyE8AndroidNotWritable(binding.BaseAPKPath); err != nil {
			return nil, errors.Join(err, baseAPK.Close())
		}
	}
	if err := baseAPK.Close(); err != nil {
		return nil, err
	}
	workerPath := filepath.Join(
		binding.NativeLibraryDir, binding.WorkerFilename,
	)
	if enforceAndroidPlatform {
		if err := verifyE8AndroidNotWritable(workerPath); err != nil {
			return nil, err
		}
	}
	worker, err := openE8AndroidPinnedFile(
		workerPath, binding.WorkerSHA256, true,
	)
	if err != nil {
		return nil, fmt.Errorf("open E8 Android packaged worker: %w", err)
	}
	if err := verifyE8AndroidPackagedELF(worker); err != nil {
		return nil, errors.Join(err, worker.Close())
	}
	return worker, nil
}

func verifyE8AndroidDirectory(path string, enforceNotWritable bool) error {
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return errors.New("E8 Android nativeLibraryDir is not an exact directory")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return errors.New("E8 Android nativeLibraryDir contains a symlink")
	}
	fd, err := unix.Open(
		path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return err
	}
	if err := unix.Close(fd); err != nil {
		return err
	}
	if enforceNotWritable {
		return verifyE8AndroidNotWritable(path)
	}
	return nil
}

func verifyE8AndroidNotWritable(paths ...string) error {
	for _, path := range paths {
		err := unix.Access(path, unix.W_OK)
		if err == nil {
			return fmt.Errorf("E8 Android package path is writable: %s", path)
		}
		if !errors.Is(err, unix.EACCES) &&
			!errors.Is(err, unix.EPERM) &&
			!errors.Is(err, unix.EROFS) {
			return fmt.Errorf(
				"E8 Android package writability is indeterminate: %w", err,
			)
		}
	}
	return nil
}

func openE8AndroidPinnedFile(
	path, expectedSHA string,
	executable bool,
) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("E8 Android package file is not exact regular data")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, errors.New("E8 Android package file contains a symlink")
	}
	file, digest, err := openAndDigestPinnedFile(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	after, afterErr := os.Lstat(path)
	if err != nil || afterErr != nil ||
		!os.SameFile(before, info) || !os.SameFile(info, after) ||
		digest != expectedSHA {
		return nil, errors.Join(
			errors.New("E8 Android package file identity or digest changed"),
			err, afterErr, file.Close(),
		)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.Join(
			errors.New("E8 Android package file is group/world writable"),
			file.Close(),
		)
	}
	if executable &&
		(info.Mode().Perm()&0o500 != 0o500 || info.Size() <= 0 ||
			info.Size() > 128<<20) {
		return nil, errors.Join(
			errors.New("E8 Android worker mode or size is invalid"),
			file.Close(),
		)
	}
	return file, nil
}

func verifyE8StaticELF(file *os.File) error {
	return verifyE8WorkerELF(file, false)
}

func verifyE8AndroidPackagedELF(file *os.File) error {
	return verifyE8WorkerELF(file, true)
}

func verifyE8WorkerELF(file *os.File, androidPackaged bool) error {
	parsed, err := elf.NewFile(file)
	if err != nil {
		return errors.New("E8 worker is not an ELF executable")
	}
	interpreter := ""
	for _, program := range parsed.Progs {
		if program.Type == elf.PT_INTERP {
			if interpreter != "" || program.Filesz == 0 || program.Filesz > 64 {
				return errors.Join(
					errors.New("E8 worker ELF interpreter is invalid"),
					parsed.Close(),
				)
			}
			data, readErr := io.ReadAll(io.LimitReader(program.Open(), 65))
			if readErr != nil || uint64(len(data)) != program.Filesz {
				return errors.Join(
					errors.New("read E8 worker ELF interpreter"),
					readErr, parsed.Close(),
				)
			}
			interpreter = strings.TrimSuffix(string(data), "\x00")
		}
	}
	if androidPackaged {
		if parsed.Class != elf.ELFCLASS64 ||
			parsed.Data != elf.ELFDATA2LSB ||
			parsed.Machine != elf.EM_AARCH64 ||
			parsed.Type != elf.ET_DYN ||
			interpreter != "/system/bin/linker64" {
			return errors.Join(
				errors.New("E8 Android worker ELF identity is not exact arm64 PIE"),
				parsed.Close(),
			)
		}
		for _, tag := range []elf.DynTag{
			elf.DT_NEEDED, elf.DT_RPATH, elf.DT_RUNPATH,
		} {
			values, dynErr := parsed.DynString(tag)
			if dynErr != nil || len(values) != 0 {
				return errors.Join(
					errors.New(
						"E8 Android worker has a dynamic library/path dependency",
					),
					dynErr, parsed.Close(),
				)
			}
		}
	} else if interpreter != "" {
		return errors.Join(
			errors.New("E8 worker must be a static no-cgo ELF"),
			parsed.Close(),
		)
	}
	if err := parsed.Close(); err != nil {
		return err
	}
	_, err = file.Seek(0, io.SeekStart)
	return err
}
