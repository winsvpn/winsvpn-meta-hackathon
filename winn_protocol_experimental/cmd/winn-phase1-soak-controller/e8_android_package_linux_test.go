//go:build linux && winn_incomplete_e8

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func newE8AndroidPackageFixture(
	t *testing.T,
) (e8AndroidPackageBinding, string) {
	t.Helper()
	installRoot := filepath.Join(t.TempDir(), "installed-package")
	nativeDir := filepath.Join(installRoot, "lib", "arm64")
	if err := os.MkdirAll(nativeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	baseAPK := filepath.Join(installRoot, "base.apk")
	baseBytes := []byte("signed-apk-fixture")
	if err := os.WriteFile(baseAPK, baseBytes, 0o400); err != nil {
		t.Fatal(err)
	}
	workerPath := filepath.Join(nativeDir, e8AndroidWorkerFilename)
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate Android package test source")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	certificate := strings.Repeat("a", 64)
	buildID := strings.Repeat("b", 64)
	command := exec.Command(
		"go", "build", "-trimpath", "-buildvcs=false",
		"-tags", "winn_incomplete_e8",
		"-ldflags=-s -w "+
			"-X main.androidPackageName=org.winsvpn.app "+
			"-X main.androidPackageVersion=3000001 "+
			"-X main.androidSigningCertSHA256="+certificate+" "+
			"-X main.androidWorkerBuildID="+buildID,
		"-o", workerPath, "./cmd/winn-local-sealed-node",
	)
	command.Dir = moduleRoot
	command.Env = append(
		os.Environ(),
		"GOTOOLCHAIN=local", "CGO_ENABLED=0",
		"GOOS=android", "GOARCH=arm64",
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Android packaged worker: %v\n%s", err, output)
	}
	if err := os.Chmod(workerPath, 0o500); err != nil {
		t.Fatal(err)
	}
	workerBytes, err := os.ReadFile(workerPath)
	if err != nil {
		t.Fatal(err)
	}
	workerSHA := admittedRawSHA(workerBytes)
	binding, err := encodeE8AndroidPackageBinding(
		e8AndroidPackageBinding{
			PackageName:                  "org.winsvpn.app",
			PackageUID:                   10000,
			VersionCode:                  3000001,
			SigningCertificateSHA256:     certificate,
			BaseAPKPath:                  baseAPK,
			BaseAPKSHA256:                admittedRawSHA(baseBytes),
			NativeLibraryDir:             nativeDir,
			WorkerSHA256:                 workerSHA,
			WorkerBuildID:                buildID,
			PackageManagerProofVersion:   "android-package-manager/v1",
			PackageManagerProofValidated: true,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding, workerPath
}

func TestE8AndroidPackagedWorkerPinsReadOnlyDescriptorAgainstReplacement(
	t *testing.T,
) {
	binding, workerPath := newE8AndroidPackageFixture(t)
	worker, err := openE8AndroidPackagedWorker(binding, false)
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	flags, err := unix.FcntlInt(worker.Fd(), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
		t.Fatal("packaged worker was not retained read-only")
	}
	before, err := worker.Stat()
	if err != nil {
		t.Fatal(err)
	}
	oldPath := workerPath + ".replaced"
	if err := os.Rename(workerPath, oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workerPath, []byte("substitute"), 0o500); err != nil {
		t.Fatal(err)
	}
	digest, err := digestE8RetainedWorker(worker)
	if err != nil || digest != binding.WorkerSHA256 {
		t.Fatal("retained packaged-worker descriptor changed after replacement")
	}
	after, err := worker.Stat()
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("retained packaged-worker inode changed after replacement")
	}
	if replacement, err := openE8AndroidPackagedWorker(binding, false); err == nil {
		_ = replacement.Close()
		t.Fatal("replaced packaged-worker path was accepted")
	}
}

func TestE8AndroidPackageBindingRejectsMalformedAndCustodyMutations(
	t *testing.T,
) {
	baseline, _ := newE8AndroidPackageFixture(t)
	if err := validateE8AndroidPackageBinding(baseline); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*e8AndroidPackageBinding){
		"package-name": func(value *e8AndroidPackageBinding) {
			value.PackageName = "invalid"
		},
		"zero-uid": func(value *e8AndroidPackageBinding) {
			value.PackageUID = 0
		},
		"zero-version": func(value *e8AndroidPackageBinding) {
			value.VersionCode = 0
		},
		"certificate": func(value *e8AndroidPackageBinding) {
			value.SigningCertificateSHA256 = "not-a-digest"
		},
		"base-apk-name": func(value *e8AndroidPackageBinding) {
			value.BaseAPKPath = filepath.Join(
				filepath.Dir(value.BaseAPKPath), "split.apk",
			)
		},
		"noncanonical-native-dir": func(value *e8AndroidPackageBinding) {
			value.NativeLibraryDir += "/../arm64"
		},
		"worker-build": func(value *e8AndroidPackageBinding) {
			value.WorkerBuildID = "not-a-digest"
		},
		"unverified-package-manager": func(value *e8AndroidPackageBinding) {
			value.PackageManagerProofValidated = false
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := baseline
			mutate(&value)
			if _, err := encodeE8AndroidPackageBinding(value); err == nil {
				t.Fatal("malformed Android package mutation was accepted")
			}
		})
	}
	fixedFilename := baseline
	fixedFilename.WorkerFilename = "attacker-worker"
	fixedFilename, err := encodeE8AndroidPackageBinding(fixedFilename)
	if err != nil || fixedFilename.WorkerFilename != e8AndroidWorkerFilename {
		t.Fatal("Go boundary did not fix the Android worker filename")
	}
	for name, mutate := range map[string]func(*e8AndroidPackageBinding){
		"base-apk-digest": func(value *e8AndroidPackageBinding) {
			value.BaseAPKSHA256 = strings.Repeat("c", 64)
		},
		"worker-digest": func(value *e8AndroidPackageBinding) {
			value.WorkerSHA256 = strings.Repeat("d", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := baseline
			mutate(&value)
			value, err := encodeE8AndroidPackageBinding(value)
			if err != nil {
				t.Fatal(err)
			}
			if file, err := openE8AndroidPackagedWorker(value, false); err == nil {
				_ = file.Close()
				t.Fatal("re-digested false Android custody mutation was accepted")
			}
		})
	}
}

func TestE8AndroidPackageBindingRejectsSymlinkedNativeLibraryDir(
	t *testing.T,
) {
	baseline, _ := newE8AndroidPackageFixture(t)
	link := filepath.Join(t.TempDir(), "native-link")
	if err := os.Symlink(baseline.NativeLibraryDir, link); err != nil {
		t.Fatal(err)
	}
	baseline.NativeLibraryDir = link
	value, err := encodeE8AndroidPackageBinding(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if file, err := openE8AndroidPackagedWorker(value, false); err == nil {
		_ = file.Close()
		t.Fatal("symlinked Android nativeLibraryDir was accepted")
	}
}

func TestE8PreparedIdentityBindsAndroidPackageVersionCertificateAndBuild(
	t *testing.T,
) {
	binding, _ := newE8AndroidPackageFixture(t)
	process, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	child := &e8Child{
		command:      &exec.Cmd{Process: process},
		processStart: 12345,
	}
	// #nosec G115 -- os.Getpid is a positive Linux pid_t in this test.
	peer := &unix.Ucred{Pid: int32(os.Getpid())}
	identity := e8PreparedIdentity{
		Schema:                    e8PreparedIdentitySchema,
		ProcessID:                 uint64(os.Getpid()),
		ProcessStartTicks:         child.processStart,
		WorkerSHA256:              binding.WorkerSHA256,
		WorkerBuildID:             binding.WorkerBuildID,
		AndroidPackageName:        binding.PackageName,
		AndroidPackageVersionCode: binding.VersionCode,
		AndroidSigningCertSHA256:  binding.SigningCertificateSHA256,
	}
	if err := validateE8PreparedIdentity(
		identity, child, peer, binding.WorkerSHA256, &binding,
	); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*e8PreparedIdentity){
		"package": func(value *e8PreparedIdentity) {
			value.AndroidPackageName = "com.attacker.substitute"
		},
		"version": func(value *e8PreparedIdentity) {
			value.AndroidPackageVersionCode++
		},
		"certificate": func(value *e8PreparedIdentity) {
			value.AndroidSigningCertSHA256 = strings.Repeat("c", 64)
		},
		"build": func(value *e8PreparedIdentity) {
			value.WorkerBuildID = strings.Repeat("d", 64)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := identity
			mutate(&value)
			if err := validateE8PreparedIdentity(
				value, child, peer, binding.WorkerSHA256, &binding,
			); err == nil {
				t.Fatal("Android package/build identity mutation was accepted")
			}
		})
	}
	if err := validateE8PreparedIdentity(
		identity, child, peer, binding.WorkerSHA256, nil,
	); err == nil {
		t.Fatal("Android identity fields were accepted without package custody")
	}
}
