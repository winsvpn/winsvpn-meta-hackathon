//go:build winn_incomplete_e8

package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"winsvpn.local/winnprotocol/internal/realcycle"
)

const (
	e8GrantSchema          = "winn-local-sealed-rehearsal-grant/v3"
	e8GrantState           = "rehearsal-only-no-production-authority"
	e8GrantScope           = "four-local-sealed-nodes-no-provider-network-credential"
	e8GrantFile            = "local-rehearsal-grant.json"
	e8GrantDomain          = "winn-local-sealed-rehearsal-grant-signature/v3"
	e8GrantObject          = "winn-local-sealed-rehearsal-grant-object/v3"
	e8ChildrenEvidenceFile = ".local-rehearsal-children-evidence.json"

	e8AcceptanceSchema = "winn-local-sealed-rehearsal-acceptance/v3"
	e8AcceptanceFile   = "local-rehearsal-acceptance.json"
	e8AcceptanceDomain = "winn-local-sealed-rehearsal-acceptance-signature/v3"
	e8AcceptanceObject = "winn-local-sealed-rehearsal-acceptance-object/v3"
	e8GrantCollection  = "winn-local-sealed-rehearsal-grant-collection/v3"

	e8SandboxPolicy = "winn-local-sealed-rehearsal-seccomp-policy/v3"
)

type e8RehearsalGrant struct {
	Schema                 string `json:"schema"`
	State                  string `json:"state"`
	Scope                  string `json:"scope"`
	GrantID                string `json:"grant_id"`
	RunID                  string `json:"run_id"`
	CycleID                string `json:"cycle_id"`
	AttemptID              string `json:"attempt_id"`
	TopologyID             string `json:"topology_id"`
	PlanSHA256             string `json:"plan_sha256"`
	PlanObjectDigest       string `json:"plan_object_digest"`
	E6ReceiptSHA256        string `json:"e6_receipt_sha256"`
	E6ReceiptObjectDigest  string `json:"e6_receipt_object_digest"`
	E7ReceiptSHA256        string `json:"e7_receipt_sha256"`
	E7ReceiptObjectDigest  string `json:"e7_receipt_object_digest"`
	WorkerPath             string `json:"worker_path"`
	WorkerSHA256           string `json:"worker_sha256"`
	SandboxPolicy          string `json:"sandbox_policy"`
	SandboxPolicyDigest    string `json:"sandbox_policy_digest"`
	RehearsalNonce         string `json:"rehearsal_nonce"`
	MaxRehearsalSeconds    uint64 `json:"max_rehearsal_seconds"`
	ProductionE7Consumable bool   `json:"production_e7_consumable"`
	ProductionAuthority    bool   `json:"production_authority"`
	AuthorizerKeyID        string `json:"authorizer_key_id"`
	Signature              string `json:"signature"`
}

type e8RehearsalAcceptance struct {
	Schema                     string `json:"schema"`
	State                      string `json:"state"`
	GrantSHA256                string `json:"grant_sha256"`
	GrantObjectDigest          string `json:"grant_object_digest"`
	E6ReceiptSHA256            string `json:"e6_receipt_sha256"`
	E6ReceiptObjectDigest      string `json:"e6_receipt_object_digest"`
	E7ReceiptSHA256            string `json:"e7_receipt_sha256"`
	E7ReceiptObjectDigest      string `json:"e7_receipt_object_digest"`
	RunID                      string `json:"run_id"`
	CycleID                    string `json:"cycle_id"`
	AttemptID                  string `json:"attempt_id"`
	TopologyID                 string `json:"topology_id"`
	WorkerPath                 string `json:"worker_path"`
	WorkerSHA256               string `json:"worker_sha256"`
	SandboxPolicyDigest        string `json:"sandbox_policy_digest"`
	RehearsalNonce             string `json:"rehearsal_nonce"`
	SupervisorExecutablePath   string `json:"supervisor_executable_path"`
	SupervisorExecutableSHA256 string `json:"supervisor_executable_sha256"`
	ProductionE7Consumable     bool   `json:"production_e7_consumable"`
	ProductionAuthority        bool   `json:"production_authority"`
	SupervisorKeyID            string `json:"supervisor_key_id"`
	Signature                  string `json:"signature"`
}

type e8GrantResult struct {
	Grant                  e8RehearsalGrant
	Acceptance             e8RehearsalAcceptance
	GrantSHA256            string
	GrantObjectDigest      string
	AcceptanceSHA256       string
	AcceptanceObjectDigest string
	CollectionDigest       string
	MaxRehearsalSeconds    uint64
}

type e8GrantUnsigned e8RehearsalGrant
type e8AcceptanceUnsigned e8RehearsalAcceptance

func e8GrantUnsignedOf(value e8RehearsalGrant) e8GrantUnsigned {
	value.Signature = ""
	return e8GrantUnsigned(value)
}

func e8AcceptanceUnsignedOf(value e8RehearsalAcceptance) e8AcceptanceUnsigned {
	value.Signature = ""
	return e8AcceptanceUnsigned(value)
}

func e8SandboxPolicyDigest() string {
	digest, err := admittedDigest(e8SandboxPolicy, []string{
		"default_errno_explicit_runtime_allowlist",
		"allow_syscalls=read,write,close,fstat,lseek,mmap,mprotect,munmap,brk,rt_sigaction,rt_sigprocmask,rt_sigreturn,ioctl,pread64,writev,sched_yield,mremap,madvise,nanosleep,getpid,exit,exit_group,fcntl,sigaltstack,gettid,futex,sched_getaffinity,clock_gettime,epoll_pwait,epoll_ctl,tgkill,eventfd2,epoll_create1,prlimit64,getrandom,rseq,restart_syscall,recvmsg",
		"no_new_privs", "cap_effective_zero", "seccomp_tsync",
		"all_thread_capability_sets_and_bounding_sets_zero",
		"deny_network_creation_and_connection", "deny_filesystem_open_and_mutation",
		"deny_kernel_credentials", "deny_process_creation_and_session_escape",
		"only_capabilities_fds_0_through_5_plus_cloexec_go_runtime_internals",
	})
	if err != nil {
		panic(err)
	}
	return digest
}

func verifyE8SignedObject(
	publicKey, signature, domain string, value any,
) error {
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(key) != ed25519.PublicKeySize ||
		base64.StdEncoding.EncodeToString(key) != publicKey {
		return errors.New("E8 role public key is malformed")
	}
	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(sig) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(sig) != signature {
		return errors.New("E8 signature is malformed")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	message := append(append([]byte(domain), 0), encoded...)
	if !ed25519.Verify(ed25519.PublicKey(key), message, sig) {
		return errors.New("E8 signature verification failed")
	}
	return nil
}

func e8RoleKey(e6 e6VerificationReceipt, role, keyID string) (string, error) {
	for _, row := range e6.RoleExtensionKeys {
		if row.Role == role && row.KeyID == keyID {
			return row.PublicKey, nil
		}
	}
	return "", errors.New("E8 signer is not an accepted E6 role key")
}

func readAuthenticatedE8Grant(
	rootPath string,
	plan e5FourNodePlan,
	e6 e6VerificationReceipt,
	e6SHA string,
	e7 e7VerificationReceipt,
	e7SHA string,
	workerPath string,
	workerSHA string,
) (e8GrantResult, error) {
	if !filepath.IsAbs(rootPath) {
		return e8GrantResult{}, errors.New("E8 grant root must be absolute")
	}
	root, err := openAdmittedPrivateDirectory(rootPath)
	if err != nil {
		return e8GrantResult{}, err
	}
	defer root.Close()
	entries, err := root.ReadDir()
	names := map[string]bool{}
	for _, entry := range entries {
		names[entry.Name()] = true
	}
	if err != nil || len(entries) < 2 || len(entries) > 7 ||
		!names[e8AcceptanceFile] || !names[e8GrantFile] {
		return e8GrantResult{}, errors.New("E8 grant root is not the exact two-file set")
	}
	for name := range names {
		if name == e8AcceptanceFile || name == e8GrantFile ||
			name == e8ChildrenEvidenceFile {
			continue
		}
		var sequence uint64
		if _, scanErr := fmt.Sscanf(
			name, e8TransactionPrefix+"%02d.json", &sequence,
		); scanErr != nil || sequence < 1 || sequence > 4 {
			return e8GrantResult{}, errors.New("E8 grant root contains an unknown file")
		}
	}
	read := func(name string) ([]byte, error) {
		file, err := openAdmittedPrivateFileMode(root, name, os.O_RDONLY, 0, 0o400)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		return readBoundedE5File(file)
	}
	grantBytes, err := read(e8GrantFile)
	if err != nil {
		return e8GrantResult{}, err
	}
	acceptanceBytes, err := read(e8AcceptanceFile)
	if err != nil {
		return e8GrantResult{}, err
	}
	var grant e8RehearsalGrant
	var acceptance e8RehearsalAcceptance
	if err := decodeStrictObject(grantBytes, &grant); err != nil {
		return e8GrantResult{}, err
	}
	if err := decodeStrictObject(acceptanceBytes, &acceptance); err != nil {
		return e8GrantResult{}, err
	}
	if grant.Schema != e8GrantSchema || grant.State != e8GrantState ||
		grant.Scope != e8GrantScope || grant.GrantID == "" ||
		grant.RunID != plan.RunID || grant.CycleID != plan.CycleID ||
		grant.AttemptID != plan.AttemptID || grant.TopologyID != plan.TopologyID ||
		grant.PlanSHA256 != e6.PlanSHA256 ||
		grant.PlanObjectDigest != plan.ObjectDigest ||
		grant.E6ReceiptSHA256 != e6SHA ||
		grant.E6ReceiptObjectDigest != e6.ObjectDigest ||
		grant.E7ReceiptSHA256 != e7SHA ||
		grant.E7ReceiptObjectDigest != e7.ObjectDigest ||
		grant.WorkerPath != workerPath || grant.WorkerSHA256 != workerSHA ||
		grant.SandboxPolicy != e8SandboxPolicy ||
		grant.SandboxPolicyDigest != e8SandboxPolicyDigest() ||
		!noncePattern.MatchString(grant.RehearsalNonce) ||
		grant.MaxRehearsalSeconds == 0 || grant.MaxRehearsalSeconds > 30 ||
		grant.ProductionE7Consumable || grant.ProductionAuthority {
		return e8GrantResult{}, errors.New("E8 rehearsal grant is not exact")
	}
	authorizer, err := e8RoleKey(
		e6, realcycle.KeyRoleDispatchAuthorizer, grant.AuthorizerKeyID,
	)
	if err != nil {
		return e8GrantResult{}, err
	}
	if err := verifyE8SignedObject(
		authorizer, grant.Signature, e8GrantDomain, e8GrantUnsignedOf(grant),
	); err != nil {
		return e8GrantResult{}, fmt.Errorf("E8 grant: %w", err)
	}
	grantObject, err := admittedDigest(e8GrantObject, grant)
	if err != nil {
		return e8GrantResult{}, err
	}
	grantSHA := admittedRawSHA(grantBytes)
	if acceptance.Schema != e8AcceptanceSchema ||
		acceptance.State != "accepted-for-local-rehearsal-only" ||
		acceptance.GrantSHA256 != grantSHA ||
		acceptance.GrantObjectDigest != grantObject ||
		acceptance.E6ReceiptSHA256 != e6SHA ||
		acceptance.E6ReceiptObjectDigest != e6.ObjectDigest ||
		acceptance.E7ReceiptSHA256 != e7SHA ||
		acceptance.E7ReceiptObjectDigest != e7.ObjectDigest ||
		acceptance.RunID != plan.RunID ||
		acceptance.CycleID != plan.CycleID ||
		acceptance.AttemptID != plan.AttemptID ||
		acceptance.TopologyID != plan.TopologyID ||
		acceptance.WorkerPath != workerPath ||
		acceptance.WorkerSHA256 != workerSHA ||
		acceptance.SandboxPolicyDigest != e8SandboxPolicyDigest() ||
		acceptance.RehearsalNonce != grant.RehearsalNonce ||
		acceptance.SupervisorExecutablePath != e6.SupervisorExecutablePath ||
		acceptance.SupervisorExecutableSHA256 !=
			e6.SupervisorExecutableSHA256 ||
		acceptance.ProductionE7Consumable || acceptance.ProductionAuthority {
		return e8GrantResult{}, errors.New("E8 rehearsal acceptance is not exact")
	}
	supervisor, err := e8RoleKey(
		e6, realcycle.KeyRoleExecutionSupervisor, acceptance.SupervisorKeyID,
	)
	if err != nil {
		return e8GrantResult{}, err
	}
	if err := verifyE8SignedObject(
		supervisor, acceptance.Signature, e8AcceptanceDomain,
		e8AcceptanceUnsignedOf(acceptance),
	); err != nil {
		return e8GrantResult{}, fmt.Errorf("E8 acceptance: %w", err)
	}
	acceptanceObject, err := admittedDigest(e8AcceptanceObject, acceptance)
	if err != nil {
		return e8GrantResult{}, err
	}
	collection, err := admittedDigest(
		e8GrantCollection, []string{grantObject, acceptanceObject},
	)
	if err != nil {
		return e8GrantResult{}, err
	}
	return e8GrantResult{
		Grant: grant, Acceptance: acceptance,
		GrantSHA256: grantSHA, GrantObjectDigest: grantObject,
		AcceptanceSHA256:       admittedRawSHA(acceptanceBytes),
		AcceptanceObjectDigest: acceptanceObject,
		CollectionDigest:       collection,
		MaxRehearsalSeconds:    grant.MaxRehearsalSeconds,
	}, nil
}
