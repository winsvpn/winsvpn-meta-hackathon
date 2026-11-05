package preparation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const (
	DefaultLinuxUnderlayNftBinary = "/usr/sbin/nft"
	DefaultLinuxUnderlayIPBinary  = "/usr/sbin/ip"

	defaultLinuxUnderlayCommandTimeout = 5 * time.Second
	defaultLinuxUnderlayCleanupRetry   = time.Second
	maxLinuxUnderlayCommandOutput      = 64 << 10
	maxSignedUnderlayEndpoint          = 2048
)

type LinuxUnderlayCommand struct {
	Path string
	Args []string
}

type LinuxUnderlayCommandResult struct {
	Stdout []byte
	Stderr []byte
}

// LinuxUnderlayCommandRunner is intentionally narrower than the Direct AWG
// process runner: mark authorization may execute only synchronous nft/ip
// commands and never starts a daemon or invokes a shell.
type LinuxUnderlayCommandRunner interface {
	Run(
		context.Context,
		LinuxUnderlayCommand,
	) (LinuxUnderlayCommandResult, error)
}

// LinuxUnderlayMarkAuthorizerConfig is an exact contract with the persistent
// Direct AWG fail-closed table. Family must be "inet", OutputChain must be
// "output", and the table must already contain underlay_ifaces,
// underlay_marks, a drop-policy output chain, and the conjunctive bypass rule.
// DirectAWGUnderlayMark is the existing policy-factory-owned anchor mark;
// FirewallMark is a different, authorizer-owned H3 mark.
//
// A named NetworkNamespace is preferred. Root namespace use is rejected unless
// AllowRootNetworkNamespace is explicitly true; setting both is ambiguous.
type LinuxUnderlayMarkAuthorizerConfig struct {
	NftBinary                 string
	IPBinary                  string
	NetworkNamespace          string
	AllowRootNetworkNamespace bool
	TableFamily               string
	TableName                 string
	OutputChain               string
	UnderlayInterface         string
	DirectAWGUnderlayMark     uint32
	FirewallMark              uint32
	CommandTimeout            time.Duration
	CleanupRetryInterval      time.Duration
	Runner                    LinuxUnderlayCommandRunner
	Now                       func() time.Time
}

// LinuxUnderlayMarkAuthorizer adds only its exact, dedicated mark to the
// existing underlay_marks set. It never creates, flushes, changes, or deletes
// the persistent fail-closed table, chain, rule, or underlay interface member.
type LinuxUnderlayMarkAuthorizer struct {
	config LinuxUnderlayMarkAuthorizerConfig

	mu      sync.Mutex
	entry   *linuxUnderlayAuthorizationEntry
	counter uint64
}

type linuxUnderlayAuthorizationEntry struct {
	expiresAt      time.Time
	leases         map[string]*linuxUnderlayMarkLease
	expiryTimer    *time.Timer
	retryTimer     *time.Timer
	cleanupPending bool
}

type linuxUnderlayMarkLease struct {
	factory *LinuxUnderlayMarkAuthorizer
	id      string
	request UnderlayMarkAuthorizationRequest

	callMu sync.Mutex
	closed atomic.Bool
}

var (
	_ UnderlayMarkAuthorizationLeaser = (*LinuxUnderlayMarkAuthorizer)(nil)
	_ Resource                        = (*linuxUnderlayMarkLease)(nil)
)

func NewLinuxUnderlayMarkAuthorizer(
	config LinuxUnderlayMarkAuthorizerConfig,
) (*LinuxUnderlayMarkAuthorizer, error) {
	if config.NftBinary == "" {
		config.NftBinary = DefaultLinuxUnderlayNftBinary
	}
	if config.IPBinary == "" {
		config.IPBinary = DefaultLinuxUnderlayIPBinary
	}
	if !validAbsoluteCommandPath(config.NftBinary) ||
		!validAbsoluteCommandPath(config.IPBinary) {
		return nil, errors.New(
			"linux underlay nft and ip paths must be absolute",
		)
	}
	if config.NetworkNamespace == "" {
		if !config.AllowRootNetworkNamespace {
			return nil, errors.New(
				"linux underlay root namespace requires explicit authorization",
			)
		}
	} else {
		if config.AllowRootNetworkNamespace ||
			!validNetworkNamespace(config.NetworkNamespace) {
			return nil, errors.New(
				"linux underlay network namespace contract is ambiguous",
			)
		}
	}
	if config.TableFamily != "inet" ||
		!validNftIdentifier(config.TableName) ||
		config.OutputChain != "output" {
		return nil, errors.New(
			"linux underlay nftables table contract is invalid",
		)
	}
	if !validUnderlayInterfaceName(config.UnderlayInterface) ||
		config.DirectAWGUnderlayMark == 0 ||
		config.FirewallMark == 0 ||
		config.FirewallMark == config.DirectAWGUnderlayMark {
		return nil, errors.New(
			"linux underlay interface or dedicated marks are invalid",
		)
	}
	if config.CommandTimeout == 0 {
		config.CommandTimeout = defaultLinuxUnderlayCommandTimeout
	}
	if config.CommandTimeout < 100*time.Millisecond ||
		config.CommandTimeout > 30*time.Second {
		return nil, errors.New(
			"linux underlay command timeout is invalid",
		)
	}
	if config.CleanupRetryInterval == 0 {
		config.CleanupRetryInterval =
			defaultLinuxUnderlayCleanupRetry
	}
	if config.CleanupRetryInterval < 10*time.Millisecond ||
		config.CleanupRetryInterval > time.Minute {
		return nil, errors.New(
			"linux underlay cleanup retry interval is invalid",
		)
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Runner == nil {
		runner, err := newDefaultLinuxUnderlayRunner(
			config.NftBinary, config.IPBinary,
		)
		if err != nil {
			return nil, err
		}
		config.Runner = runner
	}
	return &LinuxUnderlayMarkAuthorizer{config: config}, nil
}

func (factory *LinuxUnderlayMarkAuthorizer) AuthorizeUnderlayMark(
	ctx context.Context,
	request UnderlayMarkAuthorizationRequest,
) (UnderlayMarkAuthorizationLease, error) {
	if factory == nil {
		return UnderlayMarkAuthorizationLease{},
			errors.New("linux underlay authorizer is nil")
	}
	if ctx == nil {
		return UnderlayMarkAuthorizationLease{},
			errors.New("linux underlay authorization context is required")
	}
	now := factory.config.Now().UTC()
	request.ExpiresAt = request.ExpiresAt.UTC()
	if err := validateUnderlayAuthorizationRequest(request, now); err != nil {
		return UnderlayMarkAuthorizationLease{}, err
	}
	if cause := context.Cause(ctx); cause != nil {
		return UnderlayMarkAuthorizationLease{}, cause
	}

	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.entry != nil {
		entry := factory.entry
		if entry.cleanupPending ||
			!entry.expiresAt.After(now) ||
			!entry.expiresAt.Equal(request.ExpiresAt) {
			return UnderlayMarkAuthorizationLease{},
				errors.New(
					"linux underlay authorization is expiring or bound to different trust",
				)
		}
		if err := factory.verifyPersistentPolicy(ctx, true); err != nil {
			return UnderlayMarkAuthorizationLease{}, err
		}
	} else {
		cleanupPending, err := factory.installMark(ctx)
		if cleanupPending {
			factory.entry = &linuxUnderlayAuthorizationEntry{
				expiresAt:      request.ExpiresAt,
				leases:         make(map[string]*linuxUnderlayMarkLease),
				cleanupPending: true,
			}
			factory.scheduleCleanupRetryLocked(factory.entry)
		}
		if err != nil {
			return UnderlayMarkAuthorizationLease{}, err
		}
		factory.entry = &linuxUnderlayAuthorizationEntry{
			expiresAt: request.ExpiresAt,
			leases:    make(map[string]*linuxUnderlayMarkLease),
		}
		entry := factory.entry
		entry.expiryTimer = time.AfterFunc(
			request.ExpiresAt.Sub(now),
			func() { factory.expire(entry) },
		)
	}

	factory.counter++
	authorizationID := fmt.Sprintf(
		"linux-underlay-%016x", factory.counter,
	)
	lease := &linuxUnderlayMarkLease{
		factory: factory,
		id:      authorizationID,
		request: request,
	}
	factory.entry.leases[authorizationID] = lease
	return UnderlayMarkAuthorizationLease{
		CandidateID:      request.CandidateID,
		NodeID:           request.NodeID,
		Carrier:          request.Carrier,
		ManifestDigest:   request.ManifestDigest,
		ManifestSequence: request.ManifestSequence,
		SignedEndpoint:   request.SignedEndpoint,
		AuthorizationID:  authorizationID,
		InterfaceName:    factory.config.UnderlayInterface,
		FirewallMark:     factory.config.FirewallMark,
		ExpiresAt:        request.ExpiresAt,
		Resource:         lease,
	}, nil
}

func (lease *linuxUnderlayMarkLease) Close(ctx context.Context) error {
	if lease == nil || lease.factory == nil || lease.closed.Load() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lease.callMu.Lock()
	defer lease.callMu.Unlock()
	if lease.closed.Load() {
		return nil
	}
	err := lease.factory.release(ctx, lease)
	if err == nil {
		lease.closed.Store(true)
	}
	return err
}

func (factory *LinuxUnderlayMarkAuthorizer) release(
	ctx context.Context,
	lease *linuxUnderlayMarkLease,
) error {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	entry := factory.entry
	if entry == nil {
		lease.closed.Store(true)
		return nil
	}
	current, ok := entry.leases[lease.id]
	if !ok || current != lease {
		lease.closed.Store(true)
		return nil
	}
	if len(entry.leases) > 1 {
		delete(entry.leases, lease.id)
		lease.closed.Store(true)
		return nil
	}
	entry.cleanupPending = true
	if err := factory.removeMark(ctx); err != nil {
		factory.scheduleCleanupRetryLocked(entry)
		return err
	}
	factory.closeEntryLocked(entry)
	return nil
}

func (factory *LinuxUnderlayMarkAuthorizer) expire(
	entry *linuxUnderlayAuthorizationEntry,
) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.entry != entry {
		return
	}
	entry.cleanupPending = true
	ctx, cancel := context.WithTimeout(
		context.Background(), factory.config.CommandTimeout,
	)
	err := factory.removeMark(ctx)
	cancel()
	if err != nil {
		factory.scheduleCleanupRetryLocked(entry)
		return
	}
	factory.closeEntryLocked(entry)
}

func (factory *LinuxUnderlayMarkAuthorizer) retryCleanup(
	entry *linuxUnderlayAuthorizationEntry,
) {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.entry != entry || !entry.cleanupPending {
		return
	}
	entry.retryTimer = nil
	ctx, cancel := context.WithTimeout(
		context.Background(), factory.config.CommandTimeout,
	)
	err := factory.removeMark(ctx)
	cancel()
	if err != nil {
		factory.scheduleCleanupRetryLocked(entry)
		return
	}
	factory.closeEntryLocked(entry)
}

func (factory *LinuxUnderlayMarkAuthorizer) scheduleCleanupRetryLocked(
	entry *linuxUnderlayAuthorizationEntry,
) {
	if entry.retryTimer != nil {
		return
	}
	entry.retryTimer = time.AfterFunc(
		factory.config.CleanupRetryInterval,
		func() { factory.retryCleanup(entry) },
	)
}

func (factory *LinuxUnderlayMarkAuthorizer) closeEntryLocked(
	entry *linuxUnderlayAuthorizationEntry,
) {
	if factory.entry != entry {
		return
	}
	if entry.expiryTimer != nil {
		entry.expiryTimer.Stop()
	}
	if entry.retryTimer != nil {
		entry.retryTimer.Stop()
	}
	for _, lease := range entry.leases {
		lease.closed.Store(true)
	}
	factory.entry = nil
}

func (factory *LinuxUnderlayMarkAuthorizer) installMark(
	ctx context.Context,
) (bool, error) {
	if err := factory.verifyPersistentPolicy(ctx, false); err != nil {
		return false, err
	}
	present, err := factory.markPresent(ctx)
	if err != nil {
		return false, err
	}
	if present {
		return false, errors.New(
			"linux underlay mark already exists with ambiguous ownership",
		)
	}
	_, addErr := factory.runNft(ctx,
		"add", "element",
		factory.config.TableFamily,
		factory.config.TableName,
		"underlay_marks",
		"{", linuxUnderlayMark(factory.config.FirewallMark), "}",
	)
	present, readErr := factory.markPresent(ctx)
	if addErr != nil || readErr != nil || !present {
		rollbackErr := factory.removeMark(ctx)
		return rollbackErr != nil, errors.Join(
			fmt.Errorf(
				"install Linux underlay mark: %w",
				errors.Join(
					addErr,
					readErr,
					boolError(
						!present,
						"installed mark is absent from readback",
					),
				),
			),
			rollbackErr,
		)
	}
	if err := factory.verifyPersistentPolicy(ctx, true); err != nil {
		rollbackErr := factory.removeMark(ctx)
		return rollbackErr != nil, errors.Join(err, rollbackErr)
	}
	return false, nil
}

func (factory *LinuxUnderlayMarkAuthorizer) removeMark(
	ctx context.Context,
) error {
	_, deleteErr := factory.runNft(ctx,
		"delete", "element",
		factory.config.TableFamily,
		factory.config.TableName,
		"underlay_marks",
		"{", linuxUnderlayMark(factory.config.FirewallMark), "}",
	)
	present, readErr := factory.markPresent(ctx)
	if readErr != nil {
		return errors.Join(
			fmt.Errorf("remove Linux underlay mark: %w", deleteErr),
			fmt.Errorf("verify Linux underlay mark removal: %w", readErr),
		)
	}
	if present {
		return errors.Join(
			fmt.Errorf("remove Linux underlay mark: %w", deleteErr),
			errors.New("linux underlay mark remains installed"),
		)
	}
	// A failed delete with an absent readback is safe and idempotently clean.
	return nil
}

func (factory *LinuxUnderlayMarkAuthorizer) verifyPersistentPolicy(
	ctx context.Context,
	requireMark bool,
) error {
	result, err := factory.runNft(ctx,
		"-j", "list", "chain",
		factory.config.TableFamily,
		factory.config.TableName,
		factory.config.OutputChain,
	)
	if err != nil {
		return fmt.Errorf(
			"read persistent Linux fail-closed policy: %w", err,
		)
	}
	if err := validateFailClosedChainJSON(
		result.Stdout,
		factory.config.TableFamily,
		factory.config.TableName,
		factory.config.OutputChain,
	); err != nil {
		return err
	}
	present, err := factory.interfacePresent(ctx)
	if err != nil {
		return err
	}
	if !present {
		return errors.New(
			"persistent Linux underlay interface membership is absent",
		)
	}
	present, err = factory.markValuePresent(
		ctx, factory.config.DirectAWGUnderlayMark,
	)
	if err != nil {
		return err
	}
	if !present {
		return errors.New(
			"persistent Direct AWG underlay mark membership is absent",
		)
	}
	if requireMark {
		present, err := factory.markPresent(ctx)
		if err != nil {
			return err
		}
		if !present {
			return errors.New(
				"authorized Linux underlay mark membership is absent",
			)
		}
	}
	return nil
}

func (factory *LinuxUnderlayMarkAuthorizer) interfacePresent(
	ctx context.Context,
) (bool, error) {
	result, err := factory.runNft(ctx,
		"-j", "list", "set",
		factory.config.TableFamily,
		factory.config.TableName,
		"underlay_ifaces",
	)
	if err != nil {
		return false, fmt.Errorf(
			"read Linux underlay interface set: %w", err,
		)
	}
	return nftSetContains(
		result.Stdout,
		factory.config.TableFamily,
		factory.config.TableName,
		"underlay_ifaces",
		"ifname",
		factory.config.UnderlayInterface,
	)
}

func (factory *LinuxUnderlayMarkAuthorizer) markPresent(
	ctx context.Context,
) (bool, error) {
	return factory.markValuePresent(
		ctx, factory.config.FirewallMark,
	)
}

func (factory *LinuxUnderlayMarkAuthorizer) markValuePresent(
	ctx context.Context,
	mark uint32,
) (bool, error) {
	result, err := factory.runNft(ctx,
		"-j", "list", "set",
		factory.config.TableFamily,
		factory.config.TableName,
		"underlay_marks",
	)
	if err != nil {
		return false, fmt.Errorf(
			"read Linux underlay mark set: %w", err,
		)
	}
	return nftSetContains(
		result.Stdout,
		factory.config.TableFamily,
		factory.config.TableName,
		"underlay_marks",
		"mark",
		mark,
	)
}

func (factory *LinuxUnderlayMarkAuthorizer) runNft(
	ctx context.Context,
	args ...string,
) (LinuxUnderlayCommandResult, error) {
	command := LinuxUnderlayCommand{
		Path: factory.config.NftBinary,
		Args: slicesClone(args),
	}
	if factory.config.NetworkNamespace != "" {
		command.Path = factory.config.IPBinary
		command.Args = append(
			[]string{
				"netns", "exec",
				factory.config.NetworkNamespace,
				factory.config.NftBinary,
			},
			args...,
		)
	}
	if err := validateLinuxUnderlayCommand(command); err != nil {
		return LinuxUnderlayCommandResult{}, err
	}
	commandContext, cancel := context.WithTimeout(
		ctx, factory.config.CommandTimeout,
	)
	defer cancel()
	result, err := factory.config.Runner.Run(commandContext, command)
	if len(result.Stdout) > maxLinuxUnderlayCommandOutput ||
		len(result.Stderr) > maxLinuxUnderlayCommandOutput {
		clear(result.Stdout)
		clear(result.Stderr)
		return LinuxUnderlayCommandResult{},
			errors.New("linux underlay command output exceeds limit")
	}
	return result, err
}

func validateUnderlayAuthorizationRequest(
	request UnderlayMarkAuthorizationRequest,
	now time.Time,
) error {
	if !identifierPattern.MatchString(request.CandidateID) ||
		!identifierPattern.MatchString(request.NodeID) ||
		(request.Carrier != connectivity.CarrierDirectAWG &&
			request.Carrier != connectivity.CarrierHTTP3) ||
		!digestPattern.MatchString(request.ManifestDigest) ||
		request.ManifestSequence == 0 ||
		request.SignedEndpoint == "" ||
		len(request.SignedEndpoint) > maxSignedUnderlayEndpoint ||
		strings.IndexByte(request.SignedEndpoint, 0) >= 0 ||
		!request.ExpiresAt.After(now) {
		return errors.New(
			"linux underlay authorization request is invalid",
		)
	}
	return nil
}

func validateFailClosedChainJSON(
	raw []byte,
	family string,
	table string,
	chain string,
) error {
	document, err := decodeNftJSON(raw)
	if err != nil {
		return fmt.Errorf("decode Linux fail-closed policy: %w", err)
	}
	var chainFound bool
	var bypassFound bool
	for _, item := range document.Nftables {
		if current, ok := item["chain"].(map[string]any); ok &&
			jsonString(current["family"]) == family &&
			jsonString(current["table"]) == table &&
			jsonString(current["name"]) == chain &&
			jsonString(current["type"]) == "filter" &&
			jsonString(current["hook"]) == "output" &&
			jsonInteger(current["prio"]) == -150 &&
			jsonString(current["policy"]) == "drop" {
			chainFound = true
		}
		if current, ok := item["rule"].(map[string]any); ok &&
			jsonString(current["family"]) == family &&
			jsonString(current["table"]) == table &&
			jsonString(current["chain"]) == chain &&
			containsNftMatch(
				current["expr"], "mark", "@underlay_marks",
			) &&
			containsNftMatch(
				current["expr"], "oifname", "@underlay_ifaces",
			) &&
			containsJSONKey(current["expr"], "accept") {
			bypassFound = true
		}
	}
	if !chainFound || !bypassFound {
		return errors.New(
			"persistent Linux policy is not the required fail-closed contract",
		)
	}
	return nil
}

func nftSetContains(
	raw []byte,
	family string,
	table string,
	name string,
	dataType string,
	expected any,
) (bool, error) {
	document, err := decodeNftJSON(raw)
	if err != nil {
		return false, err
	}
	for _, item := range document.Nftables {
		current, ok := item["set"].(map[string]any)
		if !ok ||
			jsonString(current["family"]) != family ||
			jsonString(current["table"]) != table ||
			jsonString(current["name"]) != name ||
			jsonString(current["type"]) != dataType {
			continue
		}
		return containsNftElement(current["elem"], expected), nil
	}
	return false, fmt.Errorf(
		"nftables set %s/%s/%s is absent", family, table, name,
	)
}

type nftJSONDocument struct {
	Nftables []map[string]any `json:"nftables"`
}

func decodeNftJSON(raw []byte) (nftJSONDocument, error) {
	if len(raw) == 0 || len(raw) > maxLinuxUnderlayCommandOutput {
		return nftJSONDocument{},
			errors.New("nftables JSON size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document nftJSONDocument
	if err := decoder.Decode(&document); err != nil {
		return nftJSONDocument{}, err
	}
	if len(document.Nftables) == 0 {
		return nftJSONDocument{}, errors.New("nftables JSON is empty")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return nftJSONDocument{},
			errors.New("nftables JSON has trailing content")
	} else if !errors.Is(err, io.EOF) {
		return nftJSONDocument{}, err
	}
	return document, nil
}

func containsNftMatch(value any, key string, set string) bool {
	switch current := value.(type) {
	case []any:
		for _, item := range current {
			if containsNftMatch(item, key, set) {
				return true
			}
		}
	case map[string]any:
		if match, ok := current["match"].(map[string]any); ok {
			left, _ := match["left"].(map[string]any)
			meta, _ := left["meta"].(map[string]any)
			if jsonString(match["op"]) == "==" &&
				jsonString(meta["key"]) == key &&
				nftSetReference(match["right"]) == set {
				return true
			}
		}
		for _, item := range current {
			if containsNftMatch(item, key, set) {
				return true
			}
		}
	}
	return false
}

func nftSetReference(value any) string {
	if result, ok := value.(string); ok {
		return result
	}
	if current, ok := value.(map[string]any); ok {
		result := jsonString(current["set"])
		if result != "" && result[0] != '@' {
			return "@" + result
		}
		return result
	}
	return ""
}

func containsJSONKey(value any, expected string) bool {
	switch current := value.(type) {
	case []any:
		for _, item := range current {
			if containsJSONKey(item, expected) {
				return true
			}
		}
	case map[string]any:
		if _, ok := current[expected]; ok {
			return true
		}
		for _, item := range current {
			if containsJSONKey(item, expected) {
				return true
			}
		}
	}
	return false
}

func containsNftElement(value any, expected any) bool {
	switch current := value.(type) {
	case []any:
		for _, item := range current {
			if containsNftElement(item, expected) {
				return true
			}
		}
	case map[string]any:
		for _, item := range current {
			if containsNftElement(item, expected) {
				return true
			}
		}
	case string:
		switch wanted := expected.(type) {
		case string:
			return current == wanted
		case uint32:
			base := 10
			raw := current
			if strings.HasPrefix(current, "0x") {
				base = 16
				raw = strings.TrimPrefix(current, "0x")
			}
			parsed, err := strconv.ParseUint(raw, base, 32)
			return err == nil && uint32(parsed) == wanted
		}
	case json.Number:
		if wanted, ok := expected.(uint32); ok {
			parsed, err := strconv.ParseUint(current.String(), 10, 32)
			return err == nil && uint32(parsed) == wanted
		}
	}
	return false
}

func jsonString(value any) string {
	result, _ := value.(string)
	return result
}

func jsonInteger(value any) int64 {
	switch current := value.(type) {
	case json.Number:
		result, err := current.Int64()
		if err == nil {
			return result
		}
	case float64:
		return int64(current)
	}
	return 0
}

func linuxUnderlayMark(value uint32) string {
	return fmt.Sprintf("0x%08x", value)
}

func validAbsoluteCommandPath(value string) bool {
	return filepath.IsAbs(value) &&
		filepath.Clean(value) == value &&
		strings.IndexByte(value, 0) < 0
}

func validNetworkNamespace(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, current := range value {
		if (current < 'a' || current > 'z') &&
			(current < 'A' || current > 'Z') &&
			(current < '0' || current > '9') &&
			current != '_' && current != '-' && current != '.' {
			return false
		}
	}
	return value != "." && value != ".."
}

func validNftIdentifier(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for index, current := range value {
		if (current >= 'a' && current <= 'z') ||
			(current >= 'A' && current <= 'Z') ||
			current == '_' ||
			(index > 0 && current >= '0' && current <= '9') {
			continue
		}
		return false
	}
	return true
}

func validateLinuxUnderlayCommand(command LinuxUnderlayCommand) error {
	if !validAbsoluteCommandPath(command.Path) {
		return errors.New("linux underlay command path is invalid")
	}
	for _, argument := range command.Args {
		if strings.IndexByte(argument, 0) >= 0 {
			return errors.New(
				"linux underlay command argument contains NUL",
			)
		}
	}
	return nil
}

func slicesClone(values []string) []string {
	return append([]string(nil), values...)
}

func boolError(condition bool, message string) error {
	if condition {
		return errors.New(message)
	}
	return nil
}
