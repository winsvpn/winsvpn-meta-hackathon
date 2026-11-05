package directawg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	DefaultLinuxNftBinary        = "/usr/sbin/nft"
	DefaultLinuxResolvectlBinary = "/usr/bin/resolvectl"
	defaultLinuxPolicyHealth     = 2 * time.Second
	maxLinuxNftBatch             = 64 << 10
)

// LinuxNftResolvedPolicyConfig is local privileged configuration. The resolver
// address and nft table name are deployment inputs; remote probe endpoints stay
// in the separately signed Linux verification profile.
type LinuxNftResolvedPolicyConfig struct {
	NftBinary         string
	ResolvectlBinary  string
	TempRoot          string
	TableName         string
	UnderlayInterface string
	UnderlayMark      uint32
	DNSResolver       netip.Addr
	HealthInterval    time.Duration
	Runner            LinuxCommandRunner
}

type linuxNftBatchRunner interface {
	Run(context.Context, string) error
}

type linuxFileNftBatchRunner struct {
	binary   string
	tempRoot string
	runner   LinuxCommandRunner
}

func (runner linuxFileNftBatchRunner) Run(
	ctx context.Context,
	batch string,
) (resultErr error) {
	if ctx == nil {
		return errors.New("nftables batch context is required")
	}
	if len(batch) == 0 || len(batch) > maxLinuxNftBatch {
		return errors.New("nftables batch size is invalid")
	}
	directory, err := os.MkdirTemp(
		runner.tempRoot, "winn-nft-batch-*",
	)
	if err != nil {
		return fmt.Errorf("create nftables batch directory: %w", err)
	}
	// #nosec G302 -- this is a directory; 0700 is the intended private mode.
	if err := os.Chmod(directory, 0o700); err != nil {
		_ = os.RemoveAll(directory)
		return fmt.Errorf("secure nftables batch directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("remove nftables batch directory: %w", err),
			)
		}
	}()
	path := filepath.Join(directory, "transaction.nft")
	// #nosec G304 -- path is code-constructed via filepath.Join inside a
	// freshly created 0700 temporary directory, not derived from untrusted
	// input.
	file, err := os.OpenFile(
		path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600,
	)
	if err != nil {
		return fmt.Errorf("create nftables batch: %w", err)
	}
	_, writeError := file.WriteString(batch)
	syncError := file.Sync()
	closeError := file.Close()
	if err := errors.Join(writeError, syncError, closeError); err != nil {
		return fmt.Errorf("write nftables batch: %w", err)
	}
	_, err = runner.runner.Run(
		ctx,
		LinuxCommand{
			Path: runner.binary,
			Args: []string{"-f", path},
		},
	)
	if err != nil {
		return fmt.Errorf("apply nftables batch: %w", err)
	}
	return nil
}

// LinuxNftResolvedPolicyFactory owns one process-private nftables table. Its
// base chain is a system-wide fail-closed guard. Candidate interfaces and
// privileged underlay marks are admitted through reference-counted nft sets.
// Release is the only operation which intentionally removes the guard.
type LinuxNftResolvedPolicyFactory struct {
	config LinuxNftResolvedPolicyConfig
	batch  linuxNftBatchRunner

	mu                 sync.Mutex
	installed          bool
	released           bool
	active             int
	underlayReferences int
	anchorCounter      uint64
	anchors            map[uint64]*linuxUnderlayPolicyAnchor
}

func NewLinuxNftResolvedPolicyFactory(
	config LinuxNftResolvedPolicyConfig,
) (*LinuxNftResolvedPolicyFactory, error) {
	if config.NftBinary == "" {
		config.NftBinary = DefaultLinuxNftBinary
	}
	if config.ResolvectlBinary == "" {
		config.ResolvectlBinary = DefaultLinuxResolvectlBinary
	}
	for name, path := range map[string]string{
		"nft":        config.NftBinary,
		"resolvectl": config.ResolvectlBinary,
	} {
		if err := validateLinuxExecutable(path); err != nil {
			return nil, fmt.Errorf("%s executable: %w", name, err)
		}
	}
	if config.TempRoot != "" {
		if !filepath.IsAbs(config.TempRoot) {
			return nil, errors.New(
				"linux policy temporary root must be absolute",
			)
		}
		info, err := os.Lstat(config.TempRoot)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect Linux policy temporary root: %w", err,
			)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New(
				"linux policy temporary root must be a real directory",
			)
		}
	}
	if !validNftIdentifier(config.TableName) {
		return nil, errors.New("linux nftables table name is invalid")
	}
	if err := validateLinuxProtectedSocket(
		config.UnderlayInterface, config.UnderlayMark,
	); err != nil {
		return nil, fmt.Errorf("linux policy underlay: %w", err)
	}
	if !config.DNSResolver.IsValid() ||
		config.DNSResolver.IsUnspecified() ||
		config.DNSResolver.IsMulticast() {
		return nil, errors.New("linux policy DNS resolver is invalid")
	}
	if config.HealthInterval == 0 {
		config.HealthInterval = defaultLinuxPolicyHealth
	}
	if config.HealthInterval < 250*time.Millisecond ||
		config.HealthInterval > 30*time.Second {
		return nil, errors.New(
			"linux policy health interval is invalid",
		)
	}
	if config.Runner == nil {
		config.Runner = newExecLinuxRunner()
	}
	return &LinuxNftResolvedPolicyFactory{
		config: config,
		batch: linuxFileNftBatchRunner{
			binary: config.NftBinary, tempRoot: config.TempRoot,
			runner: config.Runner,
		},
	}, nil
}

func (factory *LinuxNftResolvedPolicyFactory) Prepare(
	ctx context.Context,
	spec LinuxPolicySpec,
) (LinuxPolicyTransaction, error) {
	if ctx == nil {
		return nil, errors.New("linux policy prepare context is required")
	}
	if err := spec.Binding.Validate(time.Now().UTC()); err != nil {
		return nil, fmt.Errorf("linux policy binding: %w", err)
	}
	if err := validateLinuxProtectedSocket(
		spec.InterfaceName, spec.FirewallMark,
	); err != nil {
		return nil, err
	}
	if !spec.InnerAddress.IsValid() ||
		spec.InnerAddress.Bits() != spec.InnerAddress.Addr().BitLen() ||
		spec.RouteTable == 0 {
		return nil, errors.New("linux policy candidate identity is invalid")
	}
	if spec.InnerAddress.Addr().Is4() != factory.config.DNSResolver.Is4() {
		return nil, errors.New(
			"linux policy candidate and DNS resolver families differ",
		)
	}

	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.released {
		return nil, errors.New("linux policy factory was released")
	}
	if !factory.installed {
		if err := factory.batch.Run(ctx, factory.installBatch()); err != nil {
			return nil, fmt.Errorf(
				"install fail-closed nftables policy: %w", err,
			)
		}
		factory.installed = true
	}
	addUnderlay := factory.underlayReferences == 0
	if err := factory.batch.Run(
		ctx, factory.admitBatch(spec.InterfaceName, addUnderlay),
	); err != nil {
		return nil, fmt.Errorf(
			"admit Linux AWG candidate into nftables policy: %w", err,
		)
	}
	if err := factory.configureCandidateResolver(ctx, spec.InterfaceName); err != nil {
		rollbackError := factory.batch.Run(
			ctx, factory.removeBatch(spec.InterfaceName, addUnderlay),
		)
		return nil, errors.Join(
			fmt.Errorf("configure candidate resolver: %w", err),
			rollbackError,
		)
	}
	factory.active++
	factory.underlayReferences++
	transaction := &linuxNftResolvedPolicyTransaction{
		factory: factory,
		spec:    spec,
		health:  make(chan error, 1),
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	// #nosec G118 -- monitor must outlive Prepare's short connect-deadline
	// ctx; it is cancelled via the transaction's own stop channel, not ctx.
	go transaction.monitor()
	return transaction, nil
}

// UnderlayMark returns the fixed mark this factory admits into its shared
// nftables underlay-bypass rule.
func (factory *LinuxNftResolvedPolicyFactory) UnderlayMark() uint32 {
	return factory.config.UnderlayMark
}

// Release intentionally removes the system kill switch. It refuses while any
// candidate transaction is live, preventing an unprotected teardown race.
func (factory *LinuxNftResolvedPolicyFactory) Release(
	ctx context.Context,
) error {
	if ctx == nil {
		return errors.New("linux policy release context is required")
	}
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if factory.active != 0 {
		return errors.New(
			"cannot release Linux kill switch with active candidates",
		)
	}
	if len(factory.anchors) != 0 || factory.underlayReferences != 0 {
		return errors.New(
			"cannot release Linux kill switch with active underlay anchors",
		)
	}
	if factory.released {
		return nil
	}
	if factory.installed {
		if err := factory.batch.Run(
			ctx,
			fmt.Sprintf(
				"delete table inet %s\n", factory.config.TableName,
			),
		); err != nil {
			return fmt.Errorf("release Linux nftables policy: %w", err)
		}
	}
	factory.installed = false
	factory.released = true
	return nil
}

func (factory *LinuxNftResolvedPolicyFactory) installBatch() string {
	return fmt.Sprintf(
		"table inet %s {\n"+
			" set tunnel_ifaces { type ifname; }\n"+
			" set underlay_ifaces { type ifname; }\n"+
			" set underlay_marks { type mark; }\n"+
			" chain output {\n"+
			"  type filter hook output priority -150; policy drop;\n"+
			"  oifname \"lo\" accept\n"+
			"  oifname @tunnel_ifaces accept\n"+
			// IPv6 routers must be able to refresh their neighbor-cache
			// entry for the selected physical underlay while the kill
			// switch is engaged. Dropping the kernel's hop-limit-255
			// Neighbor Advertisements makes the host unreachable after
			// the router's current entry ages, even though marked AWG
			// packets are still admitted locally. Limit this exception to
			// link-local/multicast NDP control messages; ordinary ICMPv6
			// and every unmarked application flow remain fail-closed.
			"  oifname @underlay_ifaces meta nfproto ipv6 "+
			"ip6 hoplimit 255 ip6 daddr { fe80::/10, ff02::/16 } "+
			"icmpv6 type { nd-router-solicit, nd-neighbor-solicit, "+
			"nd-neighbor-advert } accept\n"+
			"  meta mark @underlay_marks oifname @underlay_ifaces accept\n"+
			" }\n"+
			"}\n",
		factory.config.TableName,
	)
}

func (factory *LinuxNftResolvedPolicyFactory) admitBatch(
	interfaceName string,
	addUnderlay bool,
) string {
	var builder strings.Builder
	fmt.Fprintf(
		&builder,
		"add element inet %s tunnel_ifaces { \"%s\" }\n",
		factory.config.TableName, interfaceName,
	)
	if addUnderlay {
		builder.WriteString(factory.addUnderlayBatch())
	}
	return builder.String()
}

func (factory *LinuxNftResolvedPolicyFactory) addUnderlayBatch() string {
	return fmt.Sprintf(
		"add element inet %s underlay_ifaces { \"%s\" }\n"+
			"add element inet %s underlay_marks { 0x%x }\n",
		factory.config.TableName,
		factory.config.UnderlayInterface,
		factory.config.TableName,
		factory.config.UnderlayMark,
	)
}

func (factory *LinuxNftResolvedPolicyFactory) removeBatch(
	interfaceName string,
	removeUnderlay bool,
) string {
	var builder strings.Builder
	fmt.Fprintf(
		&builder,
		"delete element inet %s tunnel_ifaces { \"%s\" }\n",
		factory.config.TableName, interfaceName,
	)
	if removeUnderlay {
		builder.WriteString(factory.removeUnderlayBatch())
	}
	return builder.String()
}

func (factory *LinuxNftResolvedPolicyFactory) removeUnderlayBatch() string {
	return fmt.Sprintf(
		"delete element inet %s underlay_marks { 0x%x }\n"+
			"delete element inet %s underlay_ifaces { \"%s\" }\n",
		factory.config.TableName,
		factory.config.UnderlayMark,
		factory.config.TableName,
		factory.config.UnderlayInterface,
	)
}

func (factory *LinuxNftResolvedPolicyFactory) configureCandidateResolver(
	ctx context.Context,
	interfaceName string,
) error {
	commands := [][]string{
		{"dns", interfaceName, factory.config.DNSResolver.String()},
		{"default-route", interfaceName, "false"},
	}
	for _, args := range commands {
		if _, err := factory.config.Runner.Run(
			ctx,
			LinuxCommand{
				Path: factory.config.ResolvectlBinary,
				Args: args,
			},
		); err != nil {
			_, revertError := factory.config.Runner.Run(
				ctx,
				LinuxCommand{
					Path: factory.config.ResolvectlBinary,
					Args: []string{"revert", interfaceName},
				},
			)
			return errors.Join(err, revertError)
		}
	}
	return nil
}

type linuxNftResolvedPolicyTransaction struct {
	factory *LinuxNftResolvedPolicyFactory
	spec    LinuxPolicySpec

	mu                sync.Mutex
	committed         bool
	rolledBack        bool
	killSwitchEngaged bool
	health            chan error
	stop              chan struct{}
	stopped           chan struct{}
	stopOnce          sync.Once
	healthOnce        sync.Once
}

func (transaction *linuxNftResolvedPolicyTransaction) Commit(
	ctx context.Context,
) error {
	if ctx == nil {
		return errors.New("linux policy commit context is required")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.rolledBack {
		return errors.New("linux policy transaction was rolled back")
	}
	if transaction.committed {
		return nil
	}
	factory := transaction.factory
	commands := [][]string{
		{"domain", transaction.spec.InterfaceName, "~."},
		{"default-route", transaction.spec.InterfaceName, "true"},
	}
	for _, args := range commands {
		if _, err := factory.config.Runner.Run(
			ctx,
			LinuxCommand{
				Path: factory.config.ResolvectlBinary,
				Args: args,
			},
		); err != nil {
			return fmt.Errorf("commit protected resolver route: %w", err)
		}
	}
	transaction.committed = true
	return nil
}

func (transaction *linuxNftResolvedPolicyTransaction) Rollback(
	ctx context.Context,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.rolledBack {
		return nil
	}
	transaction.stopOnce.Do(func() { close(transaction.stop) })
	select {
	case <-transaction.stopped:
	case <-ctx.Done():
		return context.Cause(ctx)
	}
	factory := transaction.factory
	factory.mu.Lock()
	defer factory.mu.Unlock()
	if !transaction.killSwitchEngaged {
		removeUnderlay := factory.underlayReferences == 1
		if err := factory.batch.Run(
			ctx,
			factory.removeBatch(
				transaction.spec.InterfaceName, removeUnderlay,
			),
		); err != nil {
			// Fail closed: DNS is not restored unless nft first proves the
			// candidate interface was removed from the allow set.
			return fmt.Errorf("engage linux nftables kill switch: %w", err)
		}
		transaction.killSwitchEngaged = true
	}
	// The kill switch is engaged and stays engaged from here on regardless
	// of what follows. factory.active/underlayReferences are released only
	// once the resolver is actually reverted, so a stuck resolvectl cannot
	// let Release tear down the shared fail-closed table while this
	// candidate's resolver state is still unreverted, and a caller can
	// safely retry just this step without repeating the nft removal.
	_, resolverError := factory.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: factory.config.ResolvectlBinary,
			Args: []string{"revert", transaction.spec.InterfaceName},
		},
	)
	if resolverError != nil {
		status, statusError := factory.config.Runner.Run(
			ctx,
			LinuxCommand{
				Path: factory.config.ResolvectlBinary,
				Args: []string{"status"},
			},
		)
		interfaceMarker := "(" + transaction.spec.InterfaceName + ")"
		if statusError != nil ||
			strings.Contains(string(status.Stdout), interfaceMarker) {
			return fmt.Errorf(
				"restore linux resolver state: %w", resolverError,
			)
		}
		// systemd-resolved drops all per-link DNS state when the kernel link
		// disappears. A failed `revert` is therefore already complete only
		// when an independent global status read proves the exact link name
		// is absent. This keeps rollback retryable without stranding the
		// fail-closed table after an externally recovered link.
	}
	if factory.active > 0 {
		factory.active--
	}
	if factory.underlayReferences > 0 {
		factory.underlayReferences--
	}
	transaction.rolledBack = true
	transaction.healthOnce.Do(func() { close(transaction.health) })
	return nil
}

func (transaction *linuxNftResolvedPolicyTransaction) Health() <-chan error {
	return transaction.health
}

func (transaction *linuxNftResolvedPolicyTransaction) monitor() {
	defer close(transaction.stopped)
	ticker := time.NewTicker(
		transaction.factory.config.HealthInterval,
	)
	defer ticker.Stop()
	for {
		select {
		case <-transaction.stop:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(
				context.Background(),
				transaction.factory.config.HealthInterval,
			)
			err := transaction.checkHealth(ctx)
			cancel()
			if err != nil {
				transaction.healthOnce.Do(func() {
					transaction.health <- err
					close(transaction.health)
				})
				return
			}
		}
	}
}

func (transaction *linuxNftResolvedPolicyTransaction) checkHealth(
	ctx context.Context,
) error {
	factory := transaction.factory
	if _, err := factory.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: factory.config.NftBinary,
			Args: []string{
				"list", "chain", "inet",
				factory.config.TableName, "output",
			},
		},
	); err != nil {
		return fmt.Errorf("linux policy health check failed: %w", err)
	}
	if err := factory.verifySetMembership(
		ctx, "tunnel_ifaces",
		quotedNftElement(transaction.spec.InterfaceName),
	); err != nil {
		return err
	}
	if err := factory.verifySetMembership(
		ctx, "underlay_ifaces",
		quotedNftElement(factory.config.UnderlayInterface),
	); err != nil {
		return err
	}
	if err := factory.verifySetMembership(
		ctx, "underlay_marks",
		linuxPolicyMark(factory.config.UnderlayMark),
	); err != nil {
		return err
	}
	if _, err := factory.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: factory.config.ResolvectlBinary,
			Args: []string{"status", transaction.spec.InterfaceName},
		},
	); err != nil {
		return fmt.Errorf("linux policy health check failed: %w", err)
	}
	return nil
}

// verifySetMembership confirms the candidate's own interface, or the shared
// underlay interface/mark, is actually present in the named nftables set —
// not merely that the base chain still exists.
func (factory *LinuxNftResolvedPolicyFactory) verifySetMembership(
	ctx context.Context,
	setName string,
	element string,
) error {
	result, err := factory.config.Runner.Run(
		ctx,
		LinuxCommand{
			Path: factory.config.NftBinary,
			Args: []string{
				"list", "set", "inet", factory.config.TableName, setName,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("linux policy health check failed: %w", err)
	}
	if !strings.Contains(string(result.Stdout), element) {
		return fmt.Errorf(
			"linux policy health check found %s missing from nftables set %s",
			element, setName,
		)
	}
	return nil
}

func quotedNftElement(value string) string {
	return "\"" + value + "\""
}

func validNftIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 32 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9' && index > 0) ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}

// linuxPolicyMark must match nft's own display width for the "mark" data
// type exactly: `nft list set` always renders a mark as 8 zero-padded hex
// digits regardless of the value's magnitude or how it was written on
// insertion, so an unpadded rendering here would never satisfy the
// substring check in verifySetMembership — confirmed against a real
// nftables instance, where a mark of 0x9978 lists back as 0x00009978.
func linuxPolicyMark(value uint32) string {
	return fmt.Sprintf("0x%08x", value)
}
