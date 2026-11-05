package directawg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

type linuxRouteTransaction struct {
	runner   LinuxCommandRunner
	ipBinary string
	identity linuxCandidateIdentity
	family   string

	mu             sync.Mutex
	verifyRule     bool
	commitRule     bool
	tablePopulated bool
	rolledBack     bool
}

func newLinuxRouteTransaction(
	ctx context.Context,
	runner LinuxCommandRunner,
	ipBinary string,
	identity linuxCandidateIdentity,
	allowed []netip.Prefix,
	cleanupTimeout time.Duration,
) (*linuxRouteTransaction, error) {
	transaction := &linuxRouteTransaction{
		runner:   runner,
		ipBinary: ipBinary,
		identity: identity,
		family:   familyFlag(identity.InnerAddress.Addr()),
	}
	table := strconv.FormatUint(uint64(identity.RouteTable), 10)
	for _, prefix := range allowed {
		transaction.tablePopulated = true
		if _, err := runner.Run(
			ctx,
			LinuxCommand{
				Path: ipBinary,
				Args: []string{
					transaction.family,
					"route", "add", prefix.String(),
					"dev", identity.InterfaceName,
					"src", identity.InnerAddress.Addr().String(),
					"table", table,
				},
			},
		); err != nil {
			cleanupContext, cancel := context.WithTimeout(
				context.Background(), cleanupTimeout,
			)
			rollbackError := transaction.Rollback(cleanupContext)
			cancel()
			return nil, errors.Join(
				fmt.Errorf("prepare Linux AWG route table: %w", err),
				rollbackError,
			)
		}
	}
	transaction.verifyRule = true
	if _, err := runner.Run(
		ctx,
		LinuxCommand{
			Path: ipBinary,
			Args: []string{
				transaction.family,
				"rule", "add",
				"priority", strconv.FormatUint(
					uint64(identity.VerifyPriority), 10,
				),
				"fwmark", fmt.Sprintf("0x%x", identity.FirewallMark),
				"lookup", table,
			},
		},
	); err != nil {
		cleanupContext, cancel := context.WithTimeout(
			context.Background(), cleanupTimeout,
		)
		rollbackError := transaction.Rollback(cleanupContext)
		cancel()
		return nil, errors.Join(
			fmt.Errorf("prepare Linux AWG verification rule: %w", err),
			rollbackError,
		)
	}
	return transaction, nil
}

// Commit activates the prepopulated route table with one policy-rule command.
// This is the route transaction's atomic visibility point.
func (transaction *linuxRouteTransaction) Commit(ctx context.Context) error {
	if ctx == nil {
		return errors.New("linux AWG route commit context is required")
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.rolledBack {
		return errors.New("linux AWG route transaction was rolled back")
	}
	if transaction.commitRule {
		return nil
	}
	_, err := transaction.runner.Run(
		ctx,
		LinuxCommand{
			Path: transaction.ipBinary,
			Args: []string{
				transaction.family,
				"rule", "add",
				"priority", strconv.FormatUint(
					uint64(transaction.identity.CommitPriority), 10,
				),
				"lookup", strconv.FormatUint(
					uint64(transaction.identity.RouteTable), 10,
				),
			},
		},
	)
	if err != nil {
		return fmt.Errorf("commit Linux AWG route rule: %w", err)
	}
	transaction.commitRule = true
	return nil
}

func (transaction *linuxRouteTransaction) Rollback(
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
	var rollbackError error
	table := strconv.FormatUint(
		uint64(transaction.identity.RouteTable), 10,
	)
	if transaction.commitRule {
		_, err := transaction.runner.Run(
			ctx,
			LinuxCommand{
				Path: transaction.ipBinary,
				Args: []string{
					transaction.family,
					"rule", "del",
					"priority", strconv.FormatUint(
						uint64(transaction.identity.CommitPriority), 10,
					),
					"lookup", table,
				},
			},
		)
		rollbackError = errors.Join(rollbackError, err)
		if err == nil {
			transaction.commitRule = false
		}
	}
	if transaction.verifyRule {
		_, err := transaction.runner.Run(
			ctx,
			LinuxCommand{
				Path: transaction.ipBinary,
				Args: []string{
					transaction.family,
					"rule", "del",
					"priority", strconv.FormatUint(
						uint64(transaction.identity.VerifyPriority), 10,
					),
					"fwmark", fmt.Sprintf(
						"0x%x", transaction.identity.FirewallMark,
					),
					"lookup", table,
				},
			},
		)
		rollbackError = errors.Join(rollbackError, err)
		if err == nil {
			transaction.verifyRule = false
		}
	}
	if transaction.tablePopulated {
		_, err := transaction.runner.Run(
			ctx,
			LinuxCommand{
				Path: transaction.ipBinary,
				Args: []string{
					transaction.family,
					"route", "flush", "table", table,
				},
			},
		)
		rollbackError = errors.Join(rollbackError, err)
		if err == nil {
			transaction.tablePopulated = false
		}
	}
	transaction.rolledBack = rollbackError == nil
	return rollbackError
}
