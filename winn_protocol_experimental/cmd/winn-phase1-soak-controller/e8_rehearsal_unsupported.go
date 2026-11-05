//go:build !linux && winn_incomplete_e8

package main

import (
	"context"
	"errors"
)

func runLocalFourNode(
	context.Context, e5FourNodePlan, e6VerificationReceipt,
	e7VerificationReceipt, e8GrantResult,
	string, string, string, string, [4]string, *e8PreparedWorkerSet,
) ([4]e8NodeEvidence, error) {
	return [4]e8NodeEvidence{}, errors.New("E8 local rehearsal is Linux-only")
}

type e8PreparedWorkerSet struct{}

func prepareLocalFourNode(
	context.Context, string, string,
) (*e8PreparedWorkerSet, error) {
	return nil, errors.New("E8 retained workers require Linux")
}

func (*e8PreparedWorkerSet) Close() error { return nil }

func publishE8Receipt(*secureDirectory, []byte, e8Receipt) error {
	return errors.New("E8 local rehearsal publication is Linux-only")
}

type e8Transaction struct{}

const e8TransactionPrefix = ".local-rehearsal-consumption."

func openE8Transaction(
	string, e8GrantResult, *secureDirectory,
) (*e8Transaction, error) {
	return nil, errors.New("E8 local rehearsal transaction is Linux-only")
}

func (*e8Transaction) Close() error                { return nil }
func (*e8Transaction) phase() string               { return "" }
func (*e8Transaction) recordE3(string) error       { return nil }
func (*e8Transaction) recordChildren(string) error { return nil }
func (*e8Transaction) commit(string, string) error { return nil }
func (*e8Transaction) persistChildrenEvidence(
	e5FourNodePlan, string, string, [4]e8NodeEvidence,
) error {
	return errors.New("E8 retained children evidence requires Linux")
}
func (*e8Transaction) recoverChildrenEvidence(
	e5FourNodePlan, string, string,
) ([4]e8NodeEvidence, error) {
	return [4]e8NodeEvidence{},
		errors.New("E8 retained children evidence requires Linux")
}

func recoverOrRunE8E3(
	context.Context, AdmittedConfig, e5FourNodePlan,
) (admittedSummary, error) {
	return admittedSummary{}, errors.New("E8 local rehearsal transaction is Linux-only")
}

func recoverPublishedE8Receipt(
	*secureDirectory, *e8Transaction, e5FourNodePlan,
	e6VerificationReceipt, e7VerificationReceipt,
	string, string, string, *e8SupervisorIdentity,
) (e8Summary, bool, error) {
	return e8Summary{}, false,
		errors.New("E8 local rehearsal transaction is Linux-only")
}
