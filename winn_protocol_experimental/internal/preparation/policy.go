package preparation

import (
	"errors"

	"winsvpn.local/winnprotocol/internal/connectivity"
)

const Phase1MinimumUnusedCredentials = 8

// Phase1AutoPolicy encodes the minimum production-shaped preparation floor for
// the Phase-1 Auto gate: Direct AWG, HTTP/3, a warm HTTP/3 carrier, and eight
// unused credentials. Passing this policy does not prove that an implementation
// behind CandidatePreparer is a live production carrier.
func Phase1AutoPolicy(request Request) error {
	if request.Mode != connectivity.ModeAuto {
		return errors.New("Phase-1 preparation requires Auto mode")
	}
	if request.MinimumUnusedCredentials < Phase1MinimumUnusedCredentials ||
		request.UnusedCredentials < Phase1MinimumUnusedCredentials {
		return errors.New(
			"Phase-1 preparation requires eight unused credentials",
		)
	}
	if !containsCarrier(
		request.RequiredCarriers, connectivity.CarrierDirectAWG,
	) {
		return errors.New("Phase-1 preparation requires Direct AWG")
	}
	if !containsCarrier(
		request.RequiredCarriers, connectivity.CarrierHTTP3,
	) {
		return errors.New("Phase-1 preparation requires HTTP/3")
	}
	if !containsCarrier(
		request.RequiredWarmCarriers, connectivity.CarrierHTTP3,
	) {
		return errors.New("Phase-1 preparation requires warm HTTP/3")
	}
	return nil
}

// NewPhase1AutoManager installs Phase1AutoPolicy in addition to any
// caller-supplied policy.
func NewPhase1AutoManager(config Config) (*Manager, error) {
	additional := config.Policy
	config.Policy = func(request Request) error {
		if err := Phase1AutoPolicy(request); err != nil {
			return err
		}
		if additional != nil {
			return additional(request)
		}
		return nil
	}
	return NewManager(config)
}

func containsCarrier(
	carriers []connectivity.Carrier,
	expected connectivity.Carrier,
) bool {
	for _, carrier := range carriers {
		if carrier == expected {
			return true
		}
	}
	return false
}
