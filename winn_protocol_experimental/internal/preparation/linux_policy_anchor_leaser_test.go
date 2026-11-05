package preparation

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"winsvpn.local/winnprotocol/internal/connectivity"
	"winsvpn.local/winnprotocol/internal/directawg"
)

func TestLinuxPolicyAnchorLeaserMapsVerifiedRequestAndOwnsResource(
	t *testing.T,
) {
	now := productionNow()
	factory := &fakeLinuxPolicyAnchorFactory{}
	leaser := newTestLinuxPolicyAnchorLeaser(t, factory, now)
	request := testPolicyAnchorRequest(now.Add(time.Minute))
	lease, err := leaser.AcquireUnderlayPolicyAnchor(
		context.Background(), request,
	)
	if err != nil {
		t.Fatal(err)
	}
	specs := factory.snapshot()
	if len(specs) != 1 {
		t.Fatalf("policy anchor specs = %d; want 1", len(specs))
	}
	expected := directawg.LinuxUnderlayPolicyAnchorSpec{
		TableFamily:           "inet",
		TableName:             "winn_lock",
		OutputChain:           "output",
		UnderlayInterface:     "eth0",
		DirectAWGUnderlayMark: 0x9001,
		ExpiresAt:             request.ExpiresAt,
	}
	if specs[0] != expected ||
		lease.CandidateID != request.CandidateID ||
		lease.NodeID != request.NodeID ||
		lease.ManifestDigest != request.ManifestDigest ||
		lease.ManifestSequence != request.ManifestSequence ||
		lease.SignedEndpoint != request.SignedEndpoint ||
		!identifierPattern.MatchString(lease.AnchorID) {
		t.Fatalf("policy anchor mapping changed: %#v %#v", specs, lease)
	}
	if err := lease.Resource.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if factory.closed.Load() != 1 {
		t.Fatalf("policy anchor closes = %d; want 1", factory.closed.Load())
	}
}

func TestLinuxPolicyAnchorLeaserRejectsInvalidAndMismatchedContracts(
	t *testing.T,
) {
	now := productionNow()
	t.Run("invalid verified request", func(t *testing.T) {
		factory := &fakeLinuxPolicyAnchorFactory{}
		leaser := newTestLinuxPolicyAnchorLeaser(t, factory, now)
		request := testPolicyAnchorRequest(now.Add(time.Minute))
		request.ManifestDigest = "not-a-digest"
		if _, err := leaser.AcquireUnderlayPolicyAnchor(
			context.Background(), request,
		); err == nil {
			t.Fatal("invalid policy anchor request was accepted")
		}
		if len(factory.snapshot()) != 0 {
			t.Fatal("invalid request reached Linux policy factory")
		}
	})
	t.Run("factory result mismatch is closed", func(t *testing.T) {
		factory := &fakeLinuxPolicyAnchorFactory{
			mutate: func(lease *directawg.LinuxUnderlayPolicyAnchorLease) {
				lease.DirectAWGUnderlayMark = 0x9002
			},
		}
		leaser := newTestLinuxPolicyAnchorLeaser(t, factory, now)
		if _, err := leaser.AcquireUnderlayPolicyAnchor(
			context.Background(),
			testPolicyAnchorRequest(now.Add(time.Minute)),
		); err == nil {
			t.Fatal("mismatched Linux policy anchor was accepted")
		}
		if factory.closed.Load() != 1 {
			t.Fatalf(
				"mismatched policy anchor closes = %d; want 1",
				factory.closed.Load(),
			)
		}
	})
}

func TestLinuxPolicyAnchorLeaserConcurrentIDsAreUnique(t *testing.T) {
	now := productionNow()
	factory := &fakeLinuxPolicyAnchorFactory{}
	leaser := newTestLinuxPolicyAnchorLeaser(t, factory, now)
	const workers = 64
	ids := make(chan string, workers)
	failures := make(chan error, workers)
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			lease, err := leaser.AcquireUnderlayPolicyAnchor(
				context.Background(),
				testPolicyAnchorRequest(now.Add(time.Minute)),
			)
			if err != nil {
				failures <- err
				return
			}
			ids <- lease.AnchorID
			if err := lease.Resource.Close(context.Background()); err != nil {
				failures <- err
			}
		}()
	}
	group.Wait()
	close(ids)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	unique := make(map[string]struct{}, workers)
	for id := range ids {
		unique[id] = struct{}{}
	}
	if len(unique) != workers || factory.closed.Load() != workers {
		t.Fatalf(
			"unique IDs=%d closes=%d; want %d",
			len(unique), factory.closed.Load(), workers,
		)
	}
}

func newTestLinuxPolicyAnchorLeaser(
	t testing.TB,
	factory LinuxUnderlayPolicyAnchorFactory,
	now time.Time,
) *LinuxUnderlayPolicyAnchorLeaser {
	t.Helper()
	leaser, err := NewLinuxUnderlayPolicyAnchorLeaser(
		LinuxUnderlayPolicyAnchorLeaserConfig{
			Factory:               factory,
			TableName:             "winn_lock",
			UnderlayInterface:     "eth0",
			DirectAWGUnderlayMark: 0x9001,
			Now:                   func() time.Time { return now },
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return leaser
}

func testPolicyAnchorRequest(expiresAt time.Time) UnderlayPolicyAnchorRequest {
	return UnderlayPolicyAnchorRequest{
		CandidateID:      "h3-primary",
		NodeID:           "gateway-production",
		Carrier:          connectivity.CarrierHTTP3,
		ManifestDigest:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ManifestSequence: 7,
		SignedEndpoint:   "https://192.0.2.20:4433/winn",
		ExpiresAt:        expiresAt.UTC(),
	}
}

type fakeLinuxPolicyAnchorFactory struct {
	mu     sync.Mutex
	specs  []directawg.LinuxUnderlayPolicyAnchorSpec
	mutate func(*directawg.LinuxUnderlayPolicyAnchorLease)
	err    error
	closed atomic.Int64
}

func (factory *fakeLinuxPolicyAnchorFactory) PrepareUnderlayPolicyAnchor(
	_ context.Context,
	spec directawg.LinuxUnderlayPolicyAnchorSpec,
) (directawg.LinuxUnderlayPolicyAnchorLease, error) {
	factory.mu.Lock()
	factory.specs = append(factory.specs, spec)
	factory.mu.Unlock()
	if factory.err != nil {
		return directawg.LinuxUnderlayPolicyAnchorLease{}, factory.err
	}
	lease := directawg.LinuxUnderlayPolicyAnchorLease{
		TableFamily:           spec.TableFamily,
		TableName:             spec.TableName,
		OutputChain:           spec.OutputChain,
		UnderlayInterface:     spec.UnderlayInterface,
		DirectAWGUnderlayMark: spec.DirectAWGUnderlayMark,
		ExpiresAt:             spec.ExpiresAt,
		Resource: &policyAnchorTestResource{
			closed: &factory.closed,
		},
	}
	if factory.mutate != nil {
		factory.mutate(&lease)
	}
	return lease, nil
}

func (factory *fakeLinuxPolicyAnchorFactory) snapshot() []directawg.LinuxUnderlayPolicyAnchorSpec {
	factory.mu.Lock()
	defer factory.mu.Unlock()
	return slices.Clone(factory.specs)
}

type policyAnchorTestResource struct {
	once   sync.Once
	closed *atomic.Int64
}

func (resource *policyAnchorTestResource) Close(context.Context) error {
	if resource == nil || resource.closed == nil {
		return errors.New("policy anchor test resource is invalid")
	}
	resource.once.Do(func() {
		resource.closed.Add(1)
	})
	return nil
}

var (
	_ LinuxUnderlayPolicyAnchorFactory            = (*fakeLinuxPolicyAnchorFactory)(nil)
	_ directawg.LinuxUnderlayPolicyAnchorResource = (*policyAnchorTestResource)(nil)
)
