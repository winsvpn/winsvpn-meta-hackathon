//go:build linux

package directawg

import "context"

// PrepareUnderlayPolicyAnchor installs and verifies the shared fail-closed
// policy before a cold H3 candidate opens its first underlay socket.
func (factory *LinuxNftResolvedPolicyFactory) PrepareUnderlayPolicyAnchor(
	ctx context.Context,
	spec LinuxUnderlayPolicyAnchorSpec,
) (LinuxUnderlayPolicyAnchorLease, error) {
	return factory.prepareUnderlayPolicyAnchor(ctx, spec)
}
