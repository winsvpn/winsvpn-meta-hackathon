//go:build !linux

package directawg

import "context"

func (factory *LinuxNftResolvedPolicyFactory) PrepareUnderlayPolicyAnchor(
	context.Context,
	LinuxUnderlayPolicyAnchorSpec,
) (LinuxUnderlayPolicyAnchorLease, error) {
	return LinuxUnderlayPolicyAnchorLease{},
		ErrLinuxPolicyAnchorUnsupported
}
