//go:build !linux

package h3candidate

func NewLinuxProtectedUnderlayFactory(
	_ LinuxProtectedUnderlayConfig,
) (ProtectedUnderlayFactory, error) {
	return nil, ErrLinuxAdaptersUnsupported
}
