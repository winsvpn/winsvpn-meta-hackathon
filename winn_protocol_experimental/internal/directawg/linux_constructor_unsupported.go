//go:build !linux

package directawg

func NewLinuxController(
	_ LinuxControllerConfig,
) (TunnelController, error) {
	return nil, ErrLinuxControllerUnsupported
}
