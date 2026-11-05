//go:build linux

package directawg

func NewLinuxController(
	config LinuxControllerConfig,
) (TunnelController, error) {
	return newLinuxController(config)
}
