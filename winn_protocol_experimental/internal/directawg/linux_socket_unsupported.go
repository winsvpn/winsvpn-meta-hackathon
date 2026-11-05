//go:build !linux

package directawg

type linuxUnsupportedSocketSetter struct{}

func (linuxUnsupportedSocketSetter) Set(
	uintptr,
	string,
	uint32,
) error {
	return ErrLinuxControllerUnsupported
}

func linuxPlatformSocketSetter() linuxSocketSetter {
	return linuxUnsupportedSocketSetter{}
}
