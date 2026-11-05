//go:build !linux

package stagebreflector

func systemPrivateInterfaceController() privateInterfaceController {
	return nil
}
