//go:build windows

package securefile

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func securePrivatePath(path string) error {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errors.New("current Windows owner SID is unavailable")
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)",
	)
	if err != nil {
		return fmt.Errorf("build owner-only DACL: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("build owner-only DACL: missing DACL")
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("apply owner-only protected DACL: %w", err)
	}
	return nil
}

func validatePrivatePath(path string, directory bool) error {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		path16,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return fmt.Errorf("open private path without following reparse points: %w", err)
	}
	defer windows.CloseHandle(handle)
	return validatePrivateHandle(handle)
}

func validateOpenedPrivateFile(file *os.File) error {
	if file == nil {
		return errors.New("private file handle is unavailable")
	}
	return validatePrivateHandle(windows.Handle(file.Fd()))
}

func validatePrivateHandle(handle windows.Handle) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect opened private path: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("private path is a reparse point")
	}
	sd, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read private path security descriptor: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("private path owner is unavailable")
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !owner.Equals(user.User.Sid) {
		return errors.New("private path is not owned by the current user")
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return errors.New("private path has no restrictive DACL")
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("private path DACL is not protected")
	}
	return validateExactPrivateDACL(dacl, owner)
}

func validateExactPrivateDACL(dacl *windows.ACL, owner *windows.SID) error {
	if dacl == nil || owner == nil {
		return errors.New("private path DACL or owner is unavailable")
	}
	expected, err := windows.SecurityDescriptorFromString(
		"D:P(A;;FA;;;" + owner.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)",
	)
	if err != nil {
		return fmt.Errorf("build exact private DACL: %w", err)
	}
	expectedDACL, _, err := expected.DACL()
	if err != nil {
		return fmt.Errorf("read exact private DACL: %w", err)
	}
	actualACEs, err := canonicalDACLACEs(dacl)
	if err != nil {
		return err
	}
	expectedACEs, err := canonicalDACLACEs(expectedDACL)
	if err != nil {
		return fmt.Errorf("canonicalize exact private DACL: %w", err)
	}
	if len(actualACEs) != len(expectedACEs) {
		return errors.New("private path DACL must contain exactly three ACEs")
	}
	counts := make(map[string]int, len(expectedACEs))
	for _, ace := range expectedACEs {
		counts[ace]++
	}
	for _, ace := range actualACEs {
		if counts[ace] == 0 {
			return errors.New("private path DACL contains an unexpected ACE")
		}
		counts[ace]--
	}
	for _, count := range counts {
		if count != 0 {
			return errors.New("private path DACL is missing a required ACE")
		}
	}
	return nil
}

func canonicalDACLACEs(dacl *windows.ACL) ([]string, error) {
	if dacl == nil {
		return nil, errors.New("private path DACL is unavailable")
	}
	descriptor, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, fmt.Errorf("create DACL descriptor: %w", err)
	}
	if err := descriptor.SetDACL(dacl, true, false); err != nil {
		return nil, fmt.Errorf("attach DACL to descriptor: %w", err)
	}
	if err := descriptor.SetControl(
		windows.SE_DACL_PROTECTED,
		windows.SE_DACL_PROTECTED,
	); err != nil {
		return nil, fmt.Errorf("protect DACL descriptor: %w", err)
	}
	sddl := descriptor.String()
	if !strings.HasPrefix(sddl, "D:P") {
		return nil, errors.New("private path DACL cannot be represented canonically")
	}
	remaining := strings.TrimPrefix(sddl, "D:P")
	aces := make([]string, 0, dacl.AceCount)
	for remaining != "" {
		if remaining[0] != '(' {
			return nil, errors.New("private path DACL contains unsupported control flags")
		}
		end := strings.IndexByte(remaining, ')')
		if end < 0 {
			return nil, errors.New("private path DACL contains a malformed ACE")
		}
		aces = append(aces, remaining[:end+1])
		remaining = remaining[end+1:]
	}
	return aces, nil
}
