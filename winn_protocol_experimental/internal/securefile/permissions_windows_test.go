//go:build windows

package securefile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsPrivatePathRequiresOwnerProtectedDACLAndNoReparse(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := securePrivatePath(path); err != nil {
		t.Fatal(err)
	}
	if err := validatePrivatePath(path, false); err != nil {
		t.Fatalf("protected owner-only file was rejected: %v", err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err == nil {
		if err := validatePrivatePath(link, false); err == nil {
			t.Fatal("reparse-point secret was accepted")
		}
	}
}

func TestWindowsExactPrivateDACLRejectsMissingDuplicateMaskAndFlags(t *testing.T) {
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := user.User.Sid
	ownerText := owner.String()
	tests := []struct {
		name string
		dacl string
		ok   bool
	}{
		{
			name: "exact",
			dacl: "D:P(A;;FA;;;" + ownerText + ")(A;;FA;;;SY)(A;;FA;;;BA)",
			ok:   true,
		},
		{
			name: "exact-reordered",
			dacl: "D:P(A;;FA;;;BA)(A;;FA;;;" + ownerText + ")(A;;FA;;;SY)",
			ok:   true,
		},
		{
			name: "missing-owner",
			dacl: "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
		},
		{
			name: "duplicate-system",
			dacl: "D:P(A;;FA;;;" + ownerText + ")(A;;FA;;;SY)(A;;FA;;;SY)",
		},
		{
			name: "wrong-mask",
			dacl: "D:P(A;;FR;;;" + ownerText + ")(A;;FA;;;SY)(A;;FA;;;BA)",
		},
		{
			name: "inheritance-flags",
			dacl: "D:P(A;CI;FA;;;" + ownerText + ")(A;;FA;;;SY)(A;;FA;;;BA)",
		},
		{
			name: "deny-ace",
			dacl: "D:P(D;;FA;;;" + ownerText + ")(A;;FA;;;SY)(A;;FA;;;BA)",
		},
		{
			name: "extra-principal",
			dacl: "D:P(A;;FA;;;" + ownerText + ")(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(test.dacl)
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}
			err = validateExactPrivateDACL(dacl, owner)
			if test.ok && err != nil {
				t.Fatalf("exact DACL rejected: %v", err)
			}
			if !test.ok && err == nil {
				t.Fatal("inexact DACL accepted")
			}
		})
	}
}
