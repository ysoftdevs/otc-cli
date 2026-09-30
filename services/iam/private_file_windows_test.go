package iam

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func assertPrivateFilePermissions(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateFileDescriptor(descriptor, user.User.Sid); err != nil {
		t.Fatalf("private file ACL: %v", err)
	}
}

func TestPrivateFileWindowsDeniesConcurrentOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	file, err := createPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	other, err := os.Open(path)
	if other != nil {
		other.Close()
		t.Fatal("private response was readable while still being written")
	}
	if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("concurrent open error = %v, want sharing violation", err)
	}
}

func TestPrivateFileWindowsDoesNotInheritEveryoneAccess(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	parent := t.TempDir()
	// OI/CI propagate these grants to child files/directories. This deliberately
	// permissive fixture would expose an ordinary newly created file to Everyone.
	descriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FR;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "credentials.json")
	file, err := createPrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("synthetic credential fixture"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	assertPrivateFilePermissions(t, path)
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "synthetic credential fixture" {
		t.Fatalf("private fixture contents = %q, error = %v", contents, err)
	}
}

func TestPrivateFileWindowsRejectsUnsafeDescriptors(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid := user.User.Sid.String()
	for name, sddl := range map[string]string{
		"unprotected":   "O:" + sid + "D:(A;;FA;;;" + sid + ")",
		"other owner":   "O:WDD:P(A;;FA;;;" + sid + ")",
		"other grantee": "O:" + sid + "D:P(A;;FA;;;WD)",
		"extra grant":   "O:" + sid + "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)",
		"empty DACL":    "O:" + sid + "D:P",
		"null DACL":     "O:" + sid + "D:NO_ACCESS_CONTROL",
		"limited grant": "O:" + sid + "D:P(A;;FR;;;" + sid + ")",
		"inheritable":   "O:" + sid + "D:P(A;OI;FA;;;" + sid + ")",
	} {
		t.Run(name, func(t *testing.T) {
			descriptor, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyPrivateFileDescriptor(descriptor, user.User.Sid); err == nil {
				t.Fatal("unsafe file protection accepted")
			}
		})
	}
}

func TestPrivateFileWindowsRejectsStreamsAndDevices(t *testing.T) {
	base := filepath.Join(t.TempDir(), "existing.json")
	if err := os.WriteFile(base, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{base + ":secret", `\\.\NUL`, `\\?\C:\file`} {
		file, err := createPrivateFile(path)
		if file != nil {
			file.Close()
		}
		if err == nil {
			t.Errorf("unsafe path accepted: %s", path)
		}
	}
	contents, err := os.ReadFile(base)
	if err != nil || string(contents) != "unchanged" {
		t.Fatalf("existing file changed: %q, %v", contents, err)
	}
}
