package iam

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows FILE_ALL_ACCESS: standard required rights, SYNCHRONIZE and all file
// rights. The SDDL FA token resolves to this mask.
const privateFileAccessMask windows.ACCESS_MASK = 0x001f01ff

// createPrivateFile sets the current user's protected DACL atomically with
// creation. Unlike Unix, passing 0600 to os.OpenFile does not restrict Windows
// access. CREATE_NEW forbids replacement and zero sharing prevents concurrent
// opens while a credential response is being written.
func createPrivateFile(path string) (*os.File, error) {
	// Alternate data streams share their containing file's security descriptor.
	// Device namespaces are not ordinary files and may ignore CREATE_NEW.
	clean := filepath.Clean(path)
	if strings.Contains(clean[len(filepath.VolumeName(clean)):], ":") ||
		strings.HasPrefix(clean, `\\.\`) || strings.HasPrefix(clean, `\\?\`) {
		return nil, fmt.Errorf("private IAM output must be an ordinary file, not a stream or device path")
	}
	name, err := windows.UTF16PtrFromString(clean)
	if err != nil {
		return nil, fmt.Errorf("encode private file path: %w", err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("identify private file owner: %w", err)
	}
	sid := user.User.Sid.String()
	// P disables inherited grants; the only ACE gives this user file access.
	descriptor, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;;FA;;;" + sid + ")")
	if err != nil {
		return nil, fmt.Errorf("build private file security descriptor: %w", err)
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL, 0,
		&attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create private file", Path: path, Err: err}
	}
	// Verify through the same handle before writing anything. Filesystems that
	// discard security descriptors must fail closed, leaving only an empty file.
	if err := verifyPrivateFileHandle(handle, user.User.Sid); err != nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("verify private file protection: %w", err)
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("wrap private file handle")
	}
	return file, nil
}

func verifyPrivateFileHandle(handle windows.Handle, user *windows.SID) error {
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return fmt.Errorf("inspect file type: %w", err)
	}
	if kind != windows.FILE_TYPE_DISK {
		return fmt.Errorf("private output is not a disk file")
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read file access control: %w", err)
	}
	return verifyPrivateFileDescriptor(descriptor, user)
}

func verifyPrivateFileDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	owner, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("read file owner: %w", err)
	}
	if owner == nil || !owner.Equals(user) {
		return fmt.Errorf("private file owner differs from the current user")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("read file security control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private file permits inherited access")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("read file DACL: %w", err)
	}
	if dacl == nil || dacl.AceCount != 1 {
		return fmt.Errorf("private file must grant access only to the current user")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return fmt.Errorf("read file access grant: %w", err)
	}
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != privateFileAccessMask {
		return fmt.Errorf("private file has an unexpected access grant")
	}
	// SidStart is the first DWORD of the variable-length SID in ACCESS_ALLOWED_ACE.
	// GetAce returns the complete Windows-validated ACE allocation.
	grantee := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !grantee.Equals(user) {
		return fmt.Errorf("private file grants access to another principal")
	}
	return nil
}
