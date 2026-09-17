//go:build unix

package iam

import "os"

// createPrivateFile reserves a new file before a mutation can return secrets.
// O_EXCL also rejects existing symlinks; permissions are restricted at creation.
func createPrivateFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}
