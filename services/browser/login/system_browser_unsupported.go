//go:build !darwin && !linux && !windows

package login

import (
	"fmt"
	"runtime"
)

func SystemBrowserLogin(LoginArgs) error {
	return fmt.Errorf("legacy browser login is not implemented for %s; configure OIDC login instead", runtime.GOOS)
}
