//go:build linux

package login

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var defaultBrowserDesktopIDFunc = defaultBrowserDesktopID

func SystemBrowserLogin(loginArgs LoginArgs) error {
	browserName, err := defaultBrowserExecutable()
	if err != nil {
		return err
	}
	if err := validateControlledBrowser(browserName); err != nil {
		return fmt.Errorf("default browser %q is not supported for legacy automated credential extraction; configure OIDC login or set a Chrome/Chromium-compatible default browser", browserName)
	}

	browserPath, err := exec.LookPath(browserName)
	if err != nil {
		return fmt.Errorf("default browser executable %q was not found in PATH; install it, set another default browser, or configure OIDC login: %w", browserName, err)
	}

	loginArgs.Browser = browserName
	loginArgs.browserPath = browserPath
	return ManagedBrowserLogin(loginArgs)
}

func defaultBrowserExecutable() (string, error) {
	desktopID, err := defaultBrowserDesktopIDFunc()
	if err != nil {
		return "", err
	}

	executable, err := desktopExecutable(desktopID)
	if err != nil {
		return "", err
	}
	return executable, nil
}

func defaultBrowserDesktopID() (string, error) {
	output, err := exec.Command("xdg-settings", "get", "default-web-browser").Output()
	if err != nil {
		return "", fmt.Errorf("failed to detect default browser with xdg-settings: %w", err)
	}

	desktopID := strings.TrimSpace(string(output))
	if desktopID == "" {
		return "", fmt.Errorf("default browser is not configured; set it with xdg-settings or configure OIDC login")
	}

	return desktopID, nil
}

func desktopExecutable(desktopID string) (string, error) {
	desktopPath, err := findDesktopFile(desktopID)
	if err != nil {
		return "", err
	}

	file, err := os.Open(desktopPath)
	if err != nil {
		return "", fmt.Errorf("failed to open desktop entry %q: %w", desktopPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "Exec=") {
			continue
		}
		executable := parseDesktopExec(strings.TrimPrefix(line, "Exec="))
		if executable == "" {
			return "", fmt.Errorf("desktop entry %q has an empty Exec command", desktopPath)
		}
		return filepath.Base(executable), nil
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read desktop entry %q: %w", desktopPath, err)
	}

	return "", fmt.Errorf("desktop entry %q does not contain an Exec command", desktopPath)
}

func findDesktopFile(desktopID string) (string, error) {
	var dirs []string
	if dataHome := os.Getenv("XDG_DATA_HOME"); dataHome != "" {
		dirs = append(dirs, filepath.Join(dataHome, "applications"))
	} else if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".local", "share", "applications"))
	}

	dataDirs := os.Getenv("XDG_DATA_DIRS")
	if dataDirs == "" {
		dataDirs = "/usr/local/share:/usr/share"
	}
	for _, dir := range filepath.SplitList(dataDirs) {
		dirs = append(dirs, filepath.Join(dir, "applications"))
	}

	for _, dir := range dirs {
		desktopPath := filepath.Join(dir, desktopID)
		if _, err := os.Stat(desktopPath); err == nil {
			return desktopPath, nil
		}
	}

	return "", fmt.Errorf("desktop entry %q was not found in XDG application directories", desktopID)
}

func parseDesktopExec(execLine string) string {
	fields := strings.Fields(execLine)
	for _, field := range fields {
		if strings.HasPrefix(field, "%") {
			continue
		}
		return strings.Trim(field, `"`)
	}
	return ""
}
