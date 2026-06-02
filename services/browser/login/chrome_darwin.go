package login

import "os"

var macOSChromePaths = []string{
	"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	"/Applications/Chromium.app/Contents/MacOS/Chromium",
	"/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
	"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
}

func findChromePath() string {
	for _, p := range macOSChromePaths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
