package utils

import (
	"os"
	"runtime"
	"strings"
)

const (
	// OS:
	WindowsOS = "windows"
	LinuxOS   = "linux"
	MacOS     = "darwin"
)

func GetOsSpecificDbDir() string {
	return getOsSpecificAppDataDir() + "db" + string(os.PathSeparator)
}

// based on this answer: https://stackoverflow.com/a/68740581
func getOsSpecificAppDataDir() string {
	osType := DetectOsType()
	switch osType {
	case MacOS:
		homeDir := os.Getenv("HOME")
		if homeDir != "" {
			return homeDir + "/Library/Logs/proteus/"
		}
		return ""
	case LinuxOS:
		// from XDG Base Directory Specification: https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome != "" {
			return sanitize(dataHome) + "proteus/"
		}

		homeDir := os.Getenv("HOME")
		if homeDir != "" {
			return sanitize(homeDir) + ".local/share/proteus/"
		}
		return ""
	case WindowsOS:
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			return sanitize(localAppData) + "proteus" + string(os.PathSeparator)
		}

		appData := os.Getenv("APPDATA")
		if appData != "" {
			return sanitize(appData) + "proteus" + string(os.PathSeparator)
		}
		return ""
	default:
		return ""
	}
}

func DetectOsType() string {
	return runtime.GOOS
}

func sanitize(path string) string {
	if strings.HasSuffix(path, string(os.PathSeparator)) {
		return path
	} else {
		return path + string(os.PathSeparator)
	}
}
