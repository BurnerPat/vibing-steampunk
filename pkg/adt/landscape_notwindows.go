//go:build !windows

package adt

import (
	"os"
	"path/filepath"
	"runtime"
)

// findLandscapeFilesFromRegistry is a stub on non-Windows platforms.
// On Linux and macOS, SAP landscape files are found via environment variables
// and well-known default paths, not the Windows registry.
func findLandscapeFilesFromRegistry() []string {
	return nil
}

// sncLibraryScanDirs returns well-known directories where SAP SNC libraries
// are typically installed on Linux and macOS.
func sncLibraryScanDirs() []string {
	dirs := []string{
		"/usr/sap/snc/lib",
		"/usr/local/sap/snc/lib",
		"/opt/sap/snc/lib",
		"/usr/sap/sec",
		"/usr/local/sap/sec",
		"/opt/sap/sec",
	}

	if runtime.GOOS == "darwin" {
		dirs = append(dirs, "/Applications/Secure Login Client.app/Contents/MacOS/lib")
		if homeDir, err := os.UserHomeDir(); err == nil {
			dirs = append(dirs, filepath.Join(homeDir, "Applications", "Secure Login Client.app", "Contents", "MacOS", "lib"))
		}
	}

	return dirs
}
