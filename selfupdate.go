package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	repoOwner  = "bigtcze"
	repoName   = "pve-exporter"
	releaseAPI = "https://api.github.com/repos/" + repoOwner + "/" + repoName + "/releases/latest"
)

// GitHubRelease represents the GitHub release API response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// CheckLatestVersion queries GitHub API for the latest release
func CheckLatestVersion() (*GitHubRelease, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(releaseAPI)
	if err != nil {
		return nil, fmt.Errorf("failed to query GitHub API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub response: %w", err)
	}

	return &release, nil
}

// getBinaryName returns the expected binary name for the current platform
func getBinaryName() string {
	return fmt.Sprintf("pve-exporter-%s-%s", runtime.GOOS, runtime.GOARCH)
}

// parseVersion parses a version string into major, minor, patch integers
func parseVersion(version string) (major, minor, patch int) {
	version = strings.TrimPrefix(version, "v")
	parts := strings.Split(version, ".")
	if len(parts) >= 1 {
		if _, err := fmt.Sscanf(parts[0], "%d", &major); err != nil {
			major = 0
		}
	}
	if len(parts) >= 2 {
		if _, err := fmt.Sscanf(parts[1], "%d", &minor); err != nil {
			minor = 0
		}
	}
	if len(parts) >= 3 {
		if _, err := fmt.Sscanf(parts[2], "%d", &patch); err != nil {
			patch = 0
		}
	}
	return
}

// compareVersions returns true if newVersion is newer than currentVersion
// Versions are expected in format "v1.2.3"
func compareVersions(currentVersion, newVersion string) bool {
	// Dev version is always considered older
	if currentVersion == "dev" {
		return true
	}

	curMajor, curMinor, curPatch := parseVersion(currentVersion)
	newMajor, newMinor, newPatch := parseVersion(newVersion)

	if newMajor != curMajor {
		return newMajor > curMajor
	}
	if newMinor != curMinor {
		return newMinor > curMinor
	}
	return newPatch > curPatch
}

// findAssetURL finds the download URL for the current platform
func findAssetURL(release *GitHubRelease) (string, error) {
	binaryName := getBinaryName()
	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			return asset.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no binary found for platform %s/%s", runtime.GOOS, runtime.GOARCH)
}

// getExecutablePath returns the resolved path of the current executable
func getExecutablePath() (string, error) {
	execPath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve executable path: %w", err)
	}
	return execPath, nil
}

// downloadBinary downloads a binary from URL to a temp file
func downloadBinary(downloadURL, execPath string) (string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(downloadURL)
	if err != nil {
		return "", fmt.Errorf("failed to download binary: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp(filepath.Dir(execPath), "pve-exporter-update-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	_, err = io.Copy(tmpFile, resp.Body)
	_ = tmpFile.Close()
	if err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed to write binary: %w", err)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("failed to chmod binary: %w", err)
	}

	return tmpPath, nil
}

// verifyBinary checks if the downloaded binary is valid and executable
func verifyBinary(tmpPath string) error {
	cmd := exec.Command(tmpPath, "--version")
	output, err := cmd.CombinedOutput()
	if err == nil {
		fmt.Printf("New binary verified: %s", string(output))
		return nil
	}

	// Try with --help as fallback
	cmd = exec.Command(tmpPath, "--help")
	output, err = cmd.CombinedOutput()
	if err == nil {
		fmt.Printf("New binary verified: %s", string(output))
		return nil
	}

	// Check if file is executable using 'file' command
	cmd = exec.Command("file", tmpPath)
	fileOutput, _ := cmd.Output()
	if strings.Contains(string(fileOutput), "executable") {
		fmt.Println("New binary verified.")
		return nil
	}

	return fmt.Errorf("downloaded file is not a valid executable")
}

// replaceExecutable replaces the current executable with the new one
func replaceExecutable(execPath, tmpPath string) error {
	backupPath := execPath + ".bak"
	if err := os.Rename(execPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		if restoreErr := os.Rename(backupPath, execPath); restoreErr != nil {
			fmt.Printf("CRITICAL: Failed to restore backup: %v\n", restoreErr)
		}
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	_ = os.Remove(backupPath)
	return nil
}

// restartService attempts to restart the pve-exporter systemd service
func restartService() {
	fmt.Println("Restarting service...")
	cmd := exec.Command("systemctl", "restart", "pve-exporter")
	if err := cmd.Run(); err != nil {
		fmt.Printf("Warning: Failed to restart service: %v\n", err)
		fmt.Println("Please restart manually: systemctl restart pve-exporter")
		return
	}
	fmt.Println("Service restarted successfully!")
}

// downloadChecksums downloads and parses the checksums.txt file from a release
func downloadChecksums(release *GitHubRelease) (map[string]string, error) {
	var checksumURL string
	for _, asset := range release.Assets {
		if asset.Name == "checksums.txt" {
			checksumURL = asset.BrowserDownloadURL
			break
		}
	}
	if checksumURL == "" {
		return nil, fmt.Errorf("checksums.txt not found in release assets")
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(checksumURL)
	if err != nil {
		return nil, fmt.Errorf("failed to download checksums: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("checksums download failed with status %d", resp.StatusCode)
	}

	checksums := make(map[string]string)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			checksums[parts[1]] = parts[0] // filename -> hash
		}
	}
	return checksums, scanner.Err()
}

// verifyChecksum verifies the SHA256 checksum of a file
func verifyChecksum(filePath, expectedHash string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for checksum: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("failed to compute checksum: %w", err)
	}

	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != expectedHash {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedHash, actualHash)
	}
	return nil
}

// SelfUpdate performs the self-update process
func SelfUpdate(currentVersion string) error {
	fmt.Println("Checking for updates...")

	release, err := CheckLatestVersion()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	fmt.Printf("Current version: %s\n", currentVersion)
	fmt.Printf("Latest version:  %s\n", release.TagName)

	if !compareVersions(currentVersion, release.TagName) {
		fmt.Println("Already running the latest version!")
		return nil
	}

	downloadURL, err := findAssetURL(release)
	if err != nil {
		return err
	}

	fmt.Printf("Downloading %s...\n", getBinaryName())

	execPath, err := getExecutablePath()
	if err != nil {
		return err
	}

	tmpPath, err := downloadBinary(downloadURL, execPath)
	if err != nil {
		return err
	}

	checksums, err := downloadChecksums(release)
	if err != nil {
		fmt.Printf("Warning: Could not verify checksum: %v\n", err)
		fmt.Println("Proceeding without checksum verification...")
	} else {
		binaryName := getBinaryName()
		expectedHash, ok := checksums[binaryName]
		if !ok {
			fmt.Printf("Warning: No checksum found for %s\n", binaryName)
		} else if err := verifyChecksum(tmpPath, expectedHash); err != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("checksum verification failed: %w", err)
		} else {
			fmt.Println("Checksum verified successfully!")
		}
	}

	if err := verifyBinary(tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	if err := replaceExecutable(execPath, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	fmt.Println("Update successful!")
	restartService()
	return nil
}
