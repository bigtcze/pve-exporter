package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// withSeams swaps the self-update seams for the duration of a test.
func withSeams(t *testing.T, apiURL string, exec string) *int {
	t.Helper()
	restarts := 0

	origURL := releaseAPIURL
	origRelease := releaseHTTPClient
	origBinary := binaryHTTPClient
	origExec := executablePath
	origRestart := restartHook
	origCmd := restartCommand
	origLimits := [3]int64{maxReleaseJSONBytes, maxChecksumsBytes, maxBinaryBytes}

	releaseAPIURL = apiURL
	releaseHTTPClient = &http.Client{Timeout: 5 * time.Second}
	binaryHTTPClient = &http.Client{Timeout: 5 * time.Second}
	executablePath = func() (string, error) { return exec, nil }
	restartHook = func() { restarts++ }

	t.Cleanup(func() {
		releaseAPIURL = origURL
		releaseHTTPClient = origRelease
		binaryHTTPClient = origBinary
		executablePath = origExec
		restartHook = origRestart
		restartCommand = origCmd
		maxReleaseJSONBytes, maxChecksumsBytes, maxBinaryBytes = origLimits[0], origLimits[1], origLimits[2]
	})
	return &restarts
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// releaseServer serves a fake GitHub release with the given tag, plus the
// binary and checksums.txt assets for the current platform.
type releaseServer struct {
	t           *testing.T
	tag         string
	binary      []byte
	checksums   *string // nil means checksums.txt is not published
	checksumErr int     // non-zero status for checksums.txt
	binaryErr   int     // non-zero status for the binary asset
	srv         *httptest.Server
}

func newReleaseServer(t *testing.T, tag string, binary []byte, checksums string) *releaseServer {
	t.Helper()
	rs := &releaseServer{t: t, tag: tag, binary: binary, checksums: &checksums}
	mux := http.NewServeMux()
	mux.HandleFunc("/release", func(w http.ResponseWriter, r *http.Request) {
		assets := []map[string]string{
			{"name": getBinaryName(), "browser_download_url": rs.srv.URL + "/binary"},
		}
		if rs.checksums != nil {
			assets = append(assets, map[string]string{
				"name": "checksums.txt", "browser_download_url": rs.srv.URL + "/checksums",
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": rs.tag, "assets": assets})
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		if rs.binaryErr != 0 {
			http.Error(w, "nope", rs.binaryErr)
			return
		}
		_, _ = w.Write(rs.binary)
	})
	mux.HandleFunc("/checksums", func(w http.ResponseWriter, r *http.Request) {
		if rs.checksumErr != 0 {
			http.Error(w, "nope", rs.checksumErr)
			return
		}
		_, _ = w.Write([]byte(*rs.checksums))
	})
	rs.srv = httptest.NewServer(mux)
	t.Cleanup(rs.srv.Close)
	return rs
}

func TestCheckLatestVersion(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		rs := newReleaseServer(t, "v1.2.3", nil, "")
		withSeams(t, rs.srv.URL+"/release", "")
		rel, err := CheckLatestVersion()
		if err != nil {
			t.Fatalf("CheckLatestVersion: %v", err)
		}
		if rel.TagName != "v1.2.3" {
			t.Fatalf("tag = %q, want v1.2.3", rel.TagName)
		}
		if len(rel.Assets) != 2 || rel.Assets[0].Name != getBinaryName() {
			t.Fatalf("assets = %+v", rel.Assets)
		}
	})

	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "rate limited", http.StatusForbidden)
		}))
		t.Cleanup(srv.Close)
		withSeams(t, srv.URL, "")
		_, err := CheckLatestVersion()
		if err == nil || !strings.Contains(err.Error(), "status 403") {
			t.Fatalf("err = %v, want status 403", err)
		}
	})

	t.Run("malformed JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"tag_name": `))
		}))
		t.Cleanup(srv.Close)
		withSeams(t, srv.URL, "")
		_, err := CheckLatestVersion()
		if err == nil || !strings.Contains(err.Error(), "failed to parse") {
			t.Fatalf("err = %v, want parse failure", err)
		}
	})

	t.Run("oversize body rejected", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"tag_name":"` + strings.Repeat("a", 64) + `"}`))
		}))
		t.Cleanup(srv.Close)
		withSeams(t, srv.URL, "")
		maxReleaseJSONBytes = 16
		_, err := CheckLatestVersion()
		if !errors.Is(err, errResponseTooLarge) {
			t.Fatalf("err = %v, want errResponseTooLarge", err)
		}
	})

	t.Run("network failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		withSeams(t, url, "")
		if _, err := CheckLatestVersion(); err == nil || !strings.Contains(err.Error(), "failed to query") {
			t.Fatalf("err = %v, want query failure", err)
		}
	})
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		in                  string
		major, minor, patch int
	}{
		{"v1.2.3", 1, 2, 3},
		{"1.2.3", 1, 2, 3},
		{"v10.0.1", 10, 0, 1},
		{"v1.2", 1, 2, 0},
		{"v3", 3, 0, 0},
		{"dev", 0, 0, 0},
		{"v1.x.3", 1, 0, 3},
		{"", 0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			ma, mi, pa := parseVersion(tt.in)
			if ma != tt.major || mi != tt.minor || pa != tt.patch {
				t.Fatalf("parseVersion(%q) = %d.%d.%d, want %d.%d.%d", tt.in, ma, mi, pa, tt.major, tt.minor, tt.patch)
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		current, latest string
		newer           bool
	}{
		{"dev", "v0.0.1", true},
		{"dev", "v1.0.0", true},
		{"v1.2.3", "v1.2.4", true},
		{"v1.2.3", "v1.3.0", true},
		{"v1.2.3", "v2.0.0", true},
		{"v1.2.3", "v1.2.3", false},
		{"v1.2.3", "v1.2.2", false},
		{"v1.10.0", "v1.9.9", false},
		{"v2.0.0", "v1.99.99", false},
		{"v1.2.3", "malformed", false},
		{"v1.2.3", "", false},
	}
	for _, tt := range tests {
		if got := compareVersions(tt.current, tt.latest); got != tt.newer {
			t.Errorf("compareVersions(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.newer)
		}
	}
}

func TestFindAssetURL(t *testing.T) {
	name := getBinaryName()
	rel := &GitHubRelease{Assets: []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	}{
		{Name: "checksums.txt", BrowserDownloadURL: "https://example/checksums"},
		{Name: name, BrowserDownloadURL: "https://example/bin"},
	}}
	got, err := findAssetURL(rel)
	if err != nil || got != "https://example/bin" {
		t.Fatalf("findAssetURL = %q, %v", got, err)
	}

	rel.Assets = rel.Assets[:1]
	if _, err := findAssetURL(rel); err == nil || !strings.Contains(err.Error(), "no binary found") {
		t.Fatalf("missing asset err = %v", err)
	}
}

func TestGetBinaryNameMatchesPlatform(t *testing.T) {
	want := fmt.Sprintf("pve-exporter-%s-%s", runtime.GOOS, runtime.GOARCH)
	if got := getBinaryName(); got != want {
		t.Fatalf("getBinaryName = %q, want %q", got, want)
	}
}

func releaseWithAssets(names ...string) *GitHubRelease {
	rel := &GitHubRelease{}
	for _, name := range names {
		rel.Assets = append(rel.Assets, struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}{Name: name, BrowserDownloadURL: "https://example/" + name})
	}
	return rel
}

func TestDownloadChecksums(t *testing.T) {
	name := getBinaryName()

	t.Run("parses valid lines and ignores malformed ones", func(t *testing.T) {
		body := fmt.Sprintf("%s  %s\nnot-a-valid-line\n\nabc123  other-file\ntoo many fields here\n", "aaaa", name)
		rs := newReleaseServer(t, "v1.0.0", nil, body)
		withSeams(t, rs.srv.URL+"/release", "")
		rel := releaseWithAssets(name, "checksums.txt")
		rel.Assets[1].BrowserDownloadURL = rs.srv.URL + "/checksums"

		sums, err := downloadChecksums(rel)
		if err != nil {
			t.Fatalf("downloadChecksums: %v", err)
		}
		if sums[name] != "aaaa" || sums["other-file"] != "abc123" || len(sums) != 2 {
			t.Fatalf("checksums = %v", sums)
		}
	})

	t.Run("missing asset", func(t *testing.T) {
		withSeams(t, "", "")
		if _, err := downloadChecksums(releaseWithAssets(name)); err == nil || !strings.Contains(err.Error(), "not found") {
			t.Fatalf("err = %v, want not found", err)
		}
	})

	t.Run("non-200", func(t *testing.T) {
		rs := newReleaseServer(t, "v1.0.0", nil, "")
		rs.checksumErr = http.StatusNotFound
		withSeams(t, rs.srv.URL+"/release", "")
		rel := releaseWithAssets("checksums.txt")
		rel.Assets[0].BrowserDownloadURL = rs.srv.URL + "/checksums"
		if _, err := downloadChecksums(rel); err == nil || !strings.Contains(err.Error(), "status 404") {
			t.Fatalf("err = %v, want status 404", err)
		}
	})

	t.Run("oversize rejected", func(t *testing.T) {
		rs := newReleaseServer(t, "v1.0.0", nil, strings.Repeat("a", 100))
		withSeams(t, rs.srv.URL+"/release", "")
		maxChecksumsBytes = 10
		rel := releaseWithAssets("checksums.txt")
		rel.Assets[0].BrowserDownloadURL = rs.srv.URL + "/checksums"
		if _, err := downloadChecksums(rel); !errors.Is(err, errResponseTooLarge) {
			t.Fatalf("err = %v, want errResponseTooLarge", err)
		}
	})
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	content := []byte("hello binary")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	good := sha256Hex(content)

	if err := verifyChecksum(path, good); err != nil {
		t.Fatalf("match: %v", err)
	}
	if err := verifyChecksum(path, sha256Hex([]byte("other"))); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("mismatch err = %v", err)
	}
	if err := verifyChecksum(filepath.Join(dir, "missing"), good); err == nil || !strings.Contains(err.Error(), "failed to open") {
		t.Fatalf("missing file err = %v", err)
	}
}

func TestDownloadBinary(t *testing.T) {
	payload := []byte("#!/bin/sh\necho fake\n")

	t.Run("ok writes temp file next to executable", func(t *testing.T) {
		rs := newReleaseServer(t, "v1.0.0", payload, "")
		withSeams(t, "", "")
		dir := t.TempDir()
		execPath := filepath.Join(dir, "pve-exporter")

		tmp, err := downloadBinary(rs.srv.URL+"/binary", execPath)
		if err != nil {
			t.Fatalf("downloadBinary: %v", err)
		}
		if filepath.Dir(tmp) != dir {
			t.Fatalf("temp dir = %s, want %s", filepath.Dir(tmp), dir)
		}
		got, _ := os.ReadFile(tmp)
		if string(got) != string(payload) {
			t.Fatalf("downloaded bytes differ")
		}
		info, _ := os.Stat(tmp)
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("mode = %o, want 755", info.Mode().Perm())
		}
	})

	t.Run("non-200 leaves no temp file", func(t *testing.T) {
		rs := newReleaseServer(t, "v1.0.0", payload, "")
		rs.binaryErr = http.StatusBadGateway
		withSeams(t, "", "")
		dir := t.TempDir()
		if _, err := downloadBinary(rs.srv.URL+"/binary", filepath.Join(dir, "pve-exporter")); err == nil || !strings.Contains(err.Error(), "status 502") {
			t.Fatalf("err = %v, want status 502", err)
		}
		assertDirEmpty(t, dir)
	})

	t.Run("oversize removes temp file", func(t *testing.T) {
		rs := newReleaseServer(t, "v1.0.0", []byte(strings.Repeat("x", 64)), "")
		withSeams(t, "", "")
		maxBinaryBytes = 16
		dir := t.TempDir()
		_, err := downloadBinary(rs.srv.URL+"/binary", filepath.Join(dir, "pve-exporter"))
		if !errors.Is(err, errResponseTooLarge) {
			t.Fatalf("err = %v, want errResponseTooLarge", err)
		}
		assertDirEmpty(t, dir)
	})

	t.Run("network failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()
		withSeams(t, "", "")
		if _, err := downloadBinary(url+"/binary", filepath.Join(t.TempDir(), "x")); err == nil || !strings.Contains(err.Error(), "failed to download") {
			t.Fatalf("err = %v", err)
		}
	})
}

func assertDirEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("directory not clean, contains %v", names)
	}
}

func writeScript(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyBinary(t *testing.T) {
	dir := t.TempDir()
	t.Run("version succeeds", func(t *testing.T) {
		p := writeScript(t, dir, "ok", `echo "pve-exporter version=test"`)
		if err := verifyBinary(p); err != nil {
			t.Fatalf("verifyBinary: %v", err)
		}
	})
	t.Run("help fallback succeeds when --version fails", func(t *testing.T) {
		p := writeScript(t, dir, "helponly", `if [ "$1" = "--help" ]; then echo usage; exit 0; fi; exit 2`)
		if err := verifyBinary(p); err != nil {
			t.Fatalf("verifyBinary: %v", err)
		}
	})
	t.Run("non-executable garbage is rejected", func(t *testing.T) {
		p := filepath.Join(dir, "garbage")
		if err := os.WriteFile(p, []byte("not a program"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := verifyBinary(p); err == nil || !strings.Contains(err.Error(), "not a valid executable") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestReplaceExecutable(t *testing.T) {
	t.Run("success swaps content and removes backup", func(t *testing.T) {
		dir := t.TempDir()
		exe := filepath.Join(dir, "pve-exporter")
		tmp := filepath.Join(dir, "pve-exporter-update-1")
		must(t, os.WriteFile(exe, []byte("old"), 0o755))
		must(t, os.WriteFile(tmp, []byte("new"), 0o755))

		if err := replaceExecutable(exe, tmp); err != nil {
			t.Fatalf("replaceExecutable: %v", err)
		}
		got, _ := os.ReadFile(exe)
		if string(got) != "new" {
			t.Fatalf("executable = %q, want new", got)
		}
		if _, err := os.Stat(exe + ".bak"); !os.IsNotExist(err) {
			t.Fatalf("backup should be removed, stat err = %v", err)
		}
		if _, err := os.Stat(tmp); !os.IsNotExist(err) {
			t.Fatalf("temp file should have moved, stat err = %v", err)
		}
	})

	t.Run("install failure restores original", func(t *testing.T) {
		dir := t.TempDir()
		exe := filepath.Join(dir, "pve-exporter")
		must(t, os.WriteFile(exe, []byte("old"), 0o755))
		missingTmp := filepath.Join(dir, "does-not-exist")

		if err := replaceExecutable(exe, missingTmp); err == nil || !strings.Contains(err.Error(), "failed to install") {
			t.Fatalf("err = %v, want install failure", err)
		}
		got, err := os.ReadFile(exe)
		if err != nil || string(got) != "old" {
			t.Fatalf("original not restored: %q, %v", got, err)
		}
	})

	t.Run("backup failure reports error", func(t *testing.T) {
		dir := t.TempDir()
		err := replaceExecutable(filepath.Join(dir, "missing"), filepath.Join(dir, "tmp"))
		if err == nil || !strings.Contains(err.Error(), "failed to backup") {
			t.Fatalf("err = %v, want backup failure", err)
		}
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRestartServiceUsesCommandSeam(t *testing.T) {
	orig := restartCommand
	t.Cleanup(func() { restartCommand = orig })

	calls := 0
	restartCommand = func() error { calls++; return nil }
	restartService()
	restartCommand = func() error { calls++; return errors.New("boom") }
	restartService()
	if calls != 2 {
		t.Fatalf("restart command calls = %d, want 2", calls)
	}
}

func TestGetExecutablePathResolves(t *testing.T) {
	p, err := getExecutablePath()
	if err != nil || p == "" {
		t.Fatalf("getExecutablePath = %q, %v", p, err)
	}
	if !filepath.IsAbs(p) {
		t.Fatalf("path not absolute: %s", p)
	}
}

func TestResolveExecutablePathFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pve-exporter-real")
	must(t, os.WriteFile(target, []byte("bin"), 0o755))
	link := filepath.Join(dir, "pve-exporter")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	got, err := resolveExecutablePath(link)
	if err != nil {
		t.Fatalf("resolveExecutablePath: %v", err)
	}
	wantTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatal(err)
	}
	if got != wantTarget {
		t.Fatalf("resolved %q, want symlink target %q", got, wantTarget)
	}
}

func TestResolveExecutablePathMissingFile(t *testing.T) {
	if _, err := resolveExecutablePath(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected error for missing executable path")
	}
}

// selfUpdateFixture prepares a release server and a temp "executable" that
// must never be replaced by the real test binary.
type selfUpdateFixture struct {
	rs   *releaseServer
	exe  string
	dir  string
	orig []byte
}

func newSelfUpdateFixture(t *testing.T, tag string, payload []byte, checksums string) *selfUpdateFixture {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "pve-exporter")
	orig := []byte("original-binary")
	must(t, os.WriteFile(exe, orig, 0o755))
	rs := newReleaseServer(t, tag, payload, checksums)
	return &selfUpdateFixture{rs: rs, exe: exe, dir: dir, orig: orig}
}

func (f *selfUpdateFixture) assertOriginalUntouched(t *testing.T) {
	t.Helper()
	got, err := os.ReadFile(f.exe)
	if err != nil || string(got) != string(f.orig) {
		t.Fatalf("original executable changed: %q, %v", got, err)
	}
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		if e.Name() != "pve-exporter" {
			t.Fatalf("leftover file after failure: %s", e.Name())
		}
	}
}

func TestSelfUpdateHappyPath(t *testing.T) {
	payload := []byte("#!/bin/sh\necho \"pve-exporter version=v2.0.0\"\n")
	f := newSelfUpdateFixture(t, "v2.0.0", payload, fmt.Sprintf("%s  %s\n", sha256Hex(payload), getBinaryName()))
	restarts := withSeams(t, f.rs.srv.URL+"/release", f.exe)

	if err := SelfUpdate("v1.0.0"); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	got, _ := os.ReadFile(f.exe)
	if string(got) != string(payload) {
		t.Fatalf("executable not replaced with downloaded payload")
	}
	if *restarts != 1 {
		t.Fatalf("restart hook calls = %d, want 1", *restarts)
	}
	entries, _ := os.ReadDir(f.dir)
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}
}

func TestSelfUpdateFailurePaths(t *testing.T) {
	payload := []byte("#!/bin/sh\necho \"pve-exporter version=v2.0.0\"\n")
	good := fmt.Sprintf("%s  %s\n", sha256Hex(payload), getBinaryName())

	tests := []struct {
		name      string
		current   string
		checksums string
		noChecks  bool
		wantErr   string
	}{
		{name: "checksum mismatch", current: "v1.0.0", checksums: fmt.Sprintf("%s  %s\n", sha256Hex([]byte("tampered")), getBinaryName()), wantErr: "checksum verification failed"},
		{name: "missing checksum entry", current: "v1.0.0", checksums: "abc  other-file\n", wantErr: "no checksum found"},
		{name: "missing checksums.txt", current: "v1.0.0", noChecks: true, wantErr: "checksums.txt not found"},
		{name: "already latest", current: "v2.0.0", checksums: good},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSelfUpdateFixture(t, "v2.0.0", payload, tt.checksums)
			if tt.noChecks {
				f.rs.checksums = nil
			}
			restarts := withSeams(t, f.rs.srv.URL+"/release", f.exe)

			err := SelfUpdate(tt.current)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("SelfUpdate: %v", err)
				}
				if *restarts != 0 {
					t.Fatalf("restart called for no-op update")
				}
				f.assertOriginalUntouched(t)
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
			}
			if *restarts != 0 {
				t.Fatalf("restart hook called on failure")
			}
			f.assertOriginalUntouched(t)
		})
	}
}

func TestSelfUpdateNegativePaths(t *testing.T) {
	t.Run("release API failure", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "down", http.StatusServiceUnavailable)
		}))
		t.Cleanup(srv.Close)
		restarts := withSeams(t, srv.URL, filepath.Join(t.TempDir(), "exe"))
		if err := SelfUpdate("v1.0.0"); err == nil || !strings.Contains(err.Error(), "failed to check for updates") {
			t.Fatalf("err = %v", err)
		}
		if *restarts != 0 {
			t.Fatal("restart on failure")
		}
	})

	t.Run("no platform asset", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"tag_name":"v2.0.0","assets":[]}`))
		}))
		t.Cleanup(srv.Close)
		withSeams(t, srv.URL, filepath.Join(t.TempDir(), "exe"))
		if err := SelfUpdate("v1.0.0"); err == nil || !strings.Contains(err.Error(), "no binary found") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("executable path failure", func(t *testing.T) {
		rs := newReleaseServer(t, "v2.0.0", []byte("x"), "")
		restarts := withSeams(t, rs.srv.URL+"/release", "")
		executablePath = func() (string, error) { return "", errors.New("no exe") }
		if err := SelfUpdate("v1.0.0"); err == nil || !strings.Contains(err.Error(), "no exe") {
			t.Fatalf("err = %v", err)
		}
		if *restarts != 0 {
			t.Fatal("restart on failure")
		}
	})

	t.Run("binary download failure", func(t *testing.T) {
		payload := []byte("x")
		f := newSelfUpdateFixture(t, "v2.0.0", payload, fmt.Sprintf("%s  %s\n", sha256Hex(payload), getBinaryName()))
		f.rs.binaryErr = http.StatusInternalServerError
		restarts := withSeams(t, f.rs.srv.URL+"/release", f.exe)
		if err := SelfUpdate("v1.0.0"); err == nil {
			t.Fatal("expected download failure")
		}
		if *restarts != 0 {
			t.Fatal("restart on failure")
		}
		f.assertOriginalUntouched(t)
	})

	t.Run("checksums unavailable removes temp binary", func(t *testing.T) {
		payload := []byte("x")
		f := newSelfUpdateFixture(t, "v2.0.0", payload, "")
		f.rs.checksumErr = http.StatusBadGateway
		withSeams(t, f.rs.srv.URL+"/release", f.exe)
		if err := SelfUpdate("v1.0.0"); err == nil || !strings.Contains(err.Error(), "checksum verification is required") {
			t.Fatalf("err = %v", err)
		}
		f.assertOriginalUntouched(t)
	})

	t.Run("invalid binary rejected before replacement", func(t *testing.T) {
		payload := []byte("not runnable at all")
		f := newSelfUpdateFixture(t, "v2.0.0", payload, fmt.Sprintf("%s  %s\n", sha256Hex(payload), getBinaryName()))
		restarts := withSeams(t, f.rs.srv.URL+"/release", f.exe)
		if err := SelfUpdate("v1.0.0"); err == nil || !strings.Contains(err.Error(), "not a valid executable") {
			t.Fatalf("err = %v", err)
		}
		if *restarts != 0 {
			t.Fatal("restart on failure")
		}
		f.assertOriginalUntouched(t)
	})
}

func TestSelfUpdateRestartOnlyOnSuccess(t *testing.T) {
	payload := []byte("#!/bin/sh\necho ok\n")
	f := newSelfUpdateFixture(t, "v2.0.0", payload, fmt.Sprintf("%s  %s\n", sha256Hex(payload), getBinaryName()))
	restarts := withSeams(t, f.rs.srv.URL+"/release", f.exe)
	if err := SelfUpdate("dev"); err != nil {
		t.Fatalf("SelfUpdate: %v", err)
	}
	if *restarts != 1 {
		t.Fatalf("restart calls = %d, want exactly 1", *restarts)
	}
}
