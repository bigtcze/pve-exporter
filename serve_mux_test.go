package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeMuxEndpoints(t *testing.T) {
	reg := newTestRegistry(t)
	mux := newServeMux("/metrics", reg)

	get := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	t.Run("health", func(t *testing.T) {
		rec := get("/health")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if body := rec.Body.String(); body != "OK\n" {
			t.Fatalf("body = %q, want %q", body, "OK\n")
		}
	})

	t.Run("root links to configured metrics path", func(t *testing.T) {
		rec := get("/")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "text/html" {
			t.Fatalf("content-type = %q", ct)
		}
		body := rec.Body.String()
		for _, want := range []string{
			"<h1>Proxmox Exporter</h1>",
			`<a href="/metrics">Metrics</a>`,
			`<a href="/health">Health</a>`,
			"Version: " + version,
			"Commit: " + commit,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("root page missing %q", want)
			}
		}
	})

	t.Run("metrics serves registry in text format", func(t *testing.T) {
		rec := get("/metrics")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		body := rec.Body.String()
		for _, want := range []string{
			"# HELP pve_node_up Node is up and reachable",
			`pve_node_up{node="pve1"} 1`,
			`pve_disk_read_bytes_total{device="sda",node="pve1"} 12345`,
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("metrics output missing %q\n%s", want, body)
			}
		}
	})

	t.Run("custom metrics path is honoured", func(t *testing.T) {
		custom := newServeMux("/custom-metrics", reg)
		rec := httptest.NewRecorder()
		custom.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/custom-metrics", nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "pve_node_up") {
			t.Fatalf("custom path status=%d", rec.Code)
		}
		rec = httptest.NewRecorder()
		custom.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		if strings.Contains(rec.Body.String(), "pve_node_up") {
			t.Fatal("default /metrics must not serve metrics when a custom path is configured")
		}
	})
}
