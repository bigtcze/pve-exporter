package collector

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bigtcze/pve-exporter/config"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerTestAuthAndNodesHandlers(mux)
	registerTestClusterHandlers(mux)
	return httptest.NewTLSServer(mux)
}

func registerTestAuthAndNodesHandlers(mux *http.ServeMux) {
	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/ticket.json")
	})
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/nodes.json")
	})
	mux.HandleFunc("/api2/json/nodes/", serveTestNodeRequest)
}

func serveTestNodeRequest(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api2/json/nodes/"), "/")
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	fixture := testNodeFixture(parts)
	if fixture == "" {
		http.NotFound(w, r)
		return
	}
	serveFixture(w, fixture)
}

func testNodeFixture(parts []string) string {
	switch parts[1] {
	case "status":
		if len(parts) == 2 {
			return "testdata/node_status.json"
		}
	case "qemu":
		return testGuestFixture(parts, "qemu")
	case "lxc":
		return testGuestFixture(parts, "lxc")
	case "storage":
		if len(parts) == 2 {
			return "testdata/storage.json"
		}
	case "tasks":
		if len(parts) == 2 {
			return "testdata/tasks.json"
		}
	case "disks":
		if len(parts) >= 3 && parts[2] == "zfs" {
			return "testdata/zfs.json"
		}
	case "certificates":
		if len(parts) >= 3 && parts[2] == "info" {
			return "testdata/certificates.json"
		}
	}
	return ""
}

func testGuestFixture(parts []string, guestType string) string {
	if len(parts) == 2 {
		return "testdata/" + guestType + ".json"
	}
	if len(parts) >= 4 && parts[3] == "status" {
		return "testdata/" + guestType + "_status.json"
	}
	return ""
}

func registerTestClusterHandlers(mux *http.ServeMux) {
	for path, fixture := range map[string]string{
		"/api2/json/cluster/status":       "testdata/cluster_status.json",
		"/api2/json/cluster/resources":    "testdata/cluster_resources.json",
		"/api2/json/cluster/ha/resources": "testdata/ha_resources.json",
		"/api2/json/cluster/replication":  "testdata/replication.json",
	} {
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			serveFixture(w, fixture)
		})
	}
}

func serveFixture(w http.ResponseWriter, path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "fixture not found: "+path, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func newTestCollector(t *testing.T, server *httptest.Server) *ProxmoxCollector {
	t.Helper()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	host := u.Hostname()
	port, _ := strconv.Atoi(u.Port())

	cfg := &config.ProxmoxConfig{
		Host:               host,
		Port:               port,
		TokenID:            "test@pam!test",
		TokenSecret:        "test-secret",
		InsecureSkipVerify: true,
		Timeout:            30 * time.Second,
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c := NewProxmoxCollector(cfg, logger)

	// Use the test server's client which trusts its self-signed cert
	c.client = server.Client()
	transport := c.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c.client.Transport = transport

	return c
}
