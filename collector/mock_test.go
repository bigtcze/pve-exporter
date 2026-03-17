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

	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/ticket.json")
	})

	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/nodes.json")
	})

	mux.HandleFunc("/api2/json/nodes/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api2/json/nodes/")
		parts := strings.Split(path, "/")

		if len(parts) < 2 {
			http.NotFound(w, r)
			return
		}

		switch {
		case parts[1] == "status" && len(parts) == 2:
			serveFixture(w, "testdata/node_status.json")
		case parts[1] == "qemu" && len(parts) == 2:
			serveFixture(w, "testdata/qemu.json")
		case parts[1] == "lxc" && len(parts) == 2:
			serveFixture(w, "testdata/lxc.json")
		case parts[1] == "storage" && len(parts) == 2:
			serveFixture(w, "testdata/storage.json")
		case parts[1] == "tasks" && len(parts) == 2:
			serveFixture(w, "testdata/tasks.json")
		case parts[1] == "disks" && len(parts) >= 3 && parts[2] == "zfs":
			serveFixture(w, "testdata/zfs.json")
		case parts[1] == "certificates" && len(parts) >= 3 && parts[2] == "info":
			serveFixture(w, "testdata/certificates.json")
		case parts[1] == "qemu" && len(parts) >= 4 && parts[3] == "status":
			serveFixture(w, "testdata/qemu_status.json")
		case parts[1] == "lxc" && len(parts) >= 4 && parts[3] == "status":
			serveFixture(w, "testdata/lxc_status.json")
		default:
			http.NotFound(w, r)
		}
	})

	mux.HandleFunc("/api2/json/cluster/status", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/cluster_status.json")
	})
	mux.HandleFunc("/api2/json/cluster/resources", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/cluster_resources.json")
	})
	mux.HandleFunc("/api2/json/cluster/ha/resources", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/ha_resources.json")
	})
	mux.HandleFunc("/api2/json/cluster/replication", func(w http.ResponseWriter, r *http.Request) {
		serveFixture(w, "testdata/replication.json")
	})

	server := httptest.NewTLSServer(mux)
	return server
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
