package collector

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bigtcze/pve-exporter/config"
)

const testBarrierTimeout = 2 * time.Second

func waitForTestBarrier(r *http.Request, barrier <-chan struct{}) bool {
	timer := time.NewTimer(testBarrierTimeout)
	defer timer.Stop()
	select {
	case <-barrier:
		return true
	case <-r.Context().Done():
		return false
	case <-timer.C:
		return false
	}
}

func waitForRefreshJoins(c *ProxmoxCollector, want int) bool {
	deadline := time.Now().Add(testBarrierTimeout)
	for time.Now().Before(deadline) {
		c.mutex.Lock()
		generation := c.ticketGeneration
		joined := generation != nil && generation.refresh != nil && generation.refresh.joins >= want
		c.mutex.Unlock()
		if joined {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func apiTestCollector(t *testing.T, server *httptest.Server, cfg *config.ProxmoxConfig) *ProxmoxCollector {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Host = u.Hostname()
	cfg.Port, err = strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	c := NewProxmoxCollector(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.client = server.Client()
	transport := c.client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	c.client.Transport = transport
	return c
}

func TestAPIRequestRefreshesFreshPasswordTicketAfterUnauthorized(t *testing.T) {
	var ticketRequests atomic.Int32
	var apiRequests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, _ *http.Request) {
		ticketRequests.Add(1)
		_, _ = io.WriteString(w, `{"data":{"ticket":"new-ticket","CSRFPreventionToken":"new-csrf"}}`)
	})
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		apiRequests.Add(1)
		cookie, _ := r.Cookie("PVEAuthCookie")
		if cookie == nil || cookie.Value != "new-ticket" {
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := apiTestCollector(t, server, &config.ProxmoxConfig{User: "root@pam", Password: "secret"})
	c.ticket = "fresh-but-rejected"
	c.ticketTime = time.Now()

	body, err := c.apiRequest("/nodes")
	if err != nil {
		t.Fatalf("apiRequest failed: %v", err)
	}
	if string(body) != `{"data":[]}` {
		t.Fatalf("body = %q", body)
	}
	if got := ticketRequests.Load(); got != 1 {
		t.Fatalf("ticket requests = %d, want 1", got)
	}
	if got := apiRequests.Load(); got != 2 {
		t.Fatalf("API requests = %d, want 2", got)
	}
}

func TestConcurrentUnauthorizedRequestsSharePasswordRefresh(t *testing.T) {
	const requestCount = 8
	var ticketRequests atomic.Int32
	var rejectedRequests atomic.Int32
	allRejected := make(chan struct{})
	var rejectedOnce sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, _ *http.Request) {
		ticketRequests.Add(1)
		_, _ = io.WriteString(w, `{"data":{"ticket":"old-ticket","CSRFPreventionToken":"new-csrf"}}`)
	})
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("PVEAuthCookie")
		if cookie == nil || cookie.Value != "old-ticket" || ticketRequests.Load() == 0 {
			if rejectedRequests.Add(1) == requestCount {
				rejectedOnce.Do(func() { close(allRejected) })
			}
			if !waitForTestBarrier(r, allRejected) {
				http.Error(w, "barrier timeout", http.StatusInternalServerError)
				return
			}
			http.Error(w, "expired", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	t.Cleanup(func() { rejectedOnce.Do(func() { close(allRejected) }) })

	c := apiTestCollector(t, server, &config.ProxmoxConfig{User: "root@pam", Password: "secret"})
	c.ticket = "old-ticket"
	c.ticketTime = time.Now()

	start := make(chan struct{})
	errs := make(chan error, requestCount)
	var wg sync.WaitGroup
	for range requestCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := c.apiRequest("/nodes")
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("apiRequest failed: %v", err)
		}
	}
	if got := ticketRequests.Load(); got != 1 {
		t.Fatalf("ticket requests = %d, want 1", got)
	}
}

func TestConcurrentUnauthorizedRequestsShareFailedPasswordRefresh(t *testing.T) {
	const requestCount = 8
	var ticketRequests atomic.Int32
	var rejectedRequests atomic.Int32
	allRejected := make(chan struct{})
	var rejectedOnce sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, _ *http.Request) {
		ticketRequests.Add(1)
		http.Error(w, "login failed", http.StatusUnauthorized)
	})
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		if rejectedRequests.Add(1) == requestCount {
			rejectedOnce.Do(func() { close(allRejected) })
		}
		if !waitForTestBarrier(r, allRejected) {
			http.Error(w, "barrier timeout", http.StatusInternalServerError)
			return
		}
		http.Error(w, "expired", http.StatusUnauthorized)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	t.Cleanup(func() { rejectedOnce.Do(func() { close(allRejected) }) })

	c := apiTestCollector(t, server, &config.ProxmoxConfig{User: "root@pam", Password: "secret"})
	c.ticket = "rejected-ticket"
	c.ticketTime = time.Now()

	start := make(chan struct{})
	errs := make(chan error, requestCount)
	var wg sync.WaitGroup
	for range requestCount {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := c.apiRequest("/nodes")
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err == nil || !strings.Contains(err.Error(), "re-authentication failed") {
			t.Errorf("apiRequest error = %v, want shared refresh failure", err)
		}
	}
	if got := ticketRequests.Load(); got != 1 {
		t.Fatalf("ticket requests = %d, want 1 for rejected generation", got)
	}
	if got := rejectedRequests.Load(); got != requestCount {
		t.Fatalf("stale API requests = %d, want %d", got, requestCount)
	}

	if _, err := c.apiRequest("/nodes"); err == nil {
		t.Fatal("later apiRequest unexpectedly succeeded")
	}
	if got := ticketRequests.Load(); got != 2 {
		t.Fatalf("ticket requests after later request = %d, want 2", got)
	}
}

func TestRequestStartingDuringFailedRefreshJoinsGeneration(t *testing.T) {
	var apiRequests atomic.Int32
	var ticketRequests atomic.Int32
	loginStarted := make(chan struct{})
	releaseLogin := make(chan struct{})
	var loginStartedOnce sync.Once
	var releaseLoginOnce sync.Once
	t.Cleanup(func() { releaseLoginOnce.Do(func() { close(releaseLogin) }) })

	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, r *http.Request) {
		ticketRequests.Add(1)
		loginStartedOnce.Do(func() { close(loginStarted) })
		if !waitForTestBarrier(r, releaseLogin) {
			http.Error(w, "login barrier timeout", http.StatusInternalServerError)
			return
		}
		http.Error(w, "login failed", http.StatusUnauthorized)
	})
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, _ *http.Request) {
		apiRequests.Add(1)
		http.Error(w, "expired", http.StatusUnauthorized)
	})
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	c := apiTestCollector(t, server, &config.ProxmoxConfig{User: "root@pam", Password: "secret"})
	c.ticket = "rejected-ticket"
	c.ticketTime = time.Now()

	firstResult := make(chan error, 1)
	go func() {
		_, err := c.apiRequest("/nodes")
		firstResult <- err
	}()
	select {
	case <-loginStarted:
	case <-time.After(testBarrierTimeout):
		t.Fatal("password refresh did not start")
	}

	secondStarted := make(chan struct{})
	secondResult := make(chan error, 1)
	go func() {
		close(secondStarted)
		_, err := c.apiRequest("/nodes")
		secondResult <- err
	}()
	<-secondStarted
	if !waitForRefreshJoins(c, 1) {
		t.Fatal("second request did not join active refresh")
	}
	if got := apiRequests.Load(); got != 1 {
		t.Fatalf("stale API requests during refresh = %d, want 1", got)
	}

	releaseLoginOnce.Do(func() { close(releaseLogin) })
	for i, result := range []<-chan error{firstResult, secondResult} {
		select {
		case err := <-result:
			if err == nil || !strings.Contains(err.Error(), "re-authentication failed") {
				t.Errorf("request %d error = %v, want refresh failure", i+1, err)
			}
		case <-time.After(testBarrierTimeout):
			t.Fatalf("request %d did not consume refresh result", i+1)
		}
	}
	if got := ticketRequests.Load(); got != 1 {
		t.Fatalf("ticket requests = %d, want 1", got)
	}
	if got := apiRequests.Load(); got != 1 {
		t.Fatalf("stale API requests = %d, want 1", got)
	}

	if _, err := c.apiRequest("/nodes"); err == nil {
		t.Fatal("later apiRequest unexpectedly succeeded")
	}
	if got := ticketRequests.Load(); got != 2 {
		t.Fatalf("ticket requests after later request = %d, want 2", got)
	}
	if got := apiRequests.Load(); got != 2 {
		t.Fatalf("API requests after later request = %d, want 2", got)
	}
}

func TestAuthenticatePreservesFreshPasswordTicket(t *testing.T) {
	var ticketRequests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ticketRequests.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()

	c := apiTestCollector(t, server, &config.ProxmoxConfig{User: "root@pam", Password: "secret"})
	c.ticket = "fresh-ticket"
	c.ticketTime = time.Now()
	if err := c.authenticate(); err != nil {
		t.Fatal(err)
	}
	if got := ticketRequests.Load(); got != 0 {
		t.Fatalf("ticket requests = %d, want 0", got)
	}
}

func TestTokenUnauthorizedNeverRequestsTicket(t *testing.T) {
	var ticketRequests atomic.Int32
	var apiRequests atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, _ *http.Request) {
		ticketRequests.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	})
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		apiRequests.Add(1)
		if got := r.Header.Get("Authorization"); got != "PVEAPIToken=user@pam!metrics=token-secret" {
			t.Errorf("Authorization = %q", got)
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "token-secret"})
	if _, err := c.apiRequest("/nodes"); err == nil {
		t.Fatal("apiRequest unexpectedly succeeded")
	}
	if got := ticketRequests.Load(); got != 0 {
		t.Fatalf("ticket requests = %d, want 0", got)
	}
	if got := apiRequests.Load(); got != maxRetries {
		t.Fatalf("API requests = %d, want %d", got, maxRetries)
	}
}

func TestAPIResponseSizeLimit(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "exactly limit", size: maxResponseSize},
		{name: "over limit", size: maxResponseSize + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.CopyN(w, bytes.NewReader(bytes.Repeat([]byte("x"), tt.size)), int64(tt.size))
			}))
			defer server.Close()
			c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})

			body, err := c.apiRequest("/body")
			if (err != nil) != tt.wantErr {
				t.Fatalf("apiRequest error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(body) != maxResponseSize {
				t.Fatalf("body size = %d, want %d", len(body), maxResponseSize)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("error = %v, want explicit overflow", err)
			}
		})
	}
}

func TestOversizedUnauthorizedBodyStillRefreshes(t *testing.T) {
	var ticketRequests atomic.Int32
	var apiRequests atomic.Int32
	overflowBody := bytes.Repeat([]byte("x"), maxResponseSize+1)
	mux := http.NewServeMux()
	mux.HandleFunc("/api2/json/access/ticket", func(w http.ResponseWriter, _ *http.Request) {
		ticketRequests.Add(1)
		_, _ = io.WriteString(w, `{"data":{"ticket":"new-ticket","CSRFPreventionToken":"new-csrf"}}`)
	})
	mux.HandleFunc("/api2/json/nodes", func(w http.ResponseWriter, r *http.Request) {
		apiRequests.Add(1)
		cookie, _ := r.Cookie("PVEAuthCookie")
		if cookie == nil || cookie.Value != "new-ticket" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write(overflowBody)
			return
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	})
	server := httptest.NewTLSServer(mux)
	defer server.Close()

	c := apiTestCollector(t, server, &config.ProxmoxConfig{User: "root@pam", Password: "secret"})
	c.ticket = "rejected-ticket"
	c.ticketTime = time.Now()
	if _, err := c.apiRequest("/nodes"); err != nil {
		t.Fatal(err)
	}
	if got := ticketRequests.Load(); got != 1 {
		t.Fatalf("ticket requests = %d, want 1", got)
	}
	if got := apiRequests.Load(); got != 2 {
		t.Fatalf("API requests = %d, want 2", got)
	}
}

func TestOversizedServerErrorBodyStillRetries(t *testing.T) {
	var apiRequests atomic.Int32
	overflowBody := bytes.Repeat([]byte("x"), maxResponseSize+1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if apiRequests.Add(1) < maxRetries {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write(overflowBody)
			return
		}
		_, _ = io.WriteString(w, `{"data":[]}`)
	}))
	defer server.Close()

	c := apiTestCollector(t, server, &config.ProxmoxConfig{TokenID: "user@pam!metrics", TokenSecret: "secret"})
	if _, err := c.apiRequest("/nodes"); err != nil {
		t.Fatal(err)
	}
	if got := apiRequests.Load(); got != maxRetries {
		t.Fatalf("API requests = %d, want %d", got, maxRetries)
	}
}

func TestAuthenticationResponseSizeLimit(t *testing.T) {
	prefix := []byte(`{"data":{"ticket":"ticket","CSRFPreventionToken":"csrf"}}`)
	for _, tt := range []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "exactly limit", size: maxResponseSize},
		{name: "over limit", size: maxResponseSize + 1, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := append(append([]byte(nil), prefix...), bytes.Repeat([]byte(" "), tt.size-len(prefix))...)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			}))
			defer server.Close()
			c := apiTestCollector(t, server, &config.ProxmoxConfig{User: "root@pam", Password: "secret"})

			err := c.authenticate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("authenticate error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("error = %v, want explicit overflow", err)
			}
		})
	}
}

func TestBuildAPIURL(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{name: "DNS", host: "pve.example.com", want: "https://pve.example.com:8006/api2/json/nodes"},
		{name: "IPv4", host: "192.0.2.10", want: "https://192.0.2.10:8006/api2/json/nodes"},
		{name: "raw IPv6", host: "2001:db8::10", want: "https://[2001:db8::10]:8006/api2/json/nodes"},
		{name: "bracketed IPv6", host: "[2001:db8::10]", want: "https://[2001:db8::10]:8006/api2/json/nodes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := buildAPIURL(tt.host, 8006, "/nodes")
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("URL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildAPIURLRejectsInvalidHosts(t *testing.T) {
	for _, host := range []string{
		"https://pve.example.com",
		"pve.example.com/api",
		"root@pve.example.com",
		"pve.example.com:8006",
		"[2001:db8::10",
		"2001:db8::10]",
	} {
		t.Run(host, func(t *testing.T) {
			if got, err := buildAPIURL(host, 8006, "/nodes"); err == nil {
				t.Fatalf("buildAPIURL(%q) = %q, want error", host, got)
			}
		})
	}
}

func TestAPIPathEscapesDynamicSegments(t *testing.T) {
	got := apiPathf("/nodes/%s/%s/%d/status/current", "node/one", "qemu?#", 100)
	want := "/nodes/node%2Fone/qemu%3F%23/100/status/current"
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}

	got = apiPathf("/nodes/%s/tasks?typefilter=vzdump&limit=%d", "node/one", taskFetchLimit)
	want = "/nodes/node%2Fone/tasks?typefilter=vzdump&limit=50"
	if got != want {
		t.Fatalf("backup task path = %q, want %q", got, want)
	}

	upid := "UPID:node/one:00001234:backup%job"
	got = apiPathf("/nodes/%s/tasks/%s/log?limit=%d", "node/one", upid, maxLogLines)
	want = "/nodes/node%2Fone/tasks/UPID:node%2Fone:00001234:backup%25job/log?limit=" + fmt.Sprint(maxLogLines)
	if got != want {
		t.Fatalf("backup path = %q, want %q", got, want)
	}

	requestURL, err := buildAPIURL("pve.example.com", 8006, got)
	if err != nil {
		t.Fatal(err)
	}
	wantURL := "https://pve.example.com:8006/api2/json" + want
	if requestURL != wantURL {
		t.Fatalf("URL = %q, want %q", requestURL, wantURL)
	}
}
