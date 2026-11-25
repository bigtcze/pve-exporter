package main

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// scraperAccept is a typical Prometheus scraper Accept header. It asks for
// OpenMetrics first, but the exporter does not enable OpenMetrics, so the
// handler must fall back to the Prometheus text format 0.0.4.
const scraperAccept = "application/openmetrics-text;version=1.0.0,application/openmetrics-text;version=0.0.1;q=0.75,text/plain;version=0.0.4;q=0.5,*/*;q=0.1"

// newTestRegistry builds a deterministic registry that mimics the pve_* families
// emitted by the Proxmox collector (same names, types, label keys and HELP text
// as the README inventory). The real ProxmoxCollector cannot be used here: its
// fixture-backed test helpers live in package collector's _test files and are
// not importable from package main. Keeping the values fixed makes the
// exposition assertions exact.
func newTestRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()

	nodeUp := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pve_node_up",
		Help: "Node status (1=online)",
	}, []string{"node"})
	memUsed := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pve_node_memory_used_bytes",
		Help: "Used memory in bytes",
	}, []string{"node"})
	diskRead := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pve_disk_read_bytes_total",
		Help: "Total bytes read from disk",
	}, []string{"node", "vmid", "name", "device"})

	nodeUp.WithLabelValues("pve1").Set(1)
	memUsed.WithLabelValues("pve1").Set(4294967296)
	diskRead.WithLabelValues("pve1", "100", "web", "sda").Add(12345)

	reg := prometheus.NewRegistry()
	reg.MustRegister(nodeUp, memUsed, diskRead)
	return reg
}

// newMetricsTestServer serves the /metrics handler over loopback HTTP.
func newMetricsTestServer(t *testing.T, reg prometheus.Gatherer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newMetricsHandler(reg))
	t.Cleanup(srv.Close)
	return srv
}

// getMetrics performs a GET against the test server. An empty accept leaves the
// Accept header unset.
func getMetrics(t *testing.T, srv *httptest.Server, accept string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading body: %v", err)
	}
	return resp, body
}

// parseContentType returns the media type and parameters of a Content-Type.
func parseContentType(t *testing.T, resp *http.Response) (string, map[string]string) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("parsing Content-Type %q: %v", ct, err)
	}
	return mediaType, params
}

// familiesFromText parses a text exposition body with the given validation scheme.
func familiesFromText(t *testing.T, body []byte, scheme model.ValidationScheme) map[string]*dto.MetricFamily {
	t.Helper()
	parser := expfmt.NewTextParser(scheme)
	fams, err := parser.TextToMetricFamilies(strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("parsing text exposition: %v\nbody:\n%s", err, body)
	}
	return fams
}

// labelsOf returns the label set of a metric as a map.
func labelsOf(m *dto.Metric) map[string]string {
	out := make(map[string]string, len(m.GetLabel()))
	for _, l := range m.GetLabel() {
		out[l.GetName()] = l.GetValue()
	}
	return out
}

// assertFamilies checks that the expected families are present with the expected
// TYPE and exactly one series with the expected label keys and value.
func assertFamilies(t *testing.T, fams map[string]*dto.MetricFamily, want map[string]struct {
	typ    dto.MetricType
	labels map[string]string
	value  float64
}) {
	t.Helper()
	for name, w := range want {
		fam, ok := fams[name]
		if !ok {
			t.Errorf("family %s missing; got families: %v", name, familyNames(fams))
			continue
		}
		if got := fam.GetType(); got != w.typ {
			t.Errorf("%s TYPE = %v, want %v", name, got, w.typ)
		}
		if len(fam.GetMetric()) != 1 {
			t.Errorf("%s has %d series, want 1", name, len(fam.GetMetric()))
			continue
		}
		m := fam.GetMetric()[0]
		gotLabels := labelsOf(m)
		if len(gotLabels) != len(w.labels) {
			t.Errorf("%s label keys = %v, want %v", name, gotLabels, w.labels)
		}
		for k, v := range w.labels {
			if gotLabels[k] != v {
				t.Errorf("%s label %s = %q, want %q", name, k, gotLabels[k], v)
			}
		}
		var got float64
		switch w.typ {
		case dto.MetricType_GAUGE:
			got = m.GetGauge().GetValue()
		case dto.MetricType_COUNTER:
			got = m.GetCounter().GetValue()
		default:
			t.Fatalf("unsupported type in test: %v", w.typ)
		}
		if got != w.value {
			t.Errorf("%s value = %v, want %v", name, got, w.value)
		}
	}
}

func familyNames(fams map[string]*dto.MetricFamily) []string {
	names := make([]string, 0, len(fams))
	for n := range fams {
		names = append(names, n)
	}
	return names
}

// expectedPVEFamilies is the value/label/type contract for newTestRegistry.
func expectedPVEFamilies() map[string]struct {
	typ    dto.MetricType
	labels map[string]string
	value  float64
} {
	return map[string]struct {
		typ    dto.MetricType
		labels map[string]string
		value  float64
	}{
		"pve_node_up": {
			typ:    dto.MetricType_GAUGE,
			labels: map[string]string{"node": "pve1"},
			value:  1,
		},
		"pve_node_memory_used_bytes": {
			typ:    dto.MetricType_GAUGE,
			labels: map[string]string{"node": "pve1"},
			value:  4294967296,
		},
		"pve_disk_read_bytes_total": {
			typ:    dto.MetricType_COUNTER,
			labels: map[string]string{"node": "pve1", "vmid": "100", "name": "web", "device": "sda"},
			value:  12345,
		},
	}
}

func TestMetricsHandlerScraperAcceptFallsBackToTextV004(t *testing.T) {
	srv := newMetricsTestServer(t, newTestRegistry(t))

	for _, tc := range []struct {
		name   string
		accept string
	}{
		{name: "no Accept header", accept: ""},
		{name: "typical Prometheus scraper", accept: scraperAccept},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := getMetrics(t, srv, tc.accept)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200; body:\n%s", resp.StatusCode, body)
			}

			mediaType, params := parseContentType(t, resp)
			if mediaType != "text/plain" {
				t.Errorf("media type = %q, want text/plain", mediaType)
			}
			if params["version"] != "0.0.4" {
				t.Errorf("version = %q, want 0.0.4 (OpenMetrics is not enabled)", params["version"])
			}

			fams := familiesFromText(t, body, model.UTF8Validation)
			assertFamilies(t, fams, expectedPVEFamilies())
		})
	}
}

func TestMetricsHandlerExplicitTextV100Accept(t *testing.T) {
	srv := newMetricsTestServer(t, newTestRegistry(t))

	resp, body := getMetrics(t, srv, "text/plain;version=1.0.0")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", resp.StatusCode, body)
	}

	// Observed with prometheus/common v0.74.0: the 1.0.0 text format is in the
	// accepted list, so an explicit version=1.0.0 request is honoured rather
	// than falling back to 0.0.4.
	mediaType, params := parseContentType(t, resp)
	if mediaType != "text/plain" {
		t.Errorf("media type = %q, want text/plain", mediaType)
	}
	if params["version"] != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0 (observed behaviour with v0.74.0)", params["version"])
	}

	fams := familiesFromText(t, body, model.UTF8Validation)
	assertFamilies(t, fams, expectedPVEFamilies())
}

func TestMetricsHandlerProtobufDelimitedAccept(t *testing.T) {
	srv := newMetricsTestServer(t, newTestRegistry(t))

	resp, body := getMetrics(t, srv, "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body length %d", resp.StatusCode, len(body))
	}

	mediaType, params := parseContentType(t, resp)
	if mediaType != "application/vnd.google.protobuf" {
		t.Errorf("media type = %q, want application/vnd.google.protobuf", mediaType)
	}
	if params["proto"] != "io.prometheus.client.MetricFamily" || params["encoding"] != "delimited" {
		t.Errorf("protobuf params = %v, want proto=io.prometheus.client.MetricFamily encoding=delimited", params)
	}

	format := expfmt.ResponseFormat(resp.Header)
	if format.FormatType() != expfmt.TypeProtoDelim {
		t.Fatalf("ResponseFormat = %q, want delimited protobuf", format)
	}

	decoder := expfmt.NewDecoder(strings.NewReader(string(body)), format)
	fams := make(map[string]*dto.MetricFamily)
	for {
		fam := &dto.MetricFamily{}
		err := decoder.Decode(fam)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("decoding delimited protobuf: %v", err)
		}
		fams[fam.GetName()] = fam
	}

	assertFamilies(t, fams, expectedPVEFamilies())
}
