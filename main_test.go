package main

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// prometheus2Accept is the Accept header Prometheus 2.x sent by default
// (scrapeAcceptHeader in prometheus/prometheus scrape/scrape.go, release-2.48).
// OpenMetrics is listed first, but this exporter does not enable OpenMetrics,
// so the handler must negotiate text 0.0.4.
const prometheus2Accept = "application/openmetrics-text;version=1.0.0,application/openmetrics-text;version=0.0.1;q=0.75,text/plain;version=0.0.4;q=0.5,*/*;q=0.1"

// prometheus3Accept is the default Prometheus 3.x scrape Accept header for
// UTF-8 names with the default scrape protocols. It is the literal asserted by
// TestAcceptHeader ("default scrape protocols with no escaping") in
// prometheus/prometheus scrape/scrape_test.go on main. release-3.0 builds the
// same protocol list in acceptHeader(), but appends escaping=allow-utf-8 to
// every entry, so its string differs; main's literal is used here.
const prometheus3Accept = "application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.8,application/openmetrics-text;version=0.0.1;q=0.7,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.6,text/plain;version=0.0.4;q=0.5,*/*;q=0.4"

// scrapeProtoAccept is the delimited protobuf Accept header.
const scrapeProtoAccept = "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited"

// wantFamily is the expected contract for one single-series family.
type wantFamily struct {
	name   string
	typ    dto.MetricType
	help   string
	labels map[string]string
	value  float64
}

// newTestRegistry builds a deterministic registry that mirrors three pve_*
// families. Names, types, HELP text and label keys are copied from the
// collector's descriptors: pve_node_up (collector/collector.go ~L243, label
// {node}), pve_node_memory_used_bytes (~L268, {node}) and
// pve_disk_read_bytes_total (~L848, {node, device}), emitted from
// collector/node.go and collector/disk.go. The real ProxmoxCollector cannot be
// registered here because its fixture-backed helpers live in package
// collector's _test files and are not importable from package main. This is a
// mirror, not the collector, so update it when those descriptors change.
func newTestRegistry(t *testing.T) *prometheus.Registry {
	t.Helper()

	nodeUp := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pve_node_up",
		Help: "Node is up and reachable",
	}, []string{"node"})
	memUsed := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pve_node_memory_used_bytes",
		Help: "Used memory in bytes",
	}, []string{"node"})
	diskRead := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pve_disk_read_bytes_total",
		Help: "Total bytes read from disk",
	}, []string{"node", "device"})

	nodeUp.WithLabelValues("pve1").Set(1)
	memUsed.WithLabelValues("pve1").Set(4294967296)
	diskRead.WithLabelValues("pve1", "sda").Add(12345)

	reg := prometheus.NewRegistry()
	reg.MustRegister(nodeUp, memUsed, diskRead)
	return reg
}

// expectedPVEFamilies is the value, label, type and HELP contract for newTestRegistry.
func expectedPVEFamilies() []wantFamily {
	return []wantFamily{
		{
			name:   "pve_node_up",
			typ:    dto.MetricType_GAUGE,
			help:   "Node is up and reachable",
			labels: map[string]string{"node": "pve1"},
			value:  1,
		},
		{
			name:   "pve_node_memory_used_bytes",
			typ:    dto.MetricType_GAUGE,
			help:   "Used memory in bytes",
			labels: map[string]string{"node": "pve1"},
			value:  4294967296,
		},
		{
			name:   "pve_disk_read_bytes_total",
			typ:    dto.MetricType_COUNTER,
			help:   "Total bytes read from disk",
			labels: map[string]string{"node": "pve1", "device": "sda"},
			value:  12345,
		},
	}
}

// newMetricsTestServer serves the /metrics handler over loopback HTTP.
func newMetricsTestServer(t *testing.T, reg prometheus.Gatherer) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(newMetricsHandler(reg))
	t.Cleanup(srv.Close)
	return srv
}

// getMetrics performs a GET against /metrics. An empty accept leaves the
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

// requireStatusOK fails unless the response is 200.
func requireStatusOK(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body:\n%s", resp.StatusCode, body)
	}
}

// assertTextContentType checks the media type, version and escaping parameters
// of a text exposition response.
func assertTextContentType(t *testing.T, resp *http.Response, version, escaping string) {
	t.Helper()
	ct := resp.Header.Get("Content-Type")
	mediaType, params, err := mime.ParseMediaType(ct)
	if err != nil {
		t.Fatalf("parsing Content-Type %q: %v", ct, err)
	}
	if mediaType != "text/plain" {
		t.Errorf("media type = %q, want text/plain", mediaType)
	}
	if params["version"] != version {
		t.Errorf("version = %q, want %q (Content-Type %q)", params["version"], version, ct)
	}
	if params[model.EscapingKey] != escaping {
		t.Errorf("escaping = %q, want %q (Content-Type %q)", params[model.EscapingKey], escaping, ct)
	}
}

// familiesFromText parses a text exposition body with the given validation scheme.
func familiesFromText(t *testing.T, body []byte, scheme model.ValidationScheme) map[string]*dto.MetricFamily {
	t.Helper()
	parser := expfmt.NewTextParser(scheme)
	fams, err := parser.TextToMetricFamilies(bytes.NewReader(body))
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

// assertFamilies checks that exactly the wanted families are present, each with
// the expected TYPE, HELP, one series, exact label set and value.
func assertFamilies(t *testing.T, fams map[string]*dto.MetricFamily, want []wantFamily) {
	t.Helper()
	if len(fams) != len(want) {
		t.Errorf("got %d families %v, want %d", len(fams), familyNames(fams), len(want))
	}
	for _, w := range want {
		fam, ok := fams[w.name]
		if !ok {
			t.Errorf("family %s missing; got families: %v", w.name, familyNames(fams))
			continue
		}
		if got := fam.GetType(); got != w.typ {
			t.Errorf("%s TYPE = %v, want %v", w.name, got, w.typ)
		}
		if got := fam.GetHelp(); got != w.help {
			t.Errorf("%s HELP = %q, want %q", w.name, got, w.help)
		}
		if len(fam.GetMetric()) != 1 {
			t.Errorf("%s has %d series, want 1", w.name, len(fam.GetMetric()))
			continue
		}
		m := fam.GetMetric()[0]
		gotLabels := labelsOf(m)
		if len(gotLabels) != len(w.labels) {
			t.Errorf("%s label keys = %v, want %v", w.name, gotLabels, w.labels)
		}
		for k, v := range w.labels {
			if gotLabels[k] != v {
				t.Errorf("%s label %s = %q, want %q", w.name, k, gotLabels[k], v)
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
			t.Errorf("%s value = %v, want %v", w.name, got, w.value)
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

func TestMetricsHandlerPrometheus2AndNoAcceptNegotiateTextV004(t *testing.T) {
	srv := newMetricsTestServer(t, newTestRegistry(t))

	for _, tc := range []struct {
		name   string
		accept string
	}{
		{name: "no Accept header", accept: ""},
		{name: "Prometheus 2.x scraper", accept: prometheus2Accept},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := getMetrics(t, srv, tc.accept)
			requireStatusOK(t, resp, body)

			// OpenMetrics is not enabled, so the fallback is text 0.0.4 with
			// the default name escaping (underscores).
			assertTextContentType(t, resp, "0.0.4", "underscores")

			fams := familiesFromText(t, body, model.UTF8Validation)
			assertFamilies(t, fams, expectedPVEFamilies())
		})
	}
}

// TestMetricsHandlerPrometheus3AcceptNegotiatesTextV100 covers the Prometheus 3.x
// default header. The 1.0.0 text body must match the 0.0.4 body byte for byte.
//
// Why serving text 1.0.0 is safe for scrapers: 1.0.0 adds UTF-8 name support,
// signalled by the escaping parameter, and it does not change the text syntax.
// For names that are already legacy-valid, the encoder writes the same bytes
// for 1.0.0 and 0.0.4. The byte-equality assertion below checks this for this
// registry only; it is not a general guarantee. On the consumer side, Prometheus
// dispatches on the media type alone: textparse.New in prometheus/prometheus
// model/textparse/interface.go (release-3.0) maps any "text/plain" to its text
// parser and does not inspect the version parameter, so the same parser reads both.
func TestMetricsHandlerPrometheus3AcceptNegotiatesTextV100(t *testing.T) {
	srv := newMetricsTestServer(t, newTestRegistry(t))

	resp, body := getMetrics(t, srv, prometheus3Accept)
	requireStatusOK(t, resp, body)

	// Observed with prometheus/common v0.74.0: FmtText_1_0_0 is accepted, and
	// the matched clause's escaping=allow-utf-8 is echoed back.
	assertTextContentType(t, resp, "1.0.0", "allow-utf-8")

	fams := familiesFromText(t, body, model.UTF8Validation)
	assertFamilies(t, fams, expectedPVEFamilies())

	resp004, body004 := getMetrics(t, srv, "")
	requireStatusOK(t, resp004, body004)
	assertTextContentType(t, resp004, "0.0.4", "underscores")
	if !bytes.Equal(body, body004) {
		t.Errorf("text 1.0.0 body differs from text 0.0.4 body\n--- 1.0.0:\n%s\n--- 0.0.4:\n%s", body, body004)
	}
}

// TestMetricsHandlerExplicitTextV100Accept covers an explicit text/plain
// version=1.0.0 Accept without an escaping term.
func TestMetricsHandlerExplicitTextV100Accept(t *testing.T) {
	srv := newMetricsTestServer(t, newTestRegistry(t))

	resp, body := getMetrics(t, srv, "text/plain;version=1.0.0")
	requireStatusOK(t, resp, body)

	// Observed with prometheus/common v0.74.0: version=1.0.0 is honoured, and
	// with no escaping term in the Accept clause the default underscores applies.
	assertTextContentType(t, resp, "1.0.0", "underscores")

	fams := familiesFromText(t, body, model.UTF8Validation)
	assertFamilies(t, fams, expectedPVEFamilies())
}

func TestMetricsHandlerProtobufDelimitedAccept(t *testing.T) {
	srv := newMetricsTestServer(t, newTestRegistry(t))

	resp, body := getMetrics(t, srv, scrapeProtoAccept)
	requireStatusOK(t, resp, body)

	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parsing Content-Type: %v", err)
	}
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

	decoder := expfmt.NewDecoder(bytes.NewReader(body), format)
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

// TestMetricsHandlerContinueOnErrorServesPartialFamilies checks that a gather
// error with some families still returns 200 and the partial body
// (promhttp ContinueOnError), and that the error text is not exposed in it.
func TestMetricsHandlerContinueOnErrorServesPartialFamilies(t *testing.T) {
	full := newTestRegistry(t)
	gatherErr := errors.New("simulated failure gathering pve_disk_read_bytes_total")

	partial := prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
		mfs, err := full.Gather()
		if err != nil {
			return nil, err
		}
		kept := mfs[:0]
		for _, mf := range mfs {
			if mf.GetName() != "pve_disk_read_bytes_total" {
				kept = append(kept, mf)
			}
		}
		return kept, gatherErr
	})

	srv := newMetricsTestServer(t, partial)
	resp, body := getMetrics(t, srv, prometheus2Accept)
	requireStatusOK(t, resp, body)
	assertTextContentType(t, resp, "0.0.4", "underscores")

	if bytes.Contains(body, []byte(gatherErr.Error())) {
		t.Errorf("gather error text leaked into the response body:\n%s", body)
	}

	fams := familiesFromText(t, body, model.UTF8Validation)
	// Only the two families that gathered successfully are expected. The
	// first two entries of expectedPVEFamilies are pve_node_up and
	// pve_node_memory_used_bytes.
	assertFamilies(t, fams, expectedPVEFamilies()[:2])
}
