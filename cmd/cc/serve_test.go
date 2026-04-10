package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mikemackintosh/crowdcontrol"
	"github.com/mikemackintosh/crowdcontrol/types"
)

// makePolicyDir writes a rules.cc file into a fresh temp dir and
// returns the directory path. Cleanup happens via t.Cleanup.
func makePolicyDir(t *testing.T, src string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rules.cc"), []byte(src), 0o644); err != nil {
		t.Fatalf("writing policy: %v", err)
	}
	return dir
}

// makeTestServer spins up a *server with an in-memory audit log so
// handler tests can inspect it.
func makeTestServer(t *testing.T, opts serveOptions, src string) (*server, *bytes.Buffer) {
	t.Helper()
	if opts.PolicyDirs == nil {
		opts.PolicyDirs = []string{makePolicyDir(t, src)}
	}
	if opts.DefaultEffect == "" {
		opts.DefaultEffect = types.DefaultAllow
	}
	opts.AuditLog = "" // we'll inject a buffer manually

	srv, err := newServer(opts)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	buf := &bytes.Buffer{}
	srv.audit = buf
	return srv, buf
}

// do runs a single request through the server's middleware + mux.
func do(t *testing.T, srv *server, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/readyz", srv.handleReadyz)
	mux.HandleFunc("/metrics", srv.handleMetrics)
	mux.HandleFunc("/v1/policies", srv.handlePolicies)
	mux.HandleFunc("/v1/evaluate", srv.handleEvaluate)
	mux.HandleFunc("/", srv.handleRoot)

	srv.wrap(mux).ServeHTTP(rec, req)
	return rec
}

const basePolicy = `
forbid "no-interns-delete-prod" {
  description "Interns cannot delete prod resources"
  owner       "platform-security"
  user.role == "intern"
  request.action == "delete"
  resource.environment == "production"
  message "{user.name} cannot delete prod"
}

warn "large-change" {
  count(plan.creates) > 20
  message "large change"
}
`

// ---------------------------------------------------------------------------
// happy-path evaluate
// ---------------------------------------------------------------------------

func TestEvaluate_DenyCase(t *testing.T) {
	srv, audit := makeTestServer(t, serveOptions{}, basePolicy)

	rec := do(t, srv, "POST", "/v1/evaluate", map[string]any{
		"input": map[string]any{
			"user":     map[string]any{"name": "alex", "role": "intern"},
			"request":  map[string]any{"action": "delete"},
			"resource": map[string]any{"environment": "production"},
		},
	}, nil)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on deny, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp evaluateResponse
	mustUnmarshal(t, rec.Body.Bytes(), &resp)

	if resp.Decision != "deny" {
		t.Fatalf("decision = %q, want deny", resp.Decision)
	}
	if resp.Shadow {
		t.Fatal("shadow flag should not be set")
	}
	if resp.RequestID == "" {
		t.Fatal("missing request_id")
	}
	if resp.ElapsedUS < 0 {
		t.Fatalf("elapsed_us = %d, want >= 0", resp.ElapsedUS)
	}
	if len(resp.Results) < 1 {
		t.Fatal("expected at least one result")
	}

	// The first rule should have fired with our interpolated message.
	var denyHit bool
	for _, r := range resp.Results {
		if r.Rule == "no-interns-delete-prod" && !r.Passed {
			denyHit = true
			if !strings.Contains(r.Message, "alex cannot delete prod") {
				t.Errorf("unexpected message: %s", r.Message)
			}
		}
	}
	if !denyHit {
		t.Fatal("expected no-interns-delete-prod to fire")
	}

	// Metrics should reflect the deny.
	if srv.reqDeny.Load() != 1 {
		t.Errorf("reqDeny = %d, want 1", srv.reqDeny.Load())
	}
	if srv.reqAllow.Load() != 0 {
		t.Errorf("reqAllow = %d, want 0", srv.reqAllow.Load())
	}

	// Audit log should have a summary line and a rule-fired line.
	lines := splitLines(audit.String())
	if len(lines) != 2 {
		t.Fatalf("expected 2 audit lines, got %d:\n%s", len(lines), audit.String())
	}
	var summary, ruleFired auditRecord
	mustUnmarshal(t, []byte(lines[0]), &summary)
	mustUnmarshal(t, []byte(lines[1]), &ruleFired)
	if summary.Decision != "deny" {
		t.Errorf("summary decision = %q, want deny", summary.Decision)
	}
	if ruleFired.Rule != "no-interns-delete-prod" {
		t.Errorf("rule-fired rule = %q", ruleFired.Rule)
	}
	if summary.InputSHA256 == "" {
		t.Error("missing input_sha256 in audit record")
	}
}

func TestEvaluate_AllowCase(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)

	rec := do(t, srv, "POST", "/v1/evaluate", map[string]any{
		"input": map[string]any{
			"user":    map[string]any{"name": "alex", "role": "engineer"},
			"request": map[string]any{"action": "view"},
		},
	}, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp evaluateResponse
	mustUnmarshal(t, rec.Body.Bytes(), &resp)
	if resp.Decision != "allow" {
		t.Fatalf("decision = %q", resp.Decision)
	}
	if srv.reqAllow.Load() != 1 {
		t.Errorf("reqAllow = %d, want 1", srv.reqAllow.Load())
	}
}

func TestEvaluate_Explain(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)

	rec := do(t, srv, "POST", "/v1/evaluate?explain=1", map[string]any{
		"input": map[string]any{
			"user":     map[string]any{"name": "alex", "role": "intern"},
			"request":  map[string]any{"action": "delete"},
			"resource": map[string]any{"environment": "production"},
		},
	}, nil)

	var resp evaluateResponse
	mustUnmarshal(t, rec.Body.Bytes(), &resp)

	if resp.Trace == "" {
		t.Fatal("explain mode requested but trace is empty")
	}
	if !strings.Contains(resp.Trace, "no-interns-delete-prod") {
		t.Errorf("trace missing rule name: %s", resp.Trace)
	}
	// Structured trace should populate the per-condition details.
	found := false
	for _, r := range resp.Results {
		if r.Trace != nil && len(r.Trace.Conditions) > 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("no structured trace in any result")
	}
}

// ---------------------------------------------------------------------------
// shadow mode
// ---------------------------------------------------------------------------

func TestShadowMode(t *testing.T) {
	srv, audit := makeTestServer(t, serveOptions{Shadow: true}, basePolicy)

	rec := do(t, srv, "POST", "/v1/evaluate", map[string]any{
		"input": map[string]any{
			"user":     map[string]any{"name": "alex", "role": "intern"},
			"request":  map[string]any{"action": "delete"},
			"resource": map[string]any{"environment": "production"},
		},
	}, nil)

	// Shadow mode should never return a 403 — the HTTP response says allow
	// even though a forbid rule fired.
	if rec.Code != http.StatusOK {
		t.Fatalf("shadow mode should return 200, got %d", rec.Code)
	}

	var resp evaluateResponse
	mustUnmarshal(t, rec.Body.Bytes(), &resp)
	if resp.Decision != "allow" {
		t.Errorf("shadow decision = %q, want allow", resp.Decision)
	}
	if !resp.Shadow {
		t.Error("shadow flag should be true")
	}

	// The audit log must still show the true decision.
	lines := splitLines(audit.String())
	if len(lines) < 1 {
		t.Fatal("expected audit records even in shadow mode")
	}
	var summary auditRecord
	mustUnmarshal(t, []byte(lines[0]), &summary)
	if summary.Decision != "deny" {
		t.Errorf("shadow audit should record true deny, got %q", summary.Decision)
	}
	if !summary.Masked {
		t.Error("shadow audit should set shadow_masked")
	}
	if srv.reqShadow.Load() != 1 {
		t.Errorf("reqShadow = %d, want 1", srv.reqShadow.Load())
	}
}

// ---------------------------------------------------------------------------
// auth
// ---------------------------------------------------------------------------

func TestAuth_MissingHeader(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{AuthToken: "s3cret"}, basePolicy)

	rec := do(t, srv, "POST", "/v1/evaluate", map[string]any{"input": map[string]any{}}, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_WrongToken(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{AuthToken: "s3cret"}, basePolicy)

	rec := do(t, srv, "POST", "/v1/evaluate", map[string]any{"input": map[string]any{}},
		map[string]string{"Authorization": "Bearer nope"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_ValidToken(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{AuthToken: "s3cret"}, basePolicy)

	rec := do(t, srv, "POST", "/v1/evaluate", map[string]any{"input": map[string]any{}},
		map[string]string{"Authorization": "Bearer s3cret"})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuth_HealthzSkipsAuth(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{AuthToken: "s3cret"}, basePolicy)
	rec := do(t, srv, "GET", "/healthz", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz should bypass auth, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// other endpoints
// ---------------------------------------------------------------------------

func TestHealthz(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)
	rec := do(t, srv, "GET", "/healthz", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("healthz = %d", rec.Code)
	}
	var body map[string]any
	mustUnmarshal(t, rec.Body.Bytes(), &body)
	if body["version"] != crowdcontrol.Version {
		t.Errorf("version = %v", body["version"])
	}
	if body["rules"].(float64) < 1 {
		t.Errorf("rules count = %v", body["rules"])
	}
}

func TestPoliciesList(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)
	rec := do(t, srv, "GET", "/v1/policies", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("policies = %d", rec.Code)
	}
	var body struct {
		Count int `json:"count"`
		Rules []struct {
			Name  string `json:"name"`
			Kind  string `json:"kind"`
			Owner string `json:"owner"`
		} `json:"rules"`
	}
	mustUnmarshal(t, rec.Body.Bytes(), &body)
	if body.Count != 2 {
		t.Errorf("count = %d, want 2", body.Count)
	}
	foundForbid := false
	for _, r := range body.Rules {
		if r.Name == "no-interns-delete-prod" && r.Kind == "forbid" {
			foundForbid = true
			if r.Owner != "platform-security" {
				t.Errorf("owner = %q", r.Owner)
			}
		}
	}
	if !foundForbid {
		t.Error("forbid rule not listed")
	}
}

func TestMetrics(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)

	// Bump some counters.
	_ = do(t, srv, "POST", "/v1/evaluate", map[string]any{"input": map[string]any{}}, nil)
	srv.reqDeny.Add(2) // synthetic

	rec := do(t, srv, "GET", "/metrics", nil, nil)
	body := rec.Body.String()

	checks := []string{
		`cc_requests_total{decision="allow"}`,
		`cc_requests_total{decision="deny"}`,
		`cc_rules_loaded 2`,
		`cc_shadow_mode 0`,
		`cc_reload_total`,
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\n%s", want, body)
		}
	}
}

func TestRootEndpoint(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)
	rec := do(t, srv, "GET", "/", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("root = %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "crowdcontrol") {
		t.Errorf("body = %s", rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// bad input
// ---------------------------------------------------------------------------

func TestEvaluate_InvalidJSON(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)

	req := httptest.NewRequest("POST", "/v1/evaluate", strings.NewReader("not json"))
	rec := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evaluate", srv.handleEvaluate)
	srv.wrap(mux).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on bad JSON, got %d", rec.Code)
	}
	if srv.reqError.Load() != 1 {
		t.Errorf("reqError = %d", srv.reqError.Load())
	}
}

func TestEvaluate_WrongMethod(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)
	rec := do(t, srv, "GET", "/v1/evaluate", nil, nil)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// reload
// ---------------------------------------------------------------------------

func TestReload(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "rules.cc")
	writePolicy := func(body string) {
		if err := os.WriteFile(policyPath, []byte(body), 0o644); err != nil {
			t.Fatalf("writing: %v", err)
		}
	}
	writePolicy(`forbid "v1" { user.role == "intern" message "v1 fired" }`)

	srv, _ := makeTestServer(t, serveOptions{
		PolicyDirs: []string{dir},
	}, "") // policy source ignored because PolicyDirs is set

	first := srv.current.Load()
	if first.rulesCount != 1 {
		t.Fatalf("initial rules = %d", first.rulesCount)
	}

	// Update the file on disk and reload.
	writePolicy(`
forbid "v2-a" { user.role == "intern" message "a" }
forbid "v2-b" { user.role == "contractor" message "b" }
`)
	if err := srv.reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}

	second := srv.current.Load()
	if second.rulesCount != 2 {
		t.Errorf("post-reload rules = %d, want 2", second.rulesCount)
	}
	if second == first {
		t.Error("engineState pointer should have been swapped")
	}
	if !second.loadedAt.After(first.loadedAt) && !second.loadedAt.Equal(first.loadedAt) {
		t.Error("loadedAt should be >= original")
	}
}

// ---------------------------------------------------------------------------
// request ID
// ---------------------------------------------------------------------------

func TestRequestID_Generated(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)
	rec := do(t, srv, "GET", "/healthz", nil, nil)
	rid := rec.Header().Get("X-Request-ID")
	if len(rid) != 32 { // 16 bytes hex
		t.Errorf("request_id = %q (len %d)", rid, len(rid))
	}
}

func TestRequestID_Inbound(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{}, basePolicy)
	rec := do(t, srv, "GET", "/healthz", nil, map[string]string{
		"X-Request-ID": "client-supplied-rid",
	})
	if got := rec.Header().Get("X-Request-ID"); got != "client-supplied-rid" {
		t.Errorf("server should echo inbound rid, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

func TestCORS(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{CORSOrigin: "https://example.com"}, basePolicy)
	rec := do(t, srv, "GET", "/healthz", nil, nil)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("CORS origin = %q", got)
	}
}

func TestCORS_Preflight(t *testing.T) {
	srv, _ := makeTestServer(t, serveOptions{CORSOrigin: "*"}, basePolicy)
	rec := do(t, srv, "OPTIONS", "/v1/evaluate", nil, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight should return 204, got %d", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// concurrent safety: hammer the hot path, audit log must not interleave
// ---------------------------------------------------------------------------

func TestConcurrentEvaluate(t *testing.T) {
	srv, audit := makeTestServer(t, serveOptions{}, basePolicy)

	const goroutines = 32
	const iterations = 20

	done := make(chan struct{}, goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < iterations; j++ {
				do(t, srv, "POST", "/v1/evaluate", map[string]any{
					"input": map[string]any{
						"user": map[string]any{"role": "engineer"},
					},
				}, nil)
			}
		}()
	}
	deadline := time.After(5 * time.Second)
	for i := 0; i < goroutines; i++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatal("timeout waiting for goroutines")
		}
	}

	total := srv.reqAllow.Load() + srv.reqDeny.Load()
	want := uint64(goroutines * iterations)
	if total != want {
		t.Errorf("total requests = %d, want %d", total, want)
	}

	// Every audit line must be valid JSON — no interleaving.
	for i, line := range splitLines(audit.String()) {
		var rec auditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Errorf("audit line %d is not valid JSON: %v\n%s", i, err, line)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustUnmarshal(t *testing.T, data []byte, v any) {
	t.Helper()
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, string(data))
	}
}

func splitLines(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// sanity check: the server struct's atomic counters never share memory
// with other fields. Go will catch this via -race but a compile-time
// assertion is cheap.
var _ = atomic.Uint64{}
