// cc serve — HTTP policy decision point mode.
//
// Wraps the same Engine used by the rest of the CLI in an HTTP server so
// that callers in other languages (or separate processes) can get policy
// decisions without embedding an SDK. Also emits structured audit logs
// so every decision is traceable after the fact.
//
// Design goals:
//
//   - Zero external dependencies. Everything uses the Go standard library,
//     consistent with the rest of CrowdControl.
//   - Lock-free on the hot path. The active Engine is held in an
//     atomic.Pointer and swapped atomically on SIGHUP reload. Evaluate()
//     calls don't take any mutex.
//   - Structured, greppable audit logs. Each fired rule emits one JSON
//     line with request_id, rule, kind, owner, decision, elapsed_us, and
//     a SHA-256 of the input document.
//   - Safe by default. Shadow mode evaluates policies and emits audit
//     records but never returns "deny" to the caller — useful for dark-
//     launching a new policy.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/mikemackintosh/crowdcontrol"
	"github.com/mikemackintosh/crowdcontrol/evaluator"
	"github.com/mikemackintosh/crowdcontrol/types"
)

// ---------------------------------------------------------------------------
// serve options
// ---------------------------------------------------------------------------

type serveOptions struct {
	Addr          string
	PolicyDirs    []string
	DefaultEffect types.DefaultEffect
	AuditLog      string
	Shadow        bool
	AuthToken     string
	CORSOrigin    string
}

// engineState holds everything a request handler needs. One immutable
// engineState is published atomically whenever policies reload.
type engineState struct {
	engine     *crowdcontrol.Engine
	rulesCount int
	loadedAt   time.Time
}

// server is the HTTP PDP. It holds an atomic pointer to the current
// engineState plus counters for the metrics endpoint.
type server struct {
	opts     serveOptions
	current  atomic.Pointer[engineState]
	audit    io.Writer // may be nil if audit logging is disabled
	auditMu  atomic.Int64

	// metrics
	reqAllow     atomic.Uint64
	reqDeny      atomic.Uint64
	reqShadow    atomic.Uint64
	reqError     atomic.Uint64
	reloadCount  atomic.Uint64
	reloadErrors atomic.Uint64
	startedAt    time.Time
}

// ---------------------------------------------------------------------------
// CLI entry point
// ---------------------------------------------------------------------------

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "HTTP listen address")
	defaultEffect := fs.String("default-effect", "allow", "default effect when no rule matches: allow | deny")
	auditLog := fs.String("audit-log", "", "audit log path (use '-' for stdout, empty to disable)")
	shadow := fs.Bool("shadow", false, "shadow mode: evaluate + audit but never return deny")
	authToken := fs.String("auth-token", "", "require 'Authorization: Bearer <token>' header")
	corsOrigin := fs.String("cors", "", "CORS Access-Control-Allow-Origin value (e.g. '*' or 'https://app.example.com')")

	var policyDirs multiFlag
	fs.Var(&policyDirs, "policy", "policy directory (repeatable)")

	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `cc serve — run CrowdControl as an HTTP policy decision point

USAGE:
    cc serve --policy <dir> [--policy <dir> ...] [flags]

FLAGS:
`)
		fs.PrintDefaults()
		fmt.Fprint(fs.Output(), `
ENDPOINTS:
    GET  /healthz         liveness + version + loaded rule count
    GET  /readyz          readiness probe
    GET  /metrics         Prometheus-style text metrics
    GET  /v1/policies     list loaded rules (metadata only)
    POST /v1/evaluate     evaluate an input document

SIGNALS:
    SIGHUP                reload policies from disk (atomic swap)
    SIGINT, SIGTERM       graceful shutdown

EXAMPLES:
    cc serve --policy ./policies --addr :8080
    cc serve --policy ./policies --audit-log /var/log/cc.jsonl
    cc serve --policy ./policies --shadow --audit-log -
`)
	}

	fs.Parse(args)

	if len(policyDirs) == 0 {
		log.Fatal("serve requires at least one --policy directory")
	}

	var def types.DefaultEffect
	switch *defaultEffect {
	case "allow":
		def = types.DefaultAllow
	case "deny":
		def = types.DefaultDeny
	default:
		log.Fatalf("invalid --default-effect %q (allow|deny)", *defaultEffect)
	}

	opts := serveOptions{
		Addr:          *addr,
		PolicyDirs:    policyDirs,
		DefaultEffect: def,
		AuditLog:      *auditLog,
		Shadow:        *shadow,
		AuthToken:     *authToken,
		CORSOrigin:    *corsOrigin,
	}

	if err := serveMain(opts); err != nil {
		log.Fatal(err)
	}
}

// serveMain is split out so tests can drive it without exiting the process.
func serveMain(opts serveOptions) error {
	srv, err := newServer(opts)
	if err != nil {
		return err
	}
	defer srv.close()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/readyz", srv.handleReadyz)
	mux.HandleFunc("/metrics", srv.handleMetrics)
	mux.HandleFunc("/v1/policies", srv.handlePolicies)
	mux.HandleFunc("/v1/evaluate", srv.handleEvaluate)
	mux.HandleFunc("/", srv.handleRoot)

	httpSrv := &http.Server{
		Addr:              opts.Addr,
		Handler:           srv.wrap(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Handle signals: SIGHUP = reload, SIGINT/SIGTERM = graceful shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})

	go func() {
		for s := range sigs {
			switch s {
			case syscall.SIGHUP:
				log.Printf("SIGHUP received — reloading policies from %v", opts.PolicyDirs)
				if err := srv.reload(); err != nil {
					log.Printf("reload failed: %v", err)
					srv.reloadErrors.Add(1)
				} else {
					srv.reloadCount.Add(1)
					st := srv.current.Load()
					log.Printf("reloaded: %d rules", st.rulesCount)
				}
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("%s received — shutting down", s)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = httpSrv.Shutdown(ctx)
				close(done)
				return
			}
		}
	}()

	shadowNote := ""
	if opts.Shadow {
		shadowNote = " [SHADOW]"
	}
	st := srv.current.Load()
	log.Printf("cc serve listening on %s with %d rules%s", opts.Addr, st.rulesCount, shadowNote)

	if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("listen: %w", err)
	}
	<-done
	return nil
}

// ---------------------------------------------------------------------------
// server construction and reload
// ---------------------------------------------------------------------------

func newServer(opts serveOptions) (*server, error) {
	s := &server{opts: opts, startedAt: time.Now().UTC()}

	// Open the audit log first so a bad path fails fast.
	w, err := openAuditLog(opts.AuditLog)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	s.audit = w

	if err := s.reload(); err != nil {
		return nil, fmt.Errorf("loading policies: %w", err)
	}
	return s, nil
}

func (s *server) close() {
	if closer, ok := s.audit.(io.Closer); ok && s.audit != os.Stdout && s.audit != os.Stderr {
		_ = closer.Close()
	}
}

func (s *server) reload() error {
	eng, err := crowdcontrol.New(s.opts.PolicyDirs,
		crowdcontrol.WithDefaultEffect(s.opts.DefaultEffect),
	)
	if err != nil {
		return err
	}
	count := 0
	for _, p := range eng.Policies() {
		count += len(p.Rules)
	}
	st := &engineState{
		engine:     eng,
		rulesCount: count,
		loadedAt:   time.Now().UTC(),
	}
	s.current.Store(st)
	return nil
}

func openAuditLog(path string) (io.Writer, error) {
	switch path {
	case "":
		return io.Discard, nil
	case "-", "stdout":
		return os.Stdout, nil
	case "stderr":
		return os.Stderr, nil
	default:
		return os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	}
}

// ---------------------------------------------------------------------------
// middleware: auth, CORS, request ID, logging
// ---------------------------------------------------------------------------

type ctxKey int

const ctxKeyRequestID ctxKey = 1

func (s *server) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Request ID: prefer inbound header, otherwise generate.
		rid := r.Header.Get("X-Request-ID")
		if rid == "" {
			rid = newRequestID()
		}
		w.Header().Set("X-Request-ID", rid)
		ctx := context.WithValue(r.Context(), ctxKeyRequestID, rid)
		r = r.WithContext(ctx)

		// CORS.
		if s.opts.CORSOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", s.opts.CORSOrigin)
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		// Bearer auth. Health and readiness skip auth so k8s probes work.
		if s.opts.AuthToken != "" && !isPublicPath(r.URL.Path) {
			if !checkBearer(r.Header.Get("Authorization"), s.opts.AuthToken) {
				s.reqError.Add(1)
				writeJSON(w, http.StatusUnauthorized, map[string]any{
					"error": "unauthorized",
				})
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func isPublicPath(p string) bool {
	return p == "/healthz" || p == "/readyz"
}

func checkBearer(hdr, want string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(hdr, prefix) {
		return false
	}
	got := strings.TrimPrefix(hdr, prefix)
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a timestamp — still unique enough for correlation.
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

func requestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return v
	}
	return ""
}

// ---------------------------------------------------------------------------
// handlers
// ---------------------------------------------------------------------------

func (s *server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    "crowdcontrol",
		"version": crowdcontrol.Version,
		"endpoints": []string{
			"GET /healthz", "GET /readyz", "GET /metrics",
			"GET /v1/policies", "POST /v1/evaluate",
		},
	})
}

func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	st := s.current.Load()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "ok",
		"version":    crowdcontrol.Version,
		"rules":      st.rulesCount,
		"loaded_at":  st.loadedAt.Format(time.RFC3339),
		"shadow":     s.opts.Shadow,
		"started_at": s.startedAt.Format(time.RFC3339),
	})
}

func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	st := s.current.Load()
	if st == nil || st.engine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ready": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ready": true})
}

func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	st := s.current.Load()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP cc_requests_total Total evaluate requests by decision.\n")
	fmt.Fprintf(w, "# TYPE cc_requests_total counter\n")
	fmt.Fprintf(w, "cc_requests_total{decision=\"allow\"} %d\n", s.reqAllow.Load())
	fmt.Fprintf(w, "cc_requests_total{decision=\"deny\"} %d\n", s.reqDeny.Load())
	fmt.Fprintf(w, "cc_requests_total{decision=\"shadow_masked_deny\"} %d\n", s.reqShadow.Load())
	fmt.Fprintf(w, "cc_requests_total{decision=\"error\"} %d\n", s.reqError.Load())

	fmt.Fprintf(w, "# HELP cc_rules_loaded Number of rules currently loaded.\n")
	fmt.Fprintf(w, "# TYPE cc_rules_loaded gauge\n")
	fmt.Fprintf(w, "cc_rules_loaded %d\n", st.rulesCount)

	fmt.Fprintf(w, "# HELP cc_reload_total Number of successful policy reloads since start.\n")
	fmt.Fprintf(w, "# TYPE cc_reload_total counter\n")
	fmt.Fprintf(w, "cc_reload_total %d\n", s.reloadCount.Load())

	fmt.Fprintf(w, "# HELP cc_reload_errors_total Number of failed policy reloads since start.\n")
	fmt.Fprintf(w, "# TYPE cc_reload_errors_total counter\n")
	fmt.Fprintf(w, "cc_reload_errors_total %d\n", s.reloadErrors.Load())

	fmt.Fprintf(w, "# HELP cc_shadow_mode 1 if shadow mode is enabled, 0 otherwise.\n")
	fmt.Fprintf(w, "# TYPE cc_shadow_mode gauge\n")
	shadow := 0
	if s.opts.Shadow {
		shadow = 1
	}
	fmt.Fprintf(w, "cc_shadow_mode %d\n", shadow)
}

func (s *server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "use GET"})
		return
	}
	st := s.current.Load()
	type ruleInfo struct {
		Name        string `json:"name"`
		Kind        string `json:"kind"`
		Description string `json:"description,omitempty"`
		Owner       string `json:"owner,omitempty"`
		Link        string `json:"link,omitempty"`
	}
	var rules []ruleInfo
	for _, p := range st.engine.Policies() {
		for _, rl := range p.Rules {
			rules = append(rules, ruleInfo{
				Name:        rl.Name,
				Kind:        string(rl.Kind),
				Description: rl.Description,
				Owner:       rl.Owner,
				Link:        rl.Link,
			})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"count":     len(rules),
		"rules":     rules,
		"loaded_at": st.loadedAt.Format(time.RFC3339),
	})
}

// evaluateRequest is the JSON body shape accepted by POST /v1/evaluate.
type evaluateRequest struct {
	Input   map[string]any `json:"input"`
	Explain bool           `json:"explain,omitempty"`
}

// resultJSON is the over-the-wire form of a types.Result. We define it
// locally so the HTTP API owns its field names (snake_case) without
// polluting the core types with json tags.
type resultJSON struct {
	Rule        string     `json:"rule"`
	Kind        string     `json:"kind"`
	Passed      bool       `json:"passed"`
	Message     string     `json:"message,omitempty"`
	Description string     `json:"description,omitempty"`
	Owner       string     `json:"owner,omitempty"`
	Link        string     `json:"link,omitempty"`
	Trace       *traceJSON `json:"trace,omitempty"`
}

type traceJSON struct {
	Conditions           []conditionJSON `json:"conditions,omitempty"`
	Unlesses             []conditionJSON `json:"unlesses,omitempty"`
	AllConditionsMatched bool            `json:"all_conditions_matched"`
	SavedByUnless        bool            `json:"saved_by_unless,omitempty"`
}

type conditionJSON struct {
	Expr     string          `json:"expr"`
	Result   bool            `json:"result"`
	Actual   string          `json:"actual,omitempty"`
	Children []conditionJSON `json:"children,omitempty"`
}

func toResultJSON(results []types.Result) []resultJSON {
	out := make([]resultJSON, len(results))
	for i, r := range results {
		out[i] = resultJSON{
			Rule:        r.Rule,
			Kind:        r.Kind,
			Passed:      r.Passed,
			Message:     r.Message,
			Description: r.Description,
			Owner:       r.Owner,
			Link:        r.Link,
		}
		if r.Trace != nil {
			out[i].Trace = &traceJSON{
				Conditions:           toConditionJSON(r.Trace.Conditions),
				Unlesses:             toConditionJSON(r.Trace.Unlesses),
				AllConditionsMatched: r.Trace.AllConditionsMatched,
				SavedByUnless:        r.Trace.SavedByUnless,
			}
		}
	}
	return out
}

func toConditionJSON(cs []types.ConditionTrace) []conditionJSON {
	if len(cs) == 0 {
		return nil
	}
	out := make([]conditionJSON, len(cs))
	for i, c := range cs {
		out[i] = conditionJSON{
			Expr:     c.Expr,
			Result:   c.Result,
			Actual:   c.Actual,
			Children: toConditionJSON(c.Children),
		}
	}
	return out
}

// evaluateResponse is what the server sends back.
type evaluateResponse struct {
	RequestID   string       `json:"request_id"`
	Decision    string       `json:"decision"`
	Shadow      bool         `json:"shadow,omitempty"`
	Results     []resultJSON `json:"results"`
	Trace       string       `json:"trace,omitempty"`
	ElapsedUS   int64        `json:"elapsed_us"`
	EvaluatedAt string       `json:"evaluated_at"`
}

func (s *server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "use POST"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20)) // 4 MiB cap
	if err != nil {
		s.reqError.Add(1)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "reading body: " + err.Error()})
		return
	}

	var req evaluateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.reqError.Add(1)
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON: " + err.Error()})
		return
	}
	if req.Input == nil {
		req.Input = map[string]any{}
	}

	// Explain mode needs a fresh engine wrapper because the flag is
	// construction-time on the evaluator. We only go the slow path when
	// the caller explicitly asks for it.
	st := s.current.Load()
	eng := st.engine
	var results []types.Result
	var trace string

	start := time.Now()
	if req.Explain || queryFlag(r, "explain") {
		// Rebuild an engine with explain enabled. Uses the same parsed
		// policies from the currently-loaded state, so we don't re-read
		// the filesystem.
		explainEng := evaluator.NewFromPolicies(eng.Policies(),
			evaluator.WithDefaultEffect(s.opts.DefaultEffect),
			evaluator.WithExplain(true),
		)
		results = explainEng.Evaluate(req.Input)
		trace = evaluator.FormatExplain(results)
	} else {
		results = eng.Evaluate(req.Input)
	}
	elapsed := time.Since(start).Microseconds()

	// Compute decision.
	trueDecision := decisionFromResults(results)
	outDecision := trueDecision
	maskedByShadow := false
	if s.opts.Shadow && trueDecision == "deny" {
		outDecision = "allow"
		maskedByShadow = true
		s.reqShadow.Add(1)
	} else if trueDecision == "allow" {
		s.reqAllow.Add(1)
	} else {
		s.reqDeny.Add(1)
	}

	// Audit log: one record per response, plus one per fired deny rule.
	rid := requestID(r.Context())
	inputHash := hashInput(body)
	s.writeAudit(auditRecord{
		TS:          time.Now().UTC().Format(time.RFC3339Nano),
		RequestID:   rid,
		Decision:    trueDecision,
		Masked:      maskedByShadow,
		ElapsedUS:   elapsed,
		InputSHA256: inputHash,
	})
	for _, res := range results {
		if !res.Passed {
			s.writeAudit(auditRecord{
				TS:          time.Now().UTC().Format(time.RFC3339Nano),
				RequestID:   rid,
				Decision:    "rule_fired",
				Rule:        res.Rule,
				Kind:        string(res.Kind),
				Owner:       res.Owner,
				Message:     res.Message,
				Masked:      maskedByShadow,
				ElapsedUS:   elapsed,
				InputSHA256: inputHash,
			})
		}
	}

	resp := evaluateResponse{
		RequestID:   rid,
		Decision:    outDecision,
		Shadow:      maskedByShadow,
		Results:     toResultJSON(results),
		Trace:       trace,
		ElapsedUS:   elapsed,
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	status := http.StatusOK
	if outDecision == "deny" {
		status = http.StatusForbidden
	}
	writeJSON(w, status, resp)
}

func queryFlag(r *http.Request, key string) bool {
	v := r.URL.Query().Get(key)
	return v == "1" || v == "true" || v == "yes"
}

// decisionFromResults collapses the per-rule results into a single
// allow/deny decision, matching the semantics in evaluator.FormatResults.
func decisionFromResults(results []types.Result) string {
	for _, r := range results {
		if !r.Passed {
			return "deny"
		}
	}
	return "allow"
}

func hashInput(body []byte) string {
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// audit log
// ---------------------------------------------------------------------------

type auditRecord struct {
	TS          string `json:"ts"`
	RequestID   string `json:"request_id"`
	Decision    string `json:"decision"`
	Rule        string `json:"rule,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Owner       string `json:"owner,omitempty"`
	Message     string `json:"message,omitempty"`
	Masked      bool   `json:"shadow_masked,omitempty"`
	ElapsedUS   int64  `json:"elapsed_us,omitempty"`
	InputSHA256 string `json:"input_sha256,omitempty"`
}

// writeAudit serializes a record as a single JSON line. Writes are
// serialized via the auditMu counter to avoid interleaved lines from
// concurrent requests.
func (s *server) writeAudit(rec auditRecord) {
	if s.audit == nil || s.audit == io.Discard {
		return
	}
	buf := bytes.NewBuffer(make([]byte, 0, 256))
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(rec) // encoder appends a trailing newline
	// Serialize the write. auditMu is a cheap spin via atomic — real
	// concurrent load would warrant a sync.Mutex, but the audit path is
	// already dominated by the Write syscall, so an atomic fence is fine.
	for !s.auditMu.CompareAndSwap(0, 1) {
		// busy wait — contention here is bounded by the number of
		// goroutines issuing writes, which in turn is bounded by the
		// server's max concurrency. Good enough for v1.
	}
	_, _ = s.audit.Write(buf.Bytes())
	s.auditMu.Store(0)
}

// ---------------------------------------------------------------------------
// json helpers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}
