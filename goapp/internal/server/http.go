package server

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"puncture-go/internal/app"
)

//go:embed static/index.html
var staticFS embed.FS

type HTTPServer struct {
	state       *app.AppState
	remoteToken string
	mux         *http.ServeMux
}

func New(state *app.AppState, remoteToken string) *HTTPServer {
	s := &HTTPServer{state: state, remoteToken: strings.TrimSpace(remoteToken), mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *HTTPServer) Handler() http.Handler { return s.mux }

func (s *HTTPServer) routes() {
	s.mux.HandleFunc("/", s.handleIndex)
	s.mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	s.mux.HandleFunc("/api/state", s.handleState)
	s.mux.HandleFunc("/api/live/state", s.handleState)
	s.mux.HandleFunc("/api/export", s.handleExport)
	s.mux.HandleFunc("/api/reset", s.handleReset)

	s.mux.HandleFunc("/api/derive", s.handleDerive)
	s.mux.HandleFunc("/api/puncture", s.handlePuncture)
	s.mux.HandleFunc("/api/remote/puncture-provider", s.handleRemotePunctureProvider)

	s.mux.HandleFunc("/api/providers/add", s.handleProviderAdd)
	s.mux.HandleFunc("/api/providers/edit", s.handleProviderEdit)
	s.mux.HandleFunc("/api/providers/delete", s.handleProviderDelete)

	s.mux.HandleFunc("/api/assets/upload", s.handleAssetUpload)
	s.mux.HandleFunc("/api/assets/encrypt", s.handleAssetEncrypt)
	s.mux.HandleFunc("/api/assets/decrypt", s.handleAssetDecrypt)
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func (s *HTTPServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	blob, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(blob)
}

func (s *HTTPServer) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	blob, err := s.state.ExportStateJSON()
	if err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(blob)
}

func (s *HTTPServer) handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	if err := s.state.Reset(); err != nil {
		writeJSON(w, 500, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleDerive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var req struct {
		ProviderID int    `json:"provider_id"`
		FileTimeID int    `json:"file_time_id"`
		Purpose    string `json:"purpose"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.state.Derive(req.ProviderID, req.FileTimeID, req.Purpose); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handlePuncture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var req struct {
		ProviderID int `json:"provider_id"`
		FileTimeID int `json:"file_time_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.state.Puncture(req.ProviderID, req.FileTimeID); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleRemotePunctureProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	provided := r.Header.Get("X-Puncture-Token")
	if !s.state.RemoteTokenValid(provided, s.remoteToken) {
		writeJSON(w, 403, map[string]any{"ok": false, "error": "unauthorized"})
		return
	}
	var req struct {
		ProviderID int `json:"provider_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.state.PunctureProvider(req.ProviderID); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "provider_id": req.ProviderID, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleProviderAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var req struct {
		ProviderID  int    `json:"provider_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.state.AddProvider(req.ProviderID, req.Name, req.Description); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleProviderEdit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var req struct {
		ProviderID  int    `json:"provider_id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.state.EditProvider(req.ProviderID, req.Name, req.Description); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleProviderDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var req struct {
		ProviderID int `json:"provider_id"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := s.state.DeleteProvider(req.ProviderID); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": s.state.Snapshot()})
}

func filesFromRequest(r *http.Request) ([]*multipart.FileHeader, string, error) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		return nil, "", err
	}
	form := r.MultipartForm
	if form == nil {
		return nil, "", fmt.Errorf("multipart form missing")
	}
	files := form.File["files"]
	if len(files) == 0 {
		files = form.File["file"]
	}
	target := r.FormValue("target_subdir")
	return files, target, nil
}

func (s *HTTPServer) handleAssetUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	files, target, err := filesFromRequest(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	saved, err := s.state.SaveUploads(files, target)
	if err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error(), "state": s.state.Snapshot()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "uploaded": saved, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleAssetEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var req struct {
		PlaintextRelpaths []string `json:"plaintext_relpaths"`
		ProviderID        int      `json:"provider_id"`
		FileTimeID        int      `json:"file_time_id"`
		Purpose           string   `json:"purpose"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	saved, errs, err := s.state.Encrypt(req.PlaintextRelpaths, req.ProviderID, req.FileTimeID, req.Purpose)
	if err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error(), "errors": errs, "state": s.state.Snapshot()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "saved": saved, "errors": errs, "state": s.state.Snapshot()})
}

func (s *HTTPServer) handleAssetDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "method not allowed"})
		return
	}
	var req struct {
		RecordIDs []int `json:"record_ids"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	restored, errs, err := s.state.Decrypt(req.RecordIDs)
	if err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "error": err.Error(), "errors": errs, "state": s.state.Snapshot()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "restored": restored, "errors": errs, "state": s.state.Snapshot()})
}

func Run(addr, assetRoot string) error {
	state, err := app.NewAppState(assetRoot)
	if err != nil {
		return err
	}
	remoteToken := os.Getenv("PUNCTURE_REMOTE_TOKEN")
	h := New(state, remoteToken)
	server := &http.Server{Addr: addr, Handler: loggingMiddleware(h.Handler())}
	log.Printf("puncture-go server listening on %s", addr)
	return server.ListenAndServe()
}

func Start(addr, assetRoot string) (*http.Server, *app.AppState, error) {
	state, err := app.NewAppState(assetRoot)
	if err != nil {
		return nil, nil, err
	}
	remoteToken := os.Getenv("PUNCTURE_REMOTE_TOKEN")
	h := New(state, remoteToken)
	srv := &http.Server{Addr: addr, Handler: loggingMiddleware(h.Handler())}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("server error: %v", err)
		}
	}()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/healthz", nil)
		resp, err := http.DefaultClient.Do(req)
		if err == nil && resp != nil && resp.StatusCode == 200 {
			_ = resp.Body.Close()
			cancel()
			return srv, state, nil
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
		cancel()
		time.Sleep(120 * time.Millisecond)
	}
	return nil, nil, fmt.Errorf("server did not start in time on %s", addr)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start).Truncate(time.Millisecond))
	})
}

func ParseAddr(host string, port int) string {
	if host == "" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = 9122
	}
	return host + ":" + strconv.Itoa(port)
}
