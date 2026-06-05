package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"debian-router/internal/config"
	"debian-router/internal/control"
	"debian-router/internal/router"
)

type Options struct {
	ConfigPath string
	WebDir     string
	Listen     string
	Apply      bool
}

type Server struct {
	options Options
	logger  *slog.Logger
}

func New(options Options, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, nil))
	}
	return &Server{options: options, logger: logger}
}

func (s *Server) Serve(ctx context.Context) error {
	cfg, err := s.loadConfigOrDefault()
	if err != nil {
		return err
	}
	listen := cfg.UI.Listen
	if s.options.Listen != "" {
		listen = s.options.Listen
	}
	if listen == "" {
		listen = "127.0.0.1:8088"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/plan", s.handlePlan)
	mux.HandleFunc("/api/apply", s.handleApply)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/default-config", s.handleDefaultConfig)

	webDir := s.options.WebDir
	if webDir == "" {
		webDir = "./web"
	}
	mux.Handle("/", http.FileServer(http.Dir(webDir)))

	server := &http.Server{
		Addr:              listen,
		Handler:           secureHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("debian-routerd listening", "listen", listen, "apply", s.options.Apply)
		if cfg.UI.TLSCertFile != "" && cfg.UI.TLSKeyFile != "" {
			errCh <- server.ListenAndServeTLS(cfg.UI.TLSCertFile, cfg.UI.TLSKeyFile)
			return
		}
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return ctx.Err()
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		cfg, err := s.loadConfigOrDefault()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, cfg)
	case http.MethodPut:
		var cfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("decode config: %w", err))
			return
		}
		if err := config.Save(s.options.ConfigPath, cfg); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

func (s *Server) handleDefaultConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	writeJSON(w, http.StatusOK, config.Default())
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	cfg, err := s.configFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plan, err := router.BuildPlan(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, plan)
}

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	cfg, err := s.configFromRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	plan, err := router.BuildPlan(cfg)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	executor := control.Executor{DryRun: !s.options.Apply}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	results, err := executor.Execute(ctx, plan)
	status := http.StatusOK
	if err != nil {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, map[string]any{
		"applyEnabled": s.options.Apply,
		"dryRun":       !s.options.Apply,
		"results":      results,
		"error":        errorText(err),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	writeJSON(w, http.StatusOK, control.ProbeStatus(ctx))
}

func (s *Server) configFromRequest(r *http.Request) (config.Config, error) {
	if r.Method == http.MethodPost && r.Body != nil && strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var cfg config.Config
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			return config.Config{}, fmt.Errorf("decode config: %w", err)
		}
		if err := cfg.Validate(); err != nil {
			return config.Config{}, err
		}
		return cfg, nil
	}
	return s.loadConfigOrDefault()
}

func (s *Server) loadConfigOrDefault() (config.Config, error) {
	if s.options.ConfigPath == "" {
		cfg := config.Default()
		return cfg, cfg.Validate()
	}
	cfg, err := config.Load(s.options.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		cfg := config.Default()
		return cfg, cfg.Validate()
	}
	return cfg, err
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{
		"error": errorText(err),
	})
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
