package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"attackgraph/api/internal/migrations"
	"attackgraph/api/internal/provision"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type Principal struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}
type principalKey struct{}
type authKey struct{}
type loginAttempt struct {
	Count  int
	Window time.Time
}
type AuthStore struct {
	Pool         *pgxpool.Pool
	CookieSecure bool
	DummyHash    []byte
	mu           sync.Mutex
	attempts     map[string]loginAttempt
}

func initPostgres(ctx context.Context) (*AuthStore, error) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://attackgraph:attackgraph-postgres-local-only@localhost:5432/attackgraph?sslmode=disable"
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	var pingErr error
	for i := 0; i < 30; i++ {
		pingErr = pool.Ping(ctx)
		if pingErr == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if pingErr != nil {
		pool.Close()
		return nil, pingErr
	}
	if err = migrations.Apply(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	store := &AuthStore{Pool: pool, CookieSecure: os.Getenv("COOKIE_SECURE") == "true", attempts: map[string]loginAttempt{}}
	store.DummyHash, err = bcrypt.GenerateFromPassword([]byte("no-such-demo-account"), 12)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if os.Getenv("DEMO_MODE") == "true" {
		if err = store.seedDemo(ctx); err != nil {
			pool.Close()
			return nil, err
		}
	}
	return store, nil
}
func (a *AuthStore) seedDemo(ctx context.Context) error {
	first := os.Getenv("DEMO_PASSWORD")
	second := os.Getenv("SECOND_DEMO_PASSWORD")
	viewer := os.Getenv("DEMO_VIEWER_PASSWORD")
	if len(first) < 12 || len(second) < 12 || len(viewer) < 12 {
		return errors.New("demo passwords must be at least 12 characters")
	}
	tx, err := a.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, org := range [][2]string{{"org-northstar", "Northstar Financial"}, {"org-harbor", "Harbor Labs"}} {
		if _, err = tx.Exec(ctx, "INSERT INTO organizations(id,name) VALUES($1,$2) ON CONFLICT(id) DO NOTHING", org[0], org[1]); err != nil {
			return err
		}
	}
	for _, env := range [][4]string{{"northstar", "org-northstar", "Northstar Financial", "Synthetic enterprise demo"}, {"harbor", "org-harbor", "Harbor Labs", "Isolated empty synthetic tenant"}} {
		if _, err = tx.Exec(ctx, "INSERT INTO environments(id,organization_id,name,description) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING", env[0], env[1], env[2], env[3]); err != nil {
			return err
		}
	}
	for _, user := range [][5]string{{"user-northstar", "analyst@northstar.local", first, "org-northstar", "admin"}, {"user-harbor", "analyst@harbor.local", second, "org-harbor", "admin"}, {"user-northstar-viewer", "viewer@northstar.local", viewer, "org-northstar", "viewer"}} {
		hash, e := bcrypt.GenerateFromPassword([]byte(user[2]), 12)
		if e != nil {
			return e
		}
		if _, err = tx.Exec(ctx, "INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING", user[0], user[1], string(hash)); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO memberships(user_id,organization_id,role) VALUES($1,$2,$3) ON CONFLICT(user_id,organization_id) DO NOTHING", user[0], user[3], user[4]); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (a *AuthStore) allowAttempt(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	v := a.attempts[host]
	if now.Sub(v.Window) > time.Minute {
		v = loginAttempt{Window: now}
	}
	v.Count++
	a.attempts[host] = v
	return v.Count <= 10
}
func (a *AuthStore) login(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r.RemoteAddr) {
		fail(w, 429, "rate_limited", "Too many login attempts")
		return
	}
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	if len(input.Email) > 254 || len(input.Password) > 256 || input.Email == "" || input.Password == "" {
		fail(w, 400, "invalid_login", "Email and password are required")
		return
	}
	var user Principal
	var hash string
	err := a.Pool.QueryRow(r.Context(), "SELECT id,email,password_hash FROM users WHERE lower(email)=lower($1)", strings.TrimSpace(input.Email)).Scan(&user.ID, &user.Email, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		hash = string(a.DummyHash)
	} else if err != nil {
		fail(w, 500, "database_error", "Could not sign in")
		return
	}
	compareErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(input.Password))
	if err != nil || compareErr != nil {
		fail(w, 401, "invalid_credentials", "Invalid email or password")
		return
	}
	var tokenBytes [32]byte
	if _, err = rand.Read(tokenBytes[:]); err != nil {
		fail(w, 500, "session_error", "Could not create session")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	tokenHash := sha256.Sum256([]byte(token))
	expiry := time.Now().Add(8 * time.Hour)
	if _, err = a.Pool.Exec(r.Context(), "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES($1,$2,$3)", tokenHash[:], user.ID, expiry); err != nil {
		fail(w, 500, "session_error", "Could not create session")
		return
	}
	_, _ = a.Pool.Exec(r.Context(), "DELETE FROM sessions WHERE expires_at < now()")
	http.SetCookie(w, &http.Cookie{Name: "attackgraph_session", Value: token, Path: "/api", HttpOnly: true, Secure: a.CookieSecure, SameSite: http.SameSiteStrictMode, Expires: expiry, MaxAge: int((8 * time.Hour).Seconds())})
	write(w, 200, user)
}
func (a *AuthStore) session(ctx context.Context, r *http.Request) (Principal, error) {
	var p Principal
	cookie, err := r.Cookie("attackgraph_session")
	if err != nil {
		return p, err
	}
	hash := sha256.Sum256([]byte(cookie.Value))
	err = a.Pool.QueryRow(ctx, "SELECT u.id,u.email FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=$1 AND s.expires_at>now()", hash[:]).Scan(&p.ID, &p.Email)
	return p, err
}
func (a *AuthStore) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("attackgraph_session"); err == nil {
		hash := sha256.Sum256([]byte(cookie.Value))
		_, _ = a.Pool.Exec(r.Context(), "DELETE FROM sessions WHERE token_hash=$1", hash[:])
	}
	http.SetCookie(w, &http.Cookie{Name: "attackgraph_session", Value: "", Path: "/api", HttpOnly: true, Secure: a.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	write(w, 200, map[string]string{"status": "signed_out"})
}
func principal(r *http.Request) Principal {
	v, _ := r.Context().Value(principalKey{}).(Principal)
	return v
}
func (a *AuthStore) authorize(w http.ResponseWriter, r *http.Request, envID string, writeAccess bool) bool {
	p := principal(r)
	if p.ID == "" {
		fail(w, 401, "unauthorized", "Sign in required")
		return false
	}
	var role string
	err := a.Pool.QueryRow(r.Context(), "SELECT m.role FROM environments e JOIN memberships m ON m.organization_id=e.organization_id WHERE e.id=$1 AND m.user_id=$2", envID, p.ID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "not_found", "Environment not found")
		return false
	}
	if err != nil {
		fail(w, 500, "database_error", "Could not check access")
		return false
	}
	if writeAccess && role == "viewer" {
		fail(w, 403, "forbidden", "Editor role required")
		return false
	}
	return true
}
func (a *AuthStore) registerAuthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", a.login)
	mux.HandleFunc("POST /api/v1/auth/logout", a.logout)
	mux.HandleFunc("GET /api/v1/auth/me", func(w http.ResponseWriter, r *http.Request) { write(w, 200, principal(r)) })
	mux.HandleFunc("POST /api/v1/auth/change-password", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if !decode(w, r, &input) {
			return
		}
		if err := provision.ValidatePassword(input.NewPassword); err != nil {
			fail(w, 422, "invalid_password", err.Error())
			return
		}
		err := provision.ChangePassword(r.Context(), a.Pool, principal(r).ID, input.CurrentPassword, input.NewPassword)
		if errors.Is(err, provision.ErrInvalidCredentials) {
			fail(w, 403, "invalid_current_password", "Current password is incorrect")
			return
		}
		if errors.Is(err, provision.ErrPasswordUnchanged) {
			fail(w, 422, "invalid_password", err.Error())
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not change password")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "attackgraph_session", Value: "", Path: "/api", HttpOnly: true, Secure: a.CookieSecure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		write(w, 200, map[string]string{"status": "password_changed", "session": "revoked"})
	})
}
func (app *App) listEnvironments(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	rows, err := app.Auth.Pool.Query(r.Context(), "SELECT e.id,e.organization_id,e.name,e.description,m.role FROM environments e JOIN memberships m ON m.organization_id=e.organization_id WHERE m.user_id=$1 ORDER BY e.name", p.ID)
	if err != nil {
		fail(w, 500, "database_error", "Could not list environments")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, orgID, name, description, role string
		if err = rows.Scan(&id, &orgID, &name, &description, &role); err != nil {
			fail(w, 500, "database_error", "Could not list environments")
			return
		}
		g, e := app.graph(r.Context(), id)
		if e != nil {
			fail(w, 500, "graph_error", "Could not load environment graph")
			return
		}
		items = append(items, map[string]any{"id": id, "organization_id": orgID, "name": name, "description": description, "role": role, "asset_count": len(g.Assets)})
	}
	if rows.Err() != nil {
		fail(w, 500, "database_error", "Could not list environments")
		return
	}
	write(w, 200, items)
}
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	return err == nil && parsed.Host == r.Host && (parsed.Scheme == "http" || parsed.Scheme == "https")
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }
func (a *AuthStore) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && !sameOrigin(r) {
			fail(w, 403, "origin_denied", "Origin not allowed")
			return
		}
		if r.URL.Path == "/api/v1/health" || r.URL.Path == "/api/v1/openapi.yaml" || r.URL.Path == "/api/v1/auth/login" {
			next.ServeHTTP(w, r)
			return
		}
		p, err := a.session(r.Context(), r)
		if err != nil {
			fail(w, 401, "unauthorized", "Sign in required")
			return
		}
		ctx := context.WithValue(r.Context(), principalKey{}, p)
		ctx = context.WithValue(ctx, authKey{}, a)
		r = r.WithContext(ctx)
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" && sw.status < 400 {
			var env any
			envID := r.PathValue("id")
			if envID != "" {
				env = envID
			}
			details := map[string]string{}
			if orgID := r.PathValue("orgID"); orgID != "" {
				details["organization_id"] = orgID
			}
			encoded, _ := json.Marshal(details)
			auditCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, _ = a.Pool.Exec(auditCtx, "INSERT INTO audit_records(actor_id,environment_id,action,details) VALUES($1,$2,$3,$4)", p.ID, env, r.Method+" "+r.URL.Path, encoded)
			cancel()
		}
	})
}
