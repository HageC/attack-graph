package main

import (
	"errors"
	"net/http"

	"attackgraph/api/internal/provision"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (a *AuthStore) authorizeOrgAdmin(w http.ResponseWriter, r *http.Request, orgID string) bool {
	var role string
	err := a.Pool.QueryRow(r.Context(), "SELECT role FROM memberships WHERE organization_id=$1 AND user_id=$2", orgID, principal(r).ID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		fail(w, 404, "not_found", "Organization not found")
		return false
	}
	if err != nil {
		fail(w, 500, "database_error", "Could not check organization access")
		return false
	}
	if role != "admin" {
		fail(w, 403, "forbidden", "Administrator role required")
		return false
	}
	return true
}
func databaseConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
func (a *App) registerManagementRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/organizations/{orgID}/users", func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("orgID")
		if !a.Auth.authorizeOrgAdmin(w, r, orgID) {
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), "SELECT u.id,u.email,m.role FROM users u JOIN memberships m ON m.user_id=u.id WHERE m.organization_id=$1 ORDER BY lower(u.email)", orgID)
		if err != nil {
			fail(w, 500, "database_error", "Could not list users")
			return
		}
		defer rows.Close()
		items := []provision.User{}
		for rows.Next() {
			var item provision.User
			if err = rows.Scan(&item.ID, &item.Email, &item.Role); err != nil {
				fail(w, 500, "database_error", "Could not list users")
				return
			}
			items = append(items, item)
		}
		if rows.Err() != nil {
			fail(w, 500, "database_error", "Could not list users")
			return
		}
		write(w, 200, items)
	})
	mux.HandleFunc("POST /api/v1/organizations/{orgID}/users", func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("orgID")
		if !a.Auth.authorizeOrgAdmin(w, r, orgID) {
			return
		}
		var input struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if !decode(w, r, &input) {
			return
		}
		email, err := provision.NormalizeEmail(input.Email)
		if err != nil || provision.ValidatePassword(input.Password) != nil || provision.ValidateRole(input.Role) != nil {
			fail(w, 422, "invalid_user", "Provide a valid email, 12 to 128 byte password, and admin, editor, or viewer role")
			return
		}
		user, err := provision.AddUser(r.Context(), a.Auth.Pool, orgID, email, input.Password, input.Role)
		if databaseConflict(err) {
			fail(w, 409, "email_exists", "Email already has an account")
			return
		}
		if err != nil {
			fail(w, 500, "database_error", "Could not create user")
			return
		}
		write(w, 201, user)
	})
	mux.HandleFunc("POST /api/v1/organizations/{orgID}/environments", func(w http.ResponseWriter, r *http.Request) {
		orgID := r.PathValue("orgID")
		if !a.Auth.authorizeOrgAdmin(w, r, orgID) {
			return
		}
		var input struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		}
		if !decode(w, r, &input) {
			return
		}
		if provision.ValidateName(input.Name) != nil || len(input.Description) > 500 {
			fail(w, 422, "invalid_environment", "Provide a name of 2 to 100 characters and a description of at most 500 characters")
			return
		}
		env, err := provision.AddEnvironment(r.Context(), a.Auth.Pool, orgID, input.Name, input.Description)
		if err != nil {
			fail(w, 500, "database_error", "Could not create environment")
			return
		}
		write(w, 201, map[string]any{"id": env.ID, "organization_id": env.OrganizationID, "name": env.Name, "description": env.Description, "role": "admin", "asset_count": 0})
	})
}
