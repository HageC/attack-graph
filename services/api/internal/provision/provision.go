package provision

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidCredentials = errors.New("invalid credentials")
var ErrNotFound = errors.New("account not found")
var ErrPasswordUnchanged = errors.New("new password must differ from current password")

type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type Environment struct {
	ID             string `json:"id"`
	OrganizationID string `json:"organization_id"`
	Name           string `json:"name"`
	Description    string `json:"description"`
}
type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func newID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(value[:]), nil
}
func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 {
		return "", errors.New("valid email required")
	}
	return email, nil
}
func ValidatePassword(password string) error {
	if len(password) < 12 || len(password) > 128 {
		return errors.New("password must be 12 to 128 bytes")
	}
	return nil
}
func ValidateName(name string) error {
	if len(strings.TrimSpace(name)) < 2 || len(name) > 100 {
		return errors.New("name must be 2 to 100 characters")
	}
	return nil
}
func ValidateRole(role string) error {
	if role != "admin" && role != "editor" && role != "viewer" {
		return errors.New("role must be admin, editor, or viewer")
	}
	return nil
}

func Bootstrap(ctx context.Context, pool *pgxpool.Pool, orgName, envName, email, password string) (Organization, Environment, User, error) {
	var org Organization
	var env Environment
	var user User
	if err := ValidateName(orgName); err != nil {
		return org, env, user, fmt.Errorf("organization: %w", err)
	}
	if err := ValidateName(envName); err != nil {
		return org, env, user, fmt.Errorf("environment: %w", err)
	}
	var err error
	if email, err = NormalizeEmail(email); err != nil {
		return org, env, user, err
	}
	if err = ValidatePassword(password); err != nil {
		return org, env, user, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return org, env, user, err
	}
	org.ID, err = newID("org-")
	if err != nil {
		return org, env, user, err
	}
	env.ID, err = newID("env-")
	if err != nil {
		return org, env, user, err
	}
	user.ID, err = newID("user-")
	if err != nil {
		return org, env, user, err
	}
	org.Name = strings.TrimSpace(orgName)
	env.OrganizationID = org.ID
	env.Name = strings.TrimSpace(envName)
	env.Description = "Provisioned synthetic environment"
	user.Email = email
	user.Role = "admin"
	tx, err := pool.Begin(ctx)
	if err != nil {
		return org, env, user, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO organizations(id,name) VALUES($1,$2)", org.ID, org.Name); err != nil {
		return org, env, user, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO environments(id,organization_id,name,description) VALUES($1,$2,$3,$4)", env.ID, env.OrganizationID, env.Name, env.Description); err != nil {
		return org, env, user, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)", user.ID, user.Email, string(hash)); err != nil {
		return org, env, user, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO memberships(user_id,organization_id,role) VALUES($1,$2,$3)", user.ID, org.ID, user.Role); err != nil {
		return org, env, user, err
	}
	if err = tx.Commit(ctx); err != nil {
		return org, env, user, err
	}
	return org, env, user, nil
}

func AddUser(ctx context.Context, pool *pgxpool.Pool, orgID, email, password, role string) (User, error) {
	var user User
	var err error
	if email, err = NormalizeEmail(email); err != nil {
		return user, err
	}
	if err = ValidatePassword(password); err != nil {
		return user, err
	}
	if err = ValidateRole(role); err != nil {
		return user, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return user, err
	}
	user.ID, err = newID("user-")
	if err != nil {
		return user, err
	}
	user.Email = email
	user.Role = role
	tx, err := pool.Begin(ctx)
	if err != nil {
		return user, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "INSERT INTO users(id,email,password_hash) VALUES($1,$2,$3)", user.ID, user.Email, string(hash)); err != nil {
		return user, err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO memberships(user_id,organization_id,role) VALUES($1,$2,$3)", user.ID, orgID, user.Role); err != nil {
		return user, err
	}
	if err = tx.Commit(ctx); err != nil {
		return user, err
	}
	return user, nil
}

func AddEnvironment(ctx context.Context, pool *pgxpool.Pool, orgID, name, description string) (Environment, error) {
	var env Environment
	if err := ValidateName(name); err != nil {
		return env, err
	}
	if len(description) > 500 {
		return env, errors.New("description must be at most 500 characters")
	}
	var err error
	env.ID, err = newID("env-")
	if err != nil {
		return env, err
	}
	env.OrganizationID = orgID
	env.Name = strings.TrimSpace(name)
	env.Description = strings.TrimSpace(description)
	_, err = pool.Exec(ctx, "INSERT INTO environments(id,organization_id,name,description) VALUES($1,$2,$3,$4)", env.ID, env.OrganizationID, env.Name, env.Description)
	return env, err
}

func ChangePassword(ctx context.Context, pool *pgxpool.Pool, userID, currentPassword, newPassword string) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var oldHash string
	if err = tx.QueryRow(ctx, "SELECT password_hash FROM users WHERE id=$1 FOR UPDATE", userID).Scan(&oldHash); err != nil {
		return err
	}
	if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(currentPassword)) != nil {
		return ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(newPassword)) == nil {
		return ErrPasswordUnchanged
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "UPDATE users SET password_hash=$1 WHERE id=$2", string(hash), userID); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM sessions WHERE user_id=$1", userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func RotatePassword(ctx context.Context, pool *pgxpool.Pool, email, newPassword string) error {
	var err error
	if email, err = NormalizeEmail(email); err != nil {
		return err
	}
	if err = ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return err
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var userID string
	if err = tx.QueryRow(ctx, "UPDATE users SET password_hash=$1 WHERE lower(email)=$2 RETURNING id", string(hash), email).Scan(&userID); errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "DELETE FROM sessions WHERE user_id=$1", userID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
