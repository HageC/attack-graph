package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"attackgraph/api/internal/migrations"
	"attackgraph/api/internal/provision"
	"github.com/jackc/pgx/v5/pgxpool"
)

func required(name string) (string, error) {
	value := os.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	return value, nil
}
func run(ctx context.Context) error {
	if len(os.Args) != 2 || (os.Args[1] != "bootstrap" && os.Args[1] != "rotate-password") {
		return fmt.Errorf("usage: /provision bootstrap|rotate-password")
	}
	dsn, err := required("DATABASE_URL")
	if err != nil {
		return err
	}
	password, err := required("PROVISION_PASSWORD")
	if err != nil {
		return err
	}
	var orgName, envName, email string
	if os.Args[1] == "bootstrap" {
		if orgName, err = required("PROVISION_ORG_NAME"); err != nil {
			return err
		}
		if envName, err = required("PROVISION_ENV_NAME"); err != nil {
			return err
		}
	}
	if email, err = required("PROVISION_EMAIL"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		return err
	}
	if err = migrations.Apply(ctx, pool); err != nil {
		return err
	}
	if os.Args[1] == "rotate-password" {
		if err = provision.RotatePassword(ctx, pool, email, password); err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "password_rotated", "email": email})
	}
	org, env, user, err := provision.Bootstrap(ctx, pool, orgName, envName, email, password)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"organization": org, "environment": env, "admin": user})
}
func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
