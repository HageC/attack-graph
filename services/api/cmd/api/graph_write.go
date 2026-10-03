package main

import (
	"context"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Every API graph mutation takes this environment lock before changing Neo4j.
// Snapshot capture holds the same lock while reading all graph components.
const graphLockQuery = "MERGE (lock:EnvironmentLock {environment_id:$env}) SET lock.version=coalesce(lock.version,0)+1 RETURN lock.version"

func lockGraph(ctx context.Context, tx neo4j.ManagedTransaction, envID string) error {
	result, err := tx.Run(ctx, graphLockQuery, map[string]any{"env": envID})
	if err != nil {
		return err
	}
	_, err = result.Consume(ctx)
	return err
}

func (a *App) graphWrite(ctx context.Context, envID, query string, params map[string]any) ([]any, error) {
	session := a.DB.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)
	value, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		if err := lockGraph(ctx, tx, envID); err != nil {
			return nil, err
		}
		result, err := tx.Run(ctx, query, params)
		if err != nil {
			return nil, err
		}
		if !result.Next(ctx) {
			return nil, result.Err()
		}
		values := append([]any(nil), result.Record().Values...)
		if _, err = result.Consume(ctx); err != nil {
			return nil, err
		}
		return values, nil
	})
	if err != nil || value == nil {
		return nil, err
	}
	return value.([]any), nil
}
