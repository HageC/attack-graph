package main

import "net/http"

type SOCCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type SOCSummary struct {
	TelemetryEvents     int64      `json:"telemetry_events"`
	AdversarialEvents   int64      `json:"adversarial_events"`
	DetectedAdversarial int64      `json:"detected_adversarial"`
	Alerts              int64      `json:"alerts"`
	ActiveRules         int64      `json:"active_rules"`
	EventsByType        []SOCCount `json:"events_by_type"`
	AlertsBySeverity    []SOCCount `json:"alerts_by_severity"`
}

func (a *App) registerSOCRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/environments/{id}/soc/summary", func(w http.ResponseWriter, r *http.Request) {
		if !environment(w, r) {
			return
		}
		envID := r.PathValue("id")
		result := SOCSummary{EventsByType: []SOCCount{}, AlertsBySeverity: []SOCCount{}}
		err := a.Auth.Pool.QueryRow(r.Context(), `SELECT count(*),count(*) FILTER (WHERE ground_truth='adversarial'),count(*) FILTER (WHERE ground_truth='adversarial' AND detected) FROM security_telemetry WHERE environment_id=$1`, envID).Scan(&result.TelemetryEvents, &result.AdversarialEvents, &result.DetectedAdversarial)
		if err != nil {
			fail(w, 500, "database_error", "Could not summarize telemetry")
			return
		}
		err = a.Auth.Pool.QueryRow(r.Context(), `SELECT count(*) FROM security_alerts WHERE environment_id=$1`, envID).Scan(&result.Alerts)
		if err != nil {
			fail(w, 500, "database_error", "Could not summarize alerts")
			return
		}
		err = a.Auth.Pool.QueryRow(r.Context(), `SELECT count(*) FROM detection_rules WHERE environment_id=$1 AND enabled`, envID).Scan(&result.ActiveRules)
		if err != nil {
			fail(w, 500, "database_error", "Could not summarize rules")
			return
		}
		rows, err := a.Auth.Pool.Query(r.Context(), `SELECT event_type,count(*) FROM security_telemetry WHERE environment_id=$1 GROUP BY event_type ORDER BY count(*) DESC,event_type`, envID)
		if err != nil {
			fail(w, 500, "database_error", "Could not summarize event types")
			return
		}
		for rows.Next() {
			var item SOCCount
			if rows.Scan(&item.Name, &item.Count) != nil {
				rows.Close()
				fail(w, 500, "database_error", "Could not summarize event types")
				return
			}
			result.EventsByType = append(result.EventsByType, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			fail(w, 500, "database_error", "Could not summarize event types")
			return
		}
		rows, err = a.Auth.Pool.Query(r.Context(), `SELECT severity::text,count(*) FROM security_alerts WHERE environment_id=$1 GROUP BY severity ORDER BY severity DESC`, envID)
		if err != nil {
			fail(w, 500, "database_error", "Could not summarize alert severity")
			return
		}
		for rows.Next() {
			var item SOCCount
			if rows.Scan(&item.Name, &item.Count) != nil {
				rows.Close()
				fail(w, 500, "database_error", "Could not summarize alert severity")
				return
			}
			result.AlertsBySeverity = append(result.AlertsBySeverity, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			fail(w, 500, "database_error", "Could not summarize alert severity")
			return
		}
		write(w, 200, result)
	})
}
