// Run from services/api: go run ../../tests/integration_websocket.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const api = "http://127.0.0.1:3001/api/v1"
const stream = "ws://127.0.0.1:3001/api/v1"

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 10 * time.Second}
}

func post(c *http.Client, path string, input any, output any) error {
	body, _ := json.Marshal(input)
	response, err := c.Post(api+path, "application/json", bytes.NewReader(body))
	if err != nil { return err }
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 { return fmt.Errorf("POST %s: HTTP %d", path, response.StatusCode) }
	return json.NewDecoder(response.Body).Decode(output)
}

func dial(ctx context.Context, c *http.Client, path, origin string) (*websocket.Conn, int) {
	headers := http.Header{}
	if origin != "" { headers.Set("Origin", origin) }
	connection, response, _ := websocket.Dial(ctx, stream+path, &websocket.DialOptions{HTTPClient: c, HTTPHeader: headers})
	if response == nil { return connection, 0 }
	return connection, response.StatusCode
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	owner := client()
	var login map[string]any
	if err := post(owner, "/auth/login", map[string]string{"email":"analyst@northstar.local","password":"northstar-demo-local"}, &login); err != nil { return err }
	var snapshot struct{ ID string `json:"id"` }
	if err := post(owner, "/environments/northstar/snapshots", map[string]any{}, &snapshot); err != nil { return err }
	var run struct{ ID string `json:"id"` }
	input := map[string]any{"snapshot_id":snapshot.ID,"start_asset_id":"ws-01","target_asset_id":"id-01","seed":42,"duration_seconds":300,"max_steps":12,"initial_capabilities":[]string{"foothold"},"detection_coverage":1,"control_effectiveness":0}
	if err := post(owner, "/environments/northstar/simulations", input, &run); err != nil { return err }
	var job struct{ ID string `json:"id"` }
	if err := post(owner, "/environments/northstar/simulations/"+run.ID+"/jobs", map[string]any{}, &job); err != nil { return err }
	path := "/environments/northstar/simulation-jobs/"+job.ID+"/stream"
	if err := post(owner, "/environments/northstar/simulation-jobs/"+job.ID+"/pause", map[string]any{}, &login); err != nil { return err }
	if c, status := dial(ctx, client(), path, "http://127.0.0.1:3001"); c != nil || status != http.StatusUnauthorized { if c != nil { c.CloseNow() }; return fmt.Errorf("unauthenticated stream status %d",status) }
	if c, status := dial(ctx, owner, path, "http://other.invalid"); c != nil || status != http.StatusForbidden { if c != nil { c.CloseNow() }; return fmt.Errorf("cross-origin stream status %d",status) }
	harbor := client()
	if err := post(harbor, "/auth/login", map[string]string{"email":"analyst@harbor.local","password":"harbor-demo-local"}, &login); err != nil { return err }
	if c, status := dial(ctx, harbor, path, "http://127.0.0.1:3001"); c != nil || status != http.StatusNotFound { if c != nil { c.CloseNow() }; return fmt.Errorf("cross-tenant stream status %d",status) }
	connection, status := dial(ctx, owner, path, "http://127.0.0.1:3001")
	if connection == nil || status != http.StatusSwitchingProtocols { return fmt.Errorf("authorized stream status %d",status) }
	defer connection.CloseNow()
	var message struct { Type string `json:"type"`; Job struct { Status string `json:"status"`; EventCursor int `json:"event_cursor"`; TotalEvents int `json:"total_events"` } `json:"job"`; Event json.RawMessage `json:"event"` }
	if err := wsjson.Read(ctx,connection,&message); err != nil { return err }
	if message.Type != "state" || message.Job.Status != "paused" { return fmt.Errorf("initial stream state: %+v",message) }
	if err := post(owner, "/environments/northstar/simulation-jobs/"+job.ID+"/resume", map[string]any{}, &login); err != nil { return err }
	gotEvent, gotComplete := false, false
	for !gotComplete {
		message = struct { Type string `json:"type"`; Job struct { Status string `json:"status"`; EventCursor int `json:"event_cursor"`; TotalEvents int `json:"total_events"` } `json:"job"`; Event json.RawMessage `json:"event"` }{}
		if err := wsjson.Read(ctx,connection,&message); err != nil { return err }
		if message.Type == "event" && len(message.Event)>0 { gotEvent=true }
		if message.Type == "state" && message.Job.Status == "completed" { gotComplete=true; if message.Job.EventCursor != message.Job.TotalEvents { return fmt.Errorf("incomplete final cursor") } }
	}
	if !gotEvent { return fmt.Errorf("no streamed event frame") }
	fmt.Println("WebSocket authentication, origin, tenant, and event stream checks passed.")
	return nil
}

func main() { if err := run(); err != nil { panic(err) } }
