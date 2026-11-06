package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Exercise actual HTTP ingress, executor state transitions, and SDK HTTP egress.
func TestPushWireCallback(t *testing.T) {
	for _, transport := range []string{"jsonrpc", "http_json"} {
		for _, inline := range []bool{false, true} {
			t.Run(transport+map[bool]string{false: "/configured", true: "/inline"}[inline], func(t *testing.T) {
				type delivery struct {
					header  http.Header
					payload map[string]any
				}
				received := make(chan delivery, 16)
				webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
					}
					received <- delivery{r.Header.Clone(), payload}
					w.WriteHeader(http.StatusOK)
				}))
				defer webhook.Close()
				server := httptest.NewServer(fixtureHandler(9701, transport))
				defer server.Close()
				call := func(method, path string, params any) map[string]any {
					t.Helper()
					var body any = params
					if transport == "jsonrpc" {
						body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
						path = "/"
					}
					b, err := json.Marshal(body)
					if err != nil {
						t.Fatal(err)
					}
					req, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(b))
					if err != nil {
						t.Fatal(err)
					}
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("A2A-Version", "1.0")
					resp, err := server.Client().Do(req)
					if err != nil {
						t.Fatal(err)
					}
					defer resp.Body.Close()
					var out map[string]any
					if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != 200 || out["error"] != nil {
						t.Fatalf("wire failure %d: %v", resp.StatusCode, out)
					}
					if transport == "jsonrpc" {
						return out["result"].(map[string]any)
					}
					return out
				}
				config := map[string]any{"id": "callback", "url": webhook.URL, "token": "proof-token", "authentication": map[string]any{"scheme": "Bearer", "credentials": "proof-auth"}}
				initial := message("tck-input-required-push-wire", nil)
				if inline {
					initial["configuration"] = map[string]any{"taskPushNotificationConfig": config}
				}
				task := call("SendMessage", "/message:send", initial)["task"].(map[string]any)
				id := task["id"].(string)
				if !inline {
					config["taskId"] = id
					call("CreateTaskPushNotificationConfig", "/tasks/"+id+"/pushNotificationConfigs", config)
				}
				call("SendMessage", "/message:send", message("tck-complete-task-push-wire", id))
				deadline := time.NewTimer(3 * time.Second)
				defer deadline.Stop()
				for {
					select {
					case got := <-received:
						if got.header.Get("Authorization") != "Bearer proof-auth" || got.header.Get("A2A-Notification-Token") != "proof-token" {
							t.Fatalf("callback credentials: %v", got.header)
						}
						event, ok := got.payload["statusUpdate"].(map[string]any)
						if !ok {
							continue
						}
						if event["taskId"] != id {
							t.Fatalf("callback task: %v", got.payload)
						}
						if event["status"].(map[string]any)["state"] == "TASK_STATE_COMPLETED" {
							return
						}
					case <-deadline.C:
						t.Fatal("no completed StreamResponse callback")
					}
				}
			})
		}
	}
}
