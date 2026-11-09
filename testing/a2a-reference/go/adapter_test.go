package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCardCaching(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	r := httptest.NewRequest("GET", "/.well-known/agent-card.json", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	for _, name := range []string{"ETag", "Last-Modified", "Cache-Control"} {
		if w.Header().Get(name) == "" {
			t.Fatal(name)
		}
	}
	etag := w.Header().Get("ETag")
	r = httptest.NewRequest("GET", "/.well-known/agent-card.json", nil)
	r.Header.Set("If-None-Match", etag)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 304 || w.Body.Len() != 0 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func TestAliasesAndChangedPayloadHistory(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	created := rpc(t, h, "SendMessage", message("tck-input-required-same-id", nil), "")
	task := created["result"].(map[string]any)["task"].(map[string]any)
	id := task["id"]
	for _, text := range []string{"one", "two"} {
		params := message("tck-input-required-same-id", id)
		params["message"].(map[string]any)["parts"] = []any{map[string]any{"text": text}}
		if r := rpc(t, h, "SendMessage", params, ""); r["error"] != nil {
			t.Fatal(r)
		}
	}
	r := rpc(t, h, "GetTask", map[string]any{"id": id, "history_length": 1}, "")
	history := r["result"].(map[string]any)["history"].([]any)
	if len(history) != 1 || history[0].(map[string]any)["parts"].([]any)[0].(map[string]any)["text"] != "two" {
		t.Fatal(r)
	}
	r = rpc(t, h, "GetTask", map[string]any{"id": id, "history_length": 0}, "")
	if r["result"].(map[string]any)["history"] != nil {
		if len(r["result"].(map[string]any)["history"].([]any)) != 0 {
			t.Fatal(r)
		}
	}
	r = rpc(t, h, "ListTasks", map[string]any{"context_id": "missing"}, "")
	if _, ok := r["result"].(map[string]any)["tasks"].([]any); !ok {
		t.Fatal(r)
	}
}
func TestAliasScope(t *testing.T) {
	var seen map[string]any
	h := parameterAliases(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
			t.Fatal(err)
		}
	}))
	payload := `{"params":{"history_length":1,"metadata":{"history_length":7},"message":{"parts":[{"data":{"task_id":"user-data"}}]}}}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(payload)))
	p := seen["params"].(map[string]any)
	if p["historyLength"] != float64(1) || p["metadata"].(map[string]any)["history_length"] != float64(7) {
		t.Fatal(seen)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"params":{"task_id":"one","taskId":"two"}}`)))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestNumericMessageRole(t *testing.T) {
	for _, binding := range []string{"jsonrpc", "http_json"} {
		t.Run(binding, func(t *testing.T) {
			params := message("numeric-role", nil)
			params["message"].(map[string]any)["role"] = 1
			var payload any = params
			path := "/message:send"
			if binding == "jsonrpc" {
				payload = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": params}
				path = "/"
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", path, bytes.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("A2A-Version", "1.0")
			w := httptest.NewRecorder()
			fixtureHandler(9701, binding).ServeHTTP(w, r)
			var result map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if w.Code != 200 || result["error"] != nil {
				t.Fatal(w.Code, result)
			}
		})
	}
}

func TestNumericRoleScope(t *testing.T) {
	for _, role := range []string{"1", "2", "999", `"ROLE_USER"`} {
		var seen map[string]any
		h := parameterAliases(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
				t.Fatal(err)
			}
		}))
		payload := `{"message":{"role":` + role + `,"metadata":{"role":1},"parts":[{"data":{"role":2}}]},"metadata":{"role":1}}`
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/message:send", strings.NewReader(payload)))
		m := seen["message"].(map[string]any)
		expected := map[string]any{"1": "ROLE_USER", "2": "ROLE_AGENT", "999": float64(999), `"ROLE_USER"`: "ROLE_USER"}[role]
		if m["role"] != expected || m["metadata"].(map[string]any)["role"] != float64(1) || m["parts"].([]any)[0].(map[string]any)["data"].(map[string]any)["role"] != float64(2) || seen["metadata"].(map[string]any)["role"] != float64(1) {
			t.Fatal(seen)
		}
	}
}
func TestOversizeGetsHTTPResponse(t *testing.T) {
	server := httptest.NewServer(fixtureHandler(9701, "jsonrpc"))
	defer server.Close()
	body := strings.Repeat("a", 8<<20)
	r, err := http.NewRequest("POST", server.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("A2A-Version", "1.0")
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 413 {
		t.Fatal(resp.StatusCode)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatal(err)
	}
}
func TestParkedSubscriptionCompletes(t *testing.T) {
	for _, transport := range []string{"jsonrpc", "http_json"} {
		t.Run(transport, func(t *testing.T) {
			h := fixtureHandler(9701, transport)
			var id any
			send := func(mid string, tid any) map[string]any {
				params := message(mid, tid)
				var body any = params
				path := "/message:send"
				if transport == "jsonrpc" {
					body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": params}
					path = "/"
				}
				b, _ := json.Marshal(body)
				r := httptest.NewRequest("POST", path, bytes.NewReader(b))
				r.Header.Set("A2A-Version", "1.0")
				r.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				var out map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				if transport == "jsonrpc" {
					return out["result"].(map[string]any)
				}
				return out
			}
			id = send("tck-input-required-subscriber", nil)["task"].(map[string]any)["id"]
			server := httptest.NewServer(h)
			defer server.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			path := "/tasks/" + id.(string) + ":subscribe"
			method := "GET"
			var body io.Reader
			if transport == "jsonrpc" {
				method = "POST"
				path = "/"
				b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "SubscribeToTask", "params": map[string]any{"id": id}})
				body = bytes.NewReader(b)
			}
			r, _ := http.NewRequestWithContext(ctx, method, server.URL+path, body)
			r.Header.Set("A2A-Version", "1.0")
			r.Header.Set("Content-Type", "application/json")
			resp, err := server.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			scanner := bufio.NewScanner(resp.Body)
			first := true
			terminal := false
			for scanner.Scan() {
				line := scanner.Text()
				if !strings.HasPrefix(line, "data:") {
					continue
				}
				if first {
					first = false
					send("tck-complete-task-subscriber", id)
				}
				if strings.Contains(line, "TASK_STATE_COMPLETED") {
					terminal = true
				}
			}
			if err := scanner.Err(); err != nil {
				t.Fatal(err)
			}
			if first || !terminal {
				t.Fatal("subscription missing real initial/terminal task", first, terminal)
			}
		})
	}
}
func TestHistoryLimitAndTerminalError(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	created := rpc(t, h, "SendMessage", message("tck-input-required-limit", nil), "")
	id := created["result"].(map[string]any)["task"].(map[string]any)["id"]
	params := message("tck-complete-task-limit", id)
	params["configuration"] = map[string]any{"historyLength": 0}
	r := rpc(t, h, "SendMessage", params, "")
	task := r["result"].(map[string]any)["task"].(map[string]any)
	if history, ok := task["history"].([]any); ok && len(history) != 0 {
		t.Fatal(task)
	}
	r = rpc(t, h, "SendMessage", message("tck-complete-task-again", id), "")
	if r["error"].(map[string]any)["code"] != float64(-32004) {
		t.Fatal(r)
	}
}
