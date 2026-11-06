package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func rpc(t *testing.T, h http.Handler, method string, params any, version string) map[string]any {
	t.Helper()
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if version == "" {
		version = "1.0"
	}
	if version != "absent" {
		r.Header.Set("A2A-Version", version)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var out map[string]any
	body := w.Body.Bytes()
	if strings.Contains(w.Header().Get("Content-Type"), "text/event-stream") {
		for _, line := range strings.Split(string(body), "\n") {
			if strings.HasPrefix(line, "data: ") {
				body = []byte(strings.TrimPrefix(line, "data: "))
				break
			}
		}
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%d %s: %v", w.Code, w.Body.String(), err)
	}
	return out
}
func message(id string, task any) map[string]any {
	m := map[string]any{"messageId": id, "role": "ROLE_USER", "parts": []any{map[string]any{"text": "test"}}}
	if task != nil {
		m["taskId"] = task
	}
	return map[string]any{"message": m}
}
func TestScenarioLifecycle(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	r := rpc(t, h, "SendMessage", message("tck-input-required-1", nil), "")
	if r["error"] != nil {
		t.Fatal(r)
	}
	result := r["result"].(map[string]any)
	t.Logf("result=%v", result)
	task := result["task"].(map[string]any)
	if task["status"].(map[string]any)["state"] != "TASK_STATE_INPUT_REQUIRED" {
		t.Fatal(task)
	}
	r = rpc(t, h, "SendMessage", message("tck-complete-task-1", task["id"]), "")
	if r["error"] != nil {
		t.Fatal(r)
	}
	r = rpc(t, h, "SendMessage", message("tck-complete-task-2", task["id"]), "")
	if r["error"] == nil {
		t.Fatal("terminal task accepted", r)
	}
}
func TestPolicy(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	for _, tc := range []struct {
		name, method, version string
		params                any
	}{{"version", "SendMessage", "9.9", message("tck-complete-task", nil)},
		{"missing-version", "SendMessage", "absent", message("tck-complete-task", nil)}, {"null", "SendMessage", "", map[string]any{"message": map[string]any{"messageId": "null", "role": "ROLE_USER", "parts": []any{nil}}}}} {
		t.Run(tc.name, func(t *testing.T) {
			if r := rpc(t, h, tc.method, tc.params, tc.version); r["error"] == nil {
				t.Fatal(r)
			}
		})
	}
}
func TestUTCTimestamp(t *testing.T) {
	old := time.Local
	time.Local = time.FixedZone("nonUTC", -5*3600)
	defer func() { time.Local = old }()
	h := fixtureHandler(9701, "jsonrpc")
	r := rpc(t, h, "SendMessage", message("tck-artifact-data-1", nil), "")
	if r["error"] != nil {
		t.Fatal(r)
	}
	task := r["result"].(map[string]any)["task"].(map[string]any)
	stamp := task["status"].(map[string]any)["timestamp"].(string)
	if stamp[len(stamp)-1:] != "Z" {
		t.Fatal(stamp)
	}
	if len(task["artifacts"].([]any)) != 1 {
		t.Fatal(task)
	}
}

func TestPublicListAndSubscribe(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	r := rpc(t, h, "SendMessage", message("tck-complete-task-list", nil), "")
	if r["error"] != nil {
		t.Fatal(r)
	}
	task := r["result"].(map[string]any)["task"].(map[string]any)
	r = rpc(t, h, "ListTasks", map[string]any{}, "")
	if r["error"] != nil {
		t.Fatal(r)
	}
	if len(r["result"].(map[string]any)["tasks"].([]any)) != 1 {
		t.Fatal(r)
	}
	for _, id := range []any{task["id"], "unknown"} {
		r = rpc(t, h, "SubscribeToTask", map[string]any{"id": id}, "")
		if r["error"] == nil {
			t.Fatal(r)
		}
	}
}

func TestContentTypeBoundary(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	for _, body := range []string{`{"jsonrpc":"2.0","id":42,"method":"SendMessage"}`, "invalid"} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/plain")
		r.Header.Set("A2A-Version", "1.0")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var result map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result["error"].(map[string]any)["code"] != float64(-32005) {
			t.Fatal(result)
		}
		if body != "invalid" && result["id"] != float64(42) {
			t.Fatal(result)
		}
	}
}

func TestSubscriptionPreflightNeverOpensSSE(t *testing.T) {
	h := fixtureHandler(9701, "jsonrpc")
	created := rpc(t, h, "SendMessage", message("tck-complete-task-preflight", nil), "")
	id := created["result"].(map[string]any)["task"].(map[string]any)["id"]
	for _, tc := range []struct {
		id   any
		code float64
	}{{id, -32004}, {"does-not-exist", -32001}} {
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": "preserved", "method": "SubscribeToTask", "params": map[string]any{"id": tc.id}})
		r := httptest.NewRequest("POST", "/", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "text/event-stream")
		r.Header.Set("A2A-Version", "1.0")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if strings.Contains(w.Header().Get("Content-Type"), "event-stream") {
			t.Fatal("opened SSE", w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out["id"] != "preserved" || out["error"].(map[string]any)["code"] != tc.code {
			t.Fatal(out)
		}
	}
}

func TestRESTSubscriptionPreflight(t *testing.T) {
	h := fixtureHandler(9701, "http_json")
	body, _ := json.Marshal(message("tck-complete-task-rest", nil))
	r := httptest.NewRequest("POST", "/message:send", bytes.NewReader(body))
	r.Header.Set("A2A-Version", "1.0")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	task, ok := created["task"].(map[string]any)
	if !ok {
		t.Fatal(w.Code, created)
	}
	for _, method := range []string{"GET", "POST"} {
		for _, tc := range []struct {
			id     string
			status int
			reason string
		}{{task["id"].(string), 400, "FAILED_PRECONDITION"}, {"missing", 404, "NOT_FOUND"}} {
			r := httptest.NewRequest(method, "/tasks/"+tc.id+":subscribe", nil)
			r.Header.Set("A2A-Version", "1.0")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || strings.Contains(w.Header().Get("Content-Type"), "event-stream") {
				t.Fatal(w.Code, w.Body.String())
			}
			var out map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out["error"].(map[string]any)["status"] != tc.reason {
				t.Fatal(out)
			}
		}
	}
}

func TestActiveSubscriptionRequestPassesUnchanged(t *testing.T) {
	store := taskstore.NewInMemory(nil)
	_, err := store.Create(context.Background(), &a2a.Task{ID: "active", ContextID: "context", Status: a2a.TaskStatus{State: a2a.TaskStateWorking}})
	if err != nil {
		t.Fatal(err)
	}
	p := policy{store: store}
	for _, binding := range []string{"jsonrpc", "http_json"} {
		called := false
		want := `{"jsonrpc":"2.0","id":7,"method":"SubscribeToTask","params":{"id":"active"}}`
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			got, err := io.ReadAll(r.Body)
			if err != nil || string(got) != want {
				t.Fatal(string(got), err)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
		})
		var h http.Handler = subscriptionGuard(next, p)
		path := "/"
		if binding == "http_json" {
			h = restSubscriptionGuard(next, p)
			path = "/tasks/active:subscribe"
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(want))
		r.Header.Set("A2A-Version", "1.0")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !called {
			t.Fatal(binding, w.Body.String())
		}
	}
}
