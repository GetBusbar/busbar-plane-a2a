// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"log"
	"mime"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/a2aproject/a2a-go/v2/a2asrv/push"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
	"github.com/a2aproject/a2a-go/v2/errordetails"
)

// Executor-created timestamps use the protocol's UTC form, without changing process TZ.
func newStatus(ec *a2asrv.ExecutorContext, state a2a.TaskState, msg *a2a.Message) *a2a.TaskStatusUpdateEvent {
	event := a2a.NewStatusUpdateEvent(ec, state, msg)
	utc := event.Status.Timestamp.UTC()
	event.Status.Timestamp = &utc
	return event
}
func submitted(ec *a2asrv.ExecutorContext) *a2a.Task {
	task := a2a.NewSubmittedTask(ec, ec.Message)
	if task.Status.Timestamp != nil {
		utc := task.Status.Timestamp.UTC()
		task.Status.Timestamp = &utc
	}
	return task
}

type executor struct{}

func (executor) Execute(ctx context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		id := ec.Message.ID
		if preserveChangedMessage(ec) {
			if !yield(ec.StoredTask, nil) {
				return
			}
		}
		if strings.HasPrefix(id, "tck-message-response") {
			yield(a2a.NewMessage(a2a.MessageRoleAgent, a2a.NewTextPart("Direct message response")), nil)
			return
		}
		if ec.StoredTask != nil && ec.StoredTask.Status.State.Terminal() {
			yield(nil, a2a.ErrUnsupportedOperation)
			return
		}
		if ec.StoredTask == nil {
			if !yield(submitted(ec), nil) {
				return
			}
		}
		state := a2a.TaskStateCompleted
		var msg *a2a.Message
		status := func(s a2a.TaskState) bool { return yield(newStatus(ec, s, nil), nil) }
		artifact := func(p *a2a.Part) bool { return yield(a2a.NewArtifactEvent(ec, p), nil) }
		file := func(url bool) *a2a.Part {
			p := a2a.NewRawPart([]byte("tck"))
			if url {
				p = a2a.NewFileURLPart("https://example.com/output.txt", "text/plain")
			}
			p.Filename = "output.txt"
			p.MediaType = "text/plain"
			return p
		}
		switch {
		case strings.HasPrefix(id, "tck-input-required"):
			state = a2a.TaskStateInputRequired
		case strings.HasPrefix(id, "a2asup-auth-required"):
			state = a2a.TaskStateAuthRequired
			msg = a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("Authorization is required: obtain an OAuth access token for the downstream API out of band."))
		case strings.HasPrefix(id, "tck-reject-task"):
			state = a2a.TaskStateRejected
		case strings.HasPrefix(id, "tck-artifact-file-url"):
			if !artifact(file(true)) {
				return
			}
		case strings.HasPrefix(id, "tck-artifact-file"):
			if !artifact(file(false)) {
				return
			}
		case strings.HasPrefix(id, "tck-artifact-text"):
			if !artifact(a2a.NewTextPart("Generated text content")) {
				return
			}
		case strings.HasPrefix(id, "tck-artifact-data"):
			if !artifact(a2a.NewDataPart(map[string]any{"key": "value", "count": 42})) {
				return
			}
		case strings.HasPrefix(id, "tck-stream-artifact-chunked"):
			if !status(a2a.TaskStateWorking) {
				return
			}
			first := a2a.NewArtifactEvent(ec, a2a.NewTextPart("chunk-1 "))
			if !yield(first, nil) {
				return
			}
			last := a2a.NewArtifactUpdateEvent(ec, first.Artifact.ID, a2a.NewTextPart("chunk-2"))
			last.LastChunk = true
			if !yield(last, nil) {
				return
			}
		case strings.HasPrefix(id, "test-resubscribe-message-id"):
			if !status(a2a.TaskStateWorking) {
				return
			}
			seconds := 2.0
			if s, err := strconv.ParseFloat(os.Getenv("TCK_STREAMING_TIMEOUT"), 64); err == nil && s > 0 {
				seconds = s
			}
			timer := time.NewTimer(time.Duration(2 * seconds * float64(time.Second)))
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		case strings.HasPrefix(id, "tck-stream-artifact-file"):
			if !status(a2a.TaskStateWorking) || !artifact(file(false)) {
				return
			}
		case strings.HasPrefix(id, "tck-stream-artifact-text"):
			if !status(a2a.TaskStateWorking) || !artifact(a2a.NewTextPart("Streamed text content")) {
				return
			}
		case strings.HasPrefix(id, "tck-stream-ordering-001"):
			if !status(a2a.TaskStateWorking) || !artifact(a2a.NewTextPart("Ordered output")) {
				return
			}
		case strings.HasPrefix(id, "tck-stream-001"):
			if !status(a2a.TaskStateWorking) || !artifact(a2a.NewTextPart("Stream hello from TCK")) {
				return
			}
		case strings.HasPrefix(id, "tck-stream-003"):
			if !status(a2a.TaskStateWorking) || !artifact(a2a.NewTextPart("Stream task lifecycle")) {
				return
			}
		case strings.HasPrefix(id, "tck-stream-002"):
		default:
			msg = a2a.NewMessageForTask(a2a.MessageRoleAgent, ec, a2a.NewTextPart("Hello from TCK"))
		}
		yield(newStatus(ec, state, msg), nil)
	}
}
func (executor) Cancel(_ context.Context, ec *a2asrv.ExecutorContext) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		yield(newStatus(ec, a2a.TaskStateCanceled, nil), nil)
	}
}

type policy struct {
	a2asrv.PassthroughCallInterceptor
	store taskstore.Store
}

func (p policy) Before(ctx context.Context, cc *a2asrv.CallContext, req *a2asrv.Request) (context.Context, any, error) {
	if versions, ok := cc.ServiceParams().Get("A2A-Version"); ok {
		for _, v := range versions {
			if v != "1.0" {
				return ctx, nil, a2a.ErrVersionNotSupported
			}
		}
	} else {
		return ctx, nil, a2a.ErrVersionNotSupported
	}
	cc.User = a2asrv.NewAuthenticatedUser("public-fixture", map[string]any{"authentication": "public reference fixture"})
	if auth, ok := cc.ServiceParams().Get("Authorization"); ok && len(auth) == 1 && tokenPrincipal(auth[0]) {
		cc.User = a2asrv.NewAuthenticatedUser("reference-user", nil)
	}
	if r, ok := req.Payload.(*a2a.SubscribeToTaskRequest); ok {
		if r == nil || r.ID == "" {
			return ctx, nil, a2a.ErrInvalidParams
		}
		task, err := p.store.Get(ctx, r.ID)
		if err != nil {
			return ctx, nil, a2a.ErrTaskNotFound
		}
		if task.Task.Status.State.Terminal() {
			return ctx, nil, a2a.ErrUnsupportedOperation
		}
	}
	if r, ok := req.Payload.(*a2a.SendMessageRequest); ok {
		if r == nil || r.Message == nil || len(r.Message.Parts) == 0 {
			return ctx, nil, a2a.ErrInvalidParams
		}
		if r.Message.TaskID != "" {
			task, err := p.store.Get(ctx, r.Message.TaskID)
			if err != nil {
				return ctx, nil, err
			}
			if task.Task.Status.State.Terminal() {
				return ctx, nil, a2a.ErrUnsupportedOperation
			}
		}
		for _, p := range r.Message.Parts {
			if p == nil || p.Content == nil {
				return ctx, nil, a2a.ErrInvalidParams
			}
		}
	}
	return ctx, nil, nil
}
func main() {
	port := flag.Int("port", 9701, "loopback port")
	transport := flag.String("transport", "jsonrpc", "jsonrpc or http_json")
	flag.Parse()
	log.Fatal(http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", *port), fixtureHandler(*port, *transport)))
}
func fixtureHandler(port int, transport string) http.Handler {
	binding := a2a.TransportProtocolJSONRPC
	if transport == "http_json" {
		binding = a2a.TransportProtocolHTTPJSON
	} else if transport != "jsonrpc" {
		log.Fatal("unsupported transport")
	}
	card := &a2a.AgentCard{Name: "Go SDK TCK scenario reference", Description: "Published TCK scenario contract using a2a-go v2.4.0", Version: "1.0.0", SupportedInterfaces: []*a2a.AgentInterface{a2a.NewAgentInterface(fmt.Sprintf("http://127.0.0.1:%d", port), binding)}, DefaultInputModes: []string{"text"}, DefaultOutputModes: []string{"text"}, Capabilities: a2a.AgentCapabilities{Streaming: true, PushNotifications: true}, Skills: []a2a.AgentSkill{{ID: "tck-scenarios", Name: "TCK scenarios", Description: "In-band message ID scenario dispatch", Tags: []string{"conformance"}}}}
	store := collectionStore{taskstore.NewInMemory(&taskstore.InMemoryStoreConfig{Authenticator: a2asrv.NewTaskStoreAuthenticator()})}
	nativeHandler := a2asrv.NewHandler(executor{}, a2asrv.WithTaskStore(store), a2asrv.WithCapabilityChecks(&card.Capabilities), a2asrv.WithPushNotifications(push.NewInMemoryStore(), referencePushSender()), a2asrv.WithCallInterceptors(policy{store: store}))
	handler := referenceHandler{RequestHandler: nativeHandler, store: store}
	mux := http.NewServeMux()
	mux.Handle(a2asrv.WellKnownAgentCardPath, cachedCard(card))
	var h http.Handler = a2asrv.NewJSONRPCHandler(handler)
	if transport == "http_json" {
		h = restSubscriptionGuard(a2asrv.NewRESTHandler(handler), policy{store: store})
	}
	if transport == "jsonrpc" {
		h = parameterAliases(contentTypeGuard(subscriptionGuard(h, policy{store: store})))
	}
	mux.Handle("/", h)
	return mux
}

// Reject unsupported media before the SDK parser consumes the body. This creates
// a protocol error at the request boundary, without inspecting a downstream response.
func contentTypeGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if r.Method != http.MethodPost || (err == nil && media == "application/json") {
			next.ServeHTTP(w, r)
			return
		}
		var id any
		if body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)); err == nil {
			var envelope map[string]json.RawMessage
			if json.Unmarshal(body, &envelope) == nil {
				if raw, ok := envelope["id"]; ok {
					if err := json.Unmarshal(raw, &id); err != nil {
						id = nil
					}
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32005, "message": "Content type not supported"}}); err != nil {
			log.Printf("write content type error: %v", err)
		}
	})
}

// Validate live task state before the SDK commits SSE headers. The ordinary
// interceptor repeats these checks when the accepted request reaches execution.
func subscriptionGuard(next http.Handler, p policy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Cannot read request", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var envelope struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(body, &envelope) != nil || envelope.Method != "SubscribeToTask" {
			next.ServeHTTP(w, r)
			return
		}
		var request a2a.SubscribeToTaskRequest
		if json.Unmarshal(envelope.Params, &request) != nil {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cc := a2asrv.NewCallContext(r.Context(), a2asrv.NewServiceParams(r.Header))
		_, _, err = p.Before(ctx, cc, &a2asrv.Request{Payload: &request})
		if err == nil {
			next.ServeHTTP(w, r)
			return
		}
		code := -32602
		switch {
		case errors.Is(err, a2a.ErrTaskNotFound):
			code = -32001
		case errors.Is(err, a2a.ErrUnsupportedOperation):
			code = -32004
		case errors.Is(err, a2a.ErrVersionNotSupported):
			code = -32009
		}
		id := envelope.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": err.Error()}}); err != nil {
			log.Printf("write subscription preflight error: %v", err)
		}
	})
}

func restSubscriptionGuard(next http.Handler, p policy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method != http.MethodGet && r.Method != http.MethodPost) || !strings.HasPrefix(r.URL.Path, "/tasks/") || !strings.HasSuffix(r.URL.Path, ":subscribe") {
			next.ServeHTTP(w, r)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/tasks/"), ":subscribe")
		if strings.Contains(id, "/") {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cc := a2asrv.NewCallContext(r.Context(), a2asrv.NewServiceParams(r.Header))
		_, _, err := p.Before(ctx, cc, &a2asrv.Request{Payload: &a2a.SubscribeToTaskRequest{ID: a2a.TaskID(id)}})
		if err == nil {
			next.ServeHTTP(w, r)
			return
		}
		status := http.StatusBadRequest
		reason := "INVALID_ARGUMENT"
		switch {
		case errors.Is(err, a2a.ErrTaskNotFound):
			status = http.StatusNotFound
			reason = "NOT_FOUND"
		case errors.Is(err, a2a.ErrUnsupportedOperation) || errors.Is(err, a2a.ErrVersionNotSupported):
			reason = "FAILED_PRECONDITION"
		}
		detail := errordetails.NewErrorInfo(a2a.ErrorReason(err), a2a.ProtocolDomain, map[string]string{"taskId": id, "timestamp": time.Now().UTC().Format(time.RFC3339)})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": status, "status": reason, "message": err.Error(), "details": []*errordetails.Typed{detail}}}); err != nil {
			log.Printf("write REST subscription preflight error: %v", err)
		}
	})
}

func tokenPrincipal(auth string) bool {
	return os.Getenv("A2A_REFERENCE_TOKEN") != "" && auth == "Bearer "+os.Getenv("A2A_REFERENCE_TOKEN")
}
