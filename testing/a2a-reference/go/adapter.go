// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"time"

	"github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/a2aproject/a2a-go/v2/a2asrv/taskstore"
)

// A list with no matches is an empty collection rather than JSON null.
type collectionStore struct{ taskstore.Store }

func (s collectionStore) List(ctx context.Context, r *a2a.ListTasksRequest) (*a2a.ListTasksResponse, error) {
	result, err := s.Store.List(ctx, r)
	if err == nil && result != nil && result.Tasks == nil {
		result.Tasks = []*a2a.Task{}
	}
	return result, err
}

type referenceHandler struct {
	a2asrv.RequestHandler
	store taskstore.Store
}

func (h referenceHandler) SendMessage(ctx context.Context, r *a2a.SendMessageRequest) (a2a.SendMessageResult, error) {
	result, err := h.RequestHandler.SendMessage(ctx, r)
	if err == nil && r.Config != nil && r.Config.HistoryLength != nil {
		if task, ok := result.(*a2a.Task); ok {
			limit := *r.Config.HistoryLength
			if limit == 0 {
				task.History = []*a2a.Message{}
			} else if limit > 0 && len(task.History) > limit {
				task.History = task.History[len(task.History)-limit:]
			}
		}
	}
	return result, err
}

// The SDK execution queue closes when an executor parks a task awaiting input.
// A protocol subscription lasts until task termination, so subscribe to stored
// task versions independently of that individual execution's queue lifetime.
func (h referenceHandler) SubscribeToTask(ctx context.Context, r *a2a.SubscribeToTaskRequest) iter.Seq2[a2a.Event, error] {
	return func(yield func(a2a.Event, error) bool) {
		cc, ok := a2asrv.CallContextFrom(ctx)
		if !ok {
			ctx, cc = a2asrv.NewCallContext(ctx, nil)
		}
		cc.User = a2asrv.NewAuthenticatedUser("public-fixture", nil)
		if auth, ok := cc.ServiceParams().Get("Authorization"); ok {
			if len(auth) == 1 && tokenPrincipal(auth[0]) {
				cc.User = a2asrv.NewAuthenticatedUser("reference-user", nil)
			}
		}
		var version taskstore.TaskVersion
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			task, err := h.store.Get(ctx, r.ID)
			if err != nil {
				yield(nil, err)
				return
			}
			if task.Version != version {
				if !yield(task.Task, nil) {
					return
				}
				version = task.Version
			}
			if task.Task.Status.State.Terminal() {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}
}

func cachedCard(card *a2a.AgentCard) http.Handler {
	encoded, err := json.Marshal(card)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(encoded)
	etag := fmt.Sprintf("\"%x\"", sum)
	modified := time.Now().UTC().Truncate(time.Second)
	native := a2asrv.NewStaticAgentCardHandler(card)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("ETag", etag)
		w.Header().Set("Last-Modified", modified.Format(http.TimeFormat))
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if r.Header.Get("If-None-Match") == "" {
			if t, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !modified.After(t) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		native.ServeHTTP(w, r)
	})
}

// Accept protobuf JSON snake_case field spellings in addition to the SDK's
// lowerCamelCase tags. Only protocol parameter names are normalized; user data,
// metadata and arbitrary data-part keys are never traversed.
func parameterAliases(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		const maxBody = 16 << 20
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "Cannot read request", 400)
			return
		}
		if len(body) > 4<<20 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			_, err = io.WriteString(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Request exceeds 4 MiB"}}`)
			if err != nil {
				return
			}
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		var envelope map[string]json.RawMessage
		if json.Unmarshal(body, &envelope) != nil {
			next.ServeHTTP(w, r)
			return
		}
		var params map[string]json.RawMessage
		if json.Unmarshal(envelope["params"], &params) != nil {
			next.ServeHTTP(w, r)
			return
		}
		aliases := map[string]string{"history_length": "historyLength", "context_id": "contextId", "task_id": "taskId", "page_size": "pageSize", "page_token": "pageToken", "status_timestamp_after": "statusTimestampAfter", "include_artifacts": "includeArtifacts"}
		changed := false
		for old, key := range aliases {
			if value, ok := params[old]; ok {
				if canonical, exists := params[key]; exists && !bytes.Equal(canonical, value) {
					http.Error(w, "Conflicting protocol field spellings", http.StatusBadRequest)
					return
				}
				params[key] = value
				delete(params, old)
				changed = true
			}
		}
		if changed {
			envelope["params"], err = json.Marshal(params)
			if err != nil {
				http.Error(w, "Cannot encode parameters", 500)
				return
			}
			body, err = json.Marshal(envelope)
			if err != nil {
				http.Error(w, "Cannot encode request", 500)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
		next.ServeHTTP(w, r)
	})
}

func sameMessage(a, b *a2a.Message) bool {
	left, err := json.Marshal(a)
	if err != nil {
		return false
	}
	right, err := json.Marshal(b)
	return err == nil && bytes.Equal(left, right)
}
func preserveChangedMessage(ec *a2asrv.ExecutorContext) bool {
	if ec.StoredTask == nil {
		return false
	}
	for _, m := range ec.StoredTask.History {
		if sameMessage(m, ec.Message) {
			return false
		}
	}
	ec.StoredTask.History = append(ec.StoredTask.History, ec.Message)
	return true
}
