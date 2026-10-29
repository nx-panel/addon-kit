package panel_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nx-panel/addon-kit/panel"
)

func TestTheClientSpeaksV1WithItsTokenAndKey(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch {
		case r.URL.Path == "/api/v1/users" && calls == 1:
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
		case r.URL.Path == "/api/v1/users":
			if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("Idempotency-Key") != "order-1" {
				t.Errorf("headers = %v", r.Header)
			}
			_, _ = w.Write([]byte(`{"id":5,"name":"a"}`))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"scope"}`))
		}
	}))
	defer srv.Close()
	c := &panel.Client{Base: srv.URL + "/", Token: "tok"}
	var u struct{ ID int }
	if err := c.Post(context.Background(), "/users", map[string]any{"name": "a"}, "order-1", &u); err != nil || u.ID != 5 {
		t.Fatalf("post = %v %+v", err, u)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want the 429 waited out once", calls)
	}
	if _, err := c.Me(context.Background()); !panel.IsStatus(err, http.StatusForbidden) || err.Error() != "panel answered 403: scope" {
		t.Fatalf("me = %v", err)
	}
}
