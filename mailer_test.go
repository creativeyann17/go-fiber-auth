package fiberauth

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMailer_DisabledNoop(t *testing.T) {
	m := NewMailer("", "noreply@example.com")
	if m.Enabled() {
		t.Fatal("empty APIKey must report disabled")
	}
	if err := m.Send("a@b.c", "s", "<p>x</p>"); err != nil {
		t.Fatalf("disabled Send must no-op, got %v", err)
	}
}

func TestMailer_SendsRequest(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := NewMailer("key123", "noreply@example.com")
	m.Endpoint = srv.URL
	if err := m.Send("to@example.com", "Hello", "<p>hi</p>"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if auth != "Bearer key123" {
		t.Fatalf("auth header: got %q", auth)
	}
	if got["subject"] != "Hello" || got["from"] != "noreply@example.com" {
		t.Fatalf("bad payload: %v", got)
	}
}

func TestMailer_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}))
	defer srv.Close()

	m := NewMailer("key123", "noreply@example.com")
	m.Endpoint = srv.URL
	if err := m.Send("to@example.com", "Hello", "<p>hi</p>"); err == nil {
		t.Fatal("non-2xx must return an error")
	}
}
