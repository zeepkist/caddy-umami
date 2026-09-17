package caddyumami

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

type testHandler func(http.ResponseWriter, *http.Request) error

func (h testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return h(w, r)
}

type capturedRequest struct {
	event        capturedEvent
	userAgent    string
	forwardedFor string
}

type capturedEvent struct {
	Payload struct {
		URL      string `json:"url"`
		Website  string `json:"website"`
		Hostname string `json:"hostname"`
		Language string `json:"language"`
		Referrer string `json:"referrer"`
	} `json:"payload"`
	Type string `json:"type"`
}

func TestServeHTTPStripsIncomingQueryAndIgnoresConsentCookie(t *testing.T) {
	t.Parallel()

	captured := make(chan capturedRequest, 1)
	eventServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read event body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		var event capturedEvent
		if err := json.Unmarshal(body, &event); err != nil {
			t.Errorf("decode event body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		captured <- capturedRequest{
			event:        event,
			userAgent:    r.UserAgent(),
			forwardedFor: r.Header.Get("X-Forwarded-For"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(eventServer.Close)

	module := Umami{
		EventEndpoint:     eventServer.URL,
		WebsiteUUID:       "test-website",
		AllowedExtensions: []string{""},
		TrustedIPHeader:   "CF-Connecting-IP",
		StaticMetadata: []StaticMetadata{
			{Key: "server", Value: "node1"},
		},
		logger: zap.NewNop(),
	}

	request := httptest.NewRequest(http.MethodGet, "https://example.test/page?code=secret&filter=private", nil)
	request.AddCookie(&http.Cookie{Name: "umami_consent", Value: "false"})
	request.Header.Set("User-Agent", "test-browser/1.0")
	request.Header.Set("Accept-Language", "en-GB,en;q=0.9")
	request.Header.Set("Referer", "https://referrer.test/start")
	request.Header.Set("CF-Connecting-IP", "203.0.113.42")

	var upstreamQuery string
	next := testHandler(func(_ http.ResponseWriter, r *http.Request) error {
		upstreamQuery = r.URL.RawQuery
		return nil
	})

	if err := module.ServeHTTP(httptest.NewRecorder(), request, next); err != nil {
		t.Fatalf("serve request: %v", err)
	}
	if upstreamQuery != "code=secret&filter=private" {
		t.Fatalf("upstream query = %q, want original query", upstreamQuery)
	}

	select {
	case got := <-captured:
		if got.event.Payload.URL != "/page?server=node1" {
			t.Errorf("event URL = %q, want path plus static metadata", got.event.Payload.URL)
		}
		if strings.Contains(got.event.Payload.URL, "secret") || strings.Contains(got.event.Payload.URL, "private") {
			t.Errorf("event URL leaked incoming query: %q", got.event.Payload.URL)
		}
		if got.event.Payload.Website != "test-website" {
			t.Errorf("website = %q, want test-website", got.event.Payload.Website)
		}
		if got.event.Payload.Hostname != "example.test" {
			t.Errorf("hostname = %q, want example.test", got.event.Payload.Hostname)
		}
		if got.event.Payload.Language != "en-GB" {
			t.Errorf("language = %q, want en-GB", got.event.Payload.Language)
		}
		if got.event.Payload.Referrer != "https://referrer.test/start" {
			t.Errorf("referrer = %q, want original referrer", got.event.Payload.Referrer)
		}
		if got.userAgent != "test-browser/1.0" {
			t.Errorf("user agent = %q, want original user agent", got.userAgent)
		}
		if got.forwardedFor != "203.0.113.42" {
			t.Errorf("forwarded IP = %q, want trusted visitor IP", got.forwardedFor)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Umami event")
	}
}

func TestUnmarshalCaddyfileRejectsCookieConsent(t *testing.T) {
	t.Parallel()

	var module Umami
	err := module.UnmarshalCaddyfile(caddyfile.NewTestDispenser(`
		umami {
			event_endpoint http://umami:3000/api/send
			website_uuid test-website
			cookie_consent disable_all umami_consent
		}
	`))
	if err == nil {
		t.Fatal("expected cookie_consent to be rejected")
	}
	if !strings.Contains(err.Error(), "unknown option 'cookie_consent'") {
		t.Fatalf("unexpected error: %v", err)
	}
}

var _ caddyhttp.Handler = testHandler(nil)
