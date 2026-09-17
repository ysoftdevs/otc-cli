package iam

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	golangsdk "github.com/opentelekomcloud/gophertelekomcloud"
)

func TestIAMReadErrorsAreReturnedWithoutRetry(t *testing.T) {
	readers := []struct {
		name string
		read func(*Service) error
	}{
		{"JSON", func(s *Service) error { _, err := s.ListGroups("", ""); return err }},
		{"XML", func(s *Service) error { _, err := s.readTextVersion("v3-ext", "metadata"); return err }},
		{"catalog", func(s *Service) error { _, err := s.listProjectCatalog(); return err }},
	}
	for _, reader := range readers {
		for _, status := range []int{http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout} {
			t.Run(fmt.Sprintf("%s/%d", reader.name, status), func(t *testing.T) {
				var requests atomic.Int32
				service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					w.WriteHeader(status)
					fmt.Fprint(w, `{"error_code":"fixture-error","error_msg":"Unavailable"}`)
				})
				service.projectToken = "project-token"
				// Keep a broken 429-retry configuration from stalling the suite.
				backoff := time.Millisecond
				service.client.BackoffRetryTimeout = &backoff
				result := make(chan error, 1)
				go func() { result <- reader.read(service) }()
				var err error
				select {
				case err = <-result:
				case <-time.After(time.Second):
					t.Fatal("IAM read did not return the HTTP failure promptly; possible implicit retry")
				}
				if err == nil || requests.Load() != 1 {
					t.Fatalf("requests=%d err=%v; want one request and the HTTP error", requests.Load(), err)
				}
				if status == http.StatusTooManyRequests {
					var typed golangsdk.ErrDefault429
					if !errors.As(err, &typed) {
						t.Fatalf("wrapped 429 lost its SDK error type: %T %v", err, err)
					}
				}
				if service.client.Token() != "test-token" {
					t.Error("failed read changed the account token")
				}
			})
		}
	}
}

func TestIAMReadRejectsMalformedAndOversizedJSON(t *testing.T) {
	for _, tc := range []struct {
		name, body, message string
	}{
		{"trailing object", `{"user":{"id":"u"}} {"user":{"id":"other"}}`, "exactly one JSON value"},
		{"trailing garbage", `{"user":{"id":"u"}} invalid`, "exactly one JSON value"},
		{"truncated", `{"user":{"id":"u"}`, "invalid JSON"},
		{"oversized", `{"user":{"description":"` + strings.Repeat("x", 16<<20) + `"}}`, "exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, tc.body) })
			record, err := service.GetUser("u")
			if err == nil || record != nil || !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("malformed response accepted: record fields=%d err=%v", len(record), err)
			}
		})
	}
}

func TestIAMReadBareObjectRejectsNull(t *testing.T) {
	service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `null`) })
	record, err := service.getVersion("v3.0", "", "fixture")
	if err == nil || record != nil {
		t.Fatalf("null became successful bare object: record=%v err=%v", record, err)
	}
}

type iamReadTransport func(*http.Request) (*http.Response, error)

func (f iamReadTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type iamReadBody struct {
	io.Reader
	closed bool
}

func (b *iamReadBody) Close() error {
	b.closed = true
	return nil
}

func TestIAMReadClosesBodiesOnSuccessAndDecodeFailure(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		read       func(*Service) error
	}{
		{"JSON success", `{"user":{"id":"u"}}`, func(s *Service) error { _, err := s.GetUser("u"); return err }},
		{"JSON malformed", `invalid`, func(s *Service) error { _, err := s.GetUser("u"); return err }},
		{"XML success", `<EntityDescriptor/>`, func(s *Service) error { _, err := s.readTextVersion("v3-ext", "metadata"); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, _ := testService(t, func(w http.ResponseWriter, r *http.Request) { t.Error("custom transport was bypassed") })
			body := &iamReadBody{Reader: strings.NewReader(tc.body)}
			service.client.HTTPClient.Transport = iamReadTransport(func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: body, Request: r}, nil
			})
			_ = tc.read(service)
			if !body.closed {
				t.Fatal("IAM read left the response body open")
			}
		})
	}
}
