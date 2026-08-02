package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantAPIKey    string
		wantErr       error
		wantErrString string
	}{
		{
			name: "returns api key for valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey test-key"},
			},
			wantAPIKey: "test-key",
		},
		{
			name: "returns error when authorization header is missing",
			headers: http.Header{},
			wantErr: auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "returns error when authorization header is malformed",
			headers: http.Header{
				"Authorization": []string{"Bearer test-key"},
			},
			wantErrString: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAPIKey, err := auth.GetAPIKey(tt.headers)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}

			if tt.wantErrString != "" {
				if err == nil || err.Error() != tt.wantErrString {
					t.Fatalf("expected error %q, got %v", tt.wantErrString, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if gotAPIKey != tt.wantAPIKey {
				t.Fatalf("expected api key %q, got %q", tt.wantAPIKey, gotAPIKey)
			}
		})
	}
}
