package capi

import (
	"errors"
	"net/http"
	"testing"

	"github.com/cli/cli/v2/internal/gh"
	"github.com/stretchr/testify/require"
)

// recordingRoundTripper captures the Authorization header of every request it sees and returns a stub 200 response.
type recordingRoundTripper struct {
	authHeaders []string
}

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.authHeaders = append(r.authHeaders, req.Header.Get("Authorization"))
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: make(http.Header), Request: req}, nil
}

// sequencedAuthConfig returns a different credential on each call and records the hostname it was asked about, so a
// test can prove the transport resolves a token per request rather than once at construction time.
type sequencedAuthConfig struct {
	creds  []gh.Credential
	status gh.RefreshStatus
	err    error
	calls  []string
}

func (s *sequencedAuthConfig) ActiveTokenWithRefresh(hostname string) (gh.Credential, gh.RefreshStatus, error) {
	cred := s.creds[len(s.calls)]
	s.calls = append(s.calls, hostname)
	return cred, s.status, s.err
}

func TestCAPITransportResolvesFreshTokenPerRequest(t *testing.T) {
	base := &recordingRoundTripper{}
	auth := &sequencedAuthConfig{
		creds:  []gh.Credential{{Token: "token-1"}, {Token: "token-2"}},
		status: gh.RefreshStatusDone,
	}
	ct := newCAPITransport(auth, "github.com", "https://api.githubcopilot.com", base)

	for range 2 {
		req, err := http.NewRequest(http.MethodGet, "https://api.githubcopilot.com/foo", nil)
		require.NoError(t, err)
		_, err = ct.RoundTrip(req)
		require.NoError(t, err)
	}

	// The token is resolved once per request against the configured host, and each freshly resolved token is the one
	// presented on that request. A regression to a single construction-time lookup would reuse one token and fail here.
	require.Equal(t, []string{"github.com", "github.com"}, auth.calls)
	require.Equal(t, []string{"Bearer token-1", "Bearer token-2"}, base.authHeaders)
}

func TestCAPITransportUsesLastTokenWhenRefreshErrors(t *testing.T) {
	base := &recordingRoundTripper{}
	auth := &sequencedAuthConfig{
		creds:  []gh.Credential{{Token: "stale-token"}},
		status: gh.RefreshStatusFailed,
		err:    errors.New("network failure"),
	}
	ct := newCAPITransport(auth, "github.com", "https://api.githubcopilot.com", base)

	req, err := http.NewRequest(http.MethodGet, "https://api.githubcopilot.com/foo", nil)
	require.NoError(t, err)
	resp, err := ct.RoundTrip(req)

	// Refresh is best effort: a failed refresh still yields the last stored token, so the request proceeds with it.
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, []string{"Bearer stale-token"}, base.authHeaders)
}

func TestCAPITransportStripsAuthOnCrossHostOrDowngradeRedirect(t *testing.T) {
	tests := []struct {
		name         string
		capiBaseURL  string
		initialURL   string
		redirectURL  string
		wantAuth     string
		wantAuthCall int
	}{
		{
			name:         "same-host https redirect retains auth",
			capiBaseURL:  "https://api.githubcopilot.com",
			initialURL:   "https://api.githubcopilot.com/v1/sessions",
			redirectURL:  "https://api.githubcopilot.com/v2/sessions",
			wantAuth:     "Bearer secret-token",
			wantAuthCall: 1,
		},
		{
			name:         "cross-host redirect strips auth",
			capiBaseURL:  "https://api.githubcopilot.com",
			initialURL:   "https://api.githubcopilot.com/v1/sessions",
			redirectURL:  "https://attacker.example.com/collect",
			wantAuth:     "",
			wantAuthCall: 0,
		},
		{
			name:         "https to http scheme downgrade strips auth",
			capiBaseURL:  "https://api.githubcopilot.com",
			initialURL:   "https://api.githubcopilot.com/v1/sessions",
			redirectURL:  "http://api.githubcopilot.com/v1/sessions",
			wantAuth:     "",
			wantAuthCall: 0,
		},
		{
			name:         "untrusted non-https capiBaseURL does not attach auth",
			capiBaseURL:  "http://api.githubcopilot.com",
			initialURL:   "https://api.githubcopilot.com/v1/sessions",
			redirectURL:  "",
			wantAuth:     "",
			wantAuthCall: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &recordingRoundTripper{}
			auth := &sequencedAuthConfig{
				creds:  []gh.Credential{{Token: "secret-token"}},
				status: gh.RefreshStatusDone,
			}
			ct := newCAPITransport(auth, "github.com", tt.capiBaseURL, base)

			var req *http.Request
			if tt.redirectURL != "" {
				initialReq, err := http.NewRequest(http.MethodGet, tt.initialURL, nil)
				require.NoError(t, err)
				req, err = http.NewRequest(http.MethodGet, tt.redirectURL, nil)
				require.NoError(t, err)
				req.Header.Set("Authorization", "Bearer secret-token")
				req.Response = &http.Response{Request: initialReq}
			} else {
				var err error
				req, err = http.NewRequest(http.MethodGet, tt.initialURL, nil)
				require.NoError(t, err)
			}

			_, err := ct.RoundTrip(req)
			require.NoError(t, err)
			require.Len(t, auth.calls, tt.wantAuthCall)
			require.Equal(t, []string{tt.wantAuth}, base.authHeaders)
		})
	}
}
