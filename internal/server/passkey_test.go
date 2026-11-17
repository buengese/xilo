package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/stubbedev/xilo/internal/config"
)

// fillReader is an endless run of one byte.
type fillReader byte

func (b fillReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

// countReader records how much of its source the handler actually pulled.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// TestPasskeyFinishBodyCapped pins that both finish handlers refuse a body
// far past any real WebAuthn response without reading it to the end: go-webauthn
// decodes whatever it is handed into memory, and login finish is unauthenticated.
func TestPasskeyFinishBodyCapped(t *testing.T) {
	s, db, ts := newTestServerCfg(t, func(cfg *config.Config) { cfg.BaseURL = "http://localhost:8080" })
	bootstrapAdmin(t, db)
	blob, _ := json.Marshal(webauthn.Credential{ID: []byte("cred-id")})
	db.AddPasskey(adminID(t, db), "pk", blob)

	const sent = 32 << 20
	finish := func(path string, h http.HandlerFunc, cookies []*http.Cookie) (*httptest.ResponseRecorder, int64) {
		t.Helper()
		src := &countReader{r: io.MultiReader(strings.NewReader(`{"id":"`), io.LimitReader(fillReader('A'), sent))}
		req := httptest.NewRequest(http.MethodPost, path, src)
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec, src.n
	}

	// login: begin opens the ceremony, so finish gets as far as the body
	resp, _ := http.Post(ts.URL+"/admin/login/passkey/begin", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login begin → %d", resp.StatusCode)
	}
	resp.Body.Close()
	rec, n := finish("/admin/login/passkey/finish", s.handlePasskeyLoginFinish, nil)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Could not sign in") {
		t.Fatalf("oversized login finish → %d %q", rec.Code, rec.Body.String())
	}
	if n == 0 || n > 2*maxWebAuthnBody {
		t.Fatalf("login finish read %d of %d bytes; cap is %d", n, sent, maxWebAuthnBody)
	}

	// registration: same cap behind the session
	c := adminClient(t, ts)
	resp, _ = c.PostForm(ts.URL+"/admin/passkeys/register/begin", url.Values{"current": {adminPass}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register begin → %d", resp.StatusCode)
	}
	resp.Body.Close()
	u, _ := url.Parse(ts.URL)
	rec, n = finish("/admin/passkeys/register/finish", s.handlePasskeyRegisterFinish, c.Jar.Cookies(u))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Could not register") {
		t.Fatalf("oversized register finish → %d %q", rec.Code, rec.Body.String())
	}
	if n == 0 || n > 2*maxWebAuthnBody {
		t.Fatalf("register finish read %d of %d bytes; cap is %d", n, sent, maxWebAuthnBody)
	}
}
