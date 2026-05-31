package secure_bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"

	"github.com/0TrustCloud/guikit"
	"github.com/0TrustCloud/secure_policy"
	"github.com/0TrustCloud/auth_provider"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.BrandName == "" {
		t.Fatal("default config missing brand name")
	}

	if len(cfg.Fields) == 0 {
		t.Fatal("default config missing fields")
	}

	if len(cfg.Buttons) == 0 {
		t.Fatal("default config missing buttons")
	}
}

func TestGenerateDynamicGML(t *testing.T) {
	cfg := DefaultConfig()

	gml := GenerateDynamicGML(cfg)

	if len(gml) == 0 {
		t.Fatal("generated gml is empty")
	}
}

func TestLoginInterceptor(t *testing.T) {
	rec := httptest.NewRecorder()

	interceptor := &loginInterceptor{
		ResponseWriter: rec,
		username:       "alice",
	}

	interceptor.WriteHeader(200)

	resp := rec.Result()
	defer resp.Body.Close()

	cookies := resp.Cookies()

	if len(cookies) == 0 {
		t.Fatal("expected session cookie")
	}

	found := false
	for _, c := range cookies {
		if c.Name == "session_id" {
			found = true
		}
	}

	if !found {
		t.Fatal("session cookie missing")
	}
}

func TestWebAuthnProvider(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa generation failed: %v", err)
	}

	// Aligned with secure_policy.NewSessionManager's signature within the 0TrustCloud architecture
	sessionManager := secure_policy.NewSessionManager(nil, rsaPriv)

	gui := &guikit.GUIKit{}

	// Aligned with webauthnext.New argument mapping: (ui, sessionManager, displayName, rpid, origin)
	provider, err := webauthnext.New(
		gui,
		sessionManager,
		"Secure Test",
		"example.com",
		"https://example.com",
	)

	if err != nil {
		t.Fatalf("webauthn init failed: %v", err)
	}

	if provider == nil {
		t.Fatal("provider is nil")
	}
}
