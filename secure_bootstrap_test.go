package secure_bootstrap

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http/httptest"
	"testing"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/webauthnext"
)

func TestDefaultConfig(
	t *testing.T,
) {

	cfg := DefaultConfig()

	if cfg.BrandName == "" {

		t.Fatal(
			"default config missing brand name",
		)
	}

	if len(cfg.Fields) == 0 {

		t.Fatal(
			"default config missing fields",
		)
	}

	if len(cfg.Buttons) == 0 {

		t.Fatal(
			"default config missing buttons",
		)
	}
}

func TestGenerateDynamicGML(
	t *testing.T,
) {

	cfg := DefaultConfig()

	gml := GenerateDynamicGML(
		cfg,
	)

	if len(gml) == 0 {

		t.Fatal(
			"generated gml is empty",
		)
	}
}

func TestLoginInterceptor(
	t *testing.T,
) {

	rec := httptest.NewRecorder()

	interceptor := &loginInterceptor{
		ResponseWriter: rec,
		username:       "alice",
	}

	interceptor.WriteHeader(
		200,
	)

	resp := rec.Result()

	cookies := resp.Cookies()

	if len(cookies) == 0 {

		t.Fatal(
			"expected session cookie",
		)
	}

	found := false

	for _, c := range cookies {

		if c.Name == "session_id" {

			found = true
		}
	}

	if !found {

		t.Fatal(
			"session cookie missing",
		)
	}
}

func TestWebAuthnProvider(
	t *testing.T,
) {

	rsaPriv, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)

	if err != nil {

		t.Fatalf(
			"rsa generation failed: %v",
			err,
		)
	}

	sessionManager := secure_policy.NewSessionManager(
		nil,
		rsaPriv,
	)

	gui := &guikit.GUIKit{}

	// IMPORTANT:
	// RPID must be domain only
	// Origin must be full HTTPS URL

	provider, err := webauthnext.New(
		gui,
		sessionManager,
		"example.com",
		"https://example.com",
		"Secure Test",
	)

	if err != nil {

		t.Fatalf(
			"webauthn init failed: %v",
			err,
		)
	}

	if provider == nil {

		t.Fatal(
			"provider is nil",
		)
	}
}
