
# 🔐 secure_bootstrap

`secure_bootstrap` is a drop-in authentication UI and session management engine for `secure_network` and `guikit` applications. Think of it as a self-hosted Auth0 screen designed explicitly for passwordless Passkey authentication and OpenID Connect (OIDC) Single Sign-On (SSO).

It dynamically generates a highly customizable login interface in GUIKit Markup Language (GML), acts as a fully compliant OIDC provider for external applications, and enforces zero-trust session integrity using Device Bound Session Credentials (DBSC).

## ✨ Features

* **Dynamic Auth0-Style UI:** Instantly generate a beautiful, responsive login screen without writing frontend code.
* **Passkey Native:** Fully integrated with `webauthnext` for seamless, passwordless hardware token authentication.
* **🌐 OIDC Identity Provider:** Acts as a fully compliant OpenID Connect provider, allowing external apps to authenticate users via your node and receive signed JWTs.
* **Zero-Trust Middleware:** Includes strict `RequireAuth` middleware to protect internal routes and validate edge-network session tokens.
* **Database-Driven Config:** UI settings (logos, colors, text) can be updated live in `ultimate_db` without recompiling the application.

---

## 📦 Installation

```bash
go get github.com/gddisney/secure_bootstrap

```

*Note: This module requires `github.com/gddisney/guikit`, `github.com/gddisney/secure_network`, and `github.com/gddisney/webauthnext`.*

---

## 🚀 Quick Start

Wiring `secure_bootstrap` into your application only requires two steps: initializing the bootstrap engine, and protecting your routes.

```go
package main

import (
	"log"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
	"github.com/gddisney/secure_bootstrap"
)

func main() {
	// 1. Initialize Core Engines
	db := ultimate_db.NewDB(pool, wal)
	ui, _ := guikit.New("ui.db", "ui.wal")
	r, _ := secure_network.NewRouter(db, ui, "secure_session_token")
	wa, _ := webauthnext.New(ui, "My Secure App", "localhost", "https://localhost")

	// 2. Mount the Authentication UI & OIDC Endpoints (/auth)
	secure_bootstrap.BootstrapAuth(r, wa)

	// 3. Protect Your Routes using the Middleware
	ui.Get("/dashboard", secure_bootstrap.RequireAuth(r, func(c *guikit.Context) {
		currentUser := c.Data["CurrentUser"].(string)
		// Render protected content...
	}))

	r.Boot()
}

```

---

## 🔑 OIDC Identity Provider (SSO)

Because `secure_bootstrap` is tightly integrated with `webauthnext`, initializing the module automatically turns your application into a fully functional OpenID Connect (OIDC) Identity Provider.

External applications can redirect users to your node to authenticate using their Passkeys. Once verified, your node will issue securely signed JWTs (JSON Web Tokens) to the requesting application.

The following standard OIDC endpoints are automatically mounted:

* **Discovery:** `GET /.well-known/openid-configuration`
* **JWKS (Public Keys):** `GET /auth/keys`
* **Authorization:** `GET /auth/authorize`
* **Token Exchange:** `POST /auth/token`

---

## 🎨 UI Configuration (`UIConfig`)

The login screen is highly customizable. By default, `secure_bootstrap` uses a safe fallback configuration, but you can override it by writing a JSON payload to `ConfigPageID` in your `ultimate_db` under the key `ui_settings`.

### The Configuration Struct

```go
type UIConfig struct {
	BrandName    string     `json:"brand_name"`    // E.g., "Wiliwala"
	Logo         string     `json:"logo"`          // Emoji or image URL
	PrimaryColor string     `json:"primary_color"` // Hex code, e.g., "#1d9bf0"
	Description  string     `json:"description"`   // Subtitle text
	FormAction   string     `json:"form_action"`
	Fields       []UIField  `json:"fields"`        // Custom input fields
	Buttons      []UIButton `json:"buttons"`       // Custom auth buttons
}

```

When a user visits `/auth`, the engine reads this configuration, compiles it into raw `GML`, saves it to the local `views/` directory, and serves it via `guikit` in real-time.

---

## 🛡️ Session Security & DBSC

`secure_bootstrap` ensures that session cookies cannot be hijacked and reused on a different machine.

When the `RequireAuth` middleware wraps a route, it performs the following checks:

1. Validates the existence of the `session_id` cookie.
2. Extracts the `user_session_{username}` string.
3. Validates the **Device Bound Session Credential (DBSC)** by creating a cryptographic fingerprint of the user's exact browser and verifying it against the hardware proof stored during login.

If any check fails, the session is instantly destroyed, and the user is redirected to `/auth`.
