package secure_bootstrap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

const (
	AuthPageID   ultimate_db.PageID = 1
	ConfigPageID ultimate_db.PageID = 99
)

// --- Dynamic UI Configuration ---

// UIConfig drives the completely dynamic Auth0-style rendering
type UIConfig struct {
	BrandName    string     `json:"brand_name"`
	Logo         string     `json:"logo"`
	PrimaryColor string     `json:"primary_color"`
	Description  string     `json:"description"`
	FormAction   string     `json:"form_action"`
	Fields       []UIField  `json:"fields"`
	Buttons      []UIButton `json:"buttons"`
}

type UIField struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Placeholder string `json:"placeholder"`
}

type UIButton struct {
	Label   string `json:"label"`
	Primary bool   `json:"primary"`
	Type    string `json:"type"`
	OnClick string `json:"onclick"` // Completely dynamic JS bindings
}

// DefaultConfig provides a safe fallback matching your original GML
func DefaultConfig() UIConfig {
	return UIConfig{
		BrandName:    "Wiliwala",
		Logo:         "🌐",
		PrimaryColor: "#1d9bf0",
		Description:  "Authenticate securely using your device's native Passkey. No passwords required.",
		FormAction:   "/auth/dev",
		Fields: []UIField{
			{ID: "username", Name: "username", Type: "text", Placeholder: "Enter a Username"},
		},
		Buttons: []UIButton{
			{Label: "Sign In with Passkey", Primary: true, Type: "button", OnClick: "passkeyLogin(document.getElementById('username').value)"},
			{Label: "Register New Passkey", Primary: false, Type: "button", OnClick: "passkeyRegister(document.getElementById('username').value)"},
		},
	}
}

// GenerateDynamicGML compiles the UIConfig into the raw GML syntax string expected by GUIKit.
func GenerateDynamicGML(cfg UIConfig) string {
	var sb strings.Builder

	// Build Core Wrapper and Styles
	sb.WriteString(fmt.Sprintf(`html(
    head(
        meta:charset."utf-8"(),
        title("%s - Secure Login"),
        script:src."/auth/webauthn.js"(),
        style(
            rule("body", "background-color: #000", "font-family: -apple-system, BlinkMacSystemFont, sans-serif", "margin: 0"),
            rule(".auth-wrapper", "display: flex", "height: 100vh", "width: 100vw", "align-items: center", "justify-content: center"),
            rule(".auth-box", "width: 100%%", "max-width: 420px", "background: #16181c", "border-radius: 16px", "padding: 40px", "text-align: center", "border: 1px solid #2f3336", "box-sizing: border-box"),
            rule(".auth-logo", "font-size: 36px", "margin-bottom: 20px"),
            rule(".auth-title", "color: white", "margin: 0 0 10px 0", "font-size: 24px"),
            rule(".auth-desc", "color: #71767b", "margin-bottom: 30px", "font-size: 15px", "line-height: 1.5"),
            rule(".auth-input", "width: 100%%", "padding: 16px", "margin-bottom: 20px", "border-radius: 8px", "border: 1px solid #333", "background: #000", "color: white", "box-sizing: border-box"),
            rule(".btn-primary", "background: %s", "color: white", "border: none", "padding: 16px", "border-radius: 9999px", "cursor: pointer", "width: 100%%", "font-size: 16px", "font-weight: bold", "margin-bottom: 15px"),
            rule(".btn-secondary", "background: transparent", "color: #e7e9ea", "border: 1px solid #536471", "padding: 16px", "border-radius: 9999px", "cursor: pointer", "width: 100%%", "font-size: 16px", "font-weight: bold"),
            rule(".btn-dev", "background: #2f3336", "color: white", "border: none", "padding: 16px", "border-radius: 8px", "cursor: pointer", "width: 100%%", "font-size: 16px", "font-weight: bold", "margin-top: 15px")
        )
    ),
    body(
        div.auth-wrapper(
            div.auth-box(
                div.auth-logo("%s"),
                h2.auth-title("Sign in to %s"),
                p.auth-desc("%s"),
                form:method."POST":action."%s"(`,
		cfg.BrandName, cfg.PrimaryColor, cfg.Logo, cfg.BrandName, cfg.Description, cfg.FormAction))

	// Inject Dynamic Input Fields
	for _, field := range cfg.Fields {
		sb.WriteString(fmt.Sprintf("\n                    input.auth-input:id.\"%s\":name.\"%s\":type.\"%s\":placeholder.\"%s\"(),",
			field.ID, field.Name, field.Type, field.Placeholder))
	}

	// Inject Dynamic Buttons and JS execution contexts
	for _, btn := range cfg.Buttons {
		btnClass := ".btn-secondary"
		if btn.Primary {
			btnClass = ".btn-primary"
		}

		onclickStr := ""
		if btn.OnClick != "" {
			onclickStr = fmt.Sprintf(`:onclick."%s"`, btn.OnClick)
		}

		sb.WriteString(fmt.Sprintf("\n                    button%s:type.\"%s\"%s(\"%s\"),",
			btnClass, btn.Type, onclickStr, btn.Label))
	}

	// Close Layout
	sb.WriteString(`
                )
            )
        )
    )
)`)

	return sb.String()
}

// --- Core Bootstrap & Routing ---

// BootstrapAuth binds the dynamic identity provider directly to the router
func BootstrapAuth(router *secure_network.Router, wa *webauthnext.Provider) {

	// 1. Dynamic UI Render Route (The Auth0-like Entrypoint)
	router.Mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		
		// Pull Configuration
		txn := router.DB.BeginTxn()
		cfgBytes, err := router.DB.Read(ConfigPageID, txn, []byte("ui_settings"))
		router.DB.CommitTxn(txn)

		cfg := DefaultConfig()
		if err == nil && len(cfgBytes) > 0 {
			if parseErr := json.Unmarshal(cfgBytes, &cfg); parseErr != nil {
				cfg = DefaultConfig() // Fallback to safe structure on corruption
			}
		}

		// Compile the GML tree using the configuration
		gmlSyntax := GenerateDynamicGML(cfg)

		// Render via GUIKit
		ctx := &guikit.Context{W: w, R: r}
		router.GUIKit.RenderString(ctx, gmlSyntax)
	})

	// 2. Default Login Flow Connector
	router.Mux.HandleFunc("/auth/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if wa.Login(username, password, w, r) {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/auth?error=failed", http.StatusSeeOther)
		}
	})
}

// --- Security & Session Enforcement ---

func Fingerprint(r *http.Request) string {
	raw := r.UserAgent() + "|" + r.Header.Get("Accept-Language")
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func VerifyDBSC(router *secure_network.Router, c *guikit.Context, user string) bool {
	dbscCookie, err := c.R.Cookie("dbsc_token")
	if err != nil || dbscCookie.Value == "" {
		return false
	}

	fp := Fingerprint(c.R)
	key := []byte("dbsc:" + user + ":" + dbscCookie.Value)

	txn := router.DB.BeginTxn()
	stored, err := router.DB.Read(AuthPageID, txn, key)
	router.DB.CommitTxn(txn)

	return err == nil && string(stored) == fp
}

func RequireAuth(router *secure_network.Router, next func(c *guikit.Context)) func(c *guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		user := ""
		if strings.HasPrefix(cookie.Value, "login_") {
			user = strings.TrimPrefix(cookie.Value, "login_")
		} else if strings.HasPrefix(cookie.Value, "reg_") {
			user = strings.TrimPrefix(cookie.Value, "reg_")
		}

		if user == "" || !VerifyDBSC(router, c, user) {
			http.SetCookie(c.W, &http.Cookie{Name: "session_id", MaxAge: -1, Path: "/"})
			http.SetCookie(c.W, &http.Cookie{Name: "dbsc_token", MaxAge: -1, Path: "/"})
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}

		c.Data["CurrentUser"] = user
		next(c)
	}
}
