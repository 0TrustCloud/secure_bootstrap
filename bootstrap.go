package secure_bootstrap

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gddisney/guikit"
	"github.com/gddisney/secure_network"
	"github.com/gddisney/secure_policy"
	"github.com/gddisney/ultimate_db"
	"github.com/gddisney/webauthnext"
)

// UI Configuration
const ConfigPageID ultimate_db.PageID = 99

// [Keep GenerateDynamicGML and DefaultConfig as they were, they are functional]

func BootstrapAuth(router *secure_network.Router, wa *webauthnext.Provider, meshNode *secure_network.MeshNode, gatewayAddr string) {
	// 1. UI Route
	router.Mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		gmlSyntax := GenerateDynamicGML(DefaultConfig())
		os.MkdirAll("views", 0755)
		os.WriteFile("views/dynamic_auth.gml", []byte(gmlSyntax), 0644)
		ctx := &guikit.Context{W: w, R: r, Data: make(map[string]interface{})}
		router.GUIKit.Render(ctx, "views/dynamic_auth")
	})

	// 2. Registration Routes (JS Calls)
	router.Mux.HandleFunc("/auth/register/begin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		wa.BeginRegistration(w, r)
	})

	router.Mux.HandleFunc("/auth/register/finish", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		username := r.URL.Query().Get("username")
		// Use a local interceptor to capture the success status
		interceptor := &loginInterceptor{ResponseWriter: w, username: username}
		wa.FinishRegistration(interceptor, r)
		
		if interceptor.status == http.StatusOK && meshNode != nil {
			go meshNode.Connect(gatewayAddr)
		}
	})

	// 3. Login Routes (JS Calls)
	router.Mux.HandleFunc("/auth/login/begin", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		wa.BeginLogin(w, r)
	})

	router.Mux.HandleFunc("/auth/login/finish", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		username := r.URL.Query().Get("username")
		interceptor := &loginInterceptor{ResponseWriter: w, username: username}
		wa.FinishLogin(interceptor, r)
		
		if interceptor.status == http.StatusOK && meshNode != nil {
			go meshNode.Connect(gatewayAddr)
		}
	})
}

// Interceptor for Session Cookies
type loginInterceptor struct {
	http.ResponseWriter
	status   int
	username string
}

func (i *loginInterceptor) WriteHeader(code int) {
	if i.status == 0 {
		i.status = code
		if code == http.StatusOK {
			http.SetCookie(i.ResponseWriter, &http.Cookie{
				Name:     "session_id",
				Value:    "user_session_" + i.username,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
		}
		i.ResponseWriter.WriteHeader(code)
	}
}

func (i *loginInterceptor) Write(b []byte) (int, error) {
	if i.status == 0 {
		i.WriteHeader(http.StatusOK)
	}
	return i.ResponseWriter.Write(b)
}

// Middleware
func RequireAuth(router *secure_network.Router, next func(c *guikit.Context)) func(c *guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil || cookie.Value == "" || !strings.HasPrefix(cookie.Value, "user_session_") {
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}
		c.Data["CurrentUser"] = strings.TrimPrefix(cookie.Value, "user_session_")
		next(c)
	}
}

func RequirePolicy(pe *secure_policy.PolicyEngine, action, resource string, next func(c *guikit.Context)) func(c *guikit.Context) {
	return func(c *guikit.Context) {
		cookie, err := c.R.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
			return
		}
		user := strings.TrimPrefix(cookie.Value, "user_session_")
		if !pe.Evaluate([]byte(user), action, resource, nil) {
			c.W.WriteHeader(http.StatusForbidden)
			c.W.Write([]byte("403 Forbidden"))
			return
		}
		c.Data["CurrentUser"] = user
		next(c)
	}
}

func HandleLogout(c *guikit.Context) {
	http.SetCookie(c.W, &http.Cookie{Name: "session_id", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(c.W, c.R, "/auth", http.StatusSeeOther)
}
