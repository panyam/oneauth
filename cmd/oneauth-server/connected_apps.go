package main

import (
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/panyam/oneauth/apiauth"
	"github.com/panyam/oneauth/core"
	"github.com/panyam/oneauth/httpauth"
)

// connectedAppsPath is the page listing the clients the signed-in user
// approved (issue 516).
const connectedAppsPath = "/auth/connected-apps"

// connectedApps serves the connected-apps page and its disconnect form.
// The user always comes from the session cookie, so a form naming
// another user, or another user's client, only touches the caller's own
// grant.
type connectedApps struct {
	lister  core.ConsentLister
	apps    core.AppRegistrationStore // for client names; may be nil
	revoker *apiauth.ClientAccessRevoker
	subject func(*http.Request) string
	user    func(*http.Request) string
}

// connectedAppRow is one listed client.
type connectedAppRow struct {
	ClientID  string
	Name      string
	Scopes    []string
	GrantedAt time.Time
	ExpiresAt time.Time
}

// mount registers GET connectedAppsPath and POST connectedAppsPath+"/revoke"
// behind protect, the server's CSRF middleware.
func (c *connectedApps) mount(mux *http.ServeMux, protect func(http.Handler) http.Handler) {
	mux.Handle("GET "+connectedAppsPath, protect(http.HandlerFunc(c.list)))
	mux.Handle("POST "+connectedAppsPath+"/revoke", protect(http.HandlerFunc(c.revoke)))
}

func (c *connectedApps) list(w http.ResponseWriter, r *http.Request) {
	subject := c.subject(r)
	if subject == "" {
		http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(connectedAppsPath), http.StatusSeeOther)
		return
	}
	resp, err := c.lister.ListConsents(r.Context(), &core.ListConsentsRequest{Subject: subject})
	if err != nil {
		log.Printf("connected apps: list consents: %v", err)
		http.Error(w, "could not list connected apps", http.StatusInternalServerError)
		return
	}
	rows := make([]connectedAppRow, 0, len(resp.Grants))
	for _, g := range resp.Grants {
		rows = append(rows, connectedAppRow{
			ClientID: g.ClientID, Name: c.clientName(r, g.ClientID),
			Scopes: g.Scopes, GrantedAt: g.GrantedAt, ExpiresAt: g.ExpiresAt,
		})
	}
	data := map[string]any{
		"Title": "Connected Apps", "User": c.user(r), "Apps": rows,
		"CSRFField": httpauth.CSRFTemplateField(r),
	}
	if r.URL.Query().Get("revoked") == "1" {
		data["Flash"] = "App disconnected. It has to ask for your consent again."
	}
	renderTemplate(w, "connected_apps.html", data)
}

func (c *connectedApps) revoke(w http.ResponseWriter, r *http.Request) {
	subject := c.subject(r)
	if subject == "" {
		http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(connectedAppsPath), http.StatusSeeOther)
		return
	}
	clientID := r.PostFormValue("client_id")
	if clientID == "" {
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}
	if _, err := c.revoker.RevokeClientAccess(r.Context(), &apiauth.RevokeClientAccessRequest{Subject: subject, ClientID: clientID}); err != nil {
		log.Printf("connected apps: revoke %q: %v", clientID, err)
		http.Error(w, "could not disconnect the app", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, connectedAppsPath+"?revoked=1", http.StatusSeeOther)
}

// clientName is the registered client_name, or "" when the client has
// none or the registry can't say.
func (c *connectedApps) clientName(r *http.Request, clientID string) string {
	if c.apps == nil {
		return ""
	}
	resp, err := c.apps.GetApp(r.Context(), &core.GetAppRequest{ClientID: clientID})
	if err != nil || resp == nil || resp.App == nil {
		return ""
	}
	return resp.App.ClientName
}
