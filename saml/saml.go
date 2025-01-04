package saml

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

var samlMiddleware *samlsp.Middleware

var SAML_ISSUER = strings.TrimSpace(os.Getenv("SAML_ISSUER"))
var SAML_CALLBACK_URL = strings.TrimSpace(os.Getenv("SAML_CALLBACK_URL"))
var SAML_LOGIN_URL = strings.TrimSpace(os.Getenv("SAML_LOGIN_URL"))
var SAML_METADATA_URL = strings.TrimSpace(os.Getenv("SAML_METADATA_URL"))

// TODO - Move this to configmap
const SAML_CERT_FILE = "saml_service.cert"
const SAML_KEY_FILE = "saml_service.key"

func logout(w http.ResponseWriter, r *http.Request) {
	log.Println("did we come here for logout????")
	nameID := samlsp.AttributeFromContext(r.Context(), "urn:oasis:names:tc:SAML:attribute:subject-id")
	url, err := samlMiddleware.ServiceProvider.MakeRedirectLogoutRequest(nameID, "")
	if err != nil {
		panic(err) // TODO handle error
	}

	err = samlMiddleware.Session.DeleteSession(w, r)
	if err != nil {
		panic(err) // TODO handle error
	}

	w.Header().Add("Location", url.String())
	w.WriteHeader(http.StatusFound)
}

// TODO - also pass saml params for configuration
func RegisterSamlAuth(rg *mux.Router, callbackUrl string, handleUser HandleUserFunc) (err error) {
	keyPair, err := tls.LoadX509KeyPair(SAML_CERT_FILE, SAML_KEY_FILE)
	if err != nil {
		log.Println("Error loading key pair: ", err)
		return err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Println("Error parsing key pair: ", err)
		return
	}

	idpMetadataURL, err := url.Parse(SAML_METADATA_URL)
	if err != nil {
		log.Println("Error parsing metadata url: ", SAML_METADATA_URL, err)
		return
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient, *idpMetadataURL)
	if err != nil {
		log.Println("Error loading metadata: ", SAML_METADATA_URL, err)
		return
	}

	baseUrl := strings.TrimSpace(os.Getenv("OAUTH2_BASE_URL"))
	rootURL, err := url.Parse(fmt.Sprintf("%s/auth/", baseUrl))
	if err != nil {
		panic(err) // TODO handle error
	}

	log.Println("Root SAML Url: ", rootURL)
	log.Println("Redirect URI: ", callbackUrl)
	samlMiddleware, _ = samlsp.New(samlsp.Options{
		URL:                *rootURL,
		DefaultRedirectURI: callbackUrl,
		Key:                keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:        keyPair.Leaf,
		IDPMetadata:        idpMetadata,
		SignRequest:        true, // some IdP require the SLO request to be signed
	})

	// HACK ALERT
	// This is all a bit of a bastardization of crewjam/saml code so we can use redirect URLs
	// instead of trying to protect via RequireAccount middleware.  This is because we want a toplevel
	// login to the /login page where user can chose various kinds of auth instead of SAML always
	//
	// crewjam/saml is a pretty awesome library.  Once done with POC we will just create a new kind
	// of middleware more specific to our usecase
	rg.HandleFunc("/saml/login", func(w http.ResponseWriter, r *http.Request) {
		authReq, err := samlMiddleware.ServiceProvider.MakeAuthenticationRequest(SAML_LOGIN_URL, saml.HTTPRedirectBinding, samlMiddleware.ResponseBinding)
		r2 := r.URL.Query().Get("returnTo")
		r2url, err := url.Parse(r2)
		if err != nil {
			r2url, err = url.Parse(baseUrl)
		}
		req2 := &http.Request{URL: r2url}
		relayState, err := samlMiddleware.RequestTracker.TrackRequest(w, req2, authReq.ID)
		redirectURL, err := authReq.Redirect(relayState, &samlMiddleware.ServiceProvider)
		if err != nil {
			log.Println("error creating redirect URI: ", redirectURL)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	})
	rg.Handle("/saml/logout", http.HandlerFunc(logout))
	// rg.HandleFunc("/saml/acs", samlMiddleware.ServeACS)
	rg.HandleFunc("/saml/acs", func(w http.ResponseWriter, r *http.Request) {
		m := samlMiddleware
		err := r.ParseForm()
		if err != nil {
			log.Println("Error parsing ACS form: ", err)
			m.OnError(w, r, err)
			return
		}

		possibleRequestIDs := []string{}
		if m.ServiceProvider.AllowIDPInitiated {
			possibleRequestIDs = append(possibleRequestIDs, "")
		}

		trackedRequests := m.RequestTracker.GetTrackedRequests(r)
		for _, tr := range trackedRequests {
			possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
		}

		assertion, err := m.ServiceProvider.ParseResponse(r, possibleRequestIDs)
		if err != nil {
			log.Println("PRIDS: ", possibleRequestIDs)
			log.Println("Error parsing ACS response: ", r.Form, err)
			m.OnError(w, r, err)
			return
		}

		if err = m.Session.CreateSession(w, r, assertion); err != nil {
			log.Println("Error creating session: ", err)
			m.OnError(w, r, err)
			return
		}

		// Now with assertion we are good to go
		userInfo := map[string]any{}
		for _, attrib := range assertion.AttributeStatements {
			for _, attr := range attrib.Attributes {
				log.Println("Found Attrib: ", attr.Name, len(attr.Values), attr.Values)
				if strings.HasSuffix(attr.Name, "/claims/emailaddress") {
					userInfo["email"] = attr.Values[0].Value
				}
			}
		}
		// http.Redirect(w, r, "/", http.StatusFound)
		// TODO - This is NOT oauth but we are masking this as an oauthtoken and returning it
		token := &oauth2.Token{
			AccessToken: "auth_token",
			Expiry:      time.Now().Add(3600 * time.Second),
		}
		handleUser("saml", SAML_ISSUER, token, userInfo, w, r)
	})
	rg.Handle("/saml/", samlMiddleware)
	return
}
