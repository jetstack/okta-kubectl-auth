package okta

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"
)

type debugTransport struct {
	t   http.RoundTripper
	log zerolog.Logger
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	d.log.Debug().Msgf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	d.log.Debug().Msgf("%s", respDump)
	return resp, nil
}

type Okta struct {
	log zerolog.Logger

	BaseDomain string

	Scopes   []string
	BindAddr string

	Debug bool

	APIToken string

	ClientID     string
	ClientSecret string

	myVerifier *oidc.IDTokenVerifier
	myProvider *oidc.Provider
	myClient   *http.Client

	server *http.Server
}

func New(log *zerolog.Logger, debug bool) *Okta {
	if log == nil {
		var logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
		if debug {
			zerolog.SetGlobalLevel(zerolog.DebugLevel)
		} else {
			zerolog.SetGlobalLevel(zerolog.InfoLevel)
		}
		log = &logger
	}

	return &Okta{
		log:      *log,
		Scopes:   []string{"openid", "profile", "groups", "email"},
		BindAddr: "127.0.0.1:8888",
	}
}

// get a http client
func (o *Okta) client() *http.Client {
	if o.myClient == nil {
		o.myClient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				Dial: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).Dial,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}
		if o.Debug {
			o.myClient.Transport = debugTransport{t: o.myClient.Transport, log: o.log}
		}

	}
	return o.myClient
}

// get a oidc verifier
func (o *Okta) verifier() *oidc.IDTokenVerifier {
	if o.myVerifier == nil {
		o.myVerifier = o.provider().Verifier(&oidc.Config{ClientID: o.ClientID})
	}
	return o.myVerifier
}

// get a oidc provider
func (o *Okta) provider() *oidc.Provider {
	if o.myProvider == nil {
		ctx := oidc.ClientContext(context.Background(), o.client())
		issuerURL := o.IssuerURL()
		provider, err := oidc.NewProvider(ctx, issuerURL)
		if err != nil {
			panic(fmt.Errorf("Failed to query provider %q: %v", issuerURL, err))
		}
		o.myProvider = provider

	}
	return o.myProvider
}

// init oidc proider
func (o *Okta) offlineAsScope() bool {
	var s struct {
		// What scopes does a provider support?  See:
		// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := o.provider().Claims(&s); err != nil {
		panic(fmt.Errorf("Failed to parse provider scopes_supported: %v", err))
	}

	if len(s.ScopesSupported) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		return true
	} else {
		// See if scopes_supported has the "offline_access" scope.
		for _, scope := range s.ScopesSupported {
			if scope == oidc.ScopeOfflineAccess {
				return true
			}
		}
	}
	return false
}

// this authorizes against OIDC
func (o *Okta) Authorize(authCodeURLCh chan string) error {

	state, err := GenerateRandomString(16)
	if err != nil {
		return err
	}

	nonce, err := GenerateRandomString(16)
	if err != nil {
		return err
	}

	var authCodeURL string
	scopes := o.Scopes

	// handle offline
	if o.offlineAsScope() {
		scopes = append(scopes, "offline_access")
		authCodeURL = o.OAuth2Config(scopes).AuthCodeURL(state)
	} else {
		authCodeURL = o.OAuth2Config(scopes).AuthCodeURL(state, oauth2.AccessTypeOffline)
	}

	authCodeURLParsed, err := url.Parse(authCodeURL)
	if err != nil {
		return err
	}
	q := authCodeURLParsed.Query()
	q.Set("nonce", nonce)
	q.Set("response_mode", "form_post")
	authCodeURLParsed.RawQuery = q.Encode()
	authCodeURL = authCodeURLParsed.String()

	tokenCh, err := o.retrieveToken(state, nonce)

	fmt.Printf("\nPlease navigate to the following URL and login to your Okta account:\n\n%s\n", authCodeURL)
	// publish URL in channel
	if authCodeURLCh != nil {
		authCodeURLCh <- authCodeURL
	}

	token := <-tokenCh

	o.printApiserverConfiguration()

	o.printKubectlConfiguration(token.RefreshToken)

	return nil

}

func (o *Okta) printKubectlConfiguration(refreshToken string) {

	fmt.Printf("\nRun the following command (replacing <username> with a user in your kubeconfig) to configure kubectl for OIDC authentication:\n\nkubectl config set-credentials \\\n  --auth-provider=oidc \\\n  --auth-provider-arg=idp-issuer-url=%s \\\n  --auth-provider-arg=client-id=%s \\\n  --auth-provider-arg=client-secret=%s \\\n  --auth-provider-arg=refresh-token=%s \\\n  <username>\n", o.BaseDomain, o.ClientID, o.ClientSecret, refreshToken)

	return
}

func (o *Okta) printApiserverConfiguration() {

	fmt.Printf("\nConfigure the apiserver with the following flags:\n\n--oidc-issuer-url=%s\n--oidc-client-id=%s\n--oidc-username-claim=preferred_username\n--oidc-username-prefix=okta:\n--oidc-groups-claim=groups\n--oidc-groups-prefix=okta:\n", o.BaseDomain, o.ClientID)

	return
}

func (o *Okta) IssuerURL() string {
	return o.BaseDomain
}

func (o *Okta) RedirectURL() string {
	return fmt.Sprintf("http://%s/callback", o.BindAddr)
}

func (o *Okta) OAuth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     o.provider().Endpoint(),
		Scopes:       scopes,
		RedirectURL:  o.RedirectURL(),
	}
}

func (o *Okta) newRequest(method string, path string, reader io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(
		method,
		o.IssuerURL()+path,
		reader,
	)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", contentTypeApplicationJSON)
	req.Header.Set("Content-Type", contentTypeApplicationJSON)
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Authorization", fmt.Sprintf("SSWS %s", o.APIToken))

	return req, nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}
