package okta_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/headzoo/surf"
	"github.com/rs/zerolog"

	"github.com/jetstack/okta-kubectl-auth/pkg/okta"
)

const envAdminAPIToken = "OKTA_ADMIN_API_TOKEN"
const envOktaBaseDomain = "OKTA_BASE_DOMAIN"

func UserSession(baseDomain string, user string, password string) (string, error) {
	resp, err := http.DefaultClient.Post(
		fmt.Sprintf("%s/api/v1/authn", baseDomain),
		"application/json",
		bytes.NewReader([]byte(fmt.Sprintf(`{
  "username": "%s",
  "password": "%s",
  "relayState": "/myapp/some/deep/link/i/want/to/return/to",
  "options": {
    "multiOptionalFactorEnroll": false,
    "warnBeforePasswordExpired": false
  }
}`, user, password))),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	bodyData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	sessionToken := struct {
		SessionToken string `json:"sessionToken"`
		Status       string `json:"status"`
	}{}

	err = json.Unmarshal(bodyData, &sessionToken)
	if err != nil {
		return "", err
	}

	if sessionToken.Status != "SUCCESS" {
		return "", fmt.Errorf("login failed: %s", string(bodyData))
	}

	return sessionToken.SessionToken, nil
}

func TestOktaE2E(t *testing.T) {

	logger := zerolog.New(ioutil.Discard).With().Timestamp().Logger()
	if testing.Verbose() {
		logger = logger.Output(os.Stderr).Level(zerolog.DebugLevel)
	}

	random, err := okta.GenerateRandomString(8)
	if err != nil {
		t.Fatal("unexpected error generating random string: ", err)
	}

	o := okta.New(&logger, true)

	if os.Getenv(envAdminAPIToken) == "" || os.Getenv(envOktaBaseDomain) == "" {
		t.Skipf("Skip E2E tests as mandatory environment variables %s and/or %s are not set", envAdminAPIToken, envOktaBaseDomain)
	}

	o.BaseDomain = os.Getenv(envOktaBaseDomain)
	o.APIToken = os.Getenv(envAdminAPIToken)

	app := o.NewOIDCApplication()
	app.Label = fmt.Sprintf("okta-kubectl-auth - E2E - %s", random)

	app, err = o.ApplicationCreate(app)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	// ensure application gets deleted
	defer func() {
		if err := o.ApplicationDelete(app.ID); err != nil {
			logger.Error().Err(err).Msg("error during application delete")
		}
	}()
	logger.Info().Str("client_id", app.ID).Msg("application has been created")

	everyone, err := o.GroupEveryone()
	if err != nil {
		t.Fatal("unexpected error getting all groups: ", err)
	}
	logger.Info().Str("group_id", everyone.ID).Msg("everyone group id detected")

	// Assign everyone to application
	if err := o.ApplicationAssignGroup(app.ID, everyone.ID); err != nil {
		t.Fatal("unable to assign everyone to group: ", err)
	}

	// Get client secret
	clientSecret, err := o.ApplicationClientSecret(app.ID)
	if err != nil {
		t.Fatal("unexpected error: ", err)
	}
	logger.Info().Str("client_secret", clientSecret).Msg("acquired client secret")

	// Set clientID and clientSecret in app
	oc := okta.New(&logger, true)
	oc.Debug = testing.Verbose()
	oc.BaseDomain = os.Getenv(envOktaBaseDomain)
	oc.ClientID = app.ID
	oc.ClientSecret = clientSecret

	// Ensure we call the autorize URL as soon as it is available
	authCodeURLCh := make(chan string)
	go func() {
		b := surf.NewBrowser()
		authCodeURL := <-authCodeURLCh

		// backoff to login
		f := func() error {
			// login user
			sessionToken, err := UserSession(o.BaseDomain, "userAB@example.com", "Test!123")
			if err != nil {
				return fmt.Errorf("error creating a user login session: %s", err)
			}

			u, err := url.Parse(authCodeURL)
			if err != nil {
				return fmt.Errorf("error parsing URL: %s", err)
			}

			q := u.Query()
			q.Add("sessionToken", sessionToken)
			u.RawQuery = q.Encode()
			logger.Info().Str("url", u.String()).Msg("browsing to authCodeURL")

			err = b.Open(u.String())
			if err != nil {
				return fmt.Errorf("error browsing to autoCodeURL: %s", err)
			}
			if b.StatusCode() > 299 {
				return fmt.Errorf("unexpected status code %d", b.StatusCode())
			}

			return nil
		}

		boff := backoff.NewExponentialBackOff()
		boff.MaxElapsedTime = 5 * time.Minute
		boff.InitialInterval = 2 * time.Second

		err := backoff.Retry(f, boff)
		if err != nil {
			t.Fatalf("failed authenticating: %s", err)
		}
	}()

	// Try to get token
	err = oc.Authorize(authCodeURLCh)
	if err != nil {
		t.Fatal("unexpected error during authorize: ", err)
	}

}
