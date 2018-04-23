package okta

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

const contentTypeApplicationJSON = "application/json"

func (o *Okta) NewOIDCApplication() *Application {
	a := &Application{
		Name:       "oidc_client",
		SignOnMode: "OPENID_CONNECT",
	}
	a.Settings.OauthClient.GrantTypes = []string{
		"authorization_code",
		"refresh_token",
		"implicit",
	}
	a.Settings.OauthClient.ResponseTypes = []string{
		"code",
		"token",
		"id_token",
	}
	a.Settings.OauthClient.RedirectUris = []string{
		o.RedirectURL(),
	}
	a.Settings.OauthClient.LogoURI = "https://github.com/kubernetes/kubernetes/raw/master/logo/logo.png"
	a.Settings.OauthClient.ApplicationType = "native"
	return a
}

func (o *Okta) ApplicationAssignGroup(appID string, groupID string) error {
	req, err := o.newRequest(
		"PUT",
		fmt.Sprintf("/api/v1/apps/%s/groups/%s", appID, groupID),
		nil,
	)
	if err != nil {
		return err
	}

	resp, err := o.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode > 299 {
		return fmt.Errorf("Unexpected response code: %d, %s", resp.StatusCode, string(respBodyBytes))
	}
	return nil
}

func (o *Okta) ApplicationDelete(id string) error {
	req, err := o.newRequest(
		"POST",
		fmt.Sprintf("/api/v1/apps/%s/lifecycle/deactivate", id),
		nil,
	)
	if err != nil {
		return err
	}

	resp, err := o.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode > 299 {
		return fmt.Errorf("Unexpected response code: %d, %s", resp.StatusCode, string(respBodyBytes))
	}

	req, err = o.newRequest(
		"DELETE",
		fmt.Sprintf("/api/v1/apps/%s", id),
		nil,
	)
	if err != nil {
		return err
	}

	resp, err = o.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode > 299 {
		return fmt.Errorf("Unexpected response code: %d, %s", resp.StatusCode, string(respBodyBytes))
	}

	return nil

}

func (o *Okta) ApplicationCreate(app *Application) (*Application, error) {

	dataBytes, err := json.Marshal(app)
	if err != nil {
		return nil, err
	}

	req, err := o.newRequest(
		"POST",
		"/api/v1/apps",
		bytes.NewReader(dataBytes),
	)
	if err != nil {
		return nil, err
	}

	resp, err := o.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Unexpected response code: %d, %s", resp.StatusCode, string(respBodyBytes))
	}

	var application Application
	err = json.Unmarshal(respBodyBytes, &application)
	if err != nil {
		return nil, err
	}

	return &application, nil
}

func (o *Okta) ApplicationClientSecret(id string) (string, error) {
	req, err := o.newRequest(
		"GET",
		fmt.Sprintf(
			"/api/v1/internal/apps/%s/settings/clientcreds",
			id,
		),
		nil,
	)

	resp, err := o.client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Unexpected response code: %d, %s", resp.StatusCode, string(respBodyBytes))
	}

	var clientSecret struct {
		ClientSecret string `json:"client_secret,omitempty"`
	}
	err = json.Unmarshal(respBodyBytes, &clientSecret)
	if err != nil {
		return "", err
	}

	return clientSecret.ClientSecret, nil
}

type Application struct {
	Created     string `json:"created,omitempty"`
	Credentials struct {
		OauthClient struct {
			AutoKeyRotation         bool   `json:"autoKeyRotation,omitempty"`
			ClientID                string `json:"client_id,omitempty"`
			TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
		} `json:"oauthClient,omitempty"`
		Signing struct {
			Kid string `json:"kid,omitempty"`
		} `json:"signing,omitempty"`
		UserNameTemplate struct {
			Template string `json:"template,omitempty"`
			Type     string `json:"type,omitempty"`
		} `json:"userNameTemplate,omitempty"`
	} `json:"credentials,omitempty"`
	Features    []interface{} `json:"features,omitempty"`
	ID          string        `json:"id,omitempty"`
	Label       string        `json:"label,omitempty"`
	LastUpdated string        `json:"lastUpdated,omitempty"`
	Name        string        `json:"name,omitempty"`
	Settings    struct {
		OauthClient struct {
			ApplicationType  string      `json:"application_type,omitempty"`
			ClientURI        interface{} `json:"client_uri,omitempty"`
			GrantTypes       []string    `json:"grant_types,omitempty"`
			InitiateLoginURI string      `json:"initiate_login_uri,omitempty"`
			LogoURI          string      `json:"logo_uri,omitempty"`
			RedirectUris     []string    `json:"redirect_uris,omitempty"`
			ResponseTypes    []string    `json:"response_types,omitempty"`
		} `json:"oauthClient,omitempty"`
	} `json:"settings,omitempty"`
	SignOnMode string `json:"signOnMode,omitempty"`
	Status     string `json:"status,omitempty"`
	Visibility struct {
		AppLinks struct {
			OidcClientLink bool `json:"oidc_client_link,omitempty"`
		} `json:"appLinks,omitempty"`
	} `json:"visibility,omitempty"`
}
