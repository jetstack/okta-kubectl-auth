package okta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

const CallbackPath = "/callback"

type token struct {
	RefreshToken string // token to refresh access/id_token
	AccessToken  string // JWT with an access bearer token
	IDToken      string // OIDC JWT
}

func (o *Okta) retrieveToken(state string, nonce string) (tokenCh chan token, err error) {
	tokenCh = make(chan token)
	stopCh := make(chan struct{})

	mux := http.NewServeMux()

	mux.HandleFunc(CallbackPath, o.handleCallback(state, nonce, tokenCh, stopCh))

	o.server = &http.Server{
		Addr:    o.BindAddr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", o.server.Addr)
	if err != nil {
		return nil, err
	}

	go func() {
		err := o.server.Serve(ln)
		if err != nil && err.Error() != "http: Server closed" {
			o.log.Error().Err(err).Msg("error during serve")
		}
	}()

	return tokenCh, nil
}

func (o *Okta) handleCallback(expectedState string, expectedNonce string, tokenCh chan token, stopCh chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err           error
			tokenExchange *oauth2.Token
			t             token
		)

		rDump, err := httputil.DumpRequest(r, true)
		if err == nil {
			o.log.Debug().Interface("request", rDump).Msg("callback received")
		}

		ctx := oidc.ClientContext(r.Context(), o.client())
		oauth2Config := o.OAuth2Config(nil)
		switch r.Method {
		case "POST":
			// Authorization redirect callback from OAuth2 auth flow.
			if errMsg := r.FormValue("error"); errMsg != "" {
				errMsg += ": " + r.FormValue("error_description")
				http.Error(w, errMsg, http.StatusBadRequest)
				o.log.Error().Msg(errMsg)
				return
			}
			code := r.FormValue("code")
			if code == "" {
				errMsg := fmt.Sprintf("no code in request: %q", r.Form)
				http.Error(w, errMsg, http.StatusBadRequest)
				o.log.Error().Msg(errMsg)
				return
			}
			if state := r.FormValue("state"); state != expectedState {
				errMsg := fmt.Sprintf("expected state %q got %q", expectedState, state)
				http.Error(w, errMsg, http.StatusBadRequest)
				o.log.Error().Msg(errMsg)
				return
			}
			tokenExchange, err = oauth2Config.Exchange(ctx, code)
		default:
			errMsg := fmt.Sprintf("method not implemented: %s", r.Method)
			http.Error(w, errMsg, http.StatusBadRequest)
			o.log.Error().Msg(errMsg)
			return
		}

		if err != nil {
			errMsg := fmt.Sprintf("failed to get token: %v", err)
			http.Error(w, errMsg, http.StatusInternalServerError)
			o.log.Error().Msg(errMsg)
			return
		}

		rawIDToken, ok := tokenExchange.Extra("id_token").(string)
		if !ok {
			errMsg := "no id_token in token response"
			http.Error(w, errMsg, http.StatusInternalServerError)
			o.log.Error().Msg(errMsg)
			return
		}

		if refreshToken, ok := tokenExchange.Extra("refresh_token").(string); ok {
			t.RefreshToken = refreshToken
		}

		if t.RefreshToken == "" {
			errMsg := fmt.Sprintf("Empty refresh token")
			http.Error(w, errMsg, http.StatusInternalServerError)
			o.log.Error().Msg(errMsg)
			return
		}

		if accessToken, ok := tokenExchange.Extra("token").(string); ok {
			t.AccessToken = accessToken
		}

		idToken, err := o.verifier().Verify(r.Context(), rawIDToken)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to verify ID token: %v", err)
			http.Error(w, errMsg, http.StatusInternalServerError)
			o.log.Error().Msg(errMsg)
			return
		}
		var claims json.RawMessage
		idToken.Claims(&claims)

		buff := new(bytes.Buffer)
		json.Indent(buff, []byte(claims), "", "  ")

		o.log.Debug().Str("claims", buff.String()).Msg("claims received")

		t.IDToken = rawIDToken
		tokenCh <- t

		w.Write([]byte(`ok!`))

		// shutdown http server gracefully
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			defer cancel()
			o.server.Shutdown(ctx)
		}()
	}
}
