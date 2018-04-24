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

func (o *Okta) retrieveToken(state string) (idTokenCh chan string, err error) {
	idTokenCh = make(chan string)
	stopCh := make(chan struct{})

	mux := http.NewServeMux()

	mux.HandleFunc(CallbackPath, o.handleCallback(state, idTokenCh, stopCh))

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

	return idTokenCh, nil
}

func (o *Okta) handleCallback(expectedState string, idTokenCh chan string, stopCh chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err   error
			token *oauth2.Token
		)

		rDump, err := httputil.DumpRequest(r, true)
		if err == nil {
			o.log.Debug().Interface("request", rDump).Msg("callback received")
		}

		ctx := oidc.ClientContext(r.Context(), o.client())
		oauth2Config := o.OAuth2Config(nil)
		switch r.Method {
		case "GET":
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
			token, err = oauth2Config.Exchange(ctx, code)
		case "POST":
			// Form request from frontend to refresh a token.
			refresh := r.FormValue("refresh_token")
			if refresh == "" {
				http.Error(w, fmt.Sprintf("no refresh_token in request: %q", r.Form), http.StatusBadRequest)
				return
			}
			t := &oauth2.Token{
				RefreshToken: refresh,
				Expiry:       time.Now().Add(-time.Hour),
			}
			token, err = oauth2Config.TokenSource(ctx, t).Token()
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

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			errMsg := "no id_token in token response"
			http.Error(w, errMsg, http.StatusInternalServerError)
			o.log.Error().Msg(errMsg)
			return
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
		idTokenCh <- rawIDToken

		w.Write([]byte(`ok!`))

		// shutdown http server gracefully
		go func() {
			ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
			o.server.Shutdown(ctx)
		}()
	}
}
