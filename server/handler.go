package server

import (
	"bytes"
	"github.com/mikepc/oauth2"
	"github.com/mikepc/oauth2/errors"
	"encoding/base64"
	"github.com/valyala/fasthttp"
	"strings"
	"time"
)

type (
	// ClientInfoHandler get client info from request
	ClientInfoHandler func(ctx *fasthttp.RequestCtx) (clientID, clientSecret string, err error)

	// ClientAuthorizedHandler check the client allows to use this authorization grant type
	ClientAuthorizedHandler func(clientID string, grant oauth2.GrantType) (allowed bool, err error)

	// ClientScopeHandler check the client allows to use scope
	ClientScopeHandler func(clientID, scope string) (allowed bool, err error)

	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(ctx *fasthttp.RequestCtx) (userID string, err error)

	// PasswordAuthorizationHandler get user id from username and password
	PasswordAuthorizationHandler func(username, password string) (userID string, err error)

	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(newScope, oldScope string) (allowed bool, err error)

	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *errors.Response)

	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *errors.Response)

	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(ctx *fasthttp.RequestCtx) (scope string, err error)

	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(ctx *fasthttp.RequestCtx) (exp time.Duration, err error)

	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{})
)

// ClientFormHandler get client data from form
func ClientFormHandler(ctx *fasthttp.RequestCtx) (string, string, error) {
	clientID := ctx.FormValue("client_id")
	clientSecret := ctx.FormValue("client_secret")
	if len(clientID) == 0 || len(clientSecret) == 0 {
		return "", "", errors.ErrInvalidClient
	}
	return string(clientID), string(clientSecret), nil
}

// ClientBasicHandler get client data from basic authorization
func ClientBasicHandler(ctx *fasthttp.RequestCtx) (string, string, error) {
	auth := string(ctx.Request.Header.Peek("Authorization"))
	prefix := "Basic "

	if auth != "" && strings.HasPrefix(auth, prefix) {
		auth = auth[len(prefix):]
	}

	if b, err := base64.StdEncoding.DecodeString(auth); err != nil {
		return "", "", errors.ErrInvalidClient
	} else if arr := bytes.Split(b, []byte(":")); len(arr) != 2 {
		return "", "", errors.ErrInvalidClient
	} else {
		clientID, clientSecret := string(arr[0]), string(arr[1])
		return clientID, clientSecret, nil
	}
}
