package server

import (
	"bytes"
	"github.com/wyanlord/go-oauth2-fasthttp"
	"encoding/json"
	"fmt"
	"github.com/valyala/fasthttp"
	"net/url"
	"strings"
	"time"

	"github.com/wyanlord/go-oauth2-fasthttp/errors"
)

// NewDefaultServer create a default authorization server
func NewDefaultServer(manager oauth2.Manager) *Server {
	return NewServer(NewConfig(), manager)
}

// NewServer create authorization server
func NewServer(cfg *Config, manager oauth2.Manager) *Server {
	srv := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handler
	srv.ClientInfoHandler = ClientBasicHandler

	srv.UserAuthorizationHandler = func(ctx *fasthttp.RequestCtx) (string, error) {
		return "", errors.ErrAccessDenied
	}

	srv.PasswordAuthorizationHandler = func(username, password string) (string, error) {
		return "", errors.ErrAccessDenied
	}
	return srv
}

// Server Provide authorization server
type Server struct {
	Config                       *Config
	Manager                      oauth2.Manager
	ClientInfoHandler            ClientInfoHandler
	ClientAuthorizedHandler      ClientAuthorizedHandler
	ClientScopeHandler           ClientScopeHandler
	UserAuthorizationHandler     UserAuthorizationHandler
	PasswordAuthorizationHandler PasswordAuthorizationHandler
	RefreshingScopeHandler       RefreshingScopeHandler
	ResponseErrorHandler         ResponseErrorHandler
	InternalErrorHandler         InternalErrorHandler
	ExtensionFieldsHandler       ExtensionFieldsHandler
	AccessTokenExpHandler        AccessTokenExpHandler
	AuthorizeScopeHandler        AuthorizeScopeHandler
}

func (s *Server) redirectError(ctx *fasthttp.RequestCtx, req *AuthorizeRequest, err error) error {
	if req == nil {
		return err
	}
	data, _, _ := s.GetErrorData(err)
	return s.redirect(ctx, req, data)
}

func (s *Server) redirect(ctx *fasthttp.RequestCtx, req *AuthorizeRequest, data map[string]interface{}) error {
	uri, err := s.GetRedirectURI(req, data)
	if err != nil {
		return err
	}

	ctx.Response.Header.Set("Location", uri)
	ctx.SetStatusCode(fasthttp.StatusFound)
	return nil
}

func (s *Server) tokenError(ctx *fasthttp.RequestCtx, err error) error {
	data, statusCode, header := s.GetErrorData(err)
	return s.token(ctx, data, header, statusCode)
}

func (s *Server) token(ctx *fasthttp.RequestCtx, data map[string]interface{}, header map[string]string, statusCode ...int) error {
	ctx.Response.Header.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Response.Header.Set("Pragma", "no-cache")

	if len(header) > 0 {
		for k, v := range header {
			ctx.Response.Header.Set(k, v)
		}
	}

	status := fasthttp.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	ctx.SetStatusCode(status)
	return json.NewEncoder(ctx.Response.BodyWriter()).Encode(data)
}

// GetRedirectURI get redirect uri
func (s *Server) GetRedirectURI(req *AuthorizeRequest, data map[string]interface{}) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	if req.State != "" {
		q.Set("state", req.State)
	}

	for k, v := range data {
		q.Set(k, fmt.Sprint(v))
	}

	switch req.ResponseType {
	case oauth2.Code:
		u.RawQuery = q.Encode()
	case oauth2.Token:
		u.RawQuery = ""
		fragment, err := url.QueryUnescape(q.Encode())
		if err != nil {
			return "", err
		}
		u.Fragment = fragment
	}

	return u.String(), nil
}

// CheckResponseType check allows response type
func (s *Server) CheckResponseType(rt oauth2.ResponseType) bool {
	for _, art := range s.Config.AllowedResponseTypes {
		if art == rt {
			return true
		}
	}
	return false
}

// ValidationAuthorizeRequest the authorization request validation
func (s *Server) ValidationAuthorizeRequest(ctx *fasthttp.RequestCtx) (*AuthorizeRequest, error) {
	redirectURI := ctx.FormValue("redirect_uri")
	clientID := ctx.FormValue("client_id")
	if !(bytes.Equal(ctx.Method(), []byte("GET")) || bytes.Equal(ctx.Method(), []byte("POST"))) || clientID == nil {
		return nil, errors.ErrInvalidRequest
	}

	resType := oauth2.ResponseType(string(ctx.FormValue("response_type")))
	if resType.String() == "" {
		return nil, errors.ErrUnsupportedResponseType
	} else if allowed := s.CheckResponseType(resType); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	req := &AuthorizeRequest{
		RedirectURI:  string(redirectURI),
		ResponseType: resType,
		ClientID:     string(clientID),
		State:        string(ctx.FormValue("state")),
		Scope:        string(ctx.FormValue("scope")),
		Context:      ctx,
	}
	return req, nil
}

// GetAuthorizeToken get authorization token(code)
func (s *Server) GetAuthorizeToken(req *AuthorizeRequest) (oauth2.TokenInfo, error) {
	// check the client allows the grant type
	if fn := s.ClientAuthorizedHandler; fn != nil {
		gt := oauth2.AuthorizationCode
		if req.ResponseType == oauth2.Token {
			gt = oauth2.Implicit
		}

		allowed, err := fn(req.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	// check the client allows the authorized scope
	if fn := s.ClientScopeHandler; fn != nil {
		allowed, err := fn(req.ClientID, req.Scope)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrInvalidScope
		}
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:       req.ClientID,
		UserID:         req.UserID,
		RedirectURI:    req.RedirectURI,
		Scope:          req.Scope,
		AccessTokenExp: req.AccessTokenExp,
		Context:        req.Context,
	}
	return s.Manager.GenerateAuthToken(req.ResponseType, tgr)
}

// GetAuthorizeData get authorization response data
func (s *Server) GetAuthorizeData(rt oauth2.ResponseType, ti oauth2.TokenInfo) map[string]interface{} {
	if rt == oauth2.Code {
		return map[string]interface{}{
			"code": ti.GetCode(),
		}
	}
	return s.GetTokenData(ti)
}

// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(ctx *fasthttp.RequestCtx) error {
	req, err := s.ValidationAuthorizeRequest(ctx)
	if err != nil {
		return s.redirectError(ctx, req, err)
	}

	// user authorization
	userID, err := s.UserAuthorizationHandler(ctx)
	if err != nil {
		return s.redirectError(ctx, req, err)
	} else if userID == "" {
		return nil
	}
	req.UserID = userID

	// specify the scope of authorization
	if fn := s.AuthorizeScopeHandler; fn != nil {
		scope, err := fn(ctx)
		if err != nil {
			return err
		} else if scope != "" {
			req.Scope = scope
		}
	}

	// specify the expiration time of access token
	if fn := s.AccessTokenExpHandler; fn != nil {
		exp, err := fn(ctx)
		if err != nil {
			return err
		}
		req.AccessTokenExp = exp
	}

	ti, err := s.GetAuthorizeToken(req)
	if err != nil {
		return s.redirectError(ctx, req, err)
	}

	// If the redirect URI is empty, the default domain provided by the client is used.
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(req.ClientID)
		if err != nil {
			return err
		}
		req.RedirectURI = client.GetDomain()
	}

	return s.redirect(ctx, req, s.GetAuthorizeData(req.ResponseType, ti))
}

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(ctx *fasthttp.RequestCtx) (oauth2.GrantType, *oauth2.TokenGenerateRequest, error) {
	if v := string(ctx.Method()); !(v == "POST" || (s.Config.AllowGetAccessRequest && v == "GET")) {
		return "", nil, errors.ErrInvalidRequest
	}

	gt := oauth2.GrantType(string(ctx.FormValue("grant_type")))
	if gt.String() == "" {
		return "", nil, errors.ErrUnsupportedGrantType
	}

	clientID, clientSecret, err := s.ClientInfoHandler(ctx)
	if err != nil {
		return "", nil, err
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Context:      ctx,
	}

	switch gt {
	case oauth2.AuthorizationCode:
		tgr.RedirectURI = string(ctx.FormValue("redirect_uri"))
		tgr.Code = string(ctx.FormValue("code"))
		if tgr.RedirectURI == "" || tgr.Code == "" {
			return "", nil, errors.ErrInvalidRequest
		}
	case oauth2.PasswordCredentials:
		tgr.Scope = string(ctx.FormValue("scope"))
		username, password := string(ctx.FormValue("username")), string(ctx.FormValue("password"))
		if username == "" || password == "" {
			return "", nil, errors.ErrInvalidRequest
		}

		userID, err := s.PasswordAuthorizationHandler(username, password)
		if err != nil {
			return "", nil, err
		} else if userID == "" {
			return "", nil, errors.ErrInvalidGrant
		}
		tgr.UserID = userID
	case oauth2.ClientCredentials:
		tgr.Scope = string(ctx.FormValue("scope"))
	case oauth2.Refreshing:
		tgr.Refresh = string(ctx.FormValue("refresh_token"))
		tgr.Scope = string(ctx.FormValue("scope"))
		if tgr.Refresh == "" {
			return "", nil, errors.ErrInvalidRequest
		}
	}
	return gt, tgr, nil
}

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt oauth2.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
}

// GetAccessToken access token
func (s *Server) GetAccessToken(gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo, error) {
	if allowed := s.CheckGrantType(gt); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	if fn := s.ClientAuthorizedHandler; fn != nil {
		allowed, err := fn(tgr.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	switch gt {
	case oauth2.AuthorizationCode:
		ti, err := s.Manager.GenerateAccessToken(gt, tgr)
		if err != nil {
			switch err {
			case errors.ErrInvalidAuthorizeCode:
				return nil, errors.ErrInvalidGrant
			case errors.ErrInvalidClient:
				return nil, errors.ErrInvalidClient
			default:
				return nil, err
			}
		}
		return ti, nil
	case oauth2.PasswordCredentials, oauth2.ClientCredentials:
		if fn := s.ClientScopeHandler; fn != nil {
			allowed, err := fn(tgr.ClientID, tgr.Scope)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}
		return s.Manager.GenerateAccessToken(gt, tgr)
	case oauth2.Refreshing:
		// check scope
		if scope, scopeFn := tgr.Scope, s.RefreshingScopeHandler; scope != "" && scopeFn != nil {
			rti, err := s.Manager.LoadRefreshToken(tgr.Refresh)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}

			allowed, err := scopeFn(scope, rti.GetScope())
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}

		ti, err := s.Manager.RefreshAccessToken(tgr)
		if err != nil {
			if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
				return nil, errors.ErrInvalidGrant
			}
			return nil, err
		}
		return ti, nil
	}

	return nil, errors.ErrUnsupportedGrantType
}

// GetTokenData token data
func (s *Server) GetTokenData(ti oauth2.TokenInfo) map[string]interface{} {
	data := map[string]interface{}{
		"access_token": ti.GetAccess(),
		"token_type":   s.Config.TokenType,
		"expires_in":   int64(ti.GetAccessExpiresIn() / time.Second),
	}

	if scope := ti.GetScope(); scope != "" {
		data["scope"] = scope
	}

	if refresh := ti.GetRefresh(); refresh != "" {
		data["refresh_token"] = refresh
	}

	if fn := s.ExtensionFieldsHandler; fn != nil {
		ext := fn(ti)
		for k, v := range ext {
			if _, ok := data[k]; ok {
				continue
			}
			data[k] = v
		}
	}
	return data
}

// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(ctx *fasthttp.RequestCtx) error {
	gt, tgr, err := s.ValidationTokenRequest(ctx)
	if err != nil {
		return s.tokenError(ctx, err)
	}

	ti, err := s.GetAccessToken(gt, tgr)
	if err != nil {
		return s.tokenError(ctx, err)
	}

	return s.token(ctx, s.GetTokenData(ti), nil)
}

// GetErrorData get error response data
func (s *Server) GetErrorData(err error) (map[string]interface{}, int, map[string]string) {
	var re errors.Response
	if v, ok := errors.Descriptions[err]; ok {
		re.Error = err
		re.Description = v
		re.StatusCode = errors.StatusCodes[err]
	} else {
		if fn := s.InternalErrorHandler; fn != nil {
			if v := fn(err); v != nil {
				re = *v
			}
		}

		if re.Error == nil {
			re.Error = errors.ErrServerError
			re.Description = errors.Descriptions[errors.ErrServerError]
			re.StatusCode = errors.StatusCodes[errors.ErrServerError]
		}
	}

	if fn := s.ResponseErrorHandler; fn != nil {
		fn(&re)
	}

	data := make(map[string]interface{})
	if err := re.Error; err != nil {
		data["error"] = err.Error()
	}

	if v := re.ErrorCode; v != 0 {
		data["error_code"] = v
	}

	if v := re.Description; v != "" {
		data["error_description"] = v
	}

	if v := re.URI; v != "" {
		data["error_uri"] = v
	}

	statusCode := fasthttp.StatusInternalServerError
	if v := re.StatusCode; v > 0 {
		statusCode = v
	}

	return data, statusCode, re.Header
}

// BearerAuth parse bearer token
func (s *Server) BearerAuth(ctx *fasthttp.RequestCtx) (string, bool) {
	auth := string(ctx.Request.Header.Peek("Authorization"))
	prefix := "Bearer "
	token := ""

	if auth != "" && strings.HasPrefix(auth, prefix) {
		token = auth[len(prefix):]
	} else {
		token = string(ctx.FormValue("access_token"))
	}

	return token, token != ""
}

// ValidationBearerToken validation the bearer tokens
// https://tools.ietf.org/html/rfc6750
func (s *Server) ValidationBearerToken(ctx *fasthttp.RequestCtx) (oauth2.TokenInfo, error) {
	accessToken, ok := s.BearerAuth(ctx)
	if !ok {
		return nil, errors.ErrInvalidAccessToken
	}

	return s.Manager.LoadAccessToken(accessToken)
}
