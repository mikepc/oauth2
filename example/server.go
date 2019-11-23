package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/valyala/fasthttp"
	"log"
	"github.com/wyanlord/oauth2/errors"
	"github.com/wyanlord/oauth2/generates"
	"github.com/wyanlord/oauth2/manage"
	"github.com/wyanlord/oauth2/models"
	"github.com/wyanlord/oauth2/server"
	"github.com/wyanlord/oauth2/store"
)

func main() {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	manager.MapAccessGenerate(generates.NewJWTAccessGenerate([]byte("00000000"), jwt.SigningMethodHS512))

	clientStore := store.NewClientStore()
	_ = clientStore.Set("222222", &models.Client{
		ID:     "222222",
		Secret: "22222222",
		Domain: "http://localhost:9094",
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetClientInfoHandler(server.ClientFormHandler)

	srv.SetPasswordAuthorizationHandler(func(username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			return "123456", nil
		}

		return "", errors.ErrAccessDenied
	})

	srv.SetUserAuthorizationHandler(func(ctx *fasthttp.RequestCtx) (userID string, err error) {
		// 根据您的项目登录权限的方式来判断用户的身份，获取用户的id
		return "123456", nil
	})

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	h := fasthttp.CompressHandler(func(ctx *fasthttp.RequestCtx) {
		switch string(ctx.Path()) {
		case "/authorize":
			err := srv.HandleAuthorizeRequest(ctx)
			if err != nil {
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
				_, _ = ctx.WriteString(err.Error())
			}
		case "/token":
			_ = srv.HandleTokenRequest(ctx)
		default:
			ctx.SetStatusCode(fasthttp.StatusNotFound)
		}
	})

	log.Fatal(fasthttp.ListenAndServe(":9096", h))
}
