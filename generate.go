package oauth2

import (
	"github.com/valyala/fasthttp"
	"time"
)

type (
	// GenerateBasic provide the basis of the generated token data
	GenerateBasic struct {
		Client    ClientInfo
		UserID    string
		CreateAt  time.Time
		TokenInfo TokenInfo
		Context   *fasthttp.RequestCtx
	}

	// AuthorizeGenerate generate the authorization code interface
	AuthorizeGenerate interface {
		Token(data *GenerateBasic) (code string, err error)
	}

	// AccessGenerate generate the access and refresh tokens interface
	AccessGenerate interface {
		Token(data *GenerateBasic, isGenRefresh bool) (access, refresh string, err error)
	}
)
