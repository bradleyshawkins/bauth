package bauth

import (
	"context"
	"github.com/bradleyshawkins/berror"
	"github.com/golang-jwt/jwt/v4"
)

type authenticationKey string

const (
	authenticationContextKey authenticationKey = "authenticationKey"
)

type Authenticator interface {
	Authenticate(authentication string) (*jwt.Token, error)
}

func AddAuthenticationContext(ctx context.Context, token *jwt.Token) context.Context {
	return context.WithValue(ctx, authenticationContextKey, token)
}

func GetTokenFromContext(ctx context.Context) (*jwt.Token, error) {
	tokenVal := ctx.Value(authenticationContextKey)
	if tokenVal == nil {
		return nil, berror.New("authentication token not found", berror.WithUnauthenticated())
	}

	token, ok := tokenVal.(*jwt.Token)
	if !ok {
		return nil, berror.New("unexpected token value found", berror.WithUnauthenticated())
	}

	return token, nil
}
