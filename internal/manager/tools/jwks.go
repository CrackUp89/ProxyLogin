package tools

import (
	"fmt"
	"time"
)
import "github.com/golang-jwt/jwt/v5"
import "github.com/MicahParks/keyfunc/v3"

type JWKSValidator struct {
	jwks             keyfunc.Keyfunc
	expectedIssuer   string
	expectedAudience string
}

func NewJWKSValidator(jwksURL, issuer, audience string) (*JWKSValidator, error) {
	jwks, err := keyfunc.NewDefault([]string{jwksURL})

	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS: %w", err)
	}

	return &JWKSValidator{
		jwks:             jwks,
		expectedIssuer:   issuer,
		expectedAudience: audience,
	}, nil
}

func (v *JWKSValidator) ValidateToken(tokenString string) (*jwt.Token, error) {
	parseOptions := make([]jwt.ParserOption, 0, 4)
	parseOptions = append(parseOptions,
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(5*time.Second))

	if v.expectedAudience != "" {
		parseOptions = append(parseOptions, jwt.WithAudience(v.expectedAudience))
	}

	if v.expectedIssuer != "" {
		parseOptions = append(parseOptions, jwt.WithIssuer(v.expectedIssuer))
	}

	token, err := jwt.Parse(tokenString, v.jwks.Keyfunc, parseOptions...)

	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

func (v *JWKSValidator) ParseToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, v.jwks.Keyfunc)

	if err != nil {
		return nil, fmt.Errorf("token parsing failed: %w", err)
	}

	return token, nil
}
