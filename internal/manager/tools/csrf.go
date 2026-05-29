package tools

import (
	"crypto/subtle"

	"github.com/danielgtaylor/huma/v2"
)

type CSRF struct {
	HeaderName     string
	AllowedOrigins []string
}

func NewCSRF(headerName string, allowedOrigins []string) *CSRF {
	return &CSRF{
		HeaderName:     headerName,
		AllowedOrigins: allowedOrigins,
	}
}

func (c *CSRF) GenerateCSRFToken() (string, error) {
	return GenerateRandomString(32)
}

func (c *CSRF) IsHeaderCheckEnabled() bool {
	return len(c.HeaderName) > 0
}

func (c *CSRF) VerifyCSRFToken(token, expectedToken string) bool {
	if !c.IsHeaderCheckEnabled() {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) == 1
}

func (c *CSRF) IsOriginCheckEnabled() bool {
	return len(c.AllowedOrigins) > 0
}

func (c *CSRF) VerifyCSRFOrigin(ctx huma.Context) bool {
	if !c.IsOriginCheckEnabled() {
		return true
	}
	header := ctx.Header("Origin")
	if header == "" {
		return false
	}
	result := false
	for _, origin := range c.AllowedOrigins {
		if subtle.ConstantTimeCompare([]byte(header), []byte(origin)) == 1 {
			result = true
		}
	}
	return result
}
