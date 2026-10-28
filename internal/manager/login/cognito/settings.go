package cognito

import (
	"context"
	"net/http"
	httpTools "proxylogin/internal/manager/tools/http"

	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/danielgtaylor/huma/v2"
)

type clientCookieSettings struct {
	Enabled              bool   `json:"enabled" doc:"Tokens are delivered as cookies instead of in response bodies"`
	HTTPOnly             bool   `json:"http_only" doc:"Token cookies are http-only, so JavaScript can't read them"`
	AccessCookieName     string `json:"access_cookie_name,omitempty" doc:"Access token cookie name. Present in cookie mode without masquerade"`
	IdCookieName         string `json:"id_cookie_name,omitempty" doc:"ID token cookie name. Present in cookie mode without masquerade"`
	RefreshCookieName    string `json:"refresh_cookie_name,omitempty" doc:"Refresh token cookie name. Present in cookie mode without masquerade"`
	MasqueradeCookieName string `json:"masquerade_cookie_name,omitempty" doc:"Masquerade token cookie name. Present in cookie mode with masquerade"`
}

type clientMFASettings struct {
	Required bool `json:"required" doc:"Users must set up MFA during login if they have none"`
}

// ClientSettings are the service settings a client needs to talk to the API.
type ClientSettings struct {
	Masquerade           bool                 `json:"masquerade" doc:"Masquerade mode: real tokens are never exposed, an opaque masquerade token is issued instead"`
	Cookies              clientCookieSettings `json:"cookies"`
	CSRFHeaderName       string               `json:"csrf_header_name,omitempty" doc:"Header that carries the CSRF token in login and update flows. Absent if the CSRF header check is disabled"`
	TokenRefreshEnabled  bool                 `json:"token_refresh_enabled" doc:"POST /v1/refresh is available. False in masquerade mode, where the service refreshes tokens itself"`
	PasswordResetEnabled bool                 `json:"password_reset_enabled" doc:"The password reset endpoints are available"`
	MFA                  clientMFASettings    `json:"mfa"`
}

type ClientSettingsOutput struct {
	Body *ClientSettings
}

func (c *Cognito) clientSettings() *ClientSettings {
	cfg := c.appConfig

	cookies := clientCookieSettings{
		Enabled:  cfg.UseCookies,
		HTTPOnly: cfg.UseCookies && cfg.UseHTTPOnlyCookies,
	}
	if cfg.UseCookies {
		if cfg.Masquerade {
			cookies.MasqueradeCookieName = cfg.MasqueradedTokenCookieName
		} else {
			cookies.AccessCookieName = cfg.AccessTokenCookieName
			cookies.IdCookieName = cfg.IdTokenCookieName
			cookies.RefreshCookieName = cfg.RefreshTokenCookieName
		}
	}

	csrfHeaderName := ""
	if c.csrf.IsHeaderCheckEnabled() {
		csrfHeaderName = c.csrf.HeaderName
	}

	mfaConfig := c.poolDescription.MfaConfiguration

	return &ClientSettings{
		Masquerade:           cfg.Masquerade,
		Cookies:              cookies,
		CSRFHeaderName:       csrfHeaderName,
		TokenRefreshEnabled:  !cfg.Masquerade,
		PasswordResetEnabled: cfg.PasswordResetConfig.Enabled,
		MFA: clientMFASettings{
			Required: mfaConfig == cognitoTypes.UserPoolMfaTypeOn ||
				(c.cfg.EnforceMFA && mfaConfig == cognitoTypes.UserPoolMfaTypeOptional),
		},
	}
}

func (c *Cognito) registerGetSettings(api huma.API) {
	addressLimiter := c.newRateLimiter("settingsPerRemoteAddress")
	totalLimiter := c.newRateLimiter("settingsTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "settings",
		Method:       http.MethodGet,
		Path:         "/v1/settings",
		Summary:      "Get client settings",
		Description:  descSettings,
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, _ *struct{}) (*ClientSettingsOutput, error) {
		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		return &ClientSettingsOutput{Body: c.clientSettings()}, nil
	})
}
