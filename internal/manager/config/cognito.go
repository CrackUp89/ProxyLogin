package config

import (
	"github.com/spf13/viper"
)

type ClientConfig struct {
	ID     string
	Secret string
}

// CognitoConfig lives here rather than in the cognito package because cognito
// consumes the whole Config, so config can't import it.
type CognitoConfig struct {
	Client            ClientConfig
	ExternalClient    ClientConfig
	JWKSIssuer        string
	JWKSSigningKeyURL string
	TokenURL          string
	OpenIDConfigURL   string // not used yet
	UserPoolID        string
	EnforceMFA        bool
	// EnforceMFAForExternalLogin applies the EnforceMFA flow (MFA setup when the user has none) to external logins
	EnforceMFAForExternalLogin bool
	Workers                    uint64
	LogAllRequests             bool
	ExternalLoginRedirectURL   string
}

var CognitoEnvBinds = map[string]string{
	"cognito.clientId":                  "COGNITO_CLIENT_ID",
	"cognito.clientSecret":              "COGNITO_CLIENT_SECRET",
	"cognito.userPoolId":                "COGNITO_USER_POOL_ID",
	"cognito.jwksIssuer":                "COGNITO_JWKS_ISSUER",
	"cognito.jwksSigningKeyURL":         "COGNITO_JWKS_SIGNING_KEY_URL",
	"cognito.tokenURL":                  "COGNITO_TOKEN_URL",
	"cognito.openIdConfigURL":           "COGNITO_OPENID_CONFIG_URL",
	"cognito.enforceMFA":                "COGNITO_ENFORCE_MFA",
	"cognito.workers":                   "COGNITO_WORKERS",
	"cognito.logAllRequests":            "COGNITO_LOG_ALL_REQUESTS",
	"cognito.external.clientId":         "COGNITO_EXTERNAL_CLIENT_ID",
	"cognito.external.clientSecret":     "COGNITO_EXTERNAL_CLIENT_SECRET",
	"cognito.external.loginRedirectURL": "COGNITO_EXTERNAL_LOGIN_REDIRECT_URL",
	"cognito.external.enforceMFA":       "COGNITO_EXTERNAL_ENFORCE_MFA",
}

func SetDefaultCognitoConfig(v *viper.Viper) {
	v.SetDefault("cognito.enforceMFA", false)
	v.SetDefault("cognito.external.enforceMFA", false)
	v.SetDefault("cognito.workers", 1000)
	v.SetDefault("cognito.logAllRequests", true)
}

func LoadCognitoConfig(v *viper.Viper) (CognitoConfig, error) {
	return CognitoConfig{
		Client: ClientConfig{
			ID:     v.GetString("cognito.clientId"),
			Secret: v.GetString("cognito.clientSecret"),
		},
		ExternalClient: ClientConfig{
			ID:     v.GetString("cognito.external.clientId"),
			Secret: v.GetString("cognito.external.clientSecret"),
		},
		JWKSIssuer:                 v.GetString("cognito.jwksIssuer"),
		JWKSSigningKeyURL:          v.GetString("cognito.jwksSigningKeyURL"),
		TokenURL:                   v.GetString("cognito.tokenURL"),
		OpenIDConfigURL:            v.GetString("cognito.openIdConfigURL"),
		UserPoolID:                 v.GetString("cognito.userPoolId"),
		EnforceMFA:                 v.GetBool("cognito.enforceMFA"),
		EnforceMFAForExternalLogin: v.GetBool("cognito.external.enforceMFA"),
		Workers:                    v.GetUint64("cognito.workers"),
		LogAllRequests:             v.GetBool("cognito.logAllRequests"),
		ExternalLoginRedirectURL:   v.GetString("cognito.external.loginRedirectURL"),
	}, nil
}
