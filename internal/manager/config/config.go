package config

import (
	"fmt"
	"net/http"
	"proxylogin/internal/manager/logging"
	"proxylogin/internal/manager/login/masquerade"
	"proxylogin/internal/manager/login/passwordreset"
	"proxylogin/internal/manager/ratelimiter"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"
	httpTools "proxylogin/internal/manager/tools/http"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	URLBase                    string
	Masquerade                 bool
	UseCookies                 bool
	UseHTTPOnlyCookies         bool
	CookiesDomain              string
	CookiesPath                string
	CookiesSecure              bool
	CookieSameSite             http.SameSite
	SessionCookieName          string
	UpdateSessionCookieName    string
	AccessTokenCookieName      string
	IdTokenCookieName          string
	RefreshTokenCookieName     string
	MasqueradedTokenCookieName string
	StorageType                storage.Type
	RedisClientConfig          redisclient.Config
	RateLimiterConfig          ratelimiter.Config
	MasqueradeConfig           masquerade.Config
	HTTPToolsConfig            httpTools.Config
	PasswordResetConfig        passwordreset.Config
	CognitoConfig              CognitoConfig
	ServerConfig               ServerConfig
	LimitsConfig               LimitsConfig
	LoggingConfig              logging.Config
}

var EnvBinds = map[string]string{
	"storage.type":                          "STORAGE_TYPE",
	"token.masquerade":                      "TOKEN_MASQUERADE",
	"token.cookies.enabled":                 "TOKEN_COOKIES_ENABLED",
	"token.cookies.httpOnly":                "TOKEN_COOKIES_HTTP_ONLY",
	"token.cookies.domain":                  "TOKEN_COOKIES_DOMAIN",
	"token.cookies.path":                    "TOKEN_COOKIES_PATH",
	"token.cookies.secure":                  "TOKEN_COOKIES_SECURE",
	"token.cookies.sameSite":                "TOKEN_COOKIES_SAME_SITE",
	"token.cookies.sessionCookieName":       "TOKEN_COOKIES_SESSION_COOKIE_NAME",
	"token.cookies.updateSessionCookieName": "TOKEN_COOKIES_UPDATE_SESSION_COOKIE_NAME",
	"token.cookies.accessCookieName":        "TOKEN_COOKIES_ACCESS_COOKIE_NAME",
	"token.cookies.idCookieName":            "TOKEN_COOKIES_ID_COOKIE_NAME",
	"token.cookies.refreshCookieName":       "TOKEN_COOKIES_REFRESH_COOKIE_NAME",
	"token.cookies.masqueradedCookieName":   "TOKEN_COOKIES_MASQUERADED_COOKIE_NAME",
}

func SetDefaultConfig(v *viper.Viper) {
	v.SetDefault("storage.type", storage.MemoryType)
	v.SetDefault("token.masquerade", true)
	v.SetDefault("token.cookies.enabled", true)
	v.SetDefault("token.cookies.httpOnly", true)
	v.SetDefault("token.cookies.domain", "")
	v.SetDefault("token.cookies.path", "/")
	v.SetDefault("token.cookies.secure", true)
	v.SetDefault("token.cookies.sameSite", "")
	v.SetDefault("token.cookies.sessionCookieName", "LS")
	v.SetDefault("token.cookies.updateSessionCookieName", "US")
	v.SetDefault("token.cookies.accessCookieName", "LATC")
	v.SetDefault("token.cookies.idCookieName", "LITC")
	v.SetDefault("token.cookies.refreshCookieName", "LRTC")
	v.SetDefault("token.cookies.masqueradedCookieName", "LMTC")
}

// Prepare registers defaults and env bindings of every config section on v.
func Prepare(v *viper.Viper) (map[string]string, error) {
	SetDefaultConfig(v)
	SetDefaultCognitoConfig(v)
	SetDefaultServerConfig(v)
	SetDefaultLimitsConfig(v)
	logging.SetDefaultConfig(v)
	redisclient.SetDefaultConfig(v)
	ratelimiter.SetDefaultConfig(v)
	masquerade.SetDefaultConfig(v)
	httpTools.SetDefaultConfig(v)
	passwordreset.SetDefaultConfig(v)

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	binds := make(map[string]string)

	for _, b := range []map[string]string{
		EnvBinds,
		ServerEnvBinds,
		CognitoEnvBinds,
		LimitsEnvBinds,
		logging.EnvBinds,
		redisclient.EnvBinds,
		ratelimiter.EnvBinds,
		masquerade.EnvBinds,
		httpTools.EnvBinds,
		passwordreset.EnvBinds,
	} {
		for key, env := range b {
			if _, ok := binds[key]; ok {
				return nil, fmt.Errorf("duplicate key: %s", key)
			}
			binds[key] = env
			if err := v.BindEnv(key, env); err != nil {
				return nil, fmt.Errorf("config: bind %s: %w", env, err)
			}
		}
	}

	return binds, nil
}

func LoadConfig(v *viper.Viper) (Config, error) {
	r := Config{}

	if _, err := Prepare(v); err != nil {
		return r, err
	}

	var err error
	r.StorageType, err = storage.ParseType(v.GetString("storage.type"))
	if err != nil {
		return r, err
	}

	r.URLBase = v.GetString("http.urlBase")
	if r.URLBase == "" {
		host := v.GetString("http.host")
		if host == "" {
			host = "localhost"
		}
		port := v.GetString("http.port")
		if port != "" {
			port = ":" + port
		}
		r.URLBase = "http://" + host + port + "/v1"
	}

	r.Masquerade = v.GetBool("token.masquerade")
	r.UseCookies = v.GetBool("token.cookies.enabled")
	r.UseHTTPOnlyCookies = v.GetBool("token.cookies.httpOnly")
	r.CookiesDomain = v.GetString("token.cookies.domain")
	r.CookiesPath = v.GetString("token.cookies.path")
	r.CookiesSecure = v.GetBool("token.cookies.secure")

	r.SessionCookieName = v.GetString("token.cookies.sessionCookieName")
	r.UpdateSessionCookieName = v.GetString("token.cookies.updateSessionCookieName")
	r.AccessTokenCookieName = v.GetString("token.cookies.accessCookieName")
	r.IdTokenCookieName = v.GetString("token.cookies.idCookieName")
	r.RefreshTokenCookieName = v.GetString("token.cookies.refreshCookieName")
	r.MasqueradedTokenCookieName = v.GetString("token.cookies.masqueradedCookieName")

	if r.CookiesSecure {
		r.AccessTokenCookieName = "__Secure-" + r.AccessTokenCookieName
		r.IdTokenCookieName = "__Secure-" + r.IdTokenCookieName
		r.RefreshTokenCookieName = "__Secure-" + r.RefreshTokenCookieName
		r.MasqueradedTokenCookieName = "__Secure-" + r.MasqueradedTokenCookieName
	}

	switch v.GetString("token.cookies.sameSite") {
	case "":
		fallthrough
	case "default":
		r.CookieSameSite = http.SameSiteDefaultMode
		break
	case "lax":
		r.CookieSameSite = http.SameSiteLaxMode
		break
	case "strict":
		r.CookieSameSite = http.SameSiteStrictMode
		break
	case "none":
		r.CookieSameSite = http.SameSiteNoneMode
		break
	default:
		return r, fmt.Errorf("unknown cookie SameSite: %s", v.GetString("token.cookies.sameSite"))
	}

	if r.RedisClientConfig, err = redisclient.LoadConfig(v); err != nil {
		return r, err
	}
	if r.RateLimiterConfig, err = ratelimiter.LoadConfig(v); err != nil {
		return r, err
	}
	if r.MasqueradeConfig, err = masquerade.LoadConfig(v); err != nil {
		return r, err
	}
	if r.HTTPToolsConfig, err = httpTools.LoadConfig(v); err != nil {
		return r, err
	}
	if r.PasswordResetConfig, err = passwordreset.LoadConfig(v); err != nil {
		return r, err
	}
	if r.CognitoConfig, err = LoadCognitoConfig(v); err != nil {
		return r, err
	}
	if r.ServerConfig, err = LoadServerConfig(v); err != nil {
		return r, err
	}
	if r.LimitsConfig, err = LoadLimitsConfig(v); err != nil {
		return r, err
	}
	if r.LoggingConfig, err = logging.LoadConfig(v); err != nil {
		return r, err
	}

	return r, nil
}
