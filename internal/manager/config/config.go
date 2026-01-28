package config

import (
	"errors"
	"net/http"

	"github.com/spf13/viper"
)

type StorageType string

var (
	MemoryStorageType StorageType = "memory"
	RedisStorageType  StorageType = "redis"
)

func parseStorageType(s string) (StorageType, error) {
	switch s {
	case "memory":
		return MemoryStorageType, nil
	case "redis":
		return RedisStorageType, nil
	default:
		return "", errors.New("invalid storage type")
	}
}

var urlBase string
var masquerade bool
var useCookies bool
var useHTTPOnlyCookies bool
var cookiesDomain string
var cookiesPath string
var cookiesSecure bool
var cookieSameSite http.SameSite
var accessTokenCookieName string
var idTokenCookieName string
var refreshTokenCookieName string
var masqueradedTokenCookieName string
var storageType StorageType

func init() {
	viper.SetDefault("storage.type", MemoryStorageType)
	viper.SetDefault("token.masquerade", true)
	viper.SetDefault("token.cookies.enabled", true)
	viper.SetDefault("token.cookies.httpOnly", true)
	viper.SetDefault("token.cookies.domain", "")
	viper.SetDefault("token.cookies.path", "/")
	viper.SetDefault("token.cookies.secure", true)
	viper.SetDefault("token.cookies.sameSite", "")
	viper.SetDefault("token.cookies.accessCookieName", "LATC")
	viper.SetDefault("token.cookies.idCookieName", "LITC")
	viper.SetDefault("token.cookies.refreshCookieName", "LRTC")
	viper.SetDefault("token.cookies.masqueradedCookieName", "LMTC")
}

func LoadConfig() {
	var err error
	storageType, err = parseStorageType(viper.GetString("storage.type"))
	if err != nil {
		panic(err)
	}

	urlBase = viper.GetString("http.urlBase")
	if urlBase == "" {
		host := viper.GetString("http.host")
		if host == "" {
			host = "localhost"
		}
		port := viper.GetString("http.port")
		if port != "" {
			port = ":" + port
		}
		urlBase = "http://" + host + port + "/v1"
	}

	masquerade = viper.GetBool("token.masquerade")
	useCookies = viper.GetBool("token.cookies.enabled")
	useHTTPOnlyCookies = viper.GetBool("token.cookies.httpOnly")
	cookiesDomain = viper.GetString("token.cookies.domain")
	cookiesPath = viper.GetString("token.cookies.path")
	cookiesSecure = viper.GetBool("token.cookies.secure")

	accessTokenCookieName = viper.GetString("token.cookies.accessCookieName")
	idTokenCookieName = viper.GetString("token.cookies.idCookieName")
	refreshTokenCookieName = viper.GetString("token.cookies.refreshCookieName")
	masqueradedTokenCookieName = viper.GetString("token.cookies.masqueradedCookieName")

	if cookiesSecure {
		accessTokenCookieName = "__Secure-" + accessTokenCookieName
		idTokenCookieName = "__Secure-" + idTokenCookieName
		refreshTokenCookieName = "__Secure-" + refreshTokenCookieName
		masqueradedTokenCookieName = "__Secure-" + masqueradedTokenCookieName
	}

	switch viper.GetString("token.cookies.sameSite") {
	case "":
		fallthrough
	case "default":
		cookieSameSite = http.SameSiteDefaultMode
		break
	case "lax":
		cookieSameSite = http.SameSiteLaxMode
		break
	case "strict":
		cookieSameSite = http.SameSiteStrictMode
		break
	case "none":
		cookieSameSite = http.SameSiteNoneMode
		break
	default:
		panic("invalid cookie same-site: " + viper.GetString("token.cookies.sameSite"))
	}
}

func GetURLBase() string {
	return urlBase
}

func UseMasquerade() bool {
	return masquerade
}

func UseCookies() bool {
	return useCookies
}

func UseHTTPOnlyCookies() bool {
	return useHTTPOnlyCookies
}

func GetCookieDomain() string {
	return cookiesDomain
}

func GetCookiePath() string {
	return cookiesPath
}

func GetCookieSecure() bool {
	return cookiesSecure
}

func GetCookieSameSite() http.SameSite {
	return cookieSameSite
}

func GetAccessTokenCookieName() string {
	return accessTokenCookieName
}

func GetIDTokenCookieName() string {
	return idTokenCookieName
}

func GetRefreshTokenCookieName() string {
	return refreshTokenCookieName
}

func GetMasqueradedCookieName() string {
	return masqueradedTokenCookieName
}

func GetStorageType() StorageType {
	return storageType
}
