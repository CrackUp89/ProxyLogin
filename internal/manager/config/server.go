package config

import (
	"time"

	"github.com/spf13/viper"
)

type CORSConfig struct {
	Enabled          bool
	AllowedOrigin    string
	AllowedMethods   string
	AllowedHeaders   string
	AllowCredentials bool
}

type CSRFConfig struct {
	HeaderName     string
	AllowedOrigins []string
}

// ServerConfig lives here rather than in the server package because server
// consumes the whole Config, so config can't import it.
type ServerConfig struct {
	Address           string
	Port              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	CORS              CORSConfig
	CSRF              CSRFConfig
	DocsEnabled       bool
	OpenAPIEnabled    bool
	OpenAPISchemas    bool
}

var ServerEnvBinds = map[string]string{
	"http.address":               "HTTP_ADDRESS",
	"http.port":                  "HTTP_PORT",
	"http.cors.enabled":          "HTTP_CORS_ENABLED",
	"http.cors.allowedOrigin":    "HTTP_CORS_ALLOWED_ORIGIN",
	"http.cors.allowedMethods":   "HTTP_CORS_ALLOWED_METHODS",
	"http.cors.allowedHeaders":   "HTTP_CORS_ALLOWED_HEADERS",
	"http.cors.allowCredentials": "HTTP_CORS_ALLOW_CREDENTIALS",
	"http.readHeaderTimeout":     "HTTP_READ_HEADER_TIMEOUT",
	"http.readTimeout":           "HTTP_READ_TIMEOUT",
	"http.writeTimeout":          "HTTP_WRITE_TIMEOUT",
	"http.idleTimeout":           "HTTP_IDLE_TIMEOUT",
	"docs.enabled":               "DOCS_ENABLED",
	"openapi.enabled":            "OPENAPI_ENABLED",
	"openapi.appendSchemas":      "OPENAPI_APPEND_SCHEMAS",
	"http.csrf.headerName":       "HTTP_CSRF_HEADER_NAME",
	"http.csrf.allowedOrigins":   "HTTP_CSRF_ALLOWED_ORIGINS",
}

func SetDefaultServerConfig(v *viper.Viper) {
	v.SetDefault("http.address", "")
	v.SetDefault("http.port", "http")
	v.SetDefault("http.cors.enabled", false)
	v.SetDefault("http.cors.allowedOrigin", "*")
	v.SetDefault("http.cors.allowedMethods", "GET, POST, PUT, DELETE, OPTIONS")
	v.SetDefault("http.cors.allowedHeaders", "Content-Type, Device-Key, Location")
	v.SetDefault("http.cors.allowCredentials", true)

	v.SetDefault("http.readHeaderTimeout", 10)
	v.SetDefault("http.readTimeout", 30)
	v.SetDefault("http.writeTimeout", 60)
	v.SetDefault("http.idleTimeout", 120)

	v.SetDefault("docs.enabled", false)
	//v.SetDefault("docs.style", "stoplight") //todo: make configurable

	v.SetDefault("openapi.enabled", false)
	v.SetDefault("openapi.appendSchemas", true)

	v.SetDefault("http.csrf.headerName", "X-CSRF-Auth-Token")
}

func LoadServerConfig(v *viper.Viper) (ServerConfig, error) {
	return ServerConfig{
		Address:           v.GetString("http.address"),
		Port:              v.GetString("http.port"),
		ReadHeaderTimeout: v.GetDuration("http.readHeaderTimeout") * time.Second,
		ReadTimeout:       v.GetDuration("http.readTimeout") * time.Second,
		WriteTimeout:      v.GetDuration("http.writeTimeout") * time.Second,
		IdleTimeout:       v.GetDuration("http.idleTimeout") * time.Second,
		CORS: CORSConfig{
			Enabled:          v.GetBool("http.cors.enabled"),
			AllowedOrigin:    v.GetString("http.cors.allowedOrigin"),
			AllowedMethods:   v.GetString("http.cors.allowedMethods"),
			AllowedHeaders:   v.GetString("http.cors.allowedHeaders"),
			AllowCredentials: v.GetBool("http.cors.allowCredentials"),
		},
		CSRF: CSRFConfig{
			HeaderName:     v.GetString("http.csrf.headerName"),
			AllowedOrigins: v.GetStringSlice("http.csrf.allowedOrigins"),
		},
		DocsEnabled:    v.GetBool("docs.enabled"),
		OpenAPIEnabled: v.GetBool("openapi.enabled"),
		OpenAPISchemas: v.GetBool("openapi.appendSchemas"),
	}, nil
}
