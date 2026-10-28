package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"proxylogin/internal/manager/common"
	"proxylogin/internal/manager/config"
	"proxylogin/internal/manager/logging"
	"proxylogin/internal/manager/login/cognito"
	"proxylogin/internal/manager/tools"
	httpTools "proxylogin/internal/manager/tools/http"
	humaTools "proxylogin/internal/manager/tools/huma"
	"strings"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"go.uber.org/zap"
)

var serverLogger *zap.Logger

func getLogger() *zap.Logger {
	if serverLogger == nil {
		serverLogger = logging.NewLogger("server")
	}
	return serverLogger
}

func newHumaConfig(cfg config.ServerConfig, version string) huma.Config {
	schemaPrefix := "#/components/schemas/"
	schemasPath := "/schemas"

	registry := huma.NewMapRegistry(schemaPrefix, huma.DefaultSchemaNamer)

	r := huma.Config{
		OpenAPI: &huma.OpenAPI{
			OpenAPI: "3.1.0",
			Info: &huma.Info{
				Title:       "ProxyLogin API",
				Version:     version,
				Description: apiDescription,
			},
			Components: &huma.Components{
				Schemas: registry,
			},
		},

		Formats:                      huma.DefaultFormats,
		DefaultFormat:                "application/json",
		NoFormatFallback:             false,
		RejectUnknownQueryParameters: false,
		Transformers:                 nil,
	}

	if cfg.DocsEnabled {
		r.DocsPath = "/docs"
		r.DocsRenderer = huma.DocsRendererStoplightElements
	}

	if cfg.OpenAPIEnabled {
		r.OpenAPIPath = "/openapi"
		if cfg.OpenAPISchemas {
			r.SchemasPath = schemasPath
			r.CreateHooks = []func(huma.Config) huma.Config{
				func(c huma.Config) huma.Config {
					linkTransformer := huma.NewSchemaLinkTransformer(schemaPrefix, c.SchemasPath)
					c.OnAddOperation = append(c.OnAddOperation, linkTransformer.OnAddOperation)
					c.Transformers = append(c.Transformers, linkTransformer.Transform)
					return c
				},
			}
		}
	}

	return r
}

func Run(appConfig config.Config) error {
	logging.Setup(appConfig.LoggingConfig)

	logger := getLogger()

	versionInfo := common.GetAppVersionInfo()
	logger.Info("Starting...", zap.String("version", versionInfo.Version), zap.String("commit", versionInfo.Commit), zap.String("buildDate", versionInfo.BuildDate))

	serverConfig := appConfig.ServerConfig

	mux := http.NewServeMux()

	humaConfig := newHumaConfig(serverConfig, versionInfo.Version)
	api := humago.New(mux, humaConfig)

	// Global huma middleware: store huma.Context in context.Context for cookie access
	api.UseMiddleware(humaTools.HumaContextMiddleware)

	csrf := tools.NewCSRF(serverConfig.CSRF.HeaderName, serverConfig.CSRF.AllowedOrigins)

	commonHandlers := common.New()

	commonHandlers.AddRoutes(api)

	cognitoProvider, err := cognito.New(appConfig, csrf)
	if err != nil {
		return err
	}

	err = cognitoProvider.Start()
	if err != nil {
		return err
	}

	cognitoProvider.AddRoutes(api)

	var handler http.Handler
	handler = mux

	handler = httpTools.WithAutoRecoverMiddleware(handler)

	if serverConfig.CORS.Enabled {
		handler = withCORSMiddleware(corsWithCSRFHeader(serverConfig.CORS, serverConfig.CSRF.HeaderName), handler)
	}

	handler = httpTools.WithRequestMetadataContextMiddleware(appConfig.HTTPToolsConfig, handler)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", serverConfig.Address, serverConfig.Port),
		Handler:           handler,
		ReadHeaderTimeout: serverConfig.ReadHeaderTimeout,
		ReadTimeout:       serverConfig.ReadTimeout,
		WriteTimeout:      serverConfig.WriteTimeout,
		IdleTimeout:       serverConfig.IdleTimeout,
	}

	serverErrors := make(chan error, 1)

	go func() {
		logger.Info(fmt.Sprintf("Listening on %s", httpServer.Addr))
		if serverConfig.DocsEnabled {
			logger.Warn(fmt.Sprintf("Docs available on %s/docs", httpServer.Addr))
		}
		if serverConfig.OpenAPIEnabled {
			if serverConfig.OpenAPISchemas {
				logger.Warn("OpenAPI docs and schema generation enabled")
			} else {
				logger.Warn("OpenAPI docs generation enabled")
			}
		}

		serverErrors <- httpServer.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return err

	case sig := <-shutdown:
		logger.Info("starting graceful shutdown", zap.String("signal", sig.String()))
		cognitoProvider.Stop()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", zap.Error(err))
			if err := httpServer.Close(); err != nil {
				logger.Fatal("could not stop server", zap.Error(err))
			}
		}
	}

	return nil
}

// corsWithCSRFHeader adds the CSRF header to the allowed CORS headers, so browsers can send it cross-origin.
func corsWithCSRFHeader(cfg config.CORSConfig, csrfHeader string) config.CORSConfig {
	if csrfHeader == "" {
		return cfg
	}
	for h := range strings.SplitSeq(cfg.AllowedHeaders, ",") {
		if strings.EqualFold(strings.TrimSpace(h), csrfHeader) {
			return cfg
		}
	}
	if strings.TrimSpace(cfg.AllowedHeaders) == "" {
		cfg.AllowedHeaders = csrfHeader
	} else {
		cfg.AllowedHeaders += ", " + csrfHeader
	}
	return cfg
}

func withCORSMiddleware(cfg config.CORSConfig, next http.Handler) http.Handler {
	allowedOrigin := cfg.AllowedOrigin
	allowedMethods := cfg.AllowedMethods
	allowedHeaders := cfg.AllowedHeaders
	allowCredentials := cfg.AllowCredentials

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		if allowedOrigin == "*" {
			if allowCredentials {
				// "*" with credentials is invalid per CORS spec; reflect the request origin instead.
				if origin != "" {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Vary", "Origin")
				}
			} else {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			}
		} else {
			if origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			}
		}

		w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		if allowCredentials {
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
