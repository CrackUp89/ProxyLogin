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
	"proxylogin/internal/manager/login/masquerade"
	"proxylogin/internal/manager/login/passwordreset"
	"proxylogin/internal/manager/ratelimiter"
	"proxylogin/internal/manager/redisclient"
	httpTools "proxylogin/internal/manager/tools/http"
	humaTools "proxylogin/internal/manager/tools/huma"
	"syscall"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var serverLogger *zap.Logger

func getLogger() *zap.Logger {
	if serverLogger == nil {
		serverLogger = logging.NewLogger("server")
	}
	return serverLogger
}

func init() {
	viper.SetDefault("instance.id", "proxylogin")

	viper.SetDefault("http.address", "")
	viper.SetDefault("http.port", "http")
	viper.SetDefault("http.cors.enabled", false)
	viper.SetDefault("http.cors.allowedOrigin", "*")
	viper.SetDefault("http.cors.allowedMethods", "GET, POST, PUT, DELETE, OPTIONS")
	viper.SetDefault("http.cors.allowedHeaders", "Content-Type, Device-Key, Location")
	viper.SetDefault("http.cors.allowCredentials", true)

	viper.SetDefault("http.readHeaderTimeout", 10)
	viper.SetDefault("http.readTimeout", 30)
	viper.SetDefault("http.writeTimeout", 60)
	viper.SetDefault("http.idleTimeout", 120)
}

func Run() error {
	logging.LoadConfig()

	logger := getLogger()

	config.LoadConfig()
	redisclient.LoadConfig()
	ratelimiter.LoadConfig()
	masquerade.LoadConfig()
	httpTools.LoadConfig()
	passwordreset.LoadConfig()

	mux := http.NewServeMux()

	humaConfig := huma.DefaultConfig("ProxyLogin API", "1.0.0")
	api := humago.New(mux, humaConfig)

	// Global huma middleware: store huma.Context in context.Context for cookie access
	api.UseMiddleware(humaTools.HumaContextMiddleware)

	common.AddRoutes(api)

	var err error
	err = cognito.Start()
	if err != nil {
		return err
	}

	cognito.AddRoutes(api)

	var handler http.Handler
	handler = mux

	handler = httpTools.WithAutoRecoverMiddleware(handler)

	if viper.GetBool("http.cors.enabled") {
		handler = withCORSMiddleware(handler)
	}

	handler = httpTools.WithRequestMetadataContextMiddleware(handler)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf("%s:%s", viper.GetString("http.address"), viper.GetString("http.port")),
		Handler:           handler,
		ReadHeaderTimeout: viper.GetDuration("http.readHeaderTimeout") * time.Second,
		ReadTimeout:       viper.GetDuration("http.readTimeout") * time.Second,
		WriteTimeout:      viper.GetDuration("http.writeTimeout") * time.Second,
		IdleTimeout:       viper.GetDuration("http.idleTimeout") * time.Second,
	}

	serverErrors := make(chan error, 1)

	go func() {
		logger.Info(fmt.Sprintf("Listening on %s", httpServer.Addr))
		serverErrors <- httpServer.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return err

	case sig := <-shutdown:
		logger.Info("starting graceful shutdown", zap.String("signal", sig.String()))
		cognito.Stop()

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

func withCORSMiddleware(next http.Handler) http.Handler {
	allowedOrigin := viper.GetString("http.cors.allowedOrigin")
	allowedMethods := viper.GetString("http.cors.allowedMethods")
	allowedHeaders := viper.GetString("http.cors.allowedHeaders")
	allowCredentials := viper.GetBool("http.cors.allowCredentials")

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
