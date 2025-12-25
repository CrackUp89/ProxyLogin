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
	"proxylogin/internal/manager/login/passwordreset"
	"proxylogin/internal/manager/rds"
	httpTools "proxylogin/internal/manager/tools/http"
	"proxylogin/internal/manager/tools/ratelimiter"
	"syscall"
	"time"

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
	viper.SetDefault("http.address", "")
	viper.SetDefault("http.port", "http")
	viper.SetDefault("http.cors.enabled", false)
	viper.SetDefault("http.cors.allowedOrigin", "*")
	viper.SetDefault("http.cors.allowedMethods", "GET, POST, PUT, DELETE, OPTIONS")
	viper.SetDefault("http.cors.allowedHeaders", "Content-Type, Device-Key, Location")
}

func Run() error {
	logging.LoadConfig()

	logger := getLogger()

	config.LoadConfig()
	rds.LoadConfig()
	ratelimiter.LoadConfig()

	var err error
	passwordreset.LoadConfig()

	mux := http.NewServeMux()

	common.AddRoutes(mux)

	err = cognito.Start()
	if err != nil {
		return err
	}

	cognito.AddRoutes(mux)

	var handler http.Handler
	handler = mux

	handler = httpTools.WithAutoRecoverMiddleware(handler)

	if viper.GetBool("http.cors.enabled") {
		handler = withCORSMiddleware(handler)
	}

	handler = httpTools.WithRequestMetadataContextMiddleware(handler)

	//rt := tools.RequestTracker{}
	//handler = rt.RequestTrackerMiddleware(handler)
	//
	//go func() {
	//	for {
	//		activeRequests := rt.GetActiveRequests()
	//		for _, req := range activeRequests {
	//			fmt.Println(req.Path)
	//		}
	//		time.Sleep(1 * time.Second)
	//	}
	//}()

	httpServer := &http.Server{
		Addr:    fmt.Sprintf("%s:%s", viper.GetString("http.address"), viper.GetString("http.port")),
		Handler: handler,
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

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", allowedMethods)
		w.Header().Set("Access-Control-Allow-Headers", allowedHeaders)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
