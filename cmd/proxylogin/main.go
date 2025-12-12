package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"proxylogin/internal/manager/handlers/common"
	"proxylogin/internal/manager/handlers/login/cognito"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func loadEnv() {
	var err error

	viper.AddConfigPath(".")
	viper.SetConfigName(".env")
	viper.SetConfigType("env")

	if err = viper.ReadInConfig(); err != nil {
		log.Println("Default config loaded")
	}

	for _, key := range viper.AllKeys() {
		if err = os.Setenv(strings.ToUpper(key), viper.GetString(key)); err != nil {
			log.Fatal(err)
		}
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	allowedOrigin := viper.GetString("cors_allowed_origin")
	allowedMethods := viper.GetString("cors_allowed_methods")
	allowedHeaders := viper.GetString("cors_allowed_headers")

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

var rootCmd = &cobra.Command{
	Use: "ProxyLogin",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the ProxyLogin server",
	Long:  "Run the ProxyLogin server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return serve(cmd)
	},
}

func bindViperFlag(cmd *cobra.Command, flag string, keyOverride string) {
	key := flag
	if keyOverride != "" {
		key = keyOverride
	}

	if err := viper.BindPFlag(key, cmd.Flags().Lookup(flag)); err != nil {
		log.Fatal(err)
	}
}

func markFlagRequired(cmd *cobra.Command, flag string) {
	if err := cmd.MarkFlagRequired(flag); err != nil {
		log.Fatal(err)
	}
}

func init() {
	loadEnv()

	viper.SetEnvPrefix("")
	viper.AutomaticEnv()

	serveCmd.Flags().StringP("address", "a", "", "Address to listen on")
	bindViperFlag(serveCmd, "address", "")
	viper.SetDefault("address", ":8383")

	serveCmd.Flags().Uint64("workers", 1000, "Server workers count")
	bindViperFlag(serveCmd, "workers", "workers")
	viper.SetDefault("workers", 1000)

	serveCmd.Flags().String("cognito-client-id", "", "AWS Cognito Client ID")
	bindViperFlag(serveCmd, "cognito-client-id", "cognito_client_id")

	serveCmd.Flags().String("cognito-client-secret", "", "AWS Cognito Client Secret")
	bindViperFlag(serveCmd, "cognito-client-secret", "cognito_client_secret")

	serveCmd.Flags().String("cognito-user-pool-id", "", "AWS Cognito User Pool ID")
	bindViperFlag(serveCmd, "cognito-user-pool-id", "cognito_user_pool_id")

	serveCmd.Flags().Bool("cors-enable", false, "Enable CORS")
	bindViperFlag(serveCmd, "cors-enable", "CORS_ENABLE")

	serveCmd.Flags().String("cors-allowed-origin", "*", "Set Access-Control-Allow-Origin header for CORS")
	bindViperFlag(serveCmd, "cors-allowed-origin", "cors_allowed_origin")
	viper.SetDefault("cors_allowed_origin", "*")

	serveCmd.Flags().String("cors-allowed-methods", "GET, POST, PUT, DELETE, OPTIONS", "Set Access-Control-Allow-Methods header for CORS")
	bindViperFlag(serveCmd, "cors-allowed-methods", "cors_allowed_methods")
	viper.SetDefault("cors_allowed_methods", "GET, POST, PUT, DELETE, OPTIONS")

	serveCmd.Flags().String("cors-allowed-headers", "Content-Type, Device-Key", "Set Access-Control-Allow-Headers header for CORS")
	bindViperFlag(serveCmd, "cors-allowed-headers", "cors_allowed_headers")
	viper.SetDefault("cors_allowed_headers", "Content-Type, Device-Key")

	rootCmd.AddCommand(serveCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func main() {
	Execute()
}

func serve(cmd *cobra.Command) error {
	var err error
	mux := http.NewServeMux()

	common.AddRoutes(mux)

	err = cognito.SetClientDetails(viper.GetString("cognito_client_id"), viper.GetString("cognito_client_secret"))
	if err != nil {
		log.Fatal(err)
	}
	cognito.SetUserPoolID(viper.GetString("cognito_user_pool_id"))

	cognito.Initialize()

	stopCognitoWorkers := cognito.StartWorkers(viper.GetUint64("workers"))

	cognito.AddRoutes(mux)

	var handler http.Handler
	handler = mux

	if viper.GetBool("cors_enable") {
		handler = corsMiddleware(handler)
	}

	httpServer := &http.Server{
		Addr:    viper.GetString("address"),
		Handler: handler,
	}

	serverErrors := make(chan error, 1)

	go func() {
		log.Printf("Server starting on %s", httpServer.Addr)
		serverErrors <- httpServer.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		return err

	case sig := <-shutdown:
		log.Printf("Received signal: %v. Starting graceful shutdown...", sig)
		log.Printf("Stoping workers...")
		stopCognitoWorkers()
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
			if err := httpServer.Close(); err != nil {
				log.Fatalf("Could not stop server: %v", err)
			}
		}
	}

	return nil
}
