package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"proxylogin/internal/manager/common"
	"proxylogin/internal/manager/config"
	"proxylogin/internal/manager/server"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var version = "dev"
var commit = "none"
var buildDate = "unknown"

var mustLoadEnvFile = false

var rootCmd = &cobra.Command{
	Use: "proxylogin",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the ProxyLogin server",
	Long:  "Run the ProxyLogin server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
}

// newViper reads ./config.* (if present) into a fresh viper instance with env overrides enabled.
func newViper() (*viper.Viper, error) {
	v := viper.New()

	v.AddConfigPath(".")
	v.SetConfigName("config")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			return nil, err
		}
	}
	return v, nil
}

var printConfigCmd = &cobra.Command{
	Use:   "print-config",
	Short: "Print the config",
	Long:  "Print the config",
	RunE: func(cmd *cobra.Command, args []string) error {
		loadEnvFile()

		v, err := newViper()
		if err != nil {
			return err
		}

		binds, err := config.Prepare(v)
		if err != nil {
			return err
		}

		lcBinds := make(map[string]string)
		for k, _ := range binds {
			lcBinds[strings.ToLower(k)] = k
		}

		_, err = config.LoadConfig(v)
		if err != nil {
			return err
		}

		sortedKeys := sort.StringSlice(make([]string, 0, len(v.AllKeys())))
		sortedKeys = append(sortedKeys, v.AllKeys()...)
		sortedKeys.Sort()

		for _, key := range sortedKeys {
			nKey := lcBinds[key]
			if envKey, ok := binds[nKey]; ok {
				fmt.Printf("%s [%s]: %s\n", nKey, strings.ToUpper(envKey), v.GetString(key))
			} else {
				fmt.Printf("%s: %s\n", nKey, v.GetString(key))
			}

		}

		return nil
	},
}

func loadEnvFile() {
	if !mustLoadEnvFile {
		return
	}
	var err error

	v := viper.New()

	v.AddConfigPath(".")
	v.SetConfigName(".env")
	v.SetConfigType("env")

	if err = v.ReadInConfig(); err != nil {
		if _, ok := errors.AsType[viper.ConfigFileNotFoundError](err); !ok {
			log.Fatal(err)
		}
	}

	for _, key := range v.AllKeys() {
		if err = os.Setenv(strings.ToUpper(key), v.GetString(key)); err != nil {
			log.Fatal(err)
		}
	}
}

func init() {
	common.SetAppVersionInfo(version, commit, buildDate)

	exeName, err := os.Executable()
	if err == nil {
		rootCmd.Use = filepath.Base(exeName)
	}

	rootCmd.PersistentFlags().BoolVarP(&mustLoadEnvFile, "env", "e", false, "load environment variables from .env file")
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(printConfigCmd)
}

func run() error {
	loadEnvFile()

	v, err := newViper()
	if err != nil {
		return err
	}

	appConfig, err := config.LoadConfig(v)
	if err != nil {
		return err
	}

	return server.Run(appConfig)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
