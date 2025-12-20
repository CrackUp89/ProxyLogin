package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"proxylogin/internal/manager/server"
	"proxylogin/internal/manager/tools"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var logger = tools.NewLogger("cmd")

var rootCmd = &cobra.Command{
	Use: "ProxyLogin",
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the ProxyLogin server",
	Long:  "Run the ProxyLogin server",
	RunE: func(cmd *cobra.Command, args []string) error {
		return run()
	},
}

func loadViperConfig() error {
	if err := viper.ReadInConfig(); err != nil {
		var nf viper.ConfigFileNotFoundError
		if errors.As(err, &nf) {
			logger.Info("Config file does not exist")
		} else {
			return err
		}
	}
	return nil
}

var printConfigCmd = &cobra.Command{
	Use:   "print-config",
	Short: "Print the config",
	Long:  "Print the config",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := loadViperConfig()
		if err != nil {
			return err
		}
		sortedKeys := sort.StringSlice(make([]string, 0, len(viper.AllKeys())))
		sortedKeys = append(sortedKeys, viper.AllKeys()...)
		sortedKeys.Sort()

		for _, key := range sortedKeys {
			fmt.Printf("%s: %s\n", key, viper.GetString(key))
		}

		return nil
	},
}

func loadEnvFile() {
	var err error

	v := viper.New()

	v.AddConfigPath(".")
	v.SetConfigName(".env")
	v.SetConfigType("env")

	if err = v.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			logger.Info("Config file does not exist")
		} else {
			logger.Error(err.Error())
		}
	}

	for _, key := range v.AllKeys() {
		if err = os.Setenv(strings.ToUpper(key), v.GetString(key)); err != nil {
			log.Fatal(err)
		}
	}
}

func init() {
	loadEnvFile()

	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(printConfigCmd)
}

func run() error {
	err := loadViperConfig()
	if err != nil {
		return err
	}

	return server.Run()
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
