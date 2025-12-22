package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"proxylogin/internal/manager/server"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

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
		if !errors.As(err, &nf) {
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
		var nf viper.ConfigFileNotFoundError
		if !errors.As(err, &nf) {
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
