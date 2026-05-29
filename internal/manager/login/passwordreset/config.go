package passwordreset

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Enabled          bool
	Company          string
	Year             int
	Sender           string
	TemplateName     string
	ValidFor         time.Duration
	RedirectURL      string
	ErrorRedirectURL string
}

var EnvBinds = map[string]string{
	"password.reset.enabled":          "PASSWORD_RESET_ENABLED",
	"password.reset.company":          "PASSWORD_RESET_COMPANY",
	"password.reset.year":             "PASSWORD_RESET_YEAR",
	"password.reset.tokenValidFor":    "PASSWORD_RESET_TOKEN_VALID_FOR",
	"password.reset.sender":           "PASSWORD_RESET_SENDER",
	"password.reset.templateName":     "PASSWORD_RESET_TEMPLATE_NAME",
	"password.reset.redirectURL":      "PASSWORD_RESET_REDIRECT_URL",
	"password.reset.errorRedirectURL": "PASSWORD_RESET_ERROR_REDIRECT_URL",
}

func SetDefaultConfig(v *viper.Viper) {
	v.SetDefault("password.reset.enabled", true)
	v.SetDefault("password.reset.company", "TotallyNotEvilCompanyName")
	v.SetDefault("password.reset.year", time.Now().Year())
	v.SetDefault("password.reset.tokenValidFor", 60)
	v.SetDefault("password.reset.sender", "")
	v.SetDefault("password.reset.templateName", "PasswordResetTemplate")
	v.SetDefault("password.reset.redirectURL", "http://localhost/reset-password?token=%[1]s")
}

func LoadConfig(v *viper.Viper) (Config, error) {
	return Config{
		Enabled:          v.GetBool("password.reset.enabled"),
		Company:          v.GetString("password.reset.company"),
		Year:             v.GetInt("password.reset.year"),
		Sender:           v.GetString("password.reset.sender"),
		TemplateName:     v.GetString("password.reset.templateName"),
		ValidFor:         time.Duration(v.GetInt("password.reset.tokenValidFor")) * time.Minute,
		RedirectURL:      v.GetString("password.reset.redirectURL"),
		ErrorRedirectURL: v.GetString("password.reset.errorRedirectURL"),
	}, nil
}
