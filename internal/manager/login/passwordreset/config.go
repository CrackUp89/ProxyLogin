package passwordreset

import (
	"time"

	"github.com/spf13/viper"
)

type Settings struct {
	Enabled          bool
	Company          string
	Year             int
	Sender           string
	TemplateName     string
	ValidFor         time.Duration
	RedirectURL      string
	ErrorRedirectURL string
}

var settings Settings

func init() {
	viper.SetDefault("password.reset.enabled", true)
	viper.SetDefault("password.reset.company", "TotallyNotEvilCompanyName")
	viper.SetDefault("password.reset.year", time.Now().Year())
	viper.SetDefault("password.reset.tokenValidFor", 60)
	viper.SetDefault("password.reset.sender", "")
	viper.SetDefault("password.reset.templateName", "PasswordResetTemplate")
	viper.SetDefault("password.reset.baseURL", "")
	viper.SetDefault("password.reset.redirectURL", "http://localhost/reset-password?user=%[1]s")
}

func LoadConfig() {
	settings = Settings{
		Enabled:          viper.GetBool("password.reset.enabled"),
		Company:          viper.GetString("password.reset.company"),
		Year:             viper.GetInt("password.reset.year"),
		Sender:           viper.GetString("password.reset.sender"),
		TemplateName:     viper.GetString("password.reset.templateName"),
		ValidFor:         time.Duration(viper.GetInt("password.reset.tokenValidFor")) * time.Minute,
		RedirectURL:      viper.GetString("password.reset.redirectURL"),
		ErrorRedirectURL: viper.GetString("password.reset.errorRedirectURL"),
	}
}

func GetSettings() Settings {
	return settings
}
