package masquerade

import (
	"proxylogin/internal/manager/logging"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var masqueradeLogger *zap.Logger

func getMasqueradeLogger() *zap.Logger {
	if masqueradeLogger == nil {
		masqueradeLogger = logging.NewLogger("masquerade")
	}
	return masqueradeLogger
}

var keyLength int
var unmaskRefreshToken bool

func init() {
	viper.SetDefault("masquerade.keyLength", 256)
	viper.SetDefault("masquerade.unmaskRefreshToken", false)
}

func LoadConfig() {
	keyLength = viper.GetInt("masquerade.keyLength")
	unmaskRefreshToken = viper.GetBool("masquerade.unmaskRefreshToken")
	createStorage()
}

func UnmaskRefreshToken() bool {
	return unmaskRefreshToken
}
