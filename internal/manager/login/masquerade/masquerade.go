package masquerade

import (
	"proxylogin/internal/manager/logging"
	"proxylogin/internal/manager/redisclient"
	"proxylogin/internal/manager/storage"

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

type Config struct {
	KeyLength          int
	UnmaskRefreshToken bool
}

var EnvBinds = map[string]string{
	"masquerade.keyLength":          "MASQUERADE_KEY_LENGTH",
	"masquerade.unmaskRefreshToken": "MASQUERADE_UNMASK_REFRESH_TOKEN",
}

func SetDefaultConfig(v *viper.Viper) {
	v.SetDefault("masquerade.keyLength", 256)
	v.SetDefault("masquerade.unmaskRefreshToken", false)
}

func LoadConfig(v *viper.Viper) (Config, error) {
	return Config{
		KeyLength:          v.GetInt("masquerade.keyLength"),
		UnmaskRefreshToken: v.GetBool("masquerade.unmaskRefreshToken"),
	}, nil
}

type Masquerade struct {
	cfg     Config
	storage Storage
}

func New(cfg Config, storageType storage.Type, redisCfg redisclient.Config) (*Masquerade, error) {
	s, err := newStorage(storageType, redisCfg)
	if err != nil {
		return nil, err
	}
	return &Masquerade{cfg: cfg, storage: s}, nil
}

func (m *Masquerade) Storage() Storage {
	return m.storage
}

func (m *Masquerade) UnmaskRefreshToken() bool {
	return m.cfg.UnmaskRefreshToken
}
