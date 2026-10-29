package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/viper"
)

type RateLimit struct {
	Limit  int
	Window time.Duration
}

type LimitsConfig struct {
	Rate                 map[string]RateLimit
	MFAVerifyMaxAttempts int64
}

var defaultRateLimits = map[string][2]int{
	"loginStartPerRemoteAddress": {10, 60},
	"loginStartTotal":            {100, 1},

	"loginPerUser":          {90, 60},
	"loginPerRemoteAddress": {10, 60},
	"loginTotal":            {100, 1},

	"validatePerRemoteAddress": {6000, 60},
	"validateTotal":            {1000, 1},

	"loginMFASetupPerUser":          {5, 1},
	"loginMFASetupPerRemoteAddress": {10, 60},
	"loginMFASetupTotal":            {100, 1},

	"loginMFASetupVerifyPerUser":          {5, 1},
	"loginMFASetupVerifyPerRemoteAddress": {10, 60},
	"loginMFASetupVerifyTotal":            {100, 1},

	"loginMFAVerifyPerUser":          {5, 1},
	"loginMFAVerifyPerRemoteAddress": {10, 60},
	"loginMFAVerifyTotal":            {100, 1},

	"loginMFASelectPerUser":          {5, 1},
	"loginMFASelectPerRemoteAddress": {10, 60},
	"loginMFASelectTotal":            {100, 1},

	"loginPasswordUpdatePerUser":          {5, 1},
	"loginPasswordUpdatePerRemoteAddress": {10, 60},
	"loginPasswordUpdateTotal":            {100, 1},

	"logoutPerToken":         {5, 1},
	"logoutPerRemoteAddress": {60, 60},
	"logoutTotal":            {100, 1},

	"refreshTokensPerToken":         {5, 1},
	"refreshTokensPerUser":          {5, 1},
	"refreshTokensPerRemoteAddress": {60, 60},
	"refreshTokensTotal":            {100, 1},

	"passwordUpdateStartPerToken":         {5, 1},
	"passwordUpdateStartPerRemoteAddress": {10, 60},
	"passwordUpdateStartTotal":            {100, 1},

	"passwordUpdatePerToken":         {5, 1},
	"passwordUpdatePerRemoteAddress": {10, 60},
	"passwordUpdateTotal":            {100, 1},

	"mfaStatusPerToken":         {10, 1},
	"mfaStatusPerRemoteAddress": {600, 60},
	"mfaStatusTotal":            {1000, 1},

	"mfaSoftwareTokenUpdateStartPerToken":         {5, 1},
	"mfaSoftwareTokenUpdateStartPerRemoteAddress": {10, 60},
	"mfaSoftwareTokenUpdateStartTotal":            {100, 1},

	"mfaSoftwareTokenUpdatePerToken":         {5, 1},
	"mfaSoftwareTokenUpdatePerRemoteAddress": {10, 60},
	"mfaSoftwareTokenUpdateTotal":            {100, 1},

	"mfaSoftwareTokenUpdateVerifyPerToken":         {5, 1},
	"mfaSoftwareTokenUpdateVerifyPerRemoteAddress": {10, 60},
	"mfaSoftwareTokenUpdateVerifyTotal":            {100, 1},

	"passwordResetRequestPerEmailAndRemoteAddress": {1, 60},
	"passwordResetRequestPerEmail":                 {5, 3600},
	"passwordResetRequestPerRemoteAddress":         {10, 60},
	"passwordResetRequestTotal":                    {100, 1},

	"passwordResetValidatePerToken":         {5, 1},
	"passwordResetValidatePerRemoteAddress": {10, 60},
	"passwordResetValidateTotal":            {100, 1},

	"passwordResetFinalizePerToken":         {5, 1},
	"passwordResetFinalizePerRemoteAddress": {10, 60},
	"passwordResetFinalizeTotal":            {100, 1},

	"unmaskTokenCookiePerToken":         {100, 1},
	"unmaskTokenCookiePerRemoteAddress": {6000, 60},
	"unmaskTokenCookieTotal":            {1000, 1},

	"unmaskTokenPerToken":         {100, 1},
	"unmaskTokenPerRemoteAddress": {6000, 60},
	"unmaskTokenTotal":            {1000, 1},

	"getProfilePerToken":         {6000, 60},
	"getProfilePerRemoteAddress": {6000, 60},
	"getProfileTotal":            {1000, 1},

	"loginExternalTokenPerCode":          {2, 1},
	"loginExternalTokenPerRemoteAddress": {10, 60},
	"loginExternalTokenTotal":            {100, 1},

	"settingsPerRemoteAddress": {600, 60},
	"settingsTotal":            {1000, 1},
}

var LimitsEnvBinds = buildLimitsEnvBinds()

var camelBoundary = regexp.MustCompile(`([a-z0-9])([A-Z])|([A-Z])([A-Z][a-z])`)

func toEnvName(name string) string {
	return strings.ToUpper(camelBoundary.ReplaceAllString(name, "${1}${3}_${2}${4}"))
}

func buildLimitsEnvBinds() map[string]string {
	binds := map[string]string{
		"limits.mfaVerifyMaxAttempts": "LIMITS_MFA_VERIFY_MAX_ATTEMPTS",
	}
	for name := range defaultRateLimits {
		binds["limits.rate."+name+".limit"] = "LIMITS_" + toEnvName(name) + "_LIMIT"
		binds["limits.rate."+name+".window"] = "LIMITS_" + toEnvName(name) + "_WINDOW"
	}
	return binds
}

func SetDefaultLimitsConfig(v *viper.Viper) {
	v.SetDefault("limits.mfaVerifyMaxAttempts", 3)
	for name, d := range defaultRateLimits {
		v.SetDefault("limits.rate."+name+".limit", d[0])
		v.SetDefault("limits.rate."+name+".window", d[1])
	}
}

func LoadLimitsConfig(v *viper.Viper) (LimitsConfig, error) {
	r := LimitsConfig{
		Rate:                 make(map[string]RateLimit, len(defaultRateLimits)),
		MFAVerifyMaxAttempts: v.GetInt64("limits.mfaVerifyMaxAttempts"),
	}

	if r.MFAVerifyMaxAttempts < 1 {
		return r, fmt.Errorf("limits: mfaVerifyMaxAttempts must be at least 1")
	}

	for name := range defaultRateLimits {
		limit := v.GetInt("limits.rate." + name + ".limit")
		window := v.GetInt("limits.rate." + name + ".window")
		if limit < 1 || window < 1 {
			return r, fmt.Errorf("limits: %s: limit and window must be at least 1", name)
		}
		r.Rate[name] = RateLimit{Limit: limit, Window: time.Duration(window) * time.Second}
	}

	return r, nil
}
