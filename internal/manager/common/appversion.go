package common

type AppVersionInfo struct {
	Version   string
	Commit    string
	BuildDate string
}

var appVersionInfo *AppVersionInfo

func SetAppVersionInfo(version string, commit string, buildDate string) {
	appVersionInfo = &AppVersionInfo{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
	}
}

func GetAppVersionInfo() *AppVersionInfo {
	return appVersionInfo
}
