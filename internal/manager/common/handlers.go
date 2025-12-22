package common

import (
	"net/http"
	"proxylogin/internal/manager/logging"
	httpTools "proxylogin/internal/manager/tools/http"
	"proxylogin/internal/manager/tools/json"

	"go.uber.org/zap"
)

var commonLogger *zap.Logger

func getLogger() *zap.Logger {
	if commonLogger == nil {
		commonLogger = logging.NewLogger("commonHandlers")
	}
	return commonLogger
}

func createHealth() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if err := json.EncodeJSON(w, http.StatusOK, map[string]string{}); err != nil {
				getLogger().Error("transport error", zap.String("requestName", "health"), zap.Error(err))
			}
		})
}

func AddRoutes(mux *http.ServeMux) *http.ServeMux {
	mux.Handle("GET /v1/health", httpTools.MaxRequestSizeLimiterMiddleware(createHealth(), 1024))
	return mux
}
