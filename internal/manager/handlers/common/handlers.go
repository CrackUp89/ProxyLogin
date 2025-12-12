package common

import (
	"net/http"
	"proxylogin/internal/manager/tools"

	"go.uber.org/zap"
)

var logger = tools.NewLogger("CommonHandlers")

func createHealth() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if err := tools.EncodeJSON(w, http.StatusOK, map[string]string{}); err != nil {
				logger.Error("transport error", zap.String("requestName", "health"), zap.Error(err))
			}
		})
}

func AddRoutes(mux *http.ServeMux) *http.ServeMux {
	mux.Handle("GET /health", tools.MaxRequestSizeLimiterMiddleware(createHealth(), 1024))
	return mux
}
