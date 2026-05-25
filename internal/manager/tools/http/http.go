package http

import (
	"context"
	"net/http"
	"proxylogin/internal/manager/logging"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var proxySecret string
var proxySecretHeader string
var proxySecretStrict bool
var realIPHeader string
var forwardedForHeader string

func init() {
	viper.SetDefault("http.proxySecret", "")
	viper.SetDefault("http.proxySecretHeader", "X-Proxy-Secret")
	viper.SetDefault("http.proxySecretStrict", false)
	viper.SetDefault("http.realIPHeader", "X-Real-IP")
	viper.SetDefault("http.forwardedForHeader", "X-Forwarded-For")
}

func LoadConfig() {
	proxySecret = viper.GetString("http.proxySecret")
	proxySecretHeader = viper.GetString("http.proxySecretHeader")
	proxySecretStrict = viper.GetBool("http.proxySecretStrict")
	proxySecretCheckDisabled := proxySecret == "" || proxySecretHeader == ""

	logger := getLogger()

	realIPHeader = viper.GetString("http.realIPHeader")
	if realIPHeader != "" && proxySecretCheckDisabled {
		logger.Warn("http.realIPHeader is set, but http.proxySecret or http.proxySecretHeader is not set - this may allow real IP spoofing")
	}

	forwardedForHeader = viper.GetString("http.forwardedForHeader")
	if forwardedForHeader != "" && proxySecretCheckDisabled {
		logger.Warn("http.forwardedForHeader is set, but http.proxySecret or http.proxySecretHeader is not set - this may allow to spoof forwarding info")
	}
}

var httpToolsLogger *zap.Logger

func getLogger() *zap.Logger {
	if httpToolsLogger == nil {
		httpToolsLogger = logging.NewLogger("httpTools")
	}
	return httpToolsLogger
}

func WithAutoRecoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				getLogger().Error("handler panicked", zap.Any("err", err), zap.Stack("stack"))
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

type RequestMetadata struct {
	ID           string `json:"id"`
	Host         string `json:"host"`
	RequestURI   string `json:"uri"`
	RemoteAddr   string `json:"remote_addr"`
	RealIP       string `json:"real_ip"`
	ForwardedFor string `json:"forwarded_for"`
}

func (receiver *RequestMetadata) GetZapFields() []zap.Field {
	return []zap.Field{
		zap.String("request_id", receiver.ID),
		zap.String("host", receiver.Host),
		zap.String("uri", receiver.RequestURI),
		zap.String("remote_addr", receiver.RemoteAddr),
		zap.String("real_ip", receiver.RealIP),
		zap.String("forwarded_for", receiver.ForwardedFor),
	}
}

func (receiver *RequestMetadata) GetClientIP() string {
	if receiver.RealIP != "" {
		return receiver.RealIP
	}
	lastIdx := strings.LastIndex(receiver.RemoteAddr, ":")
	if lastIdx == -1 {
		return receiver.RemoteAddr
	}
	return receiver.RemoteAddr[:lastIdx]
}

func getLoggerWithRequestMetadataFields(l *zap.Logger, md *RequestMetadata) *zap.Logger {
	if md == nil {
		return l
	}
	return l.WithLazy(md.GetZapFields()...)
}

func validateProxySecret(r *http.Request) (string, bool, bool) {
	if proxySecret == "" || proxySecretHeader == "" {
		return "", true, false
	}
	requestProxySecret := r.Header.Get(proxySecretHeader)
	valid := requestProxySecret == proxySecret
	return requestProxySecret, valid, !valid && proxySecretStrict
}

func WithRequestMetadataContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		md := &RequestMetadata{
			ID:         uuid.NewString(),
			Host:       r.Host,
			RequestURI: r.RequestURI,
			RemoteAddr: r.RemoteAddr,
		}

		requestProxySecret, proxySecretValid, abort := validateProxySecret(r)

		if !proxySecretValid {
			getLoggerWithRequestMetadataFields(getLogger(), md).Error("proxy secret is invalid", zap.String("proxySecret", requestProxySecret))
		}

		if abort {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if proxySecretValid && realIPHeader != "" {
			md.RealIP = r.Header.Get(realIPHeader)
		}

		if proxySecretValid && forwardedForHeader != "" {
			md.ForwardedFor = r.Header.Get(forwardedForHeader)
		}

		md.GetClientIP()

		ctx := context.WithValue(r.Context(), "requestMetadata", md)

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func GetRequestMetadataFromContext(ctx context.Context) (*RequestMetadata, bool) {
	metadata, ok := ctx.Value("requestMetadata").(*RequestMetadata)
	return metadata, ok
}

type RequestInfo struct {
	Method    string
	Path      string
	StartTime time.Time
}

type RequestTracker struct {
	requests sync.Map
	counter  int64
}

func (rt *RequestTracker) RequestTrackerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := atomic.AddInt64(&rt.counter, 1)

		info := RequestInfo{
			Method:    r.Method,
			Path:      r.URL.Path,
			StartTime: time.Now(),
		}

		rt.requests.Store(id, info)
		defer rt.requests.Delete(id)

		next.ServeHTTP(w, r)
	})
}

func (rt *RequestTracker) GetActiveRequests() []RequestInfo {
	var active []RequestInfo
	rt.requests.Range(func(key, value interface{}) bool {
		active = append(active, value.(RequestInfo))
		return true
	})
	return active
}

func logTransportError(err error, logger *zap.Logger, md *RequestMetadata) {
	if err != nil {
		fields := []zap.Field{
			zap.Error(err),
		}

		if md != nil {
			fields = append(fields, md.GetZapFields()...)
		}
		logger.Error("transport error", fields...)
	}
}

func LogTransportError(err error, ctx context.Context, logger *zap.Logger) {
	if err != nil {
		md, ok := GetRequestMetadataFromContext(ctx)
		if !ok {
			logger.Error("failed to get request metadata", zap.Stack("stack"))
		}
		logTransportError(err, logger, md)
	}
}

func AttachRequestLogger(ctx context.Context, baseLogger *zap.Logger) (context.Context, *zap.Logger) {
	md, ok := GetRequestMetadataFromContext(ctx)
	if !ok {
		getLogger().Warn("context has no request metadata")
	}

	l := getLoggerWithRequestMetadataFields(baseLogger, md)
	return context.WithValue(ctx, "requestLogger", l), l
}

func GetRequestLogger(ctx context.Context, fallbackLogger *zap.Logger) *zap.Logger {
	v := ctx.Value("requestLogger")
	l, ok := v.(*zap.Logger)
	if !ok {
		logger := fallbackLogger
		logger.Error("context has no logger. using default handler logger", zap.Stack("stack"))
		return logger
	}
	return l
}
