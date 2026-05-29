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

type Config struct {
	ProxySecret        string
	ProxySecretHeader  string
	ProxySecretStrict  bool
	RealIPHeader       string
	ForwardedForHeader string
}

var EnvBinds = map[string]string{
	"http.proxySecret":        "HTTP_PROXY_SECRET",
	"http.proxySecretHeader":  "HTTP_PROXY_SECRET_HEADER",
	"http.proxySecretStrict":  "HTTP_PROXY_SECRET_STRICT",
	"http.realIPHeader":       "HTTP_REAL_IP_HEADER",
	"http.forwardedForHeader": "HTTP_FORWARDED_FOR_HEADER",
}

func SetDefaultConfig(v *viper.Viper) {
	v.SetDefault("http.proxySecret", "")
	v.SetDefault("http.proxySecretHeader", "X-Proxy-Secret")
	v.SetDefault("http.proxySecretStrict", false)
	v.SetDefault("http.realIPHeader", "X-Real-IP")
	v.SetDefault("http.forwardedForHeader", "X-Forwarded-For")
}

func LoadConfig(v *viper.Viper) (Config, error) {
	r := Config{
		ProxySecret:        v.GetString("http.proxySecret"),
		ProxySecretHeader:  v.GetString("http.proxySecretHeader"),
		ProxySecretStrict:  v.GetBool("http.proxySecretStrict"),
		RealIPHeader:       v.GetString("http.realIPHeader"),
		ForwardedForHeader: v.GetString("http.forwardedForHeader"),
	}

	return r, nil
}

func (c Config) proxySecretCheckDisabled() bool {
	return c.ProxySecret == "" || c.ProxySecretHeader == ""
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
	RemotePort   string `json:"remote_port"`
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
	return receiver.RemoteAddr
}

func getLoggerWithRequestMetadataFields(l *zap.Logger, md *RequestMetadata) *zap.Logger {
	if md == nil {
		return l
	}
	return l.WithLazy(md.GetZapFields()...)
}

func validateProxySecret(cfg Config, r *http.Request) (string, bool, bool) {
	if cfg.proxySecretCheckDisabled() {
		return "", true, false
	}
	requestProxySecret := r.Header.Get(cfg.ProxySecretHeader)
	valid := requestProxySecret == cfg.ProxySecret
	return requestProxySecret, valid, !valid && cfg.ProxySecretStrict
}

func warnAboutSpoofableHeaders(cfg Config) {
	if !cfg.proxySecretCheckDisabled() {
		return
	}

	logger := getLogger()

	if cfg.RealIPHeader != "" {
		logger.Warn("http.realIPHeader is set, but http.proxySecret or http.proxySecretHeader is not set - this may allow real IP spoofing")
	}

	if cfg.ForwardedForHeader != "" {
		logger.Warn("http.forwardedForHeader is set, but http.proxySecret or http.proxySecretHeader is not set - this may allow to spoof forwarding info")
	}
}

func WithRequestMetadataContextMiddleware(cfg Config, next http.Handler) http.Handler {
	warnAboutSpoofableHeaders(cfg)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		remote := strings.Split(r.RemoteAddr, ":")
		md := &RequestMetadata{
			ID:         uuid.NewString(),
			Host:       r.Host,
			RequestURI: r.RequestURI,
			RemoteAddr: remote[0],
			RemotePort: remote[1],
		}

		requestProxySecret, proxySecretValid, abort := validateProxySecret(cfg, r)

		if !proxySecretValid {
			getLoggerWithRequestMetadataFields(getLogger(), md).Error("proxy secret is invalid", zap.String("proxySecret", requestProxySecret))
		}

		if abort {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if proxySecretValid && cfg.RealIPHeader != "" {
			md.RealIP = r.Header.Get(cfg.RealIPHeader)
		}

		if proxySecretValid && cfg.ForwardedForHeader != "" {
			md.ForwardedFor = r.Header.Get(cfg.ForwardedForHeader)
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
