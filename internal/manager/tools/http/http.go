package http

import (
	"context"
	"errors"
	"net/http"
	"proxylogin/internal/manager/logging"
	"proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

var httpToolsLogger *zap.Logger

func getLogger() *zap.Logger {
	if httpToolsLogger == nil {
		httpToolsLogger = logging.NewLogger("httpTools")
	}
	return httpToolsLogger
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

func NewErrorResponse(code int, message string) ErrorResponse {
	return ErrorResponse{Code: code, Message: message}
}

func WriteTooManyRequests(w http.ResponseWriter) error {
	return json.EncodeJSON(w, http.StatusTooManyRequests, NewErrorResponse(-2, "too many requests"))
}

func WriteBadRequest(w http.ResponseWriter, err error) error {
	var msg string
	code := -1
	if err != nil {
		msg = err.Error()
		var v types.GenericError
		if errors.As(err, &v) {
			code = v.Code()
		}
	} else {
		msg = "Bad Request"
	}

	return json.EncodeJSON(w, http.StatusBadRequest, NewErrorResponse(code, msg))
}

func WriteInternalServiceError(w http.ResponseWriter, err error) error {
	var msg string
	if err != nil {
		msg = err.Error()
	} else {
		msg = "Internal service error"
	}

	return json.EncodeJSON(w, http.StatusInternalServerError, NewErrorResponse(http.StatusInternalServerError, msg))
}

func WriteUnauthorized(w http.ResponseWriter, err error) error {
	var msg string
	if err != nil {
		msg = err.Error()
	} else {
		msg = "Unauthorized"
	}

	return json.EncodeJSON(w, http.StatusUnauthorized, NewErrorResponse(http.StatusUnauthorized, msg))
}

func WriteJSON(w http.ResponseWriter, data interface{}) error {
	if data == nil {
		w.WriteHeader(http.StatusOK)
		return nil
	} else {
		if json.EncodeJSON(w, http.StatusOK, data) != nil {
			return WriteInternalServiceError(w, nil)
		}
	}
	return nil
}

func MaxRequestSizeLimiterMiddleware(next http.Handler, maxContentLength int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > maxContentLength {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		next.ServeHTTP(w, r)
	})
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
	return receiver.RemoteAddr[:strings.LastIndex(receiver.RemoteAddr, ":")]
}

func GetLoggerWithRequestMetadataFields(l *zap.Logger, ctx context.Context) *zap.Logger {
	md, ok := GetRequestMetadataFromContext(ctx)
	if ok {
		l = l.WithLazy(md.GetZapFields()...)
	} else {
		getLogger().Warn("context has no request metadata")
	}
	return l
}

func WithRequestMetadataContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "requestMetadata", RequestMetadata{
			ID:           uuid.NewString(),
			Host:         r.Host,
			RequestURI:   r.RequestURI,
			RemoteAddr:   r.RemoteAddr,
			RealIP:       r.Header.Get("X-Real-IP"),
			ForwardedFor: r.Header.Get("X-Forwarded-For"),
		})

		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

func GetRequestMetadataFromContext(ctx context.Context) (*RequestMetadata, bool) {
	metadata, ok := ctx.Value("requestMetadata").(RequestMetadata)
	return &metadata, ok
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

func ReadFirstNamedCookie(r *http.Request, name string) *http.Cookie {
	cookies := r.CookiesNamed(name)
	if len(cookies) == 0 {
		return nil
	}
	return cookies[0]
}
