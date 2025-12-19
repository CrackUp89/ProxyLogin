package tools

import (
	"context"
	"errors"
	"net/http"
	"proxylogin/internal/manager/handlers/login/types"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

var logger = NewLogger("HTTPTools")

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

func NewErrorResponse(code int, message string) ErrorResponse {
	return ErrorResponse{Code: code, Message: message}
}

func HTTPWriteBadRequest(w http.ResponseWriter, err error) error {
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

	return EncodeJSON(w, http.StatusBadRequest, NewErrorResponse(code, msg))
}

func HTTPWriteInternalServiceError(w http.ResponseWriter, err error) error {
	var msg string
	if err != nil {
		msg = err.Error()
	} else {
		msg = "Internal service error"
	}

	return EncodeJSON(w, http.StatusInternalServerError, NewErrorResponse(http.StatusInternalServerError, msg))
}

func HTTPWriteUnauthorized(w http.ResponseWriter, err error) error {
	var msg string
	if err != nil {
		msg = err.Error()
	} else {
		msg = "Unauthorized"
	}

	return EncodeJSON(w, http.StatusUnauthorized, NewErrorResponse(http.StatusUnauthorized, msg))
}

func HTTPWriteJSON(w http.ResponseWriter, data interface{}) error {
	if data == nil {
		w.WriteHeader(http.StatusOK)
		return nil
	} else {
		if EncodeJSON(w, http.StatusOK, data) != nil {
			return HTTPWriteInternalServiceError(w, nil)
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
				logger.Error("handler panicked", zap.Any("panic", err), zap.Stack("stack"))
				w.WriteHeader(http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type RequestMetadata struct {
	Host         string `json:"host"`
	RequestURI   string `json:"uri"`
	RemoteAddr   string `json:"remote_addr"`
	RealIP       string `json:"real_ip"`
	ForwardedFor string `json:"forwarded_for"`
}

func (receiver *RequestMetadata) GetZapFields() []zap.Field {
	return []zap.Field{
		zap.String("host", receiver.Host),
		zap.String("uri", receiver.RequestURI),
		zap.String("remote_addr", receiver.RemoteAddr),
		zap.String("real_ip", receiver.RealIP),
		zap.String("forwarded_for", receiver.ForwardedFor),
	}
}

func WithRequestMetadataContextMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), "requestMetadata", RequestMetadata{
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
