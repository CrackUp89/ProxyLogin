package tools

import "net/http"

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
}

func NewErrorResponse(code int, message string) ErrorResponse {
	return ErrorResponse{Code: code, Message: message}
}

func HTTPWriteBadRequest(w http.ResponseWriter, err error) error {
	var msg string
	if err != nil {
		msg = err.Error()
	} else {
		msg = "Bad Request"
	}

	return EncodeJSON(w, http.StatusBadRequest, NewErrorResponse(http.StatusBadRequest, msg))
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
