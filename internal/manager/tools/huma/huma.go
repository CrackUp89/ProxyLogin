package huma

import (
	"context"
	"net/http"
	"proxylogin/internal/manager/login/types"

	"github.com/danielgtaylor/huma/v2"
)

type humaContextKeyType struct{}

var HumaContextKey = humaContextKeyType{}

// HumaContextMiddleware stores the huma.Context in the request context
// so that handlers can access it for setting headers/cookies.
func HumaContextMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	rCtx = context.WithValue(rCtx, HumaContextKey, ctx)
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

// MapError converts a types.GenericError to a huma.StatusError.
func MapError(err types.GenericError) error {
	if err == nil {
		return nil
	}

	var status int
	switch err.Type() {
	case types.AuthErrorType:
		status = http.StatusUnauthorized
	case types.BadDataErrorType:
		status = http.StatusBadRequest
	case types.TooManyRequestsErrorType:
		status = http.StatusTooManyRequests
	case types.InternalErrorType:
		status = http.StatusInternalServerError
	default:
		status = http.StatusInternalServerError
	}

	return huma.NewError(status, err.Error())
}

// MapTaskError is a convenience wrapper that extracts the error from a TaskResult-like err field.
func MapTaskError(err types.GenericError) error {
	return MapError(err)
}
