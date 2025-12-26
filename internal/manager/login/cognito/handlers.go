package cognito

import (
	"context"
	"errors"
	"net/http"
	"proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
	httpTools "proxylogin/internal/manager/tools/http"
	"proxylogin/internal/manager/tools/json"
	"proxylogin/internal/manager/tools/ratelimiter"
	"time"

	"go.uber.org/zap"
)

var handlersLogger *zap.Logger

func getHandlersLogger() *zap.Logger {
	if handlersLogger == nil {
		handlersLogger = getLogger().Named("handlers")
	}
	return handlersLogger
}

func newSessionKey() string {
	return tools.GenerateRandomString(32)
}

func logTransportError(err error, ctx context.Context) {
	if err != nil {
		logger := getHandlersLogger()
		fields := []zap.Field{
			zap.Error(err),
		}

		md, ok := httpTools.GetRequestMetadataFromContext(ctx)
		if ok {
			fields = append(fields, md.GetZapFields()...)
		} else {
			logger.Error("failed to get request metadata", zap.Stack("stack"))
		}

		logger.Error("transport error", fields...)
	}
}

func attachRequestLogger(ctx context.Context) (context.Context, *zap.Logger) {
	l := httpTools.GetLoggerWithRequestMetadataFields(getHandlersLogger(), ctx)
	return context.WithValue(ctx, "requestLogger", l), l
}

func getRequestLogger(ctx context.Context) *zap.Logger {
	v := ctx.Value("requestLogger")
	l, ok := v.(*zap.Logger)
	if !ok {
		logger := getHandlersLogger()
		logger.Error("context has no logger. using default handler logger")
		return logger
	}
	return l
}

func processError(w http.ResponseWriter, err types.GenericError, ctx context.Context) bool {
	if err != nil {
		requestLogger := getRequestLogger(ctx)

		var authError *types.GenericAuthenticationError
		if errors.As(err, &authError) ||
			errors.Is(err, types.InvalidUserOrPasswordError) ||
			errors.Is(err, types.InvalidMFACodeError) ||
			errors.Is(err, types.InvalidVerificationCodeError) {
			requestLogger.Warn("authentication error", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteUnauthorized(w, err), ctx)
			return false
		}

		var internalError *types.InternalError
		if errors.As(err, &internalError) || errors.Is(err, NoChallengeOrAuthenticationResultError) || errors.Is(err, InconclusiveResponseError) {
			requestLogger.Error("internal error", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteInternalServiceError(w, err), ctx)
			return false
		}

		var badRequestError *types.BadRequestError
		var nextStepError *NextStepError
		if errors.As(err, &badRequestError) || errors.As(err, &nextStepError) {
			requestLogger.Warn("bad request", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteInternalServiceError(w, err), ctx)
			return false
		}

		var tooManyTasks *types.TooManyTasks
		if errors.As(err, &tooManyTasks) {
			requestLogger.Error("too many tasks", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteTooManyRequests(w), ctx)
			return false
		}

		requestLogger.Warn("unknown error", zap.Error(err), zap.String("privateError", err.PrivateError()))
		logTransportError(httpTools.WriteInternalServiceError(w, err), ctx)
		return false
	}

	return true
}

func processTaskError(w http.ResponseWriter, result TaskResult, ctx context.Context) bool {
	return processError(w, result.Err, ctx)
}

func processTaskResponse(w http.ResponseWriter, result TaskResult, ctx context.Context) {
	if !processTaskError(w, result, ctx) {
		return
	}

	logTransportError(httpTools.WriteJSON(w, NextStepResponse{
		NextStep: result.NextStep,
		Session:  result.SessionKey,
		Payload:  result.Payload,
	}), ctx)
}

func decodeAndValidate[T WithValidation](w http.ResponseWriter, r *http.Request) (T, bool) {
	ctx := r.Context()
	requestLogger := getRequestLogger(ctx)

	value, err := json.DecodeJSON[T](r)

	if err != nil {
		requestLogger.Warn("malformed JSON", zap.Error(err))
		logTransportError(httpTools.WriteBadRequest(w, err), ctx)
		return value, false
	}

	if issues := value.Validate(); len(issues) > 0 {
		requestLogger.Warn("invalid request params", zap.Error(err))
		logTransportError(httpTools.WriteBadRequest(w, types.NewValidationError(issues)), r.Context())
		return value, false
	}

	return value, true
}

func attachLoggerContextToRequest(r *http.Request) *http.Request {
	ctx, _ := attachRequestLogger(r.Context())
	return r.WithContext(ctx)
}

func attachDeadline(r *http.Request) (*http.Request, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	return r.WithContext(ctx), cancel
}

func getRequestMetadataFromContextOrPanic(ctx context.Context) *httpTools.RequestMetadata {
	md, ok := httpTools.GetRequestMetadataFromContext(ctx)
	if !ok {
		panic("failed to get request metadata")
	}
	return md
}

func processLimiter(limiter ratelimiter.Limiter, key string, w http.ResponseWriter, ctx context.Context) (bool, error) {
	if allow, err := limiter.Allow(ctx, key); err != nil {
		return allow, err
	} else if !allow {
		requestLogger := getRequestLogger(ctx)
		requestLogger.Warn("rate limit exceeded")
		logTransportError(httpTools.WriteTooManyRequests(w), ctx)
		return false, nil
	}
	return true, nil
}

func createLogin() http.Handler {
	//originLimiter := ratelimiter.NewLimiter(rate.Every(10*time.Millisecond), 100)
	userLimiter := ratelimiter.NewLimiter("createLoginUser", 2, time.Second)

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			//md := getRequestMetadataFromContextOrPanic(r.Context())

			//if !originLimiter.Allow(md.GetClientIP()) {
			//	logTransportError(httpTools.WriteTooManyRequests(w), r.Context())
			//	return
			//}

			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[loginRequest](w, r)
			if !ok {
				return
			}

			if allowed, err := processLimiter(userLimiter, value.User, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := AddLoginTask(r.Context(), newSessionKey(), value.User, value.Password)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createMFASetup() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[mfaSetupRequest](w, r)
			if !ok {
				return
			}

			trc, err := AddMFASetupTask(r.Context(), value.Session, value.User, types.MFAType(value.MFAType))

			if !processError(w, err, r.Context()) {
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createMFASetupVerifySoftwareToken() http.Handler {
	userLimiter := ratelimiter.NewLimiter("createMFASetupVerifySoftwareTokenUser", 5, time.Second)

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[mfaSetupVerifySoftwareTokenRequest](w, r)
			if !ok {
				return
			}

			if allowed, err := processLimiter(userLimiter, value.User, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := AddMFASetupVerifySoftwareTokenTask(r.Context(), value.Session, value.User, value.Code)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createMFAVerify() http.Handler {
	userLimiter := ratelimiter.NewLimiter("createMFAVerifyUser", 5, time.Second)

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[mfaSoftwareTokenVerifyRequest](w, r)
			if !ok {
				return
			}

			if allowed, err := processLimiter(userLimiter, value.User, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := AddMFAVerifyTask(r.Context(), value.Session, value.User, value.Code)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createRefreshToken() http.Handler {
	userLimiter := ratelimiter.NewLimiter("createRefreshTokenUser", 5, time.Second)

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			r = attachLoggerContextToRequest(r)

			value, ok := decodeAndValidate[refreshTokenRequest](w, r)
			if !ok {
				return
			}

			if allowed, err := processLimiter(userLimiter, value.User, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := AddRefreshTokenTask(r.Context(), "", value.User, value.Token)

			if !processError(w, err, r.Context()) {
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createLogOut() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value, ok := decodeAndValidate[logOutRequest](w, r)
			if !ok {
				return
			}

			trc, err := AddLogOutTask(r.Context(), "", value.Token)

			if !processError(w, err, r.Context()) {
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createSatisfyPasswordUpdateRequest() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[satisfyPasswordUpdateRequest](w, r)
			if !ok {
				return
			}

			trc, err := AddSatisfyPasswordUpdateRequestTask(r.Context(), value.Session, value.User, value.Password, value.Attributes)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createUpdatePasswordRequest() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[updatePasswordRequest](w, r)
			if !ok {
				return
			}
			trc, err := AddUpdatePasswordTask(r.Context(), value.AccessToken, value.CurrentPassword, value.NewPassword)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createGetMFAStatus() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[getMFAStatusRequest](w, r)
			if !ok {
				return
			}

			trc, err := AddGetMFAStatusTask(r.Context(), value.AccessToken)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createUpdateMFA() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[updateMFARequest](w, r)
			if !ok {
				return
			}
			trc, err := AddUpdateMFATask(r.Context(), newSessionKey(), value.AccessToken, value.MFAType)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createVerifyUpdateMFA() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[verifyMFAUpdateRequest](w, r)
			if !ok {
				return
			}
			trc, err := AddVerifyMFAUpdateTask(r.Context(), value.Session, value.AccessToken, value.Code)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createSelectMFA() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[selectMFARequest](w, r)
			if !ok {
				return
			}
			trc, err := AddSelectMFATask(r.Context(), value.Session, value.User, value.MFAType)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createInitiatePasswordResetRequest() http.Handler {
	emailLimiter := ratelimiter.NewLimiter("createInitiatePasswordResetRequestEmail", 1, 5*time.Minute)

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[initiatePasswordResetRequest](w, r)
			if !ok {
				return
			}

			if allowed, err := processLimiter(emailLimiter, value.Email, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := AddInitiatePasswordResetTask(r.Context(), value.Email)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createResetPasswordRequest() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			token := passwordResetToken(r.URL.Query().Get("token"))

			if issues := token.Validate(); len(issues) > 0 {
				logTransportError(httpTools.WriteBadRequest(w, types.NewValidationError(issues)), r.Context())
				return
			}

			trc, err := AddResetPasswordTask(r.Context(), string(token))

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc
			if !processTaskError(w, taskResult, r.Context()) {
				return
			}

			w.Header().Add("Location", taskResult.Payload.(string))
			w.WriteHeader(http.StatusFound)
		})
}

func createFinalizePasswordResetRequest() http.Handler {
	userLimiter := ratelimiter.NewLimiter("createFinalizePasswordResetRequestUser", 5, time.Second)
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndValidate[finalizePasswordResetRequest](w, r)
			if !ok {
				return
			}

			if allowed, err := processLimiter(userLimiter, value.User, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := AddFinalizePasswordResetTask(r.Context(), value.User, value.Code, value.Password)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func withRequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = attachLoggerContextToRequest(r)
		next.ServeHTTP(w, r)
	})
}

func withDefaultRequestSizeLimit(next http.Handler) http.Handler {
	return httpTools.MaxRequestSizeLimiterMiddleware(next, 10*1024)
}

func withDefaultMiddleware(next http.Handler) http.Handler {
	return withRequestLogger(withDefaultRequestSizeLimit(next))
}

func AddRoutes(mux *http.ServeMux) *http.ServeMux {
	mux.Handle("POST /v1/login", withDefaultMiddleware(createLogin()))
	mux.Handle("POST /v1/login/password/update", withDefaultMiddleware(createSatisfyPasswordUpdateRequest()))
	mux.Handle("POST /v1/login/mfa/select", withDefaultMiddleware(createSelectMFA()))
	mux.Handle("POST /v1/login/mfa/setup", withDefaultMiddleware(createMFASetup()))
	mux.Handle("POST /v1/login/mfa/setup/verify", withDefaultMiddleware(createMFASetupVerifySoftwareToken()))
	mux.Handle("POST /v1/login/mfa/verify", withDefaultMiddleware(createMFAVerify()))
	mux.Handle("POST /v1/refresh", withDefaultMiddleware(createRefreshToken()))
	mux.Handle("POST /v1/logout", withDefaultMiddleware(createLogOut()))
	mux.Handle("POST /v1/password/update", withDefaultMiddleware(createUpdatePasswordRequest()))
	mux.Handle("GET /v1/password/reset", withDefaultMiddleware(createResetPasswordRequest()))
	mux.Handle("POST /v1/password/reset/request", withDefaultMiddleware(createInitiatePasswordResetRequest()))
	mux.Handle("POST /v1/password/reset/finalize", withDefaultMiddleware(createFinalizePasswordResetRequest()))
	mux.Handle("POST /v1/mfa/status", withDefaultMiddleware(createGetMFAStatus()))
	mux.Handle("POST /v1/mfa/update", withDefaultMiddleware(createUpdateMFA()))
	mux.Handle("POST /v1/mfa/update/verify", withDefaultMiddleware(createVerifyUpdateMFA()))
	return mux
}
