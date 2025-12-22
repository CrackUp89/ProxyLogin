package cognito

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools"
	httpTools "proxylogin/internal/manager/tools/http"
	"proxylogin/internal/manager/tools/json"
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

func logTransportError(requestName string, err error) {
	if err != nil {
		getHandlersLogger().Error("transport error", zap.String("requestName", requestName), zap.Error(err))
	}
}

func attachRequestLogger(ctx context.Context, requestName string) (context.Context, *zap.Logger) {
	l := httpTools.GetLoggerWithRequestMetadataFields(getHandlersLogger().With(zap.String("request", requestName)), ctx)
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

func processTaskError(w http.ResponseWriter, result TaskResult, ctx context.Context) bool {
	if result.Err != nil {
		requestLogger := getRequestLogger(ctx)
		var internalError *types.InternalError
		if errors.As(result.Err, &internalError) || errors.Is(result.Err, NoChallengeOrAuthenticationResultError) || errors.Is(result.Err, InconclusiveResponseError) {
			requestLogger.Error("internal error", zap.Error(result.Err), zap.String("privateError", result.Err.PrivateError()))
			logTransportError("task response error handler", httpTools.WriteInternalServiceError(w, result.Err))
			return false
		}

		var badRequestError *types.BadRequestError
		var nextStepError *NextStepError
		if errors.As(result.Err, &badRequestError) || errors.As(result.Err, &nextStepError) {
			requestLogger.Warn("bad request", zap.Error(result.Err), zap.String("privateError", result.Err.PrivateError()))
			logTransportError("task response error handler", httpTools.WriteInternalServiceError(w, result.Err))
			return false
		}

		var authError *types.GenericAuthenticationError
		if errors.As(result.Err, &authError) {
			requestLogger.Warn("authentication error", zap.Error(result.Err), zap.String("privateError", result.Err.PrivateError()))
			logTransportError("task response error handler", httpTools.WriteUnauthorized(w, result.Err))
			return false
		}

		requestLogger.Warn("unknown error", zap.Error(result.Err), zap.String("privateError", result.Err.PrivateError()))
		logTransportError("task response error handler", httpTools.WriteInternalServiceError(w, result.Err))
		return false
	}

	return true
}

func processTaskResponse(w http.ResponseWriter, result TaskResult, ctx context.Context) {
	if !processTaskError(w, result, ctx) {
		return
	}

	logTransportError("task response", httpTools.WriteJSON(w, NextStepResponse{
		NextStep: result.NextStep,
		Session:  result.SessionKey,
		Payload:  result.Payload,
	}))
}

func decodeAndValidate[T WithValidation](w http.ResponseWriter, r *http.Request, componentName string) (T, bool) {
	value, err := json.DecodeJSON[T](r)
	if err != nil {
		logTransportError(componentName, httpTools.WriteBadRequest(w, err))
		return value, false
	}

	if issues := value.Validate(); len(issues) > 0 {
		logTransportError(componentName, httpTools.WriteBadRequest(w, types.NewValidationError(issues)))
		return value, false
	}

	return value, true
}

func attachLoggerContextToRequest(r *http.Request, requestName string) *http.Request {
	ctx, _ := attachRequestLogger(r.Context(), requestName)
	return r.WithContext(ctx)
}

func createLogin() http.Handler {
	requestName := "login"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[loginRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddLoginTask(r.Context(), newSessionKey(), value.User, value.Password)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			if errors.Is(taskResult.Err, types.InvalidUserOrPasswordError) {
				logTransportError(requestName, httpTools.WriteUnauthorized(w, fmt.Errorf("invalid user or password")))
				return
			}

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createMFASetup() http.Handler {
	requestName := "mfa setup"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[mfaSetupRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddMFASetupTask(r.Context(), value.Session, value.User, types.MFAType(value.MFAType))

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createMFASetupVerifySoftwareToken() http.Handler {
	requestName := "mfa setup verify software token"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[mfaSetupVerifySoftwareTokenRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddMFASetupVerifySoftwareTokenTask(r.Context(), value.Session, value.User, value.Code)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			if errors.Is(taskResult.Err, types.InvalidMFASetupSoftwareTokenError) {
				logTransportError(requestName, httpTools.WriteUnauthorized(w, fmt.Errorf("invalid mfa code")))
				return
			}

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createMFAVerify() http.Handler {
	requestName := "mfa verify"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[mfaSoftwareTokenVerifyRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddMFAVerifyTask(r.Context(), value.Session, value.User, value.Code)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			if errors.Is(taskResult.Err, types.InvalidMFACodeError) {
				logTransportError(requestName, httpTools.WriteUnauthorized(w, fmt.Errorf("invalid mfa code")))
				return
			}

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createRefreshToken() http.Handler {
	requestName := "refresh token"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[refreshTokenRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddRefreshTokenTask(r.Context(), "", value.User, value.Token)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createLogOut() http.Handler {
	requestName := "logout"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value, ok := decodeAndValidate[logOutRequest](w, r, requestName)
			if !ok {
				return
			}

			r = attachLoggerContextToRequest(r.WithContext(r.Context()), requestName)

			trc, err := AddLogOutTask(r.Context(), "", value.Token)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createSatisfyPasswordUpdateRequest() http.Handler {
	requestName := "satisfy password update request"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[satisfyPasswordUpdateRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddSatisfyPasswordUpdateRequestTask(r.Context(), value.Session, value.User, value.Password, value.Attributes)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createUpdatePasswordRequest() http.Handler {
	requestName := "update password"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[updatePasswordRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddUpdatePasswordTask(r.Context(), value.AccessToken, value.CurrentPassword, value.NewPassword)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createGetMFAStatus() http.Handler {
	requestName := "get MFA status"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[getMFAStatusRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddGetMFAStatusTask(r.Context(), value.AccessToken)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createUpdateMFA() http.Handler {
	requestName := "update MFA"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[updateMFARequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddUpdateMFATask(r.Context(), newSessionKey(), value.AccessToken, value.MFAType)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createVerifyUpdateMFA() http.Handler {
	requestName := "verify MFA update"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[verifyMFAUpdateRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddVerifyMFAUpdateTask(r.Context(), value.Session, value.AccessToken, value.Code)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createSelectMFA() http.Handler {
	requestName := "select MFA"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[selectMFARequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddSelectMFATask(r.Context(), value.Session, value.User, value.MFAType)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createInitiatePasswordResetRequest() http.Handler {
	requestName := "initiate password reset request"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[initiatePasswordResetRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddInitiatePasswordResetTask(r.Context(), value.Email)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createResetPasswordRequest() http.Handler {
	requestName := "reset password request"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			token := passwordResetToken(r.URL.Query().Get("token"))

			if issues := token.Validate(); len(issues) > 0 {
				logTransportError(requestName, httpTools.WriteBadRequest(w, types.NewValidationError(issues)))
				return
			}

			trc, err := AddResetPasswordTask(r.Context(), string(token))

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
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
	requestName := "initiate password reset request"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			r = attachLoggerContextToRequest(r.WithContext(ctx), requestName)

			value, ok := decodeAndValidate[finalizePasswordResetRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddFinalizePasswordResetTask(r.Context(), value.User, value.Code, value.Password)

			if err != nil {
				logTransportError(requestName, httpTools.WriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func withDefaultRequestSizeLimit(h http.Handler) http.Handler {
	return httpTools.MaxRequestSizeLimiterMiddleware(h, 10*1024)
}

func AddRoutes(mux *http.ServeMux) *http.ServeMux {
	mux.Handle("POST /v1/login", withDefaultRequestSizeLimit(createLogin()))
	mux.Handle("POST /v1/login/password/update", withDefaultRequestSizeLimit(createSatisfyPasswordUpdateRequest()))
	mux.Handle("POST /v1/login/mfa/select", withDefaultRequestSizeLimit(createSelectMFA()))
	mux.Handle("POST /v1/login/mfa/setup", withDefaultRequestSizeLimit(createMFASetup()))
	mux.Handle("POST /v1/login/mfa/setup/verify", withDefaultRequestSizeLimit(createMFASetupVerifySoftwareToken()))
	mux.Handle("POST /v1/login/mfa/verify", withDefaultRequestSizeLimit(createMFAVerify()))
	mux.Handle("POST /v1/refresh", withDefaultRequestSizeLimit(createRefreshToken()))
	mux.Handle("POST /v1/logout", withDefaultRequestSizeLimit(createLogOut()))
	mux.Handle("POST /v1/password/update", withDefaultRequestSizeLimit(createUpdatePasswordRequest()))
	mux.Handle("GET /v1/password/reset", withDefaultRequestSizeLimit(createResetPasswordRequest()))
	mux.Handle("POST /v1/password/reset/request", withDefaultRequestSizeLimit(createInitiatePasswordResetRequest()))
	mux.Handle("POST /v1/password/reset/finalize", withDefaultRequestSizeLimit(createFinalizePasswordResetRequest()))
	mux.Handle("POST /v1/mfa/status", withDefaultRequestSizeLimit(createGetMFAStatus()))
	mux.Handle("POST /v1/mfa/update", withDefaultRequestSizeLimit(createUpdateMFA()))
	mux.Handle("POST /v1/mfa/update/verify", withDefaultRequestSizeLimit(createVerifyUpdateMFA()))
	return mux
}
