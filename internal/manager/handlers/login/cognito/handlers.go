package cognito

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"proxylogin/internal/manager/handlers/login/types"
	"proxylogin/internal/manager/tools"
	"time"

	"go.uber.org/zap"
)

var logger = tools.NewLogger("CognitoHandlers")

func newSessionKey() string {
	return tools.GenerateRandomString(32)
}

func logTransportError(requestName string, err error) {
	if err != nil {
		logger.Error("transport error", zap.String("requestName", requestName), zap.Error(err))
	}
}

func taskResponse(w http.ResponseWriter, result TaskResult) {
	if result.Err != nil {
		logger.Warn(result.Err.PrivateError(), zap.String("error", result.Err.Error()), zap.Int("code", result.Err.Code()))
		logTransportError("task response", tools.HTTPWriteBadRequest(w, result.Err))
		return
	}

	logTransportError("task response", tools.HTTPWriteJSON(w, NextStepResponse{
		NextStep: result.NextStep,
		Session:  result.SessionKey,
		Payload:  result.Payload,
	}))
}

func decodeAndValidate[T WithValidation](w http.ResponseWriter, r *http.Request, componentName string) (T, bool) {
	value, err := tools.DecodeJSON[T](r)
	if err != nil {
		logTransportError(componentName, tools.HTTPWriteBadRequest(w, err))
		return value, false
	}

	if issues := value.Validate(); len(issues) > 0 {
		logTransportError(componentName, tools.HTTPWriteBadRequest(w, types.NewValidationError(issues)))
		return value, false
	}

	return value, true
}

func createLogin() http.Handler {
	requestName := "login"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			value, ok := decodeAndValidate[loginRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddLoginTask(ctx, newSessionKey(), value.User, value.Password)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			if errors.Is(taskResult.Err, types.InvalidUserOrPasswordError) {
				logTransportError(requestName, tools.HTTPWriteUnauthorized(w, fmt.Errorf("invalid user or password")))
				return
			}

			taskResponse(w, taskResult)
		})
}

func createMFASetup() http.Handler {
	requestName := "mfa setup"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			value, ok := decodeAndValidate[mfaSetupRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddMFASetupTask(ctx, value.Session, value.User, types.MFASetupType(value.MFAType))

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResponse(w, <-trc)
		})
}

func createMFASetupVerifySoftwareToken() http.Handler {
	requestName := "mfa setup verify software token"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			value, ok := decodeAndValidate[mfaSetupVerifySoftwareTokenRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddMFASetupVerifySoftwareTokenTask(ctx, value.Session, value.User, value.Code)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			if errors.Is(taskResult.Err, types.InvalidMFASetupSoftwareTokenError) {
				logTransportError(requestName, tools.HTTPWriteUnauthorized(w, fmt.Errorf("invalid mfa code")))
				return
			}

			taskResponse(w, taskResult)
		})
}

func createMFASoftwareTokenVerify() http.Handler {
	requestName := "mfa verify software token"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			value, ok := decodeAndValidate[mfaSoftwareTokenVerifyRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddMFASoftwareTokenVerifyTask(ctx, value.Session, value.User, value.Code)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			if errors.Is(taskResult.Err, types.InvalidMFASoftwareTokenError) {
				logTransportError(requestName, tools.HTTPWriteUnauthorized(w, fmt.Errorf("invalid mfa code")))
				return
			}

			taskResponse(w, taskResult)
		})
}

func createRefreshToken() http.Handler {
	requestName := "refresh token"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
			defer cancel()

			value, ok := decodeAndValidate[refreshTokenRequest](w, r, requestName)
			if !ok {
				return
			}

			trc, err := AddRefreshTokenTask(ctx, "", value.User, value.Token)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResponse(w, <-trc)
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

			trc, err := AddLogOutTask(r.Context(), "", value.Token)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResponse(w, <-trc)
		})
}

func createSatisfyPasswordUpdateRequest() http.Handler {
	requestName := "satisfy password update request"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value, ok := decodeAndValidate[satisfyPasswordUpdateRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddSatisfyPasswordUpdateRequestTask(r.Context(), value.Session, value.User, value.Password, value.Attributes)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			taskResponse(w, taskResult)
		})
}

func createUpdatePasswordRequest() http.Handler {
	requestName := "update password"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value, ok := decodeAndValidate[updatePasswordRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddUpdatePasswordTask(r.Context(), value.AccessToken, value.CurrentPassword, value.NewPassword)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			taskResponse(w, taskResult)
		})
}

func createGetMFAStatus() http.Handler {
	requestName := "get MFA status"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value, ok := decodeAndValidate[getMFAStatusRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddGetMFAStatusTask(r.Context(), value.AccessToken)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			taskResponse(w, taskResult)
		})
}

func createUpdateMFA() http.Handler {
	requestName := "update MFA"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value, ok := decodeAndValidate[updateMFARequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddUpdateMFATask(r.Context(), newSessionKey(), value.AccessToken, value.MFAType)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			taskResponse(w, taskResult)
		})
}

func createVerifyUpdateMFA() http.Handler {
	requestName := "verify MFA update"
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			value, ok := decodeAndValidate[verifyMFAUpdateRequest](w, r, requestName)
			if !ok {
				return
			}
			trc, err := AddVerifyMFAUpdateTask(r.Context(), value.Session, value.AccessToken, value.Code)

			if err != nil {
				logTransportError(requestName, tools.HTTPWriteBadRequest(w, err))
				return
			}

			taskResult := <-trc

			taskResponse(w, taskResult)
		})
}

func defaultRequestSizeLimit(h http.Handler) http.Handler {
	return tools.MaxRequestSizeLimiterMiddleware(h, 10*1024)
}

func AddRoutes(mux *http.ServeMux) *http.ServeMux {
	mux.Handle("POST /v1/login", defaultRequestSizeLimit(createLogin()))
	mux.Handle("POST /v1/login/password/update", defaultRequestSizeLimit(createSatisfyPasswordUpdateRequest()))
	mux.Handle("POST /v1/login/mfa/setup", defaultRequestSizeLimit(createMFASetup()))
	mux.Handle("POST /v1/login/mfa/setup/verify", defaultRequestSizeLimit(createMFASetupVerifySoftwareToken()))
	mux.Handle("POST /v1/login/mfa/verify", defaultRequestSizeLimit(createMFASoftwareTokenVerify()))
	mux.Handle("POST /v1/refresh", defaultRequestSizeLimit(createRefreshToken()))
	mux.Handle("POST /v1/logout", defaultRequestSizeLimit(createLogOut()))
	mux.Handle("POST /v1/password/update", defaultRequestSizeLimit(createUpdatePasswordRequest()))
	mux.Handle("POST /v1/mfa/status", defaultRequestSizeLimit(createGetMFAStatus()))
	mux.Handle("POST /v1/mfa/update", defaultRequestSizeLimit(createUpdateMFA()))
	mux.Handle("POST /v1/mfa/update/verify", defaultRequestSizeLimit(createVerifyUpdateMFA()))
	return mux
}
