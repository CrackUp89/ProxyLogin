package cognito

import (
	"context"
	"net/http"
	"proxylogin/internal/manager/config"
	"proxylogin/internal/manager/login/passwordreset"
	"proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/ratelimiter"
	"proxylogin/internal/manager/tools"
	httpTools "proxylogin/internal/manager/tools/http"
	"proxylogin/internal/manager/tools/json"
	"strings"
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

func getAuthTokenFromContext(ctx context.Context) string {
	auth := ctx.Value(AuthContextVarName)

	if auth == nil {
		return ""
	}

	if t, ok := auth.(TokenAuth); ok {
		return t.Token
	}

	if t, ok := auth.(MasqueradedAuth); ok {
		return t.Token
	}

	panic("unknown auth type")
}

func processError(w http.ResponseWriter, err types.GenericError, ctx context.Context) bool {
	if err != nil {
		requestLogger := getRequestLogger(ctx)

		switch err.Type() {
		case types.AuthErrorType:
			requestLogger.Warn("authentication error", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteUnauthorized(w, err), ctx)
			break
		case types.BadDataErrorType:
			requestLogger.Warn("bad request", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteBadRequest(w, err), ctx)
			break
		case types.OverloadErrorType:
			requestLogger.Error("overloaded", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteTooManyRequests(w), ctx)
			break
		case types.InternalErrorType:
			requestLogger.Error("internal error", zap.Error(err), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteInternalServiceError(w, err), ctx)
			break
		default:
			handlersLogger.Error("unknown error type", zap.Error(err), zap.String("type", string(err.Type())), zap.String("privateError", err.PrivateError()))
			logTransportError(httpTools.WriteInternalServiceError(w, err), ctx)
			break
		}
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

	if result.Flags.Has(AuthInfoTaskResultFlag) {
		processAuthResponse(ctx, w, result)
		return
	}

	if result.Flags.Has(LogoutTaskResultFlag) && config.UseCookies() {
		http.SetCookie(w, dropCookie(config.GetMasqueradedCookieName()))
		http.SetCookie(w, dropCookie(config.GetAccessTokenCookieName()))
		http.SetCookie(w, dropCookie(config.GetRefreshTokenCookieName()))
		http.SetCookie(w, dropCookie(config.GetIDTokenCookieName()))
	}

	logTransportError(httpTools.WriteJSON(w, NextStepResponse{
		NextStep: result.NextStep,
		Session:  result.SessionKey,
		Payload:  result.Payload,
	}), ctx)
}

func decodeAndValidate[T WithValidation](r *http.Request) (T, error) {
	ctx := r.Context()
	requestLogger := getRequestLogger(ctx)

	value, err := json.DecodeJSON[T](r)

	if err != nil {
		requestLogger.Warn("malformed JSON", zap.Error(err))
		return value, err
	}

	if issues := value.Validate(); len(issues) > 0 {
		requestLogger.Warn("invalid request params", zap.Error(err))
		return value, types.NewValidationError(issues)
	}

	return value, nil
}

func decodeAndProcessValidationErrors[T WithValidation](w http.ResponseWriter, r *http.Request) (T, bool) {
	d, err := decodeAndValidate[T](r)
	ctx := r.Context()

	if err != nil {
		logTransportError(httpTools.WriteBadRequest(w, types.NewBadRequestError(err.Error(), err.Error(), err)), ctx)
		return d, false
	}

	return d, true
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

func createCookie(name string, val string, expires time.Time) *http.Cookie {
	result := &http.Cookie{
		Name:     name,
		Value:    val,
		HttpOnly: config.UseHTTPOnlyCookies(),
		Path:     config.GetCookiePath(),
		Secure:   config.GetCookieSecure(),
		SameSite: config.GetCookieSameSite(),
	}

	domain := config.GetCookieDomain()
	if domain != "" {
		result.Domain = domain
	}

	if !expires.IsZero() {
		result.MaxAge = int(expires.Sub(time.Now()) / time.Second)
		result.Expires = expires
	}

	return result
}

func dropCookie(name string) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		HttpOnly: config.UseHTTPOnlyCookies(),
		Path:     config.GetCookiePath(),
		Secure:   config.GetCookieSecure(),
		SameSite: config.GetCookieSameSite(),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
}

func processAuthResponse(ctx context.Context, w http.ResponseWriter, taskResult TaskResult) bool {
	if taskResult.Err == nil && taskResult.Payload != nil {
		remember := taskResult.Flags.Has(RememberTaskResultFlag)
		if p, ok := taskResult.Payload.(*types.MasqueradedToken); ok {
			var expires time.Time
			if remember {
				expires = p.TokenExpires
			} else {
				expires = time.Time{}
			}
			http.SetCookie(w, createCookie(config.GetMasqueradedCookieName(), p.Token, expires))
			logTransportError(httpTools.WriteJSON(w, loginResponse{
				LoginType: MasqueradeLoginResponseLoginType,
			}), ctx)
			return true
		}
		if p, ok := taskResult.Payload.(*types.AuthTokenSet); ok {
			if config.UseCookies() {

				if p.RefreshToken != "" {
					var refreshExpires time.Time
					if remember {
						refreshExpires = p.RefreshTokenExpires
					} else {
						refreshExpires = time.Time{}
					}
					http.SetCookie(w, createCookie(config.GetRefreshTokenCookieName(), p.RefreshToken, refreshExpires))
				}

				var accessExpires time.Time
				var idExpires time.Time
				if remember {
					accessExpires = p.AccessTokenExpires
					idExpires = p.IdTokenExpires
				} else {
					accessExpires = time.Time{}
					idExpires = time.Time{}
				}

				var expires time.Time

				http.SetCookie(w, createCookie(config.GetAccessTokenCookieName(), p.AccessToken, accessExpires))
				http.SetCookie(w, createCookie(config.GetIDTokenCookieName(), p.IdToken, idExpires))

				resp := &loginResponse{
					LoginType: CookiesLoginResponseLoginType,
				}

				if !p.AccessTokenExpires.IsZero() {
					resp.Expires = &p.AccessTokenExpires
				}

				if !p.IdTokenExpires.IsZero() && p.IdTokenExpires.Before(expires) {
					expires = p.IdTokenExpires
				}

				if !expires.IsZero() {
					resp.Expires = &expires
				}

				logTransportError(httpTools.WriteJSON(w, resp), ctx)
			} else {
				logTransportError(httpTools.WriteJSON(w, loginResponse{
					LoginType: TokenSetLoginResponseLoginType,
					LoginData: p,
				}), ctx)
			}
			return true
		}
	}
	return false
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

			value, ok := decodeAndProcessValidationErrors[loginRequest](w, r)
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

			trc, err := createLoginTask(r.Context(), newSessionKey(), value.User, value.Password, value.Remember)

			if !processError(w, err, r.Context()) {
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createMFASetup() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			value, ok := decodeAndProcessValidationErrors[mfaSetupRequest](w, r)
			if !ok {
				return
			}

			trc, err := createMFASetupTask(r.Context(), value.Session, value.User, types.MFAType(value.MFAType))

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

			value, ok := decodeAndProcessValidationErrors[mfaSetupVerifySoftwareTokenRequest](w, r)
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

			trc, err := createMFASetupVerifySoftwareTokenTask(r.Context(), value.Session, value.User, value.Code)

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

			value, ok := decodeAndProcessValidationErrors[mfaSoftwareTokenVerifyRequest](w, r)
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

			trc, err := createMFAVerifyTask(r.Context(), value.Session, value.User, value.Code)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createRefreshToken() http.Handler {
	tokenLimiter := ratelimiter.NewLimiter("createRefreshToken", 5, time.Second)

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			r = attachLoggerContextToRequest(r)

			value, ok := decodeAndProcessValidationErrors[refreshTokenRequest](w, r)
			if !ok {
				return
			}

			if allowed, err := processLimiter(tokenLimiter, value.Token, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := createRefreshTokenTask(r.Context(), value.User, value.Token, value.Remember)

			if !processError(w, err, r.Context()) {
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createLogOut() http.Handler {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {

			var token string

			if r.ContentLength > 0 {
				value, requestErr := decodeAndValidate[logOutRequest](r)
				if requestErr == nil {
					token = value.Token
				}
			}

			trc, err := createLogOutTask(r.Context(), token)

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

			value, ok := decodeAndProcessValidationErrors[satisfyPasswordUpdateRequest](w, r)
			if !ok {
				return
			}

			trc, err := createSatisfyPasswordUpdateRequestTask(r.Context(), value.Session, value.User, value.Password, value.Attributes)

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

			value, ok := decodeAndProcessValidationErrors[updatePasswordRequest](w, r)
			if !ok {
				return
			}
			trc, err := createUpdatePasswordTask(r.Context(), value.CurrentPassword, value.NewPassword)

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

			trc, err := createGetMFAStatusTask(r.Context())

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

			value, ok := decodeAndProcessValidationErrors[updateMFARequest](w, r)
			if !ok {
				return
			}
			trc, err := createUpdateMFASoftwareTokenTask(r.Context(), newSessionKey(), value.MFAType)

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

			value, ok := decodeAndProcessValidationErrors[verifyMFAUpdateRequest](w, r)
			if !ok {
				return
			}
			trc, err := createVerifyMFAUpdateTask(r.Context(), value.Session, value.Code)

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

			value, ok := decodeAndProcessValidationErrors[selectMFARequest](w, r)
			if !ok {
				return
			}
			trc, err := createSelectMFATask(r.Context(), value.Session, value.User, value.MFAType)

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

			value, ok := decodeAndProcessValidationErrors[initiatePasswordResetRequest](w, r)
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

			trc, err := createInitiatePasswordResetTask(r.Context(), value.Email)

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

			trc, err := createResetPasswordTask(r.Context(), string(token))

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

			value, ok := decodeAndProcessValidationErrors[finalizePasswordResetRequest](w, r)
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

			trc, err := createFinalizePasswordResetTask(r.Context(), value.User, value.Code, value.Password)

			if !processError(w, err, r.Context()) {
				return
			}

			taskResult := <-trc

			processTaskResponse(w, taskResult, r.Context())
		})
}

func createUnmaskToken(getParams func(r *http.Request) (string, types.GenericError)) http.Handler {
	tokenLimiter := ratelimiter.NewLimiter("unmaskToken", 100, time.Second)

	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			r = attachLoggerContextToRequest(r)

			token, err := getParams(r)

			if !processError(w, err, r.Context()) {
				return
			}

			if allowed, err := processLimiter(tokenLimiter, token, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := createUnmaskTokenTask(r.Context(), token)

			if !processError(w, err, r.Context()) {
				return
			}

			processTaskResponse(w, <-trc, r.Context())
		})
}

func createUnmaskTokenGet() http.Handler {
	return createUnmaskToken(func(r *http.Request) (string, types.GenericError) {
		c := httpTools.ReadFirstNamedCookie(r, config.GetMasqueradedCookieName())

		if c == nil || c.Value == "" {
			return "", types.UnauthorizedError
		}

		return c.Value, nil
	})
}

func createUnmaskTokenPost() http.Handler {
	return createUnmaskToken(func(r *http.Request) (string, types.GenericError) {
		value, err := decodeAndValidate[unmaskTokenRequest](r)

		if err != nil {
			return "", types.NewBadRequestError(err.Error(), err.Error(), err)
		}

		return value.Token, nil
	})
}

func createGetProfileRequest() http.Handler {
	userLimiter := ratelimiter.NewLimiter("createProfileRequest", 6000, time.Minute)
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			r, cancel := attachDeadline(r)
			defer cancel()

			token := getAuthTokenFromContext(r.Context())

			if token == "" {
				processError(w, types.UnauthorizedError, r.Context())
				return
			}

			if allowed, err := processLimiter(userLimiter, token, w, r.Context()); err != nil {
				if !processError(w, types.NewInternalError("limiter error", err), r.Context()) {
					return
				}
			} else if !allowed {
				return
			}

			trc, err := createGetProfileTask(r.Context())

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

func withAuthAndDefaultMiddleware(next http.Handler) http.Handler {
	return withRequestLogger(withDefaultRequestSizeLimit(withAuthTokenContext(next)))
}

func withAuthTokenContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ctx = r.Context()
		if config.UseCookies() {
			if config.UseMasquerade() {
				c := httpTools.ReadFirstNamedCookie(r, config.GetMasqueradedCookieName())
				if c != nil && c.Value != "" {
					ctx = context.WithValue(ctx, AuthContextVarName, MasqueradedAuth{Token: c.Value})
				}
			} else {
				c := httpTools.ReadFirstNamedCookie(r, config.GetAccessTokenCookieName())
				if c != nil && c.Value != "" {
					ctx = context.WithValue(ctx, AuthContextVarName, TokenAuth{Token: c.Value})
				}
			}
		} else {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				ctx = context.WithValue(ctx, AuthContextVarName, TokenAuth{Token: strings.TrimPrefix(auth, "Bearer ")})
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withIdTokenContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ctx = r.Context()
		if config.UseCookies() {
			if !config.UseMasquerade() {
				c := httpTools.ReadFirstNamedCookie(r, config.GetIDTokenCookieName())
				if c != nil && c.Value != "" {
					ctx = context.WithValue(ctx, IdTokenContextVarName, c.Value)
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withRefreshTokenContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ctx = r.Context()
		if config.UseCookies() {
			if !config.UseMasquerade() {
				c := httpTools.ReadFirstNamedCookie(r, config.GetRefreshTokenCookieName())
				if c != nil && c.Value != "" {
					ctx = context.WithValue(ctx, RefreshTokenContextVarName, c.Value)
				}
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func appendMiddleware(handler http.Handler, middleware ...func(next http.Handler) http.Handler) http.Handler {
	if len(middleware) == 0 {
		return handler
	}

	for i := 0; i < len(middleware); i++ {
		handler = middleware[i](handler)
	}
	return handler
}

func AddRoutes(mux *http.ServeMux) *http.ServeMux {
	mux.Handle("POST /v1/login", withDefaultMiddleware(createLogin()))
	mux.Handle("POST /v1/login/password/update", withDefaultMiddleware(createSatisfyPasswordUpdateRequest()))
	mux.Handle("POST /v1/login/mfa/select", withDefaultMiddleware(createSelectMFA()))
	mux.Handle("POST /v1/login/mfa/setup", withDefaultMiddleware(createMFASetup()))
	mux.Handle("POST /v1/login/mfa/setup/verify", withDefaultMiddleware(createMFASetupVerifySoftwareToken()))
	mux.Handle("POST /v1/login/mfa/verify", withDefaultMiddleware(createMFAVerify()))
	mux.Handle("POST /v1/logout", withAuthAndDefaultMiddleware(withRefreshTokenContext(createLogOut())))
	mux.Handle("POST /v1/password/update", withAuthAndDefaultMiddleware(createUpdatePasswordRequest()))
	mux.Handle("POST /v1/mfa/status", withAuthAndDefaultMiddleware(createGetMFAStatus()))
	mux.Handle("POST /v1/mfa/update", withAuthAndDefaultMiddleware(createUpdateMFA()))
	mux.Handle("POST /v1/mfa/update/verify", withAuthAndDefaultMiddleware(createVerifyUpdateMFA()))

	if passwordreset.GetSettings().Enabled {
		mux.Handle("GET /v1/password/reset", withDefaultMiddleware(createResetPasswordRequest()))
		mux.Handle("POST /v1/password/reset/request", withDefaultMiddleware(createInitiatePasswordResetRequest()))
		mux.Handle("POST /v1/password/reset/finalize", withDefaultMiddleware(createFinalizePasswordResetRequest()))
	}

	if !config.UseMasquerade() {
		mux.Handle("POST /v1/refresh", appendMiddleware(createRefreshToken(), withRefreshTokenContext, withIdTokenContext, withDefaultMiddleware))
	}

	if config.UseCookies() {
		if config.UseMasquerade() {
			mux.Handle("GET /v1/unmask", withAuthAndDefaultMiddleware(createUnmaskTokenGet()))
		}
		mux.Handle("GET /v1/profile", withAuthAndDefaultMiddleware(withIdTokenContext(createGetProfileRequest())))
	} else {
		if config.UseMasquerade() {
			mux.Handle("POST /v1/unmask", withDefaultMiddleware(createUnmaskTokenPost()))
		}
	}

	return mux
}
