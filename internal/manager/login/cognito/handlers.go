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
	humaTools "proxylogin/internal/manager/tools/huma"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
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

func attachRequestLogger(ctx context.Context) (context.Context, *zap.Logger) {
	return httpTools.AttachRequestLogger(ctx, getHandlersLogger())
}

func getRequestLogger(ctx context.Context) *zap.Logger {
	return httpTools.GetRequestLogger(ctx, getHandlersLogger())
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

// ---------------------------------------------------------------------------
// Rate limiter helpers
// ---------------------------------------------------------------------------

func checkLimiter(limiter ratelimiter.Limiter, key string, ctx context.Context) error {
	requestLogger := getRequestLogger(ctx)
	if allow, err := limiter.Allow(ctx, key); err != nil {
		requestLogger.Error("limiter error", zap.Error(err))
		return humaTools.MapError(types.NewInternalError("limiter error", err))
	} else if !allow {
		requestLogger.Warn("too many requests")
		return humaTools.MapError(types.TooManyRequests)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Cookie helpers
// ---------------------------------------------------------------------------

func createCookie(name string, val string, expires time.Time) http.Cookie {
	result := http.Cookie{
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

func dropCookie(name string) http.Cookie {
	return http.Cookie{
		Name:     name,
		HttpOnly: config.UseHTTPOnlyCookies(),
		Path:     config.GetCookiePath(),
		Secure:   config.GetCookieSecure(),
		SameSite: config.GetCookieSameSite(),
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	}
}

// ---------------------------------------------------------------------------
// Auth context middleware (huma-level)
// ---------------------------------------------------------------------------

func withAuthTokenContextMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	if config.UseCookies() {
		if config.UseMasquerade() {
			val := readCookieFromHumaContext(ctx, config.GetMasqueradedCookieName())
			if val != "" {
				rCtx = context.WithValue(rCtx, AuthContextVarName, MasqueradedAuth{Token: val})
			}
		} else {
			val := readCookieFromHumaContext(ctx, config.GetAccessTokenCookieName())
			if val != "" {
				rCtx = context.WithValue(rCtx, AuthContextVarName, TokenAuth{Token: val})
			}
		}
	} else {
		auth := ctx.Header("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			rCtx = context.WithValue(rCtx, AuthContextVarName, TokenAuth{Token: strings.TrimPrefix(auth, "Bearer ")})
		}
	}
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

func withIdTokenContextMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	if config.UseCookies() && !config.UseMasquerade() {
		val := readCookieFromHumaContext(ctx, config.GetIDTokenCookieName())
		if val != "" {
			rCtx = context.WithValue(rCtx, IdTokenContextVarName, val)
		}
	}
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

func withRefreshTokenContextMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	if config.UseCookies() && !config.UseMasquerade() {
		val := readCookieFromHumaContext(ctx, config.GetRefreshTokenCookieName())
		if val != "" {
			rCtx = context.WithValue(rCtx, RefreshTokenContextVarName, val)
		}
	}
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

func withRequestLoggerMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	rCtx, _ = attachRequestLogger(rCtx)
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

func readCookieFromHumaContext(ctx huma.Context, name string) string {
	cookieHeader := ctx.Header("Cookie")
	if cookieHeader == "" {
		return ""
	}
	header := http.Header{}
	header.Set("Cookie", cookieHeader)
	request := http.Request{Header: header}
	c, err := request.Cookie(name)
	if err != nil || c.Value == "" {
		return ""
	}
	return c.Value
}

// ---------------------------------------------------------------------------
// Task response helpers (return values instead of writing to ResponseWriter)
// ---------------------------------------------------------------------------

func logError(err types.GenericError, ctx context.Context) {
	if err == nil {
		return
	}
	requestLogger := getRequestLogger(ctx)
	switch err.Type() {
	case types.AuthErrorType:
		requestLogger.Warn("authentication error", zap.Error(err), zap.String("privateError", err.PrivateError()))
	case types.BadDataErrorType:
		requestLogger.Warn("bad request", zap.Error(err), zap.String("privateError", err.PrivateError()))
	case types.TooManyRequestsErrorType:
		requestLogger.Warn("too many requests", zap.Error(err), zap.String("privateError", err.PrivateError()))
	case types.InternalErrorType:
		requestLogger.Error("internal error", zap.Error(err), zap.String("privateError", err.PrivateError()), zap.Stack("stack"))
	default:
		handlersLogger.Error("unknown error type", zap.Error(err), zap.String("type", string(err.Type())), zap.String("privateError", err.PrivateError()), zap.Stack("stack"))
	}
}

func buildAuthResponse(_ context.Context, taskResult interface {
	WithGenericError
	WithAuthResults
}) *TaskResponseOutput[*AuthTaskResponse] {
	if taskResult.GetError() != nil {
		return nil
	}

	taskAuthResults := taskResult.GetAuthResults()
	if taskAuthResults == nil {
		return nil
	}

	taskAuthResultsData := taskResult.GetAuthResults().GetAuthResultsData()
	if taskAuthResultsData == nil {
		return nil
	}

	remember := taskAuthResults.GetRemember()
	if p, ok := taskAuthResultsData.(*types.MasqueradedToken); ok {
		var expires time.Time
		if remember {
			expires = p.TokenExpires
		} else {
			expires = time.Time{}
		}

		if config.UseCookies() {
			return &TaskResponseOutput[*AuthTaskResponse]{
				Body: &AuthTaskResponse{
					AuthResult: newLoginResponseMasquerade(nil),
				},
				SetCookie: []http.Cookie{
					createCookie(config.GetMasqueradedCookieName(), p.Token, expires),
				},
			}
		}

		return &TaskResponseOutput[*AuthTaskResponse]{
			Body: &AuthTaskResponse{
				AuthResult: newLoginResponseMasquerade(p),
			},
		}
	}

	if p, ok := taskAuthResultsData.(*types.AuthTokenSet); ok {
		if config.UseCookies() {
			responseCookies := make([]http.Cookie, 0, 3)

			if p.RefreshToken != "" {
				var refreshExpires time.Time
				if remember {
					refreshExpires = p.RefreshTokenExpires
				} else {
					refreshExpires = time.Time{}
				}
				responseCookies = append(responseCookies, createCookie(config.GetRefreshTokenCookieName(), p.RefreshToken, refreshExpires))
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

			responseCookies = append(responseCookies,
				createCookie(config.GetAccessTokenCookieName(), p.AccessToken, accessExpires),
				createCookie(config.GetIDTokenCookieName(), p.IdToken, idExpires))

			return &TaskResponseOutput[*AuthTaskResponse]{
				Body: &AuthTaskResponse{
					AuthResult: newLoginResponseTokenSet(nil),
				},
				SetCookie: responseCookies,
			}
		}

		return &TaskResponseOutput[*AuthTaskResponse]{Body: &AuthTaskResponse{
			AuthResult: newLoginResponseTokenSet(p),
		}}
	}
	getHandlersLogger().Error("unknown auth payload type", zap.String("dataType", reflect.TypeOf(taskAuthResultsData).Name()))
	return nil
}

func getLogOutCookies() []http.Cookie {
	return []http.Cookie{
		dropCookie(config.GetMasqueradedCookieName()),
		dropCookie(config.GetAccessTokenCookieName()),
		dropCookie(config.GetRefreshTokenCookieName()),
		dropCookie(config.GetIDTokenCookieName()),
	}
}

func processSideEffects[T any](sideEffects []SideEffect, response *TaskResponseOutput[T]) *TaskResponseOutput[T] {
	for _, sideEffect := range sideEffects {
		switch sideEffect.GetType() {
		case LogOutSideEffect:
			response.SetSetCookie(append(response.GetSetCookie(), getLogOutCookies()...))
			break
		}
	}
	return response
}

func buildTaskResponse(ctx context.Context, result TaskResult) (*GenericTaskResponseOutput, error) {
	taskError := result.GetError()
	if taskError != nil {
		logError(taskError, ctx)
		return nil, humaTools.MapError(taskError)
	}

	return processSideEffects(result.GetSideEffects(), &GenericTaskResponseOutput{
		Body: result.GetPayload(),
	}), nil
}

func buildLoginTaskResponse(ctx context.Context, result LoginStepResult) (*TaskResponseOutput[*AuthTaskResponse], error) {
	taskError := result.GetError()
	if taskError != nil {
		logError(taskError, ctx)
		return nil, humaTools.MapError(taskError)
	}

	if result.GetAuthResults() != nil {
		return processSideEffects(result.GetSideEffects(), buildAuthResponse(ctx, result)), nil
	}

	return processSideEffects(result.GetSideEffects(), &TaskResponseOutput[*AuthTaskResponse]{
		Body: &AuthTaskResponse{
			NextStep: result.GetNextLoginStep(),
		},
	}), nil
}

func buildLoginFinalTaskResponse(ctx context.Context, result LoginFinalStepResult) (*TaskResponseOutput[*AuthTaskResponse], error) {
	taskError := result.GetError()
	if taskError != nil {
		logError(taskError, ctx)
		return nil, humaTools.MapError(taskError)
	}

	if result.GetAuthResults() != nil {
		return processSideEffects(result.GetSideEffects(), buildAuthResponse(ctx, result)), nil
	}

	err := types.NewInternalError("task result is empty", nil)

	logError(err, ctx)
	return nil, humaTools.MapError(err)
}

// ---------------------------------------------------------------------------
// MFA verify total limiter
// ---------------------------------------------------------------------------

var verifyUserMFATokenOnLoginLimiter ratelimiter.TotalLimiter
var verifyUserMFATokenOnLoginLimiterOnce sync.Once

func getVerifyUserMFATokenOnLoginLimiter() ratelimiter.TotalLimiter {
	verifyUserMFATokenOnLoginLimiterOnce.Do(func() {
		verifyUserMFATokenOnLoginLimiter = ratelimiter.NewTotalLimiter("verifyUserMFATokenOnLogin", 3)
	})
	return verifyUserMFATokenOnLoginLimiter
}

func dropUserMFATokenOnLoginLimiter(ctx context.Context, key string) {
	if err := getVerifyUserMFATokenOnLoginLimiter().Drop(context.Background(), key); err != nil {
		getRequestLogger(ctx).Warn("unable to drop limiter", zap.Error(err))
	}
}

// ---------------------------------------------------------------------------
// Huma handler registrations
// ---------------------------------------------------------------------------

func registerLogin(api huma.API) {
	userLimiter := ratelimiter.NewLimiter("createLoginUser", 2, time.Second)

	huma.Register(api, huma.Operation{
		OperationID:  "login",
		Method:       http.MethodPost,
		Path:         "/v1/login",
		Summary:      "Authenticate user",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *LoginInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := checkLimiter(userLimiter, input.Body.User, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createLoginTask(ctx, newSessionKey(), input.Body.User, input.Body.Password, input.Body.Remember)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		dropUserMFATokenOnLoginLimiter(ctx, input.Body.User)

		return buildLoginTaskResponse(ctx, <-trc)
	})
}

func registerValidate(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "validate",
		Method:      http.MethodPost,
		Path:        "/v1/validate",
		Summary:     "Validate tokens",
		Description: "Validates one or more JWT tokens and returns per-token validity.\n\n" +
			"**Token sources** (mutually exclusive):\n" +
			"- **Cookie mode** — tokens are read automatically from the configured cookies " +
			"(`token.cookies.accessCookieName`, `token.cookies.idCookieName`).\n" +
			"- **Explicit map** — supply a `tokens` object whose keys are arbitrary names and values are raw JWT strings. " +
			"When `tokens` is present, cookies are ignored.\n\n" +
			"**Response status**:\n" +
			"- `return_unauthorized: no` — always returns `200`.\n" +
			"- `return_unauthorized: any` *(default)* — returns `401` if at least one token is invalid.\n" +
			"- `return_unauthorized: all` — returns `401` only if every token is invalid.\n\n" +
			"The response body shape is the same for both `200` and `401`: " +
			"`tokens` maps each name to a boolean, and `validation_errors` (present when `return_errors: true`) " +
			"maps each failed name to a human-readable error string.",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
		Responses: map[string]*huma.Response{
			"401": {
				Content: map[string]*huma.MediaType{
					"application/json": {
						Schema: api.OpenAPI().Components.Schemas.Schema(reflect.TypeOf(TokenValidationTaskResponse{}), true, ""),
					},
				},
				Description: "Returned if any / all tokens are invalid when `return_unauthorized` is set to `any` / `all`",
			},
			"default": {
				Content: map[string]*huma.MediaType{
					"application/json": {
						Schema: defaultErrorResponseSchema,
					},
				},
			},
		},
	}, func(ctx context.Context, input *TokenValidationInput) (*TokenValidationTaskOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		tokens := input.Body.Tokens

		if tokens == nil {
			hc, ok := ctx.Value(humaTools.HumaContextKey).(huma.Context)
			if !ok {
				return nil, humaTools.MapError(types.NewInternalError("huma context not found", nil))
			}

			tokens = map[string]string{}

			addToken := func(tokenName string) {
				if tokenName != "" {
					if token := readCookieFromHumaContext(hc, tokenName); token != "" {
						tokens[tokenName] = token
					}
				}
			}

			addToken(config.GetAccessTokenCookieName())
			addToken(config.GetIDTokenCookieName())
		}

		if len(tokens) == 0 {
			return nil, humaTools.MapError(types.NewBadRequestError("no tokens provided", "no tokens provided", nil))
		}

		trc, taskErr := createTokenValidationTask(ctx, tokens)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		tr := <-trc

		taskError := tr.GetError()
		if taskError != nil {
			logError(taskError, ctx)
			return nil, humaTools.MapError(taskError)
		}

		result := &TokenValidationTaskResponse{
			Tokens: tr.Validity,
		}

		if input.Body.ReturnErrors {
			result.ValidationError = tr.ValidationErrors
		}

		status := http.StatusOK
		switch input.Body.ReturnUnauthorized {
		case ReturnUnauthorizedAny:
			for _, valid := range tr.Validity {
				if !valid {
					status = http.StatusUnauthorized
					break
				}
			}
		case ReturnUnauthorizedAll:
			status = http.StatusUnauthorized
			for _, valid := range tr.Validity {
				if valid {
					status = http.StatusOK
					break
				}
			}
		}

		return &TokenValidationTaskOutput{
			Status: status,
			Body:   result,
		}, nil
	})
}

func registerMFASetup(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-setup",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/setup",
		Summary:      "Initiate MFA setup",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *MFASetupInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createMFASetupTask(ctx, input.Body.Session, input.Body.User, types.MFAType(input.Body.MFAType))
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildLoginTaskResponse(ctx, <-trc)
	})
}

func registerMFASetupVerifySoftwareToken(api huma.API) {
	userLimiter := ratelimiter.NewLimiter("createMFASetupVerifySoftwareTokenUser", 5, time.Second)

	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-setup-verify",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/setup/verify",
		Summary:      "Verify MFA setup with TOTP code",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *MFASetupVerifySoftwareTokenInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := checkLimiter(userLimiter, input.Body.User, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createMFASetupVerifySoftwareTokenTask(ctx, input.Body.Session, input.Body.User, input.Body.Code)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildLoginTaskResponse(ctx, <-trc)
	})
}

func registerMFAVerify(api huma.API) {
	userLimiter := ratelimiter.NewLimiter("createMFAVerifyUser", 5, time.Second)

	dropUserLoginSession := func(ctx context.Context, loginSessionKey string) {
		if err := dropLoginSession(context.Background(), loginSessionKey); err != nil {
			getRequestLogger(ctx).Warn("unable to drop limiter", zap.Error(err))
		}
	}

	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-verify",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/verify",
		Summary:      "Verify MFA code during login",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *MFASoftwareTokenVerifyInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := checkLimiter(userLimiter, input.Body.User, ctx); err != nil {
			return nil, err
		}

		if allowed, err := getVerifyUserMFATokenOnLoginLimiter().Allow(ctx, input.Body.User); err != nil {
			logError(types.NewInternalError("limiter error", err), ctx)
			return nil, humaTools.MapError(types.NewInternalError("limiter error", err))
		} else if !allowed {
			dropUserMFATokenOnLoginLimiter(ctx, input.Body.User)
			dropUserLoginSession(ctx, input.Body.Session)
			logError(types.UnauthorizedError, ctx)
			return nil, humaTools.MapError(types.UnauthorizedError)
		}

		trc, taskErr := createMFAVerifyTask(ctx, input.Body.Session, input.Body.User, input.Body.Code)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		taskResult := <-trc

		resp, err := buildLoginTaskResponse(ctx, taskResult)
		if err == nil {
			dropUserMFATokenOnLoginLimiter(ctx, input.Body.User)
		}

		return resp, err
	})
}

func registerSelectMFA(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-select",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/select",
		Summary:      "Select MFA method during login",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *SelectMFAInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createSelectMFATask(ctx, input.Body.Session, input.Body.User, input.Body.MFAType)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildLoginTaskResponse(ctx, <-trc)
	})
}

func registerSatisfyPasswordUpdate(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "login-password-update",
		Method:       http.MethodPost,
		Path:         "/v1/login/password/update",
		Summary:      "Satisfy password update challenge during login",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *SatisfyPasswordUpdateInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createSatisfyPasswordUpdateRequestTask(ctx, input.Body.Session, input.Body.User, input.Body.Password, input.Body.Attributes)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildLoginTaskResponse(ctx, <-trc)
	})
}

func registerLogout(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "logout",
		Method:       http.MethodPost,
		Path:         "/v1/logout",
		Summary:      "Log out user",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withAuthTokenContextMiddleware, withRefreshTokenContextMiddleware},
	}, func(ctx context.Context, input *struct {
		Body *logOutRequest `required:"false"`
	}) (*GenericTaskResponseOutput, error) {
		var token string
		if input.Body != nil {
			token = input.Body.Token
		}

		trc, taskErr := createLogOutTask(ctx, token)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildTaskResponse(ctx, <-trc)
	})
}

func registerRefreshToken(api huma.API) {
	tokenLimiter := ratelimiter.NewLimiter("createRefreshToken", 5, time.Second)
	userLimiter := ratelimiter.NewLimiter("createRefreshTokenUser", 5, time.Second)

	huma.Register(api, huma.Operation{
		OperationID:  "refresh",
		Method:       http.MethodPost,
		Path:         "/v1/refresh",
		Summary:      "Refresh authentication tokens",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withRefreshTokenContextMiddleware, withIdTokenContextMiddleware},
	}, func(ctx context.Context, input *RefreshTokenInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := checkLimiter(tokenLimiter, input.Body.Token, ctx); err != nil {
			return nil, err
		}
		if err := checkLimiter(userLimiter, input.Body.Token, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createRefreshTokenTask(ctx, input.Body.User, input.Body.Token, input.Body.Remember)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildLoginFinalTaskResponse(ctx, <-trc)
	})
}

func registerUpdatePassword(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "password-update",
		Method:       http.MethodPost,
		Path:         "/v1/password/update",
		Summary:      "Update user password",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *UpdatePasswordInput) (*GenericTaskResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createUpdatePasswordTask(ctx, input.Body.CurrentPassword, input.Body.NewPassword)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildTaskResponse(ctx, <-trc)
	})
}

func registerGetMFAStatus(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "mfa-status",
		Method:       http.MethodGet,
		Path:         "/v1/mfa/status",
		Summary:      "Get MFA configuration status",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *struct{}) (*TaskResponseOutput[*types.MFAStatus], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createGetMFAStatusTask(ctx)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		result := <-trc

		taskError := result.GetError()
		if taskError != nil {
			logError(taskError, ctx)
			return nil, humaTools.MapError(taskError)
		}

		return processSideEffects(result.GetSideEffects(), &TaskResponseOutput[*types.MFAStatus]{
			Body: result.status,
		}), nil
	})
}

func registerUpdateMFA(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "mfa-update",
		Method:       http.MethodPost,
		Path:         "/v1/mfa/update",
		Summary:      "Initiate MFA type update",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *UpdateMFAInput) (*TaskResponseOutput[*updateMFASoftwareTokenTaskResultPayload], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createUpdateMFASoftwareTokenTask(ctx, input.Body.MFAType)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		result := <-trc

		taskError := result.GetError()
		if taskError != nil {
			logError(taskError, ctx)
			return nil, humaTools.MapError(taskError)
		}

		return processSideEffects(result.GetSideEffects(), &TaskResponseOutput[*updateMFASoftwareTokenTaskResultPayload]{
			Body: result.payload,
		}), nil
	})
}

func registerVerifyUpdateMFA(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "mfa-update-verify",
		Method:       http.MethodPost,
		Path:         "/v1/mfa/update/verify",
		Summary:      "Verify TOTP code for MFA update",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *VerifyMFAUpdateInput) (*GenericTaskResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createVerifyMFAUpdateTask(ctx, input.Body.Code)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildTaskResponse(ctx, <-trc)
	})
}

func registerInitiatePasswordReset(api huma.API) {
	emailLimiter := ratelimiter.NewLimiter("createInitiatePasswordResetRequestEmail", 1, 5*time.Minute)

	huma.Register(api, huma.Operation{
		OperationID:  "password-reset-request",
		Method:       http.MethodPost,
		Path:         "/v1/password/reset/request",
		Summary:      "Initiate password reset",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *InitiatePasswordResetInput) (*GenericTaskResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := checkLimiter(emailLimiter, input.Body.Email, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createInitiatePasswordResetTask(ctx, input.Body.Email)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildTaskResponse(ctx, <-trc)
	})
}

func registerResetPassword(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID:  "password-reset",
		Method:       http.MethodGet,
		Path:         "/v1/password/reset",
		Summary:      "Validate password reset token and redirect",
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *PasswordResetInput) (*struct{}, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		trc, taskErr := createResetPasswordTask(ctx, input.Token)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		taskResult := <-trc
		if taskResult.Err != nil {
			logError(taskResult.Err, ctx)
			return nil, humaTools.MapError(taskResult.Err)
		}

		hc, ok := ctx.Value(humaTools.HumaContextKey).(huma.Context)
		if ok {
			hc.SetHeader("Location", taskResult.redirectTo)
			hc.SetStatus(http.StatusFound)
		}

		return nil, nil
	})
}

func registerFinalizePasswordReset(api huma.API) {
	userLimiter := ratelimiter.NewLimiter("createFinalizePasswordResetRequestUser", 5, time.Second)

	huma.Register(api, huma.Operation{
		OperationID:  "password-reset-finalize",
		Method:       http.MethodPost,
		Path:         "/v1/password/reset/finalize",
		Summary:      "Finalize password reset",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *FinalizePasswordResetInput) (*GenericTaskResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := checkLimiter(userLimiter, input.Body.Token, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createFinalizePasswordResetTask(ctx, input.Body.Token, input.Body.Code, input.Body.Password)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildTaskResponse(ctx, <-trc)
	})
}

func registerUnmaskTokenGet(api huma.API) {
	tokenLimiter := ratelimiter.NewLimiter("unmaskToken", 100, time.Second)

	huma.Register(api, huma.Operation{
		OperationID:  "unmask-get",
		Method:       http.MethodGet,
		Path:         "/v1/unmask",
		Summary:      "Unmask token from cookie",
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *struct{}) (*GenericTaskResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		hc, ok := ctx.Value(humaTools.HumaContextKey).(huma.Context)
		if !ok {
			return nil, humaTools.MapError(types.NewInternalError("huma context not found", nil))
		}

		token := readCookieFromHumaContext(hc, config.GetMasqueradedCookieName())
		if token == "" {
			logError(types.UnauthorizedError, ctx)
			return nil, humaTools.MapError(types.UnauthorizedError)
		}

		if err := checkLimiter(tokenLimiter, token, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createUnmaskTokenTask(ctx, token)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildTaskResponse(ctx, <-trc)
	})
}

func registerUnmaskTokenPost(api huma.API) {
	tokenLimiter := ratelimiter.NewLimiter("unmaskTokenPost", 100, time.Second)

	huma.Register(api, huma.Operation{
		OperationID:  "unmask-post",
		Method:       http.MethodPost,
		Path:         "/v1/unmask",
		Summary:      "Unmask token from request body",
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *UnmaskTokenInput) (*GenericTaskResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		if err := checkLimiter(tokenLimiter, input.Body.Token, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createUnmaskTokenTask(ctx, input.Body.Token)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return buildTaskResponse(ctx, <-trc)
	})
}

func registerGetProfile(api huma.API) {
	tokenLimiter := ratelimiter.NewLimiter("createProfileRequest", 6000, time.Minute)

	huma.Register(api, huma.Operation{
		OperationID:  "profile",
		Method:       http.MethodGet,
		Path:         "/v1/profile",
		Summary:      "Get user profile",
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, withAuthTokenContextMiddleware, withIdTokenContextMiddleware},
	}, func(ctx context.Context, input *struct{}) (*TaskResponseOutput[*UserIdTokenProfile], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		token := getAuthTokenFromContext(ctx)
		if token == "" {
			logError(types.UnauthorizedError, ctx)
			return nil, humaTools.MapError(types.UnauthorizedError)
		}

		if err := checkLimiter(tokenLimiter, token, ctx); err != nil {
			return nil, err
		}

		trc, taskErr := createGetProfileTask(ctx)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		result := <-trc

		taskError := result.GetError()
		if taskError != nil {
			logError(taskError, ctx)
			return nil, humaTools.MapError(taskError)
		}

		return processSideEffects(result.GetSideEffects(), &TaskResponseOutput[*UserIdTokenProfile]{
			Body: result.Profile,
		}), nil
	})
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

func AddRoutes(api huma.API) {
	registerSharedSchemas(api)

	registerLogin(api)
	registerSatisfyPasswordUpdate(api)
	registerSelectMFA(api)
	registerMFASetup(api)
	registerMFASetupVerifySoftwareToken(api)
	registerMFAVerify(api)
	registerLogout(api)
	registerUpdatePassword(api)
	registerGetMFAStatus(api)
	registerUpdateMFA(api)
	registerVerifyUpdateMFA(api)

	if passwordreset.GetSettings().Enabled {
		registerResetPassword(api)
		registerInitiatePasswordReset(api)
		registerFinalizePasswordReset(api)
	}

	if !config.UseMasquerade() {
		registerRefreshToken(api)
	}

	if config.UseCookies() {
		if config.UseMasquerade() {
			registerUnmaskTokenGet(api)
		}
	} else {
		if config.UseMasquerade() {
			registerUnmaskTokenPost(api)
		}
	}

	registerGetProfile(api)

	registerValidate(api)
}
