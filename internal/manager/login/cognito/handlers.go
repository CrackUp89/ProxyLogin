package cognito

import (
	"context"
	"net/http"
	"proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/ratelimiter"
	httpTools "proxylogin/internal/manager/tools/http"
	humaTools "proxylogin/internal/manager/tools/huma"
	"reflect"
	"strings"
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

func attachRequestLogger(ctx context.Context) (context.Context, *zap.Logger) {
	return httpTools.AttachRequestLogger(ctx, getHandlersLogger())
}

func getRequestLogger(ctx context.Context) *zap.Logger {
	return httpTools.GetRequestLogger(ctx, getHandlersLogger())
}

func getAuthTokenFromContext(ctx context.Context) string {
	auth := getAuthFromContext(ctx)

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

func (c *Cognito) newRateLimiter(name string) ratelimiter.Limiter {
	l, ok := c.appConfig.LimitsConfig.Rate[name]
	if !ok {
		panic("no rate limit configured for " + name)
	}
	if l.Limit < 1 || l.Window < 1 {
		return ratelimiter.NoOpLimiter
	}
	return c.limiters.NewLimiter(name, l.Limit, l.Window)
}

type limiterTask struct {
	limiter ratelimiter.Limiter
	key     string
}
type limitValidator struct {
	ctx    context.Context
	limits []*limiterTask
}

func newLimitValidator(ctx context.Context) *limitValidator {
	return &limitValidator{
		ctx:    ctx,
		limits: []*limiterTask{},
	}
}

func (l *limitValidator) add(limiter ratelimiter.Limiter, key string) *limitValidator {
	l.limits = append(l.limits, &limiterTask{
		limiter: limiter,
		key:     key,
	})
	return l
}

func (l *limitValidator) validate() error {
	var err error
	for _, limit := range l.limits {
		if err = l.checkLimiter(limit); err != nil {
			return err
		}
	}
	return nil
}

func (l *limitValidator) checkLimiter(task *limiterTask) error {
	requestLogger := getRequestLogger(l.ctx)
	if allow, err := task.limiter.Allow(l.ctx, task.key); err != nil {
		requestLogger.Error("limiter error", zap.Error(err))
		return humaTools.MapError(types.NewInternalError("limiter error", err))
	} else if !allow {
		requestLogger.Warn("too many requests")
		return humaTools.MapError(types.TooManyRequests)
	}
	return nil
}

func (c *Cognito) createCookie(name string, val string, httpOnly bool, expires time.Time) http.Cookie {
	result := http.Cookie{
		Name:     name,
		Value:    val,
		HttpOnly: httpOnly,
		Path:     c.appConfig.CookiesPath,
		Secure:   c.appConfig.CookiesSecure,
		SameSite: c.appConfig.CookieSameSite,
	}

	domain := c.appConfig.CookiesDomain
	if domain != "" {
		result.Domain = domain
	}

	if !expires.IsZero() {
		result.MaxAge = int(expires.Sub(time.Now()) / time.Second)
		result.Expires = expires
	}

	return result
}

func (c *Cognito) createAuthCookie(name string, val string, expires time.Time) http.Cookie {
	return c.createCookie(name, val, c.appConfig.UseHTTPOnlyCookies, expires)
}

func (c *Cognito) dropCookie(name string) http.Cookie {
	return http.Cookie{
		Name:    name,
		Path:    c.appConfig.CookiesPath,
		MaxAge:  -1,
		Expires: time.Unix(0, 0),
	}
}

func (c *Cognito) createLoginSessionCookie(val string) http.Cookie {
	//session cookie is always http-only
	return c.createCookie(c.appConfig.SessionCookieName, val, true, time.Now().Add(c.loginSessionValidFor))
}

func (c *Cognito) dropLoginSessionCookie() http.Cookie {
	return c.dropCookie(c.appConfig.SessionCookieName)
}

// ---------------------------------------------------------------------------
// Auth context middleware (huma-level)
// ---------------------------------------------------------------------------

func (c *Cognito) withAuthTokenContextMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	if c.appConfig.UseCookies {
		if c.appConfig.Masquerade {
			val := readCookieFromHumaContext(ctx, c.appConfig.MasqueradedTokenCookieName)
			if val != "" {
				rCtx = context.WithValue(rCtx, AuthContextVarName, MasqueradedAuth{Token: val})
			}
		} else {
			val := readCookieFromHumaContext(ctx, c.appConfig.AccessTokenCookieName)
			if val != "" {
				rCtx = context.WithValue(rCtx, AuthContextVarName, TokenAuth{Token: val})
			}
		}
	} else {
		auth := ctx.Header("Authorization")
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			if c.appConfig.Masquerade {
				rCtx = context.WithValue(rCtx, AuthContextVarName, MasqueradedAuth{Token: token})
			} else {
				rCtx = context.WithValue(rCtx, AuthContextVarName, TokenAuth{Token: token})
			}
		}
	}
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

func (c *Cognito) withIdTokenContextMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	if c.appConfig.UseCookies && !c.appConfig.Masquerade {
		val := readCookieFromHumaContext(ctx, c.appConfig.IdTokenCookieName)
		if val != "" {
			rCtx = context.WithValue(rCtx, IdTokenContextVarName, val)
		}
	}
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

func (c *Cognito) withRefreshTokenContextMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	if c.appConfig.UseCookies && !c.appConfig.Masquerade {
		val := readCookieFromHumaContext(ctx, c.appConfig.RefreshTokenCookieName)
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

func (c *Cognito) withLoginSessionMiddleware(ctx huma.Context, next func(huma.Context)) {
	rCtx := ctx.Context()
	val := readCookieFromHumaContext(ctx, c.appConfig.SessionCookieName)
	if val != "" {
		rCtx = context.WithValue(rCtx, LoginSessionContextVarName, val)
	}
	ctx = huma.WithContext(ctx, rCtx)
	next(ctx)
}

func (c *Cognito) withCSRFHeaderMiddleware(ctx huma.Context, next func(huma.Context)) {
	if c.csrf.IsHeaderCheckEnabled() {
		rCtx := ctx.Context()
		val := ctx.Header(c.csrf.HeaderName)
		if val != "" {
			rCtx = context.WithValue(rCtx, CSRFTokenContextVarName, val)
		}
		ctx = huma.WithContext(ctx, rCtx)
	}
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

func getMasqueradedTokenFromContext(ctx context.Context) string {
	auth := getAuthFromContext(ctx)

	if auth == nil {
		return ""
	}

	if t, ok := auth.(MasqueradedAuth); ok {
		return t.Token
	}

	return ""
}

func readStringFromContext(ctx context.Context, name string) string {
	v := ctx.Value(name)
	if v == nil {
		return ""
	}
	if t, ok := v.(string); ok {
		return t
	}
	return ""
}

func getIdTokenFromContext(ctx context.Context) string {
	return readStringFromContext(ctx, IdTokenContextVarName)
}

func getRefreshTokenFromContext(ctx context.Context) string {
	return readStringFromContext(ctx, RefreshTokenContextVarName)
}

func getLoginSessionIdFromContext(ctx context.Context) string {
	return readStringFromContext(ctx, LoginSessionContextVarName)
}

func getCSRFTokenFromContext(ctx context.Context) string {
	return readStringFromContext(ctx, CSRFTokenContextVarName)
}

// requireCSRFToken returns the CSRF token sent with a login flow request.
// It fails if the header check is enabled and the token is missing.
func (c *Cognito) requireCSRFToken(ctx context.Context) (string, error) {
	csrfToken := getCSRFTokenFromContext(ctx)
	if csrfToken == "" && c.csrf.IsHeaderCheckEnabled() {
		return "", humaTools.MapError(types.GenericMissingCSRFTokenError)
	}
	return csrfToken, nil
}

func getAuthFromContext(ctx context.Context) any {
	return ctx.Value(AuthContextVarName)
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

func (c *Cognito) buildMasqueradedTokenAuthResponse(p *types.MasqueradedToken, remember bool) (*AuthTaskResponse, []http.Cookie) {
	var expires time.Time
	if remember {
		expires = p.TokenExpires
	} else {
		expires = time.Time{}
	}

	if c.appConfig.UseCookies {
		return &AuthTaskResponse{
			AuthResult: newLoginResponseMasquerade(nil),
		}, []http.Cookie{
			c.createAuthCookie(c.appConfig.MasqueradedTokenCookieName, p.Token, expires),
		}
	}

	return &AuthTaskResponse{
		AuthResult: newLoginResponseMasquerade(nil),
	}, []http.Cookie{}
}

func (c *Cognito) buildAuthTokenSetCookies(p *types.AuthTokenSet, remember bool) []http.Cookie {
	responseCookies := make([]http.Cookie, 0, 3)

	if p.RefreshToken != "" {
		var refreshExpires time.Time
		if remember {
			refreshExpires = *p.RefreshTokenExpires
		} else {
			refreshExpires = time.Time{}
		}
		responseCookies = append(responseCookies, c.createAuthCookie(c.appConfig.RefreshTokenCookieName, p.RefreshToken, refreshExpires))
	}

	var accessExpires time.Time
	var idExpires time.Time
	if remember {
		accessExpires = *p.AccessTokenExpires
		idExpires = *p.IdTokenExpires
	} else {
		accessExpires = time.Time{}
		idExpires = time.Time{}
	}

	responseCookies = append(responseCookies,
		c.createAuthCookie(c.appConfig.AccessTokenCookieName, p.AccessToken, accessExpires),
		c.createAuthCookie(c.appConfig.IdTokenCookieName, p.IdToken, idExpires))

	return responseCookies
}

func (c *Cognito) buildTokenSetAuthResponse(p *types.AuthTokenSet, remember bool) (*AuthTaskResponse, []http.Cookie) {
	if c.appConfig.UseCookies {
		return &AuthTaskResponse{
			AuthResult: newLoginResponseTokenSet(nil),
		}, c.buildAuthTokenSetCookies(p, remember)
	}

	return &AuthTaskResponse{
		AuthResult: newLoginResponseTokenSet(p),
	}, []http.Cookie{}
}

func (c *Cognito) buildAuthResponse(_ context.Context, taskResult interface {
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
	dropLoginSessionCookie := c.dropLoginSessionCookie()

	var body *AuthTaskResponse
	var cookies []http.Cookie

	switch taskAuthResultsData.(type) {
	case *types.MasqueradedToken:
		body, cookies = c.buildMasqueradedTokenAuthResponse(taskAuthResultsData.(*types.MasqueradedToken), remember)
		break
	case *types.AuthTokenSet:
		body, cookies = c.buildTokenSetAuthResponse(taskAuthResultsData.(*types.AuthTokenSet), remember)
		break
	default:
		panic("invalid auth results type")
	}

	return &TaskResponseOutput[*AuthTaskResponse]{
		Body:      body,
		SetCookie: append(cookies, dropLoginSessionCookie),
	}
}

func (c *Cognito) getLogOutCookies() []http.Cookie {
	return []http.Cookie{
		c.dropCookie(c.appConfig.MasqueradedTokenCookieName),
		c.dropCookie(c.appConfig.AccessTokenCookieName),
		c.dropCookie(c.appConfig.RefreshTokenCookieName),
		c.dropCookie(c.appConfig.IdTokenCookieName),
		c.dropLoginSessionCookie(),
	}
}

func processSideEffects[T any](c *Cognito, sideEffects []SideEffect, response *TaskResponseOutput[T]) *TaskResponseOutput[T] {
	for _, sideEffect := range sideEffects {
		switch sideEffect.GetType() {
		case LogOutSideEffect:
			response.SetCookie = append(response.SetCookie, c.getLogOutCookies()...)
			break
		}
	}
	return response
}

func (c *Cognito) buildTaskResponse(ctx context.Context, result TaskResult) (*GenericTaskResponseOutput, error) {
	taskError := result.GetError()
	if taskError != nil {
		logError(taskError, ctx)
		return nil, humaTools.MapError(taskError)
	}

	return processSideEffects(c, result.GetSideEffects(), &GenericTaskResponseOutput{
		Body: result.GetPayload(),
	}), nil
}

func (c *Cognito) buildLoginTaskResponse(ctx context.Context, result LoginStepResult) (*TaskResponseOutput[*AuthTaskResponse], error) {
	taskError := result.GetError()
	if taskError != nil {
		logError(taskError, ctx)
		return nil, humaTools.MapError(taskError)
	}

	if result.GetAuthResults() != nil {
		return processSideEffects(c, result.GetSideEffects(), c.buildAuthResponse(ctx, result)), nil
	}

	ns := result.GetNextLoginStep()

	return processSideEffects(c, result.GetSideEffects(), &TaskResponseOutput[*AuthTaskResponse]{
		Body: &AuthTaskResponse{
			NextStep: NextLoginStepResponse{
				Step:    ns.NextStep,
				Payload: ns.Payload,
			},
		},
		SetCookie: []http.Cookie{c.createLoginSessionCookie(ns.LoginSessionId)},
	}), nil
}

func (c *Cognito) buildLoginFinalTaskResponse(ctx context.Context, result LoginFinalStepResult) (*TaskResponseOutput[*AuthTaskResponse], error) {
	taskError := result.GetError()
	if taskError != nil {
		logError(taskError, ctx)
		return nil, humaTools.MapError(taskError)
	}

	if result.GetAuthResults() != nil {
		return processSideEffects(c, result.GetSideEffects(), c.buildAuthResponse(ctx, result)), nil
	}

	err := types.NewInternalError("task result is empty", nil)

	logError(err, ctx)
	return nil, humaTools.MapError(err)
}

// ---------------------------------------------------------------------------
// MFA verify total limiter
// ---------------------------------------------------------------------------

func (c *Cognito) getVerifyUserMFATokenOnLoginLimiter() ratelimiter.TotalLimiter {
	c.verifyUserMFATokenOnLoginLimiterOnce.Do(func() {
		c.verifyUserMFATokenOnLoginLimiter = c.limiters.NewTotalLimiter("verifyUserMFATokenOnLogin", c.appConfig.LimitsConfig.MFAVerifyMaxAttempts)
	})
	return c.verifyUserMFATokenOnLoginLimiter
}

func (c *Cognito) dropUserMFATokenOnLoginLimiter(ctx context.Context, key string) {
	if err := c.getVerifyUserMFATokenOnLoginLimiter().Drop(context.Background(), key); err != nil {
		getRequestLogger(ctx).Warn("unable to drop limiter", zap.Error(err))
	}
}

func (c *Cognito) registerLoginStart(api huma.API) {
	addressLimiter := c.newRateLimiter("loginStartPerRemoteAddress")
	totalLimiter := c.newRateLimiter("loginStartTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "login-start",
		Method:       http.MethodPost,
		Path:         "/v1/login/start",
		Summary:      "Issue a login session",
		Description:  descLoginStart,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *struct{}) (*LoginStartResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(totalLimiter, "total").
			add(addressLimiter, rm.GetClientIP()).
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createLoginStartTask(ctx)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		taskResult := <-trc

		taskError := taskResult.GetError()
		if taskError != nil {
			logError(taskError, ctx)
			return nil, humaTools.MapError(taskError)
		}

		return &LoginStartResponseOutput{
			SetCookie: []http.Cookie{c.createLoginSessionCookie(taskResult.LoginSessionId)},
			Body:      LoginStartResponseBody{CSRFToken: taskResult.CSRFToken},
		}, nil
	})
}

// ---------------------------------------------------------------------------
// Huma handler registrations
// ---------------------------------------------------------------------------

func (c *Cognito) registerLogin(api huma.API) {
	addressLimiter := c.newRateLimiter("loginPerRemoteAddress")
	userLimiter := c.newRateLimiter("loginPerUser")
	totalLimiter := c.newRateLimiter("loginTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "login",
		Method:       http.MethodPost,
		Path:         "/v1/login",
		Summary:      "Authenticate user",
		Description:  descLogin,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withLoginSessionMiddleware, c.withCSRFHeaderMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *LoginInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		sessionId := getLoginSessionIdFromContext(ctx)
		if sessionId == "" {
			return nil, humaTools.MapError(types.GenericMissingLoginSessionIdError)
		}

		csrfToken, err := c.requireCSRFToken(ctx)
		if err != nil {
			return nil, err
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(userLimiter, input.Body.User).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createLoginTask(ctx, sessionId, input.Body.User, input.Body.Password, input.Body.Remember, csrfToken)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		c.dropUserMFATokenOnLoginLimiter(ctx, input.Body.User)

		return c.buildLoginTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerValidate(api huma.API) {
	addressLimiter := c.newRateLimiter("validatePerRemoteAddress")
	totalLimiter := c.newRateLimiter("validateTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "validate",
		Method:       http.MethodPost,
		Path:         "/v1/validate",
		Summary:      "Validate tokens",
		Description:  descValidate,
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

			addToken(c.appConfig.AccessTokenCookieName)
			addToken(c.appConfig.IdTokenCookieName)
		}

		if len(tokens) == 0 {
			return nil, humaTools.MapError(types.GenericNoTokensProvidedError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createTokenValidationTask(ctx, tokens)
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

func (c *Cognito) registerMFASetup(api huma.API) {
	userLimiter := c.newRateLimiter("loginMFASetupPerUser")
	addressLimiter := c.newRateLimiter("loginMFASetupPerRemoteAddress")
	totalLimiter := c.newRateLimiter("loginMFASetupTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-setup",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/setup",
		Summary:      "Initiate MFA enrolment during login",
		Description:  descLoginMFASetup,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withLoginSessionMiddleware, c.withCSRFHeaderMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *MFASetupInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(userLimiter, input.Body.User).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		sessionId := getLoginSessionIdFromContext(ctx)
		if sessionId == "" {
			return nil, humaTools.MapError(types.GenericMissingLoginSessionIdError)
		}

		csrfToken, err := c.requireCSRFToken(ctx)
		if err != nil {
			return nil, err
		}

		trc, taskErr := c.createMFASetupTask(ctx, sessionId, input.Body.User, types.MFAType(input.Body.MFAType), csrfToken)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildLoginTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerMFASetupVerifyToken(api huma.API) {
	userLimiter := c.newRateLimiter("loginMFASetupVerifyPerUser")
	addressLimiter := c.newRateLimiter("loginMFASetupVerifyPerRemoteAddress")
	totalLimiter := c.newRateLimiter("loginMFASetupVerifyTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-setup-verify",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/setup/verify",
		Summary:      "Confirm MFA software token enrolment during login",
		Description:  descLoginMFASetupVerify,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withLoginSessionMiddleware, c.withCSRFHeaderMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *MFASetupVerifyTokenInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(userLimiter, input.Body.User).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		sessionId := getLoginSessionIdFromContext(ctx)
		if sessionId == "" {
			return nil, humaTools.MapError(types.GenericMissingLoginSessionIdError)
		}

		csrfToken, err := c.requireCSRFToken(ctx)
		if err != nil {
			return nil, err
		}

		trc, taskErr := c.createMFASetupVerifySoftwareTokenTask(ctx, sessionId, input.Body.User, input.Body.Code, csrfToken)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildLoginTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerMFAVerify(api huma.API) {
	userLimiter := c.newRateLimiter("loginMFAVerifyPerUser")
	addressLimiter := c.newRateLimiter("loginMFAVerifyPerRemoteAddress")
	totalLimiter := c.newRateLimiter("loginMFAVerifyTotal")

	dropUserLoginSession := func(ctx context.Context, loginSessionId string) {
		if err := c.dropLoginSession(context.Background(), loginSessionId); err != nil {
			getRequestLogger(ctx).Warn("unable to drop limiter", zap.Error(err))
		}
	}

	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-verify",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/verify",
		Summary:      "Verify MFA code during login",
		Description:  descLoginMFAVerify,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withLoginSessionMiddleware, c.withCSRFHeaderMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *MFATokenVerifyInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(userLimiter, input.Body.User).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		sessionId := getLoginSessionIdFromContext(ctx)
		if sessionId == "" {
			return nil, humaTools.MapError(types.GenericMissingLoginSessionIdError)
		}

		csrfToken, err := c.requireCSRFToken(ctx)
		if err != nil {
			return nil, err
		}

		if allowed, err := c.getVerifyUserMFATokenOnLoginLimiter().Allow(ctx, input.Body.User); err != nil {
			logError(types.NewInternalError("limiter error", err), ctx)
			return nil, humaTools.MapError(types.NewInternalError("limiter error", err))
		} else if !allowed {
			c.dropUserMFATokenOnLoginLimiter(ctx, input.Body.User)
			dropUserLoginSession(ctx, sessionId)
			logError(types.GenericUnauthorizedError, ctx)
			return nil, humaTools.MapError(types.GenericUnauthorizedError)
		}

		trc, taskErr := c.createMFAVerifyTask(ctx, sessionId, input.Body.User, input.Body.Code, csrfToken)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		taskResult := <-trc

		resp, err := c.buildLoginTaskResponse(ctx, taskResult)
		if err == nil {
			c.dropUserMFATokenOnLoginLimiter(ctx, input.Body.User)
		}

		return resp, err
	})
}

func (c *Cognito) registerSelectMFA(api huma.API) {
	userLimiter := c.newRateLimiter("loginMFASelectPerUser")
	addressLimiter := c.newRateLimiter("loginMFASelectPerRemoteAddress")
	totalLimiter := c.newRateLimiter("loginMFASelectTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "login-mfa-select",
		Method:       http.MethodPost,
		Path:         "/v1/login/mfa/select",
		Summary:      "Select MFA method during login",
		Description:  descLoginMFASelect,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withLoginSessionMiddleware, c.withCSRFHeaderMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *SelectMFAInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(userLimiter, input.Body.User).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		sessionId := getLoginSessionIdFromContext(ctx)
		if sessionId == "" {
			return nil, humaTools.MapError(types.GenericMissingLoginSessionIdError)
		}

		csrfToken, err := c.requireCSRFToken(ctx)
		if err != nil {
			return nil, err
		}

		trc, taskErr := c.createSelectMFATask(ctx, sessionId, input.Body.User, input.Body.MFAType, csrfToken)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildLoginTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerSatisfyPasswordUpdate(api huma.API) {
	userLimiter := c.newRateLimiter("loginPasswordUpdatePerUser")
	addressLimiter := c.newRateLimiter("loginPasswordUpdatePerRemoteAddress")
	totalLimiter := c.newRateLimiter("loginPasswordUpdateTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "login-password-update",
		Method:       http.MethodPost,
		Path:         "/v1/login/password/update",
		Summary:      "Complete forced password change during login",
		Description:  descLoginPasswordUpdate,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withLoginSessionMiddleware, c.withCSRFHeaderMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *SatisfyPasswordUpdateInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		sessionId := getLoginSessionIdFromContext(ctx)
		if sessionId == "" {
			return nil, humaTools.MapError(types.GenericMissingLoginSessionIdError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(userLimiter, input.Body.User).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		csrfToken, err := c.requireCSRFToken(ctx)
		if err != nil {
			return nil, err
		}

		trc, taskErr := c.createSatisfyPasswordUpdateRequestTask(ctx, sessionId, input.Body.User, input.Body.Password, input.Body.Attributes, csrfToken)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildLoginTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerLogout(api huma.API) {
	tokenLimiter := c.newRateLimiter("logoutPerToken")
	addressLimiter := c.newRateLimiter("logoutPerRemoteAddress")
	totalLimiter := c.newRateLimiter("logoutTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "logout",
		Method:       http.MethodPost,
		Path:         "/v1/logout",
		Summary:      "Log out user",
		Description:  descLogout,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAuthTokenContextMiddleware, c.withRefreshTokenContextMiddleware},
	}, func(ctx context.Context, input *struct {
		Body *logOutRequest `required:"false"`
	}) (*GenericTaskResponseOutput, error) {
		var token string
		if input.Body != nil && input.Body.Token != "" {
			token = input.Body.Token
		} else {
			if c.appConfig.Masquerade {
				token = getMasqueradedTokenFromContext(ctx)
			} else {
				token = getRefreshTokenFromContext(ctx)
			}
		}

		if token == "" {
			return nil, humaTools.MapError(types.GenericNoRefreshTokenProvidedError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createLogOutTask(ctx, token)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerRefreshToken(api huma.API) {
	tokenLimiter := c.newRateLimiter("refreshTokensPerToken")
	userLimiter := c.newRateLimiter("refreshTokensPerUser")
	addressLimiter := c.newRateLimiter("refreshTokensPerRemoteAddress")
	totalLimiter := c.newRateLimiter("refreshTokensTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "refresh-tokens",
		Method:       http.MethodPost,
		Path:         "/v1/refresh",
		Summary:      "Refresh authentication tokens (requires masquerade disabled)",
		Description:  descRefreshTokens,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withRefreshTokenContextMiddleware, c.withIdTokenContextMiddleware},
	}, func(ctx context.Context, input *RefreshTokenInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		if c.appConfig.Masquerade {
			return nil, huma.NewError(http.StatusNotImplemented, "token refresh is not available in masquerade mode")
		}

		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		var token string
		if input.Body.Token != nil {
			token = *input.Body.Token
		} else {
			hc, ok := ctx.Value(humaTools.HumaContextKey).(huma.Context)
			if !ok {
				return nil, humaTools.MapError(types.NewInternalError("huma context not found", nil))
			}

			token = readCookieFromHumaContext(hc, c.appConfig.RefreshTokenCookieName)
		}

		if token == "" {
			return nil, humaTools.MapError(types.GenericNoRefreshTokenProvidedError)
		}

		remember := false
		if input.Body.Remember != nil {
			remember = *input.Body.Remember
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(userLimiter, input.Body.User).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createRefreshTokenTask(ctx, input.Body.User, getIdTokenFromContext(ctx), token, remember)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildLoginFinalTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerUpdatePassword(api huma.API) {
	tokenLimiter := c.newRateLimiter("passwordUpdatePerToken")
	addressLimiter := c.newRateLimiter("passwordUpdatePerRemoteAddress")
	totalLimiter := c.newRateLimiter("passwordUpdateTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "password-update",
		Method:       http.MethodPost,
		Path:         "/v1/password/update",
		Summary:      "Update user password",
		Description:  descPasswordUpdate,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *UpdatePasswordInput) (*GenericTaskResponseOutput, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		token := getAuthTokenFromContext(ctx)
		if token == "" {
			logError(types.GenericUnauthorizedError, ctx)
			return nil, humaTools.MapError(types.GenericUnauthorizedError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createUpdatePasswordTask(ctx, input.Body.CurrentPassword, input.Body.NewPassword, getAuthFromContext(ctx))
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerGetMFAStatus(api huma.API) {
	tokenLimiter := c.newRateLimiter("mfaStatusPerToken")
	addressLimiter := c.newRateLimiter("mfaStatusPerRemoteAddress")
	totalLimiter := c.newRateLimiter("mfaStatusTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "mfa-status",
		Method:       http.MethodGet,
		Path:         "/v1/mfa/status",
		Summary:      "Get user MFA status",
		Description:  descMFAStatus,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *struct{}) (*TaskResponseOutput[*types.MFAStatus], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		token := getAuthTokenFromContext(ctx)
		if token == "" {
			logError(types.GenericUnauthorizedError, ctx)
			return nil, humaTools.MapError(types.GenericUnauthorizedError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createGetMFAStatusTask(ctx, getAuthFromContext(ctx))
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

		return processSideEffects(c, result.GetSideEffects(), &TaskResponseOutput[*types.MFAStatus]{
			Body: result.status,
		}), nil
	})
}

func (c *Cognito) registerUpdateMFASoftwareToken(api huma.API) {
	tokenLimiter := c.newRateLimiter("mfaSoftwareTokenUpdatePerToken")
	addressLimiter := c.newRateLimiter("mfaSoftwareTokenUpdatePerRemoteAddress")
	totalLimiter := c.newRateLimiter("mfaSoftwareTokenUpdateTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "mfa-software-token-update",
		Method:       http.MethodPost,
		Path:         "/v1/mfa/software/update",
		Summary:      "Initiate MFA software token update",
		Description:  descMFASoftwareTokenUpdate,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAuthTokenContextMiddleware},
	}, func(ctx context.Context, _ *struct{}) (*TaskResponseOutput[*updateMFASoftwareTokenTaskResultPayload], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		token := getAuthTokenFromContext(ctx)
		if token == "" {
			logError(types.GenericUnauthorizedError, ctx)
			return nil, humaTools.MapError(types.GenericUnauthorizedError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createUpdateMFASoftwareTokenTask(ctx, getAuthFromContext(ctx))
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

		return processSideEffects(c, result.GetSideEffects(), &TaskResponseOutput[*updateMFASoftwareTokenTaskResultPayload]{
			Body: result.payload,
		}), nil
	})
}

func (c *Cognito) registerVerifyUpdateMFASoftwareToken(api huma.API) {
	tokenLimiter := c.newRateLimiter("mfaSoftwareTokenUpdateVerifyPerToken")
	addressLimiter := c.newRateLimiter("mfaSoftwareTokenUpdateVerifyPerRemoteAddress")
	totalLimiter := c.newRateLimiter("mfaSoftwareTokenUpdateVerifyTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "mfa-software-token-update-verify",
		Method:       http.MethodPost,
		Path:         "/v1/mfa/update/software/verify",
		Summary:      "Confirm MFA software token setup",
		Description:  descMFASoftwareTokenUpdateVerify,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAuthTokenContextMiddleware},
	}, func(ctx context.Context, input *VerifyMFASoftwareTokenUpdateInput) (*struct{}, error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		token := getAuthTokenFromContext(ctx)
		if token == "" {
			logError(types.GenericUnauthorizedError, ctx)
			return nil, humaTools.MapError(types.GenericUnauthorizedError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createVerifyMFASoftwareTokenUpdateTask(ctx, input.Body.Code, getAuthFromContext(ctx))
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

		return nil, nil
	})
}

func (c *Cognito) registerInitiatePasswordReset(api huma.API) {
	emailLimiter := c.newRateLimiter("passwordResetRequestPerEmail")
	addressLimiter := c.newRateLimiter("passwordResetRequestPerRemoteAddress")
	totalLimiter := c.newRateLimiter("passwordResetRequestTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "password-reset-request",
		Method:       http.MethodPost,
		Path:         "/v1/password/reset/request",
		Summary:      "Initiate password reset (requires `password.reset.enabled`)",
		Description:  descPasswordResetRequest,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *InitiatePasswordResetInput) (*GenericTaskResponseOutput, error) {
		if !c.appConfig.PasswordResetConfig.Enabled {
			return nil, huma.NewError(http.StatusNotImplemented, "password reset is disabled")
		}

		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(emailLimiter, input.Body.Email).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createInitiatePasswordResetTask(ctx, input.Body.Email)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) registerResetPassword(api huma.API) {
	tokenLimiter := c.newRateLimiter("passwordResetValidatePerToken")
	addressLimiter := c.newRateLimiter("passwordResetValidatePerRemoteAddress")
	totalLimiter := c.newRateLimiter("passwordResetValidateTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "password-reset-validate",
		Method:       http.MethodGet,
		Path:         "/v1/password/reset",
		Summary:      "Validate reset link and redirect (requires `password.reset.enabled`)",
		Description:  descPasswordResetValidate,
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *PasswordResetInput) (*struct{}, error) {
		if !c.appConfig.PasswordResetConfig.Enabled {
			return nil, huma.NewError(http.StatusNotImplemented, "password reset is disabled")
		}

		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, input.Token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createResetPasswordTask(ctx, input.Token)
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

func (c *Cognito) registerFinalizePasswordReset(api huma.API) {
	tokenLimiter := c.newRateLimiter("passwordResetFinalizePerToken")
	addressLimiter := c.newRateLimiter("passwordResetFinalizePerRemoteAddress")
	totalLimiter := c.newRateLimiter("passwordResetFinalizeTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "password-reset-finalize",
		Method:       http.MethodPost,
		Path:         "/v1/password/reset/finalize",
		Summary:      "Finalize password reset (requires `password.reset.enabled`)",
		Description:  descPasswordResetFinalize,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *FinalizePasswordResetInput) (*GenericTaskResponseOutput, error) {
		if !c.appConfig.PasswordResetConfig.Enabled {
			return nil, huma.NewError(http.StatusNotImplemented, "password reset is disabled")
		}

		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, input.Body.Token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createFinalizePasswordResetTask(ctx, input.Body.Token, input.Body.Code, input.Body.Password)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildTaskResponse(ctx, <-trc)
	})
}

func (c *Cognito) unmaskTokenResult(ctx context.Context, limits *limitValidator, token string, remember bool) (*UnmaskTokenResult, error) {
	if token == "" {
		logError(types.GenericUnauthorizedError, ctx)
		return nil, humaTools.MapError(types.GenericUnauthorizedError)
	}

	if err := limits.validate(); err != nil {
		return nil, err
	}

	trc, taskErr := c.createUnmaskTokenTask(ctx, token)
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

	if c.appConfig.UseCookies {
		return &UnmaskTokenResult{
			Body:      UnmaskTokenResultBody{},
			SetCookie: c.buildAuthTokenSetCookies(result.tokenSet, remember),
		}, nil
	}

	return &UnmaskTokenResult{
		Body: UnmaskTokenResultBody{
			AccessToken:  result.tokenSet.AccessToken,
			IdToken:      result.tokenSet.IdToken,
			RefreshToken: result.tokenSet.RefreshToken,
		},
	}, nil
}

func (c *Cognito) registerUnmaskTokenGet(api huma.API) {
	tokenLimiter := c.newRateLimiter("unmaskTokenCookiePerToken")
	addressLimiter := c.newRateLimiter("unmaskTokenCookiePerRemoteAddress")
	totalLimiter := c.newRateLimiter("unmaskTokenCookieTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "unmask-token-cookie",
		Method:       http.MethodGet,
		Path:         "/v1/unmask",
		Summary:      "Exchange masquerade token for real tokens via cookie (requires masquerade + cookie mode)",
		Description:  descUnmaskTokenCookie,
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAuthTokenContextMiddleware},
		Parameters: []*huma.Param{
			{
				Name:     c.appConfig.MasqueradedTokenCookieName,
				In:       "cookie",
				Schema:   &huma.Schema{Type: "string"},
				Required: true,
			},
		},
	}, func(ctx context.Context, input *UnmaskTokenInputGet) (*UnmaskTokenResult, error) {
		if !c.appConfig.Masquerade || !c.appConfig.UseCookies {
			return nil, huma.NewError(http.StatusNotImplemented, "masquerade cookie mode is disabled")
		}

		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		hc, ok := ctx.Value(humaTools.HumaContextKey).(huma.Context)
		if !ok {
			return nil, humaTools.MapError(types.NewInternalError("huma context not found", nil))
		}

		token := readCookieFromHumaContext(hc, c.appConfig.MasqueradedTokenCookieName)

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		limits := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total")

		return c.unmaskTokenResult(ctx, limits, token, input.Remember)
	})
}

func (c *Cognito) registerUnmaskTokenPost(api huma.API) {
	tokenLimiter := c.newRateLimiter("unmaskTokenPerToken")
	addressLimiter := c.newRateLimiter("unmaskTokenPerRemoteAddress")
	totalLimiter := c.newRateLimiter("unmaskTokenTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "unmask-token",
		Method:       http.MethodPost,
		Path:         "/v1/unmask",
		Summary:      "Exchange masquerade token for real tokens (requires masquerade mode)",
		Description:  descUnmaskToken,
		MaxBodyBytes: 10 * 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware},
	}, func(ctx context.Context, input *UnmaskTokenInputPost) (*UnmaskTokenResult, error) {
		if !c.appConfig.Masquerade {
			return nil, huma.NewError(http.StatusNotImplemented, "masquerade mode is disabled")
		}

		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		limits := newLimitValidator(ctx).
			add(tokenLimiter, input.Body.Token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total")

		return c.unmaskTokenResult(ctx, limits, input.Body.Token, input.Body.Remember)
	})
}

func (c *Cognito) registerGetProfile(api huma.API) {
	tokenLimiter := c.newRateLimiter("getProfilePerToken")
	addressLimiter := c.newRateLimiter("getProfilePerRemoteAddress")
	totalLimiter := c.newRateLimiter("getProfileTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "get-profile",
		Method:       http.MethodGet,
		Path:         "/v1/profile",
		Summary:      "Get authenticated user profile",
		Description:  descGetProfile,
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withAuthTokenContextMiddleware, c.withIdTokenContextMiddleware},
	}, func(ctx context.Context, input *struct{}) (*TaskResponseOutput[*UserIdTokenProfile], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		token := getAuthTokenFromContext(ctx)
		if token == "" {
			logError(types.GenericUnauthorizedError, ctx)
			return nil, humaTools.MapError(types.GenericUnauthorizedError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(tokenLimiter, token).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		trc, taskErr := c.createGetProfileTask(ctx, getMasqueradedTokenFromContext(ctx), getIdTokenFromContext(ctx))
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

		return processSideEffects(c, result.GetSideEffects(), &TaskResponseOutput[*UserIdTokenProfile]{
			Body: result.Profile,
		}), nil
	})
}

func (c *Cognito) registerExternalLoginRequest(api huma.API) {
	codeLimiter := c.newRateLimiter("loginExternalTokenPerCode")
	addressLimiter := c.newRateLimiter("loginExternalTokenPerRemoteAddress")
	totalLimiter := c.newRateLimiter("loginExternalTokenTotal")

	huma.Register(api, huma.Operation{
		OperationID:  "login-external-token",
		Method:       http.MethodPost,
		Path:         "/v1/login/external",
		Summary:      "Login with external token",
		Description:  descExternalLogin,
		MaxBodyBytes: 1024,
		Middlewares:  huma.Middlewares{withRequestLoggerMiddleware, c.withLoginSessionMiddleware, c.withCSRFHeaderMiddleware, c.withAllowedOriginMiddleware},
	}, func(ctx context.Context, input *ExternalLoginInput) (*TaskResponseOutput[*AuthTaskResponse], error) {
		ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		sessionId := getLoginSessionIdFromContext(ctx)
		if sessionId == "" {
			return nil, humaTools.MapError(types.GenericMissingLoginSessionIdError)
		}

		rm, _ := httpTools.GetRequestMetadataFromContext(ctx)
		if err := newLimitValidator(ctx).
			add(codeLimiter, input.Body.Code).
			add(addressLimiter, rm.GetClientIP()).
			add(totalLimiter, "total").
			validate(); err != nil {
			return nil, err
		}

		csrfToken, err := c.requireCSRFToken(ctx)
		if err != nil {
			return nil, err
		}

		trc, taskErr := c.createExternalLoginTask(ctx, sessionId, input.Body.Code, input.Body.Remember, csrfToken)
		if taskErr != nil {
			logError(taskErr, ctx)
			return nil, humaTools.MapError(taskErr)
		}

		return c.buildLoginTaskResponse(ctx, <-trc)
	})
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

func (c *Cognito) AddRoutes(api huma.API) {
	c.withAllowedOriginMiddleware = func(ctx huma.Context, next func(huma.Context)) {
		if !c.csrf.VerifyCSRFOrigin(ctx) {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden, "missing or invalid CSRF token")
			return
		}
		next(ctx)
	}

	registerSharedSchemas(api)

	c.registerLoginStart(api)
	c.registerLogin(api)
	c.registerExternalLoginRequest(api)
	c.registerSelectMFA(api)
	c.registerMFASetup(api)
	c.registerMFASetupVerifyToken(api)
	c.registerMFAVerify(api)
	c.registerSatisfyPasswordUpdate(api)
	c.registerLogout(api)

	c.registerUpdatePassword(api)

	c.registerGetMFAStatus(api)
	c.registerUpdateMFASoftwareToken(api)
	c.registerVerifyUpdateMFASoftwareToken(api)

	c.registerInitiatePasswordReset(api)
	c.registerResetPassword(api)
	c.registerFinalizePasswordReset(api)

	c.registerUnmaskTokenGet(api)
	c.registerUnmaskTokenPost(api)
	c.registerRefreshToken(api)

	c.registerGetProfile(api)

	c.registerValidate(api)
}
