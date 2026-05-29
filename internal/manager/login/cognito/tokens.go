package cognito

import (
	"context"
	loginTypes "proxylogin/internal/manager/login/types"
	"proxylogin/internal/manager/tools/locking"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	cognitoTypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

func (c *Cognito) resolveAuthToken(ctx context.Context, auth any) (*loginTypes.AuthTokenSet, loginTypes.GenericError) {
	switch auth.(type) {
	case TokenAuth:
		return &loginTypes.AuthTokenSet{
			AccessToken: auth.(TokenAuth).Token,
		}, nil
	case MasqueradedAuth:
		requestLogger := getRequestLoggerFromContext(ctx)
		tokenSet, err := c.unmaskToken(ctx, auth.(MasqueradedAuth).Token, requestLogger, true, false)
		if err != nil {
			return nil, err
		}
		return tokenSet, nil
	}
	panic("unknown auth type")
}

func (c *Cognito) validateTokenOrigin(token string) loginTypes.GenericError {
	t, err := c.jwksValidator.ParseToken(token)
	if t == nil || t.Claims == nil {
		return loginTypes.NewGenericAuthError("unable to parse token or token has no claims", "invalid token", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return loginTypes.GenericNoClaimsError
	}

	tokenClientId, ok := claims["client_id"].(string)
	if !ok || tokenClientId == "" {
		return loginTypes.GenericNoClientIdError
	}
	if tokenClientId != c.cfg.Client.ID {
		return loginTypes.GenericInvalidClientIdError
	}

	issuer, err := t.Claims.GetIssuer()
	if err != nil || issuer == "" {
		return loginTypes.GenericNoIssuerError
	}
	if issuer != c.cfg.JWKSIssuer {
		return loginTypes.GenericInvalidIssuerError
	}

	return nil
}

func checkAuthToken[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, accessToken string, ef errorFactory[R, PR]) PR {
	if accessToken == "" {
		return ef(loginTypes.GenericUnauthorizedError)
	}

	_, err := c.jwksValidator.ValidateToken(accessToken)

	if err != nil {
		return ef(loginTypes.NewGenericAuthError("jwks validation failed", "invalid token", err))
	}

	return nil
}

func checkAuth[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, ctx context.Context, auth any, ef errorFactory[R, PR]) (*loginTypes.AuthTokenSet, PR) {
	tokenSet, authErr := c.resolveAuthToken(ctx, auth)

	if authErr != nil {
		return nil, ef(authErr)
	}

	return tokenSet, checkAuthToken(c, tokenSet.AccessToken, ef)
}

func (c *Cognito) refreshToken(ctx context.Context, token string, user string) (*cognitoTypes.AuthenticationResultType, error) {
	if c.useAuthToRefresh {
		input := &cognitoidentityprovider.InitiateAuthInput{
			AuthFlow: cognitoTypes.AuthFlowTypeRefreshTokenAuth,
			ClientId: aws.String(c.cfg.Client.ID),
			AuthParameters: map[string]string{
				"REFRESH_TOKEN": token,
			},
		}

		if c.cfg.Client.Secret != "" {
			input.AuthParameters["SECRET_HASH"] = computeSecretHash(c.cfg.Client.Secret, user, c.cfg.Client.ID)
		}

		result, err := c.cognitoClient.InitiateAuth(ctx, input)
		if err != nil {
			return nil, err
		}
		return result.AuthenticationResult, nil
	}

	input := &cognitoidentityprovider.GetTokensFromRefreshTokenInput{
		ClientId:     aws.String(c.cfg.Client.ID),
		RefreshToken: aws.String(token),
	}

	if c.cfg.Client.Secret != "" {
		input.ClientSecret = aws.String(c.cfg.Client.Secret)
	}

	result, err := c.cognitoClient.GetTokensFromRefreshToken(ctx, input)

	if err != nil {
		return nil, err
	}
	return result.AuthenticationResult, nil

}

func (c *Cognito) dropMasqueradedToken(token string, requestLogger *zap.Logger) {
	err := c.masq.Storage().DropMasqueradedRecord(context.Background(), token)
	if err != nil {
		requestLogger.Error("failed to drop masqueraded token", zap.Error(err))
	}
}

func (c *Cognito) unmaskToken(ctx context.Context, token string, requestLogger *zap.Logger, refreshExpired bool, appendRefreshToken bool) (*loginTypes.AuthTokenSet, loginTypes.GenericError) {
	if token == "" {
		return nil, loginTypes.GenericUnauthorizedError
	}

	d, err := c.masq.Storage().GetMasqueradedRecord(ctx, token)
	if err != nil {
		return nil, loginTypes.NewInternalError("unable to unmask token", err)
	}

	if d == nil {
		return nil, loginTypes.GenericInvalidTokenMaskError
	}

	if refreshExpired {
		deadline := time.Now().Add(10 * time.Second)
		refreshRequired := false

		if !d.Tokens[loginTypes.AuthTokenType].Expires.After(deadline) {
			refreshRequired = true
		}

		if !d.Tokens[loginTypes.IDTokenType].Expires.After(deadline) {
			refreshRequired = true
		}

		//if at, ok := d.Tokens[loginTypes.AuthTokenType]; ok {
		//	if err := validateTokenOrigin(at.Value); err != nil {
		//		go func() {
		//			requestLogger.Error("auth token is invalid; removing masqueraded record", zap.Error(err))
		//			if err := masq.Storage().DropMasqueradedRecord(context.Background(), token); err != nil {
		//				requestLogger.Error("failed to drop masqueraded token", zap.Error(err))
		//			}
		//		}()
		//
		//		return nil, err
		//	}
		//} else {
		//	requestLogger.Warn("token set has no auth token - skipping pool check")
		//}

		if refreshRequired {
			requestLogger.Log(c.processingLogLevel, "refresh required")

			if rt, ok := d.Tokens[loginTypes.RefreshTokenType]; ok {
				var ttl time.Duration
				if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
					ttl = deadline.Sub(time.Now())
				} else {
					ttl = 60 * time.Second
				}

				ro := locking.GetReturnOnce[*cognitoTypes.AuthenticationResultType](c.locks, token, ttl)
				authResults, err := ro.Do(ctx, func(ctx context.Context) (*cognitoTypes.AuthenticationResultType, error) {
					return c.refreshToken(ctx, rt.Value, d.User)
				})

				if err != nil {
					c.dropMasqueradedToken(token, requestLogger)
					return nil, loginTypes.NewGenericAuthError("unable to refresh token", "authentication error", err)
				}

				r, err := c.authResultToAuthTokenSet(authenticationResultFromCognitoType(authResults))
				if err != nil {
					c.dropMasqueradedToken(token, requestLogger)
					return nil, loginTypes.NewGenericAuthError("unable to convert auth result to token set", "authentication error", err)
				}

				return r, nil
			}
			return nil, loginTypes.GenericNoRefreshTokenError
		}
	}

	return tokenSetToAuthPayload(d.Tokens, appendRefreshToken), nil
}
