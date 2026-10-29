package cognito

import (
	"context"
	"errors"
	appconfig "proxylogin/internal/manager/config"
	"proxylogin/internal/manager/login/masquerade"
	loginTypes "proxylogin/internal/manager/login/types"
	"slices"
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

func extractClaim(token *jwt.Token, claim string) (any, bool) {
	if token.Valid && token.Claims != nil {
		if claims, ok := token.Claims.(jwt.MapClaims); token.Valid && ok {
			if v, ok := claims[claim]; ok {
				return v, true
			}
		}
	}
	return nil, false
}

const (
	accessTokenUse = "access"
	idTokenUse     = "id"
)

// validateAccessToken validates the signature, expiry and issuer of an access token and checks that it
// is an access token issued to one of the configured app clients
func (c *Cognito) validateAccessToken(token string) (*jwt.Token, loginTypes.GenericError) {
	return c.validateCognitoToken(token, accessTokenUse)
}

// validateCognitoToken validates the signature, expiry and issuer of a token, checks that its token_use is one of
// allowedUses and that it was issued to one of the configured app clients (client_id for access tokens, aud for id tokens)
func (c *Cognito) validateCognitoToken(token string, allowedUses ...string) (*jwt.Token, loginTypes.GenericError) {
	t, err := c.jwksValidator.ValidateToken(token)
	if err != nil {
		return nil, loginTypes.NewGenericAuthError("jwks validation failed", "invalid token", err)
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return nil, loginTypes.GenericNoClaimsError
	}

	tokenUse, _ := claims["token_use"].(string)
	if !slices.Contains(allowedUses, tokenUse) {
		return nil, loginTypes.GenericInvalidTokenUseError
	}

	switch tokenUse {
	case accessTokenUse:
		tokenClientId, _ := claims["client_id"].(string)
		if tokenClientId == "" {
			return nil, loginTypes.GenericNoClientIdError
		}
		if !c.isKnownClientId(tokenClientId) {
			return nil, loginTypes.GenericInvalidClientIdError
		}
	case idTokenUse:
		aud, err := t.Claims.GetAudience()
		if err != nil || len(aud) == 0 {
			return nil, loginTypes.GenericNoClientIdError
		}
		if !slices.ContainsFunc(aud, c.isKnownClientId) {
			return nil, loginTypes.GenericInvalidClientIdError
		}
	}

	return t, nil
}

// isKnownClientId reports whether tokens issued to clientId are accepted: the main client or, when configured, the external login client
func (c *Cognito) isKnownClientId(clientId string) bool {
	return clientId == c.cfg.Client.ID || (c.cfg.ExternalClient.ID != "" && clientId == c.cfg.ExternalClient.ID)
}

func checkAuthToken[R any, PR interface {
	*R
	WithTaskResultBase
}](c *Cognito, accessToken string, ef errorFactory[R, PR]) PR {
	if accessToken == "" {
		return ef(loginTypes.GenericUnauthorizedError)
	}

	if _, err := c.validateAccessToken(accessToken); err != nil {
		return ef(err)
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

// clientConfig returns the app client with the given id: the external login client when it matches, the main client otherwise
func (c *Cognito) clientConfig(clientId string) appconfig.ClientConfig {
	if clientId != "" && clientId == c.cfg.ExternalClient.ID {
		return c.cfg.ExternalClient
	}
	return c.cfg.Client
}

// refreshToken exchanges a refresh token for new tokens; the token must be refreshed with the client it was issued to
func (c *Cognito) refreshToken(ctx context.Context, client appconfig.ClientConfig, token string, user string) (*cognitoTypes.AuthenticationResultType, error) {
	if c.useAuthToRefresh {
		input := &cognitoidentityprovider.InitiateAuthInput{
			AuthFlow: cognitoTypes.AuthFlowTypeRefreshTokenAuth,
			ClientId: aws.String(client.ID),
			AuthParameters: map[string]string{
				"REFRESH_TOKEN": token,
			},
		}

		if client.Secret != "" {
			input.AuthParameters["SECRET_HASH"] = computeSecretHash(client.Secret, user, client.ID)
		}

		result, err := c.cognitoClient.InitiateAuth(ctx, input)
		if err != nil {
			return nil, err
		}
		return result.AuthenticationResult, nil
	}

	input := &cognitoidentityprovider.GetTokensFromRefreshTokenInput{
		ClientId:     aws.String(client.ID),
		RefreshToken: aws.String(token),
	}

	if client.Secret != "" {
		input.ClientSecret = aws.String(client.Secret)
	}

	result, err := c.cognitoClient.GetTokensFromRefreshToken(ctx, input)

	if err != nil {
		return nil, err
	}
	return result.AuthenticationResult, nil

}

const (
	masqueradeRefreshTimeout = 30 * time.Second
	// tokens expiring within this margin are refreshed ahead of time
	masqueradeRefreshMargin = 10 * time.Second
	// extra lock lifetime on top of masqueradeRefreshTimeout
	masqueradeRefreshLockMargin = 5 * time.Second
	masqueradeRefreshLockPrefix = "masqueradeRefresh:"
)

// isRefreshTokenRejected reports whether Cognito rejected the refresh token itself (expired, revoked or reused),
// as opposed to a transient failure, after which the refresh token may still be valid
func isRefreshTokenRejected(err error) bool {
	if _, ok := errors.AsType[*cognitoTypes.NotAuthorizedException](err); ok {
		return true
	}
	if _, ok := errors.AsType[*cognitoTypes.RefreshTokenReuseException](err); ok {
		return true
	}
	return false
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
		refreshRequired := masqueradeRefreshRequired(d)

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

			if _, ok := d.Tokens[loginTypes.RefreshTokenType]; !ok {
				return nil, loginTypes.GenericNoRefreshTokenError
			}

			refreshed, gErr := c.refreshMasqueradedToken(ctx, token, requestLogger)
			if gErr != nil {
				return nil, gErr
			}
			return tokenSetToAuthPayload(refreshed.Tokens, appendRefreshToken), nil
		}
	}

	return tokenSetToAuthPayload(d.Tokens, appendRefreshToken), nil
}

// masqueradeRefreshRequired reports whether the access or ID token of a masqueraded record expires within the next
// few seconds
func masqueradeRefreshRequired(d *masquerade.MasqueradedRecord) bool {
	deadline := time.Now().Add(masqueradeRefreshMargin)
	return !d.Tokens[loginTypes.AuthTokenType].Expires.After(deadline) ||
		!d.Tokens[loginTypes.IDTokenType].Expires.After(deadline)
}

// refreshMasqueradedToken refreshes the masqueraded record stored under token. Concurrent refreshes of the same record
// (across all instances when redis storage is used) are serialized by a lock; whoever gets the lock after a
// successful refresh finds the new tokens in storage and returns them without refreshing again.
func (c *Cognito) refreshMasqueradedToken(ctx context.Context, token string, requestLogger *zap.Logger) (*masquerade.MasqueradedRecord, loginTypes.GenericError) {
	// the refresh is not cancelled with the request, so a client disconnecting mid-refresh doesn't lose the new tokens
	refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), masqueradeRefreshTimeout)
	defer cancel()

	// the lock outlives the refresh, so it can't expire mid-refresh and let another refresh in
	unlock, err := c.locks.Lock(refreshCtx, masqueradeRefreshLockPrefix+token, masqueradeRefreshTimeout+masqueradeRefreshLockMargin)
	if err != nil {
		return nil, loginTypes.NewInternalError("unable to refresh token", err)
	}
	defer unlock()

	// the record may have been refreshed while waiting for the lock
	d, err := c.masq.Storage().GetMasqueradedRecord(refreshCtx, token)
	if err != nil {
		return nil, loginTypes.NewInternalError("unable to unmask token", err)
	}
	if d == nil {
		return nil, loginTypes.GenericInvalidTokenMaskError
	}
	if !masqueradeRefreshRequired(d) {
		return d, nil
	}

	rt, ok := d.Tokens[loginTypes.RefreshTokenType]
	if !ok {
		return nil, loginTypes.GenericNoRefreshTokenError
	}

	refreshed, err := c.refreshMasqueradedRecord(refreshCtx, token, d, rt, requestLogger)
	if err != nil {
		if !isRefreshTokenRejected(err) {
			return nil, loginTypes.NewInternalError("unable to refresh token", err)
		}
		c.dropMasqueradedToken(token, requestLogger)
		return nil, loginTypes.NewGenericAuthError("unable to refresh token", "authentication error", err)
	}

	return refreshed, nil
}

// refreshMasqueradedRecord refreshes the tokens of a masqueraded record and stores the new tokens under the same key
func (c *Cognito) refreshMasqueradedRecord(ctx context.Context, key string, d *masquerade.MasqueradedRecord, refreshToken masquerade.TokenRecord, requestLogger *zap.Logger) (*masquerade.MasqueradedRecord, error) {
	authResults, err := c.refreshToken(ctx, c.clientConfig(d.ClientID), refreshToken.Value, d.User)
	if err != nil {
		return nil, err
	}
	if authResults == nil {
		return nil, errors.New("refresh returned no authentication result")
	}

	tokenSet, expires, err := c.authResultToMasqueradeTokenSet(authenticationResultFromCognitoType(authResults))
	if err != nil {
		return nil, err
	}

	// a new refresh token is only returned when rotation is enabled; keep the current one otherwise
	if _, ok := tokenSet[loginTypes.RefreshTokenType]; !ok {
		tokenSet[loginTypes.RefreshTokenType] = refreshToken
		if refreshToken.Expires.After(expires) {
			expires = refreshToken.Expires
		}
	}

	mr := &masquerade.MasqueradedRecord{
		Tokens:   tokenSet,
		User:     d.User,
		ClientID: d.ClientID,
	}

	// the refreshed tokens are still valid for this request, so a failed store is only logged
	if err := c.masq.Storage().StoreMasqueradedRecord(ctx, key, mr, expires); err != nil {
		requestLogger.Error("failed to store refreshed masqueraded record", zap.Error(err))
	}

	return mr, nil
}
