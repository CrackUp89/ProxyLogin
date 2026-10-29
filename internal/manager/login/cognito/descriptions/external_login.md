Logs in with an authorization code issued by the Cognito hosted UI or an external identity provider. The code is exchanged at `cognito.tokenURL` using the external app client (`cognito.external.clientId` / `cognito.external.clientSecret`) and `cognito.external.loginRedirectURL` as the redirect URI.

Requires the login session cookie and CSRF header from `/v1/login/start`.

**Request fields**:
- `code` *(required)* — authorization code received from the external authentication authority.
- `remember` *(optional)* — if `true`, issued cookies carry a persistent `Max-Age`/`Expires`.

**Response**: the same as a completed `/v1/login` — tokens (or the masquerade token) are returned or set as cookies and the login session is closed. Tokens are later refreshed with the external app client.

**MFA enforcement**: when `cognito.external.enforceMFA` is `true` (default `false`) and the user pool has MFA set to optional, a user without MFA gets `next_step: mfa_setup` instead of tokens, exactly as with `cognito.enforceMFA` for `/v1/login`. This requires the external client's access token to carry the `aws.cognito.signin.user.admin` scope, and does not work for federated users, whom Cognito MFA does not cover.
