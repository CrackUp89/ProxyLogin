Logs in with an authorization code issued by the Cognito hosted UI or an external identity provider.

**Not implemented yet** — the endpoint is registered but does not work.

Requires the login session cookie and CSRF header from `/v1/login/start`.

**Request fields**:
- `code` *(required)* — authorization code received from the external authentication authority.
- `remember` *(optional)* — if `true`, issued cookies carry a persistent `Max-Age`/`Expires`.
