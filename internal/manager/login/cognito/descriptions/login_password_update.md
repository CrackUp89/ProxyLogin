Sets a new password to satisfy a mandatory password-change challenge during the login flow.

This endpoint is called after receiving a `next_step: new_password` response. Cognito issues this challenge when the user's password has been administratively set or reset and must be changed before access is granted. The preceding response may include a `payload.required` field listing additional attributes that must be supplied alongside the new password.

Requires the login session cookie and CSRF header from `/v1/login/start`.

**Request fields**:
- `user` *(required)* — username or email address.
- `password` *(required)* — new password chosen by the user.
- `attributes` *(optional)* — map of additional user attributes required by the pool (keys are listed in `payload.required` of the preceding step).

**On success**: the password is updated and the login flow continues. The response may contain a further `next_step` (e.g. MFA setup) or, if no more steps are required, tokens are delivered using the same mechanism as the `/v1/login` endpoint.
