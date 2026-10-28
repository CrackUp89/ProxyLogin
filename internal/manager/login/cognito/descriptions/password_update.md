Changes the password for the currently authenticated user.

Requires a valid auth token via cookie or `Authorization: Bearer` header, plus the update session cookie and CSRF header from `/v1/password/update/start`.

**Request fields**:
- `current_password` *(required)* — the user's existing password.
- `new_password` *(required)* — the new password to set.

**On success**: the update session is closed and its cookie is cleared.
