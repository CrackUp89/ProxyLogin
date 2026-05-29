Changes the password for the currently authenticated user.

Requires a valid auth token via cookie or `Authorization: Bearer` header.

**Request fields**:
- `current_password` *(required)* — the user's existing password.
- `new_password` *(required)* — the new password to set.
