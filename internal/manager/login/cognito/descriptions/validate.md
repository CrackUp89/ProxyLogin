Validates one or more JWT tokens and returns per-token validity.

**Token sources** (mutually exclusive):
- **Cookie mode** — tokens are read automatically from the configured cookies (`token.cookies.accessCookieName`, `token.cookies.idCookieName`).
- **Explicit map** — supply a `tokens` object whose keys are arbitrary names and values are raw JWT strings. When `tokens` is present, cookies are ignored.

**Response status**:
- `return_unauthorized: no` — always returns `200`.
- `return_unauthorized: any` *(default)* — returns `401` if at least one token is invalid.
- `return_unauthorized: all` — returns `401` only if every token is invalid.

The response body shape is the same for both `200` and `401`: `tokens` maps each name to a boolean, and `validation_errors` (present when `return_errors: true`) maps each failed name to a human-readable error string.
