# EpiHack Auth Service

Standalone FastAPI service for AWS Cognito authentication used by the EpiHack epidemic radar platform.

## Setup

```bash
cp .env.example .env   # fill in your Cognito values
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8001
```

Interactive docs available at `http://localhost:8001/docs`.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | No | AWS key (omit to use instance role / `AWS_PROFILE`) |
| `AWS_SECRET_ACCESS_KEY` | No | AWS secret |
| `AWS_REGION` | No | AWS region (default: `us-east-2`) |
| `COGNITO_USER_POOL_ID` | Yes | Cognito User Pool ID (e.g. `us-east-2_XXXXXXXXX`) |
| `COGNITO_CLIENT_ID` | Yes | App client ID |
| `COGNITO_CLIENT_SECRET` | No | App client secret (leave blank if client has none) |
| `COGNITO_AUTHORITY` | No | Override issuer URL (auto-derived from region + pool ID if blank) |
| `CORS_ORIGINS` | No | Comma-separated allowed origins (default: `http://localhost:5173`) |
| `ENVIRONMENT` | No | `development` / `production` |

---

## API Reference

All endpoints are prefixed with `/auth`.

### Health

#### `GET /health`

Returns service status.

**Response `200`**
```json
{ "status": "ok", "env": "development" }
```

---

### Register

#### `POST /auth/register`

Create a new user account. Cognito sends a verification code to the user's email.

**Request body**
```json
{
  "name": "Alice Smith",
  "email": "alice@example.com",
  "password": "Str0ng!Pass",
  "role": "citizen"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `name` | string | Yes | Display name stored as `name` attribute |
| `email` | string | Yes | Used as the Cognito username |
| `password` | string | Yes | Must meet the User Pool's password policy |
| `role` | string | No | Stored as `custom:role` (default: `citizen`) |

**Response `201`**
```json
{ "needs_confirmation": true }
```

**Error responses**

| Status | Detail |
|---|---|
| `409` | An account with this email already exists |
| `422` | Password does not meet policy requirements |
| `400` | Other Cognito error |

---

### Confirm Email

#### `POST /auth/confirm`

Submit the 6-digit verification code sent to the user's email after registration.

**Request body**
```json
{
  "email": "alice@example.com",
  "code": "123456"
}
```

**Response `200`**
```json
{ "confirmed": true }
```

**Error responses**

| Status | Detail |
|---|---|
| `400` | Invalid verification code |
| `400` | Verification code has expired — request a new one |

---

### Resend Confirmation Code

#### `POST /auth/resend-confirmation`

Re-send the email verification code for an unconfirmed account.

**Request body**
```json
{ "email": "alice@example.com" }
```

**Response `200`**
```json
{ "sent": true }
```

---

### Login

#### `POST /auth/login`

Authenticate and receive tokens.

**Request body**
```json
{
  "email": "alice@example.com",
  "password": "Str0ng!Pass"
}
```

**Response `200`**
```json
{
  "id_token": "<JWT>",
  "access_token": "<JWT>",
  "refresh_token": "<opaque>",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

| Token | Use |
|---|---|
| `id_token` | Pass as `Authorization: Bearer <id_token>` to protected endpoints |
| `access_token` | Required for `/auth/logout-with-token` and direct Cognito API calls |
| `refresh_token` | Exchange for new tokens via `/auth/refresh` |

**Error responses**

| Status | Detail |
|---|---|
| `401` | Invalid email or password |
| `403` | Please confirm your email before signing in |

---

### Refresh Tokens

#### `POST /auth/refresh`

Exchange a refresh token for a new `id_token` and `access_token` without re-entering credentials.

**Request body**
```json
{
  "refresh_token": "<opaque>",
  "email": "alice@example.com"
}
```

> `email` is required only when the Cognito app client has a secret (needed to compute `SECRET_HASH`). It can be omitted otherwise.

**Response `200`**
```json
{
  "id_token": "<JWT>",
  "access_token": "<JWT>",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

**Error responses**

| Status | Detail |
|---|---|
| `401` | Refresh token is invalid or expired |

---

### Logout

#### `POST /auth/logout-with-token?access_token=<token>`

Invalidate all tokens for the user (Cognito global sign-out). Requires the **access_token** (not the id_token).

**Query parameter**

| Parameter | Required | Description |
|---|---|---|
| `access_token` | Yes | The `access_token` returned by `/auth/login` or `/auth/refresh` |

**Response `200`**
```json
{ "logged_out": true }
```

**Error responses**

| Status | Detail |
|---|---|
| `401` | Access token is invalid or expired |

---

### Forgot Password

#### `POST /auth/forgot-password`

Trigger the password-reset flow. Cognito sends a reset code to the user's email.

> Always returns `{ "code_sent": true }` regardless of whether the account exists, to prevent user enumeration.

**Request body**
```json
{ "email": "alice@example.com" }
```

**Response `200`**
```json
{ "code_sent": true }
```

---

### Confirm Forgot Password

#### `POST /auth/confirm-forgot-password`

Complete the password-reset flow by submitting the reset code and the new password.

**Request body**
```json
{
  "email": "alice@example.com",
  "code": "123456",
  "new_password": "N3wStr0ng!Pass"
}
```

**Response `200`**
```json
{ "password_reset": true }
```

**Error responses**

| Status | Detail |
|---|---|
| `400` | Invalid reset code |
| `400` | Reset code has expired — request a new one |
| `422` | New password does not meet policy requirements |

---

### Current User

#### `GET /auth/me`

Decode the id_token and return the current user's claims.

**Headers**
```
Authorization: Bearer <id_token>
```

**Response `200`**
```json
{
  "sub": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "email": "alice@example.com",
  "name": "Alice Smith",
  "role": "citizen",
  "groups": []
}
```

**Error responses**

| Status | Detail |
|---|---|
| `401` | Could not validate credentials |

---

## Token Validation (for other services)

Import `get_current_user` from `app.jwt_validator` as a FastAPI dependency to protect any endpoint:

```python
from app.jwt_validator import get_current_user
from fastapi import Depends

@router.get("/protected")
async def protected(current_user: dict = Depends(get_current_user)):
    return {"email": current_user["email"]}
```

Tokens are validated against the Cognito User Pool's public JWKS keys (RS256). Keys are fetched lazily on first use and refreshed automatically on key-ID cache miss to handle Cognito key rotation.
