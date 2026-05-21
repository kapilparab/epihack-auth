# EpiHack Auth Service

Standalone FastAPI service for AWS Cognito authentication used by the EpiHack epidemic radar platform.
Supports multiple frontend app clients from a single deployment.

## Deploy to AWS Lambda (container image)

### Prerequisites

- AWS CLI configured (`aws configure`)
- Docker running locally
- IAM permissions for ECR and Lambda

### 1. Build and push the image

ECR repository: `arn:aws:ecr:us-east-2:206896361792:repository/epihack`

```bash
REPO=206896361792.dkr.ecr.us-east-2.amazonaws.com/epihack

# Authenticate Docker to ECR
aws ecr get-login-password --region us-east-2 | docker login --username AWS --password-stdin 206896361792.dkr.ecr.us-east-2.amazonaws.com

# Build for Lambda (amd64 required, provenance=false required)
docker build --platform linux/amd64 --provenance=false -t epihack-auth .
docker tag epihack-auth:latest $REPO:latest
docker push $REPO:latest
```

### 2. Create the Lambda function

1. **Lambda → Create function → Container image**
2. **Function name:** `epihack-auth`
3. **Container image URI:** `206896361792.dkr.ecr.us-east-2.amazonaws.com/epihack:latest`
4. **Architecture:** `x86_64`
5. Click **Create function**

### 3. Add environment variables

In the Lambda console go to **Configuration → Environment variables** and add:

| Key | Value |
|---|---|
| `ENVIRONMENT` | `production` |
| `COGNITO_REGION` | `us-east-2` |
| `COGNITO_USER_POOL_ID` | `us-east-2_YoX88Tklu` |
| `COGNITO_CLIENT_IDS` | `<client-id-app1>,<client-id-app2>` |
| `COGNITO_CLIENT_SECRETS` | `<secret-app1>,<secret-app2>` (blank entry if a client has no secret) |
| `CORS_ORIGINS` | `https://your-frontend-domain.com` |

> `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_REGION` are reserved by Lambda and cannot be set. Credentials are provided automatically via the Lambda execution role.

### 4. Grant Cognito permissions to the execution role

The Lambda execution role needs permission to call Cognito. In **IAM → Roles → find the Lambda role → Add permissions**, attach:

```
arn:aws:iam::aws:policy/AmazonCognitoPowerUser
```

### 5. Add a Function URL (public HTTPS endpoint)

1. **Configuration → Function URL → Create function URL**
2. **Auth type:** `NONE`
3. Copy the URL — your service is live at `https://<url-id>.lambda-url.us-east-2.on.aws`

### 6. Redeploy after an image update

```bash
# Push a new image (see step 1), then update the function
aws lambda update-function-code \
  --function-name epihack-auth \
  --image-uri 206896361792.dkr.ecr.us-east-2.amazonaws.com/epihack:latest \
  --region us-east-2
```

---

## Local Setup

```bash
cp .env .env.local   # edit with your local Cognito values
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8080
```

Interactive docs available at `http://localhost:8080/docs`.

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `COGNITO_REGION` | No | AWS region for Cognito (default: `us-east-2`) |
| `COGNITO_USER_POOL_ID` | Yes | Cognito User Pool ID (e.g. `us-east-2_XXXXXXXXX`) |
| `COGNITO_CLIENT_IDS` | Yes | Comma-separated app client IDs, one per frontend |
| `COGNITO_CLIENT_SECRETS` | No | Comma-separated secrets in the same order as IDs; leave entry blank if a client has no secret |
| `COGNITO_AUTHORITY` | No | Override issuer URL (auto-derived from `COGNITO_REGION` + `COGNITO_USER_POOL_ID` if blank) |
| `CORS_ORIGINS` | No | Comma-separated allowed origins (default: `http://localhost:5173`) |
| `ENVIRONMENT` | No | `development` / `production` |

---

## API Reference

All endpoints are prefixed with `/auth`. Every request body requires a `client_id` field matching one of the registered app clients.

### Health

#### `GET /health`

Returns service status.

**Response `200`**
```json
{ "status": "ok", "env": "production" }
```

---

### Register

#### `POST /auth/register`

Create a new user account. Cognito sends a verification code to the user's email.

**Request body**
```json
{
  "client_id": "<your-app-client-id>",
  "name": "Alice Smith",
  "email": "alice@example.com",
  "password": "Str0ng!Pass",
  "role": "citizen"
}
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `client_id` | string | Yes | Must match a registered app client |
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
| `400` | Unknown client_id |
| `409` | An account with this email already exists |
| `422` | Password does not meet policy requirements |

---

### Confirm Email

#### `POST /auth/confirm`

Submit the 6-digit verification code sent to the user's email after registration.

**Request body**
```json
{
  "client_id": "<your-app-client-id>",
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
| `400` | Unknown client_id |
| `400` | Invalid verification code |
| `400` | Verification code has expired — request a new one |

---

### Resend Confirmation Code

#### `POST /auth/resend-confirmation`

Re-send the email verification code for an unconfirmed account.

**Request body**
```json
{
  "client_id": "<your-app-client-id>",
  "email": "alice@example.com"
}
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
  "client_id": "<your-app-client-id>",
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
| `400` | Unknown client_id |
| `401` | Invalid email or password |
| `403` | Please confirm your email before signing in |

---

### Refresh Tokens

#### `POST /auth/refresh`

Exchange a refresh token for a new `id_token` and `access_token` without re-entering credentials.

**Request body**
```json
{
  "client_id": "<your-app-client-id>",
  "email": "alice@example.com",
  "refresh_token": "<opaque>"
}
```

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
| `400` | Unknown client_id |
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
{
  "client_id": "<your-app-client-id>",
  "email": "alice@example.com"
}
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
  "client_id": "<your-app-client-id>",
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
| `400` | Unknown client_id |
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

Tokens are validated against the Cognito User Pool's public JWKS keys (RS256). Keys are fetched lazily on first use and refreshed automatically on key-ID cache miss to handle Cognito key rotation. Tokens from any registered app client are accepted.
