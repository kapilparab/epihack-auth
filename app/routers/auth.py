from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from app.cognito import auth_params, client, secret_hash
from app.config import get_settings
from app.jwt_validator import get_current_user

_settings = get_settings()

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Helpers ──────────────────────────────────────────────────────

def _validate_client(client_id: str) -> None:
    """Raise 400 if client_id is not in the registered allow-list."""
    if client_id not in _settings.allowed_client_ids:
        raise HTTPException(status_code=400, detail=f"Unknown client_id: {client_id}")


# ── Request models ───────────────────────────────────────────────

class RegisterRequest(BaseModel):
    client_id: str
    name: str
    email: EmailStr
    password: str
    role: str = "citizen"


class LoginRequest(BaseModel):
    client_id: str
    email: EmailStr
    password: str


class ConfirmRequest(BaseModel):
    client_id: str
    email: EmailStr
    code: str


class ResendConfirmationRequest(BaseModel):
    client_id: str
    email: EmailStr


class RefreshRequest(BaseModel):
    client_id: str
    refresh_token: str
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    client_id: str
    email: EmailStr


class ConfirmForgotPasswordRequest(BaseModel):
    client_id: str
    email: EmailStr
    code: str
    new_password: str


# ── Endpoints ────────────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register(req: RegisterRequest):
    """Create a new Cognito user. Returns whether email confirmation is pending."""
    _validate_client(req.client_id)
    try:
        sh = secret_hash(req.email, req.client_id)
        kwargs: dict = dict(
            ClientId=req.client_id,
            Username=req.email,
            Password=req.password,
            UserAttributes=[
                {"Name": "email",       "Value": req.email},
                {"Name": "name",        "Value": req.name},
                {"Name": "custom:role", "Value": req.role},
            ],
        )
        if sh:
            kwargs["SecretHash"] = sh
        resp = client.sign_up(**kwargs)
        return {"needs_confirmation": not resp["UserConfirmed"]}
    except client.exceptions.UsernameExistsException:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    except client.exceptions.InvalidPasswordException as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/confirm")
async def confirm(req: ConfirmRequest):
    """Confirm a user's email address with the verification code sent by Cognito."""
    _validate_client(req.client_id)
    try:
        sh = secret_hash(req.email, req.client_id)
        kwargs: dict = dict(
            ClientId=req.client_id,
            Username=req.email,
            ConfirmationCode=req.code,
        )
        if sh:
            kwargs["SecretHash"] = sh
        client.confirm_sign_up(**kwargs)
        return {"confirmed": True}
    except client.exceptions.CodeMismatchException:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    except client.exceptions.ExpiredCodeException:
        raise HTTPException(status_code=400, detail="Verification code has expired — request a new one")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/resend-confirmation")
async def resend_confirmation(req: ResendConfirmationRequest):
    """Resend the email verification code."""
    _validate_client(req.client_id)
    try:
        sh = secret_hash(req.email, req.client_id)
        kwargs: dict = dict(ClientId=req.client_id, Username=req.email)
        if sh:
            kwargs["SecretHash"] = sh
        client.resend_confirmation_code(**kwargs)
        return {"sent": True}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/login")
async def login(req: LoginRequest):
    """Authenticate with Cognito USER_PASSWORD_AUTH flow. Returns id, access, and refresh tokens."""
    _validate_client(req.client_id)
    try:
        resp = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=auth_params(req.email, req.client_id, {"PASSWORD": req.password}),
            ClientId=req.client_id,
        )
        result = resp["AuthenticationResult"]
        return {
            "id_token":      result["IdToken"],
            "access_token":  result["AccessToken"],
            "refresh_token": result["RefreshToken"],
            "expires_in":    result["ExpiresIn"],
            "token_type":    result["TokenType"],
        }
    except client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    except client.exceptions.UserNotConfirmedException:
        raise HTTPException(status_code=403, detail="Please confirm your email before signing in")
    except client.exceptions.UserNotFoundException:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/refresh")
async def refresh(req: RefreshRequest):
    """Exchange a refresh token for a new id_token and access_token."""
    _validate_client(req.client_id)
    try:
        params: dict = {"REFRESH_TOKEN": req.refresh_token}
        sh = secret_hash(req.email, req.client_id)
        if sh:
            params["SECRET_HASH"] = sh
        resp = client.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=params,
            ClientId=req.client_id,
        )
        result = resp["AuthenticationResult"]
        return {
            "id_token":     result["IdToken"],
            "access_token": result["AccessToken"],
            "expires_in":   result["ExpiresIn"],
            "token_type":   result["TokenType"],
        }
    except client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail="Refresh token is invalid or expired")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/logout-with-token")
async def logout_with_token(access_token: str):
    """
    Invalidate all tokens for the current user using the Cognito access_token.
    Send the access_token as a query parameter: POST /auth/logout-with-token?access_token=...
    """
    try:
        client.global_sign_out(AccessToken=access_token)
        return {"logged_out": True}
    except client.exceptions.NotAuthorizedException:
        raise HTTPException(status_code=401, detail="Access token is invalid or expired")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/forgot-password")
async def forgot_password(req: ForgotPasswordRequest):
    """Trigger the Cognito forgot-password flow. Sends a reset code to the user's email."""
    _validate_client(req.client_id)
    try:
        sh = secret_hash(req.email, req.client_id)
        kwargs: dict = dict(ClientId=req.client_id, Username=req.email)
        if sh:
            kwargs["SecretHash"] = sh
        client.forgot_password(**kwargs)
        return {"code_sent": True}
    except client.exceptions.UserNotFoundException:
        return {"code_sent": True}  # don't reveal whether the account exists
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/confirm-forgot-password")
async def confirm_forgot_password(req: ConfirmForgotPasswordRequest):
    """Complete the forgot-password flow by submitting the reset code and new password."""
    _validate_client(req.client_id)
    try:
        sh = secret_hash(req.email, req.client_id)
        kwargs: dict = dict(
            ClientId=req.client_id,
            Username=req.email,
            ConfirmationCode=req.code,
            Password=req.new_password,
        )
        if sh:
            kwargs["SecretHash"] = sh
        client.confirm_forgot_password(**kwargs)
        return {"password_reset": True}
    except client.exceptions.CodeMismatchException:
        raise HTTPException(status_code=400, detail="Invalid reset code")
    except client.exceptions.ExpiredCodeException:
        raise HTTPException(status_code=400, detail="Reset code has expired — request a new one")
    except client.exceptions.InvalidPasswordException as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    """Return the claims from the validated id_token."""
    return {
        "sub":    current_user.get("sub"),
        "email":  current_user.get("email"),
        "name":   current_user.get("name"),
        "role":   current_user.get("custom:role"),
        "groups": current_user.get("cognito:groups", []),
    }
