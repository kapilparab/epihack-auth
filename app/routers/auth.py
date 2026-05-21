from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from app.cognito import auth_params, client, secret_hash
from app.config import get_settings
from app.jwt_validator import get_current_user

_settings = get_settings()
_CLIENT_ID = _settings.COGNITO_CLIENT_ID

router = APIRouter(prefix="/auth", tags=["Authentication"])


# ── Request models ───────────────────────────────────────────────

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: str = "citizen"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ConfirmRequest(BaseModel):
    email: EmailStr
    code: str


class ResendConfirmationRequest(BaseModel):
    email: EmailStr


class RefreshRequest(BaseModel):
    refresh_token: str
    email: EmailStr


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ConfirmForgotPasswordRequest(BaseModel):
    email: EmailStr
    code: str
    new_password: str


# ── Endpoints ────────────────────────────────────────────────────

@router.post("/register", status_code=201)
async def register(req: RegisterRequest):
    """Create a new Cognito user. Returns whether email confirmation is pending."""
    try:
        sh = secret_hash(req.email)
        kwargs: dict = dict(
            ClientId=_CLIENT_ID,
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
    try:
        sh = secret_hash(req.email)
        kwargs: dict = dict(
            ClientId=_CLIENT_ID,
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
    try:
        sh = secret_hash(req.email)
        kwargs: dict = dict(ClientId=_CLIENT_ID, Username=req.email)
        if sh:
            kwargs["SecretHash"] = sh
        client.resend_confirmation_code(**kwargs)
        return {"sent": True}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/login")
async def login(req: LoginRequest):
    """Authenticate with Cognito USER_PASSWORD_AUTH flow. Returns id, access, and refresh tokens."""
    try:
        resp = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=auth_params(req.email, {"PASSWORD": req.password}),
            ClientId=_CLIENT_ID,
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
    try:
        params = {"REFRESH_TOKEN": req.refresh_token}
        sh = secret_hash(req.email)
        if sh:
            params["SECRET_HASH"] = sh
        resp = client.initiate_auth(
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters=params,
            ClientId=_CLIENT_ID,
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


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """
    Invalidate all tokens for the current user (global sign-out).
    Requires a valid access_token in the Authorization: Bearer header.
    Note: pass the access_token here, not the id_token.
    """
    try:
        # get_current_user validates the id_token; for global_sign_out we need
        # the access_token which is not parsed here — the client must send it
        # separately. We accept it as a query param to keep it out of logs.
        raise HTTPException(
            status_code=501,
            detail=(
                "Pass the access_token directly to /auth/logout-with-token. "
                "global_sign_out requires the access_token, not the id_token."
            ),
        )
    except HTTPException:
        raise


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
    try:
        sh = secret_hash(req.email)
        kwargs: dict = dict(ClientId=_CLIENT_ID, Username=req.email)
        if sh:
            kwargs["SecretHash"] = sh
        client.forgot_password(**kwargs)
        return {"code_sent": True}
    except client.exceptions.UserNotFoundException:
        # Don't reveal whether the account exists
        return {"code_sent": True}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/confirm-forgot-password")
async def confirm_forgot_password(req: ConfirmForgotPasswordRequest):
    """Complete the forgot-password flow by submitting the reset code and new password."""
    try:
        sh = secret_hash(req.email)
        kwargs: dict = dict(
            ClientId=_CLIENT_ID,
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
        "sub":   current_user.get("sub"),
        "email": current_user.get("email"),
        "name":  current_user.get("name"),
        "role":  current_user.get("custom:role"),
        "groups": current_user.get("cognito:groups", []),
    }
