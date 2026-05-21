import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from jose import jwt as jose_jwt

from app.config import get_settings

_settings = get_settings()
_oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


class _JWKSValidator:
    """
    Validates Cognito id_tokens (RS256) using the pool's JWKS endpoint.
    Keys are fetched lazily and refreshed on key-ID cache miss to handle rotation.
    """

    def __init__(self) -> None:
        self._jwks_url = f"{_settings.cognito_authority}/.well-known/jwks.json"
        self._keys: dict[str, dict] = {}

    def _refresh(self) -> None:
        resp = httpx.get(self._jwks_url, timeout=10)
        resp.raise_for_status()
        self._keys = {k["kid"]: k for k in resp.json()["keys"]}

    def decode(self, token: str) -> dict:
        kid = jose_jwt.get_unverified_headers(token).get("kid", "")
        if kid not in self._keys:
            self._refresh()
        if kid not in self._keys:
            raise JWTError(f"Unknown signing key: {kid}")
        return jose_jwt.decode(
            token,
            self._keys[kid],
            algorithms=["RS256"],
            audience=_settings.COGNITO_CLIENT_ID,
            issuer=_settings.cognito_authority,
        )


_validator = _JWKSValidator()


async def get_current_user(token: str = Depends(_oauth2)) -> dict:
    """Validate a Cognito id_token and return its claims. Use as a FastAPI dependency."""
    try:
        return _validator.decode(token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
