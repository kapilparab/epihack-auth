import base64
import hashlib
import hmac

import boto3

from app.config import get_settings

_settings = get_settings()

client = boto3.client(
    "cognito-idp",
    region_name=_settings.AWS_REGION,
    aws_access_key_id=_settings.AWS_ACCESS_KEY_ID or None,
    aws_secret_access_key=_settings.AWS_SECRET_ACCESS_KEY or None,
)


def secret_hash(username: str) -> str | None:
    """Compute the HMAC-SHA256 SECRET_HASH Cognito requires when the app client has a secret."""
    if not _settings.COGNITO_CLIENT_SECRET:
        return None
    msg = (username + _settings.COGNITO_CLIENT_ID).encode()
    key = _settings.COGNITO_CLIENT_SECRET.encode()
    return base64.b64encode(hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()).decode()


def auth_params(username: str, extra: dict) -> dict:
    params = {"USERNAME": username, **extra}
    h = secret_hash(username)
    if h:
        params["SECRET_HASH"] = h
    return params
