import base64
import hashlib
import hmac

import boto3

from app.config import get_settings

_settings = get_settings()

client = boto3.client(
    "cognito-idp",
    region_name=_settings.COGNITO_REGION,
)


def secret_hash(username: str, client_id: str) -> str | None:
    """Compute the HMAC-SHA256 SECRET_HASH for the given app client."""
    client_secret = _settings.cognito_clients.get(client_id, "")
    if not client_secret:
        return None
    msg = (username + client_id).encode()
    key = client_secret.encode()
    return base64.b64encode(hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()).decode()


def auth_params(username: str, client_id: str, extra: dict) -> dict:
    params = {"USERNAME": username, **extra}
    h = secret_hash(username, client_id)
    if h:
        params["SECRET_HASH"] = h
    return params
