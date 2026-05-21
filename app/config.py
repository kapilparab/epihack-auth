from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings

_ENV_FILE = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"

    # AWS credentials
    AWS_ACCESS_KEY_ID: str = ""
    AWS_SECRET_ACCESS_KEY: str = ""
    AWS_REGION: str = "us-east-2"

    # Cognito
    COGNITO_USER_POOL_ID: str = ""
    COGNITO_CLIENT_ID: str = ""
    COGNITO_CLIENT_SECRET: str = ""

    # Derived — set automatically from pool ID + region if blank
    COGNITO_AUTHORITY: str = ""

    # CORS
    CORS_ORIGINS: str = "http://localhost:5173"

    @property
    def cognito_authority(self) -> str:
        if self.COGNITO_AUTHORITY:
            return self.COGNITO_AUTHORITY
        return f"https://cognito-idp.{self.AWS_REGION}.amazonaws.com/{self.COGNITO_USER_POOL_ID}"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",")]

    class Config:
        env_file = str(_ENV_FILE)
        case_sensitive = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
