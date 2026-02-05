from pydantic import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Database Configuration
    DB_USER: str = "root"
    DB_PASSWORD: str = "root"
    DB_HOST: str = "localhost"
    DB_PORT: int = 3306
    DB_NAME: str = "fast_api"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

    @property
    def database_url(self) -> str:
        """Construct database URL from individual components"""
        return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    # JWT Configuration
    ACCESS_TOKEN_EXP_TIME: int = 15
    SECRET_KEY : str
    ALGORITHM : str = 'HS256'
    REFRESH_TOKEN_EXP_TIME : int
    REFRESH_SECRET_KEY : str

    # Email Verification Configuration (OTP-based)
    OTP_EXPIRY_MINUTES: int = 10  # OTP expiry time in minutes

    # n8n Webhook Configuration
    N8N_WEBHOOK_BASE_URL: str = "http://localhost:5678/webhook"

    # Logging Configuration
    LOG_LEVEL: str = "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    LOG_TO_FILE: bool = True


# Global settings instance
settings = Settings()
