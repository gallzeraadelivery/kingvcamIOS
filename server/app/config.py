from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    public_url: str = "https://kingvcam.com"
    database_url: str = "sqlite:///./kingvcam.db"
    nowpayments_api_key: str = ""
    nowpayments_ipn_secret: str = ""
    nowpayments_api_url: str = "https://api.nowpayments.io/v1"
    admin_token: str = ""
    admin_user: str = "admin"
    admin_password: str = ""
    secret_key: str = ""


settings = Settings()
