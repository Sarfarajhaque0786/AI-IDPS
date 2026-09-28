from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60
    PREVENTION_MODE: str = "SIMULATION"  # OFF | SIMULATION | ACTIVE-LAB

    class Config:
        env_file = ".env"


settings = Settings()