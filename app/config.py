from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    gateway_ip: str = "192.168.1.1"
    interface: str = "eth0"
    auth_password: str
    arp_interval: float = 2.0
    db_path: str = "/data/netguard.db"
    tz: str = "America/New_York"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
