import os
from pathlib import Path

from dotenv import dotenv_values, load_dotenv


def load_backend_environment(path: Path | None = None) -> None:
    environment_file = path or Path(__file__).resolve().parents[1] / ".env"
    configured_environment = os.getenv("APP_ENV")
    if configured_environment and configured_environment.lower() == "production":
        return
    if not configured_environment:
        file_environment = dotenv_values(environment_file).get("APP_ENV", "development")
        if isinstance(file_environment, str) and file_environment.lower() == "production":
            os.environ["APP_ENV"] = "production"
            return
    load_dotenv(environment_file, override=False)


load_backend_environment()