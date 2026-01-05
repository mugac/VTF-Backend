from pydantic_settings import BaseSettings
from pathlib import Path
import sys
import os

class Settings(BaseSettings):
    STORAGE_PATH: Path = Path("data")
    # Cesta k Python interpretu ve venv (výchozí je aktuální Python)
    PYTHON_PATH: Path = Path(sys.executable)

    class Config:
        env_file = ".env"
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Pokud je PYTHON_PATH relativní, převedeme ji na absolutní vzhledem k project root
        if not self.PYTHON_PATH.is_absolute():
            # Najdeme root projektu (kde je .env)
            current_file = Path(__file__)
            project_root = current_file.parent.parent.parent  # app/core/config.py -> VTF-Backend/
            self.PYTHON_PATH = (project_root / self.PYTHON_PATH).resolve()

settings = Settings()