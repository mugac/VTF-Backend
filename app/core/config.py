from pydantic_settings import BaseSettings
from pathlib import Path
from typing import Optional
import sys
import os

# Vypočítáme BASE_DIR před inicializací Settings
_current_file = Path(__file__)
_BASE_DIR = _current_file.parent.parent.parent  # app/core/config.py -> VTF-Backend/

class Settings(BaseSettings):
    STORAGE_PATH: Path = Path("data")
    # Cesta k Python interpretu ve venv (výchozí je aktuální Python)
    PYTHON_PATH: Path = Path(sys.executable)
    
    # Statické cesty vypočítané při importu
    BASE_DIR: Path = _BASE_DIR
    SYMBOLS_CACHE: Path = _BASE_DIR / "data" / "symbols_cache"
    TEMP_DIR: Path = _BASE_DIR / "data" / "temp"

    class Config:
        env_file = ".env"
        arbitrary_types_allowed = True
    
    def model_post_init(self, __context):
        """Volá se po inicializaci modelu"""
        # Pokud je PYTHON_PATH relativní, převedeme ji na absolutní vzhledem k project root
        if not self.PYTHON_PATH.is_absolute():
            object.__setattr__(self, 'PYTHON_PATH', (self.BASE_DIR / self.PYTHON_PATH).resolve())

settings = Settings()