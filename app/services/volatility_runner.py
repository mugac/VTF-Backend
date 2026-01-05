import subprocess
import logging
import time
import sys
import platform 
from pathlib import Path

from app.core.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def run_volatility_analysis(dump_path: Path, plugin: str):

    analysis_id = dump_path.stem 
    output_dir = dump_path.parent
    cache_file = output_dir / f"{plugin.split('.')[-1].lower()}.json"

    logger.info(f"[{analysis_id}] Začíná analýza pluginem: {plugin}")

    time.sleep(10)
    
    # Použijeme Python z konfigurace (měl by být z venv)
    python_path = settings.PYTHON_PATH
    
    # Najdeme vol v Scripts adresáři venv
    scripts_dir = python_path.parent
    vol_executable = "vol.exe" if platform.system() == "Windows" else "vol"
    vol_path = scripts_dir / vol_executable
    
    logger.info(f"[{analysis_id}] Používám Python: {python_path}")
    logger.info(f"[{analysis_id}] Hledám vol v: {vol_path}")
    
    if not vol_path.exists():
        logger.error(f"[{analysis_id}] Spouštěcí skript Volatility nebyl nalezen v: {vol_path}")
        logger.info(f"[{analysis_id}] Zkusím spustit přímo přes Python modul...")
        # Jako fallback zkusíme spustit přímo jako Python modul
        command = [
            str(python_path),
            "-m", "volatility3.cli",
            "-f", str(dump_path),
            "--output-dir", str(output_dir),
            "--renderer", "json",
            plugin
        ]
    else:
        command = [
            str(vol_path),
            "-f", str(dump_path),
            "--output-dir", str(output_dir),
            "--renderer", "json",
            plugin
        ]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        if result.returncode == 0:
        # Proces proběhl, vezmeme jeho standardní výstup a uložíme ho do našeho cache souboru
            with open(cache_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            logger.info(f"[{analysis_id}] Analýza dokončena. Výsledky uloženy do {cache_file}")
        else:
            # Proces selhal, zalogujeme chybový výstup
            logger.error(f"[{analysis_id}] Volatility skončilo s chybou (exit code: {result.returncode}):")
            logger.error(f"[{analysis_id}] STDERR:\n{result.stderr}")

    except Exception as e:
        logger.error(f"[{analysis_id}] Kritická chyba při spouštění podprocesu: {e}")