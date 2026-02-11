import subprocess
import logging
import sys
import platform
import json
from pathlib import Path
from datetime import datetime

from app.core.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _clean_children(data):
    """Remove empty __children keys from Volatility JSON output to reduce size."""
    if isinstance(data, list):
        for item in data:
            _clean_children(item)
    elif isinstance(data, dict):
        if "__children" in data and data["__children"] == []:
            del data["__children"]
        for value in list(data.values()):
            _clean_children(value)
    return data


def _build_vol_command(dump_path: Path, plugin: str, symbol_path: Path = None, pid: int = None, extra_args: dict = None) -> list:
    """Build the Volatility 3 CLI command."""
    python_path = settings.PYTHON_PATH
    scripts_dir = python_path.parent
    vol_executable = "vol.exe" if platform.system() == "Windows" else "vol"
    vol_path = scripts_dir / vol_executable

    if not vol_path.exists():
        logger.info(f"vol not found at {vol_path}, using python -m volatility3.cli")
        command = [str(python_path), "-m", "volatility3.cli", "-f", str(dump_path)]
    else:
        command = [str(vol_path), "-f", str(dump_path)]

    if symbol_path and symbol_path.exists():
        command.extend(["-s", str(symbol_path.parent)])

    command.extend(["--renderer", "json", plugin])

    # Add --pid if specified
    if pid is not None:
        command.extend(["--pid", str(pid)])

    # Add any extra plugin-specific arguments
    if extra_args:
        for key, value in extra_args.items():
            command.extend([f"--{key}", str(value)])

    return command


def run_volatility_analysis(dump_path: Path, plugin: str, symbol_path: Path = None, pid: int = None, extra_args: dict = None):
    """
    Run a Volatility 3 plugin against a memory dump.
    Creates marker files for status tracking:
      - <plugin>.running  — while analysis is in progress
      - <plugin>.json     — on success (result data)
      - <plugin>.error    — on failure (error details)
    When pid is specified, files are named <plugin>_pid<N>.json etc.
    """
    analysis_id = dump_path.stem
    output_dir = dump_path.parent
    plugin_short = plugin.split('.')[-1].lower()
    
    # Per-PID results get a different filename
    suffix = f"_pid{pid}" if pid is not None else ""
    cache_file = output_dir / f"{plugin_short}{suffix}.json"
    running_marker = output_dir / f"{plugin_short}{suffix}.running"
    error_file = output_dir / f"{plugin_short}{suffix}.error"

    logger.info(f"[{analysis_id}] Starting analysis with plugin: {plugin}")
    if symbol_path:
        logger.info(f"[{analysis_id}] Using custom symbols: {symbol_path}")

    # Create running marker
    start_time = datetime.utcnow()
    running_marker.write_text(json.dumps({
        "plugin": plugin,
        "started_at": start_time.isoformat(),
    }), encoding="utf-8")

    # Clean up any previous error file
    if error_file.exists():
        error_file.unlink()

    command = _build_vol_command(dump_path, plugin, symbol_path, pid=pid, extra_args=extra_args)
    logger.info(f"[{analysis_id}] Command: {' '.join(command)}")

    try:
        # Use cwd=output_dir so plugins that write files (e.g. DumpFiles)
        # output to the analysis directory instead of the server root.
        result = subprocess.run(command, capture_output=True, text=True, check=False, cwd=str(output_dir))

        if result.returncode == 0:
            # Parse JSON, clean __children, and save
            try:
                parsed = json.loads(result.stdout)
                cleaned = _clean_children(parsed)
                with open(cache_file, "w", encoding="utf-8") as f:
                    json.dump(cleaned, f, ensure_ascii=False)
            except json.JSONDecodeError:
                # If stdout is not valid JSON, write it raw
                with open(cache_file, "w", encoding="utf-8") as f:
                    f.write(result.stdout)

            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.info(f"[{analysis_id}] Analysis completed in {duration:.1f}s. Results: {cache_file}")
        else:
            # Plugin failed — write error file
            error_info = {
                "plugin": plugin,
                "exit_code": result.returncode,
                "stderr": result.stderr,
                "stdout_preview": result.stdout[:500] if result.stdout else "",
                "failed_at": datetime.utcnow().isoformat(),
                "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
            }
            error_file.write_text(json.dumps(error_info, indent=2, ensure_ascii=False), encoding="utf-8")
            logger.error(f"[{analysis_id}] Plugin failed (exit code {result.returncode}): {result.stderr[:300]}")

    except Exception as e:
        error_info = {
            "plugin": plugin,
            "exit_code": -1,
            "stderr": str(e),
            "stdout_preview": "",
            "failed_at": datetime.utcnow().isoformat(),
            "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
        }
        error_file.write_text(json.dumps(error_info, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.error(f"[{analysis_id}] Critical error: {e}")

    finally:
        # Always remove running marker
        if running_marker.exists():
            running_marker.unlink()