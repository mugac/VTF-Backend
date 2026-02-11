from pathlib import Path
import json
import csv
import io
from typing import Optional, List, Dict

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from app.core.config import settings
from app.services.volatility_runner import run_volatility_analysis
from app.api.v1.plugins import (
    get_plugin_list,
    get_plugin_info,
    is_valid_plugin,
    get_all_categories,
    get_plugins_by_category,
    AVAILABLE_PLUGINS,
    PLUGIN_PRESETS,
)

router = APIRouter()


# ─── Request / Response Models ─────────────────────────────────────────

class RunAnalysisRequest(BaseModel):
    plugin: str
    force: bool = False
    pid: Optional[int] = None  # Optional PID filter for per-process plugins


class BatchAnalysisRequest(BaseModel):
    plugins: List[str]
    force: bool = False

@router.post("/analysis/{analysis_id}/run")
async def run_analysis(analysis_id: str, request: RunAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Endpoint pro spuštění analýzy konkrétním pluginem.
    Pro Linux dumpy automaticky použije matching symbol file pokud existuje.
    force=true přepíše existující výsledky.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found. Upload a file first.")
    
    # Načteme metadata pro zjištění OS
    metadata_path = analysis_dir / "metadata.json"
    metadata = {}
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    
    os_type = metadata.get("os_type")
    kernel_version = metadata.get("kernel_version")
    
    # Najdeme memory dump soubor (první .vmem nebo .mem soubor)
    dump_files = list(analysis_dir.glob("*.vmem")) + list(analysis_dir.glob("*.mem")) + list(analysis_dir.glob("*.raw")) + list(analysis_dir.glob("*.lime"))
    
    if not dump_files:
        raise HTTPException(status_code=404, detail="Memory dump file not found in analysis directory.")
    
    dump_path = dump_files[0]
    
    if not is_valid_plugin(request.plugin):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plugin. Available plugins: {', '.join(get_plugin_list())}"
        )
    
    # Check PID requirements
    plugin_info = get_plugin_info(request.plugin)
    if plugin_info and plugin_info.requires_pid and request.pid is None:
        raise HTTPException(
            status_code=400,
            detail=f"Plugin {request.plugin} requires a PID. Provide 'pid' in the request."
        )
    
    plugin_name = request.plugin.split('.')[-1].lower()
    suffix = f"_pid{request.pid}" if request.pid is not None else ""
    result_file = analysis_dir / f"{plugin_name}{suffix}.json"
    running_marker = analysis_dir / f"{plugin_name}{suffix}.running"
    error_file = analysis_dir / f"{plugin_name}{suffix}.error"

    # Check if plugin is currently running
    if running_marker.exists():
        return {
            "message": "Analysis is already running for this plugin.",
            "status": "running",
            "plugin": request.plugin
        }

    # Check if already completed (unless force=true)
    if result_file.exists() and not request.force:
        return {
            "message": "Analysis already completed for this plugin.",
            "status": "completed",
            "plugin": request.plugin
        }
    
    # If force, remove old results and errors
    if request.force:
        if result_file.exists():
            result_file.unlink()
        if error_file.exists():
            error_file.unlink()

    # Pro Linux dumpy potřebujeme symbol file
    symbol_path = _find_symbol_for_linux(os_type, kernel_version)

    background_tasks.add_task(
        run_volatility_analysis, dump_path, request.plugin, symbol_path, 
        pid=request.pid
    )
    
    return {
        "message": "Analysis started.",
        "analysis_id": analysis_id,
        "plugin": request.plugin,
        "pid": request.pid,
        "status": "running",
        "os_type": os_type,
        "symbols_used": str(symbol_path) if symbol_path else None
    }


def _find_symbol_for_linux(os_type: Optional[str], kernel_version: Optional[str]) -> Optional[Path]:
    """Find matching symbol file for Linux analysis."""
    if os_type != "linux":
        return None
    
    symbol_cache = settings.SYMBOLS_CACHE
    if not symbol_cache.exists():
        return None
    
    symbol_files = [f for f in symbol_cache.glob("*.json") if f.name != "metadata.json"]
    if not symbol_files:
        return None
    
    # Try to match by kernel version from symbol metadata
    if kernel_version:
        metadata_file = symbol_cache / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, "r") as f:
                    meta = json.load(f)
                for sym_file in symbol_files:
                    sym_meta = meta.get(sym_file.stem, {})
                    sym_kernel = sym_meta.get("kernel_version", "")
                    if sym_kernel and kernel_version in sym_kernel:
                        return sym_file
            except Exception:
                pass
    
    # Fallback: use first available symbol
    return symbol_files[0]


@router.post("/analysis/{analysis_id}/run-batch")
async def run_batch_analysis(analysis_id: str, request: BatchAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Spustí analýzu pro více pluginů najednou.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    metadata_path = analysis_dir / "metadata.json"
    metadata = {}
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    
    os_type = metadata.get("os_type")
    kernel_version = metadata.get("kernel_version")
    
    dump_files = list(analysis_dir.glob("*.vmem")) + list(analysis_dir.glob("*.mem")) + list(analysis_dir.glob("*.raw")) + list(analysis_dir.glob("*.lime"))
    if not dump_files:
        raise HTTPException(status_code=404, detail="Memory dump file not found.")
    dump_path = dump_files[0]

    # Validate all plugins
    invalid = [p for p in request.plugins if not is_valid_plugin(p)]
    if invalid:
        raise HTTPException(status_code=400, detail=f"Invalid plugins: {', '.join(invalid)}")

    symbol_path = _find_symbol_for_linux(os_type, kernel_version)

    started = []
    skipped = []

    for plugin in request.plugins:
        plugin_short = plugin.split('.')[-1].lower()
        result_file = analysis_dir / f"{plugin_short}.json"
        running_marker = analysis_dir / f"{plugin_short}.running"
        error_file = analysis_dir / f"{plugin_short}.error"

        if running_marker.exists():
            skipped.append({"plugin": plugin, "reason": "already_running"})
            continue
        
        if result_file.exists() and not request.force:
            skipped.append({"plugin": plugin, "reason": "already_completed"})
            continue

        if request.force:
            if result_file.exists():
                result_file.unlink()
            if error_file.exists():
                error_file.unlink()

        background_tasks.add_task(run_volatility_analysis, dump_path, plugin, symbol_path)
        started.append(plugin)

    return {
        "message": f"Batch analysis started: {len(started)} plugins queued, {len(skipped)} skipped.",
        "analysis_id": analysis_id,
        "started": started,
        "skipped": skipped,
    }

@router.get("/plugins")
async def get_available_plugins(os_type: Optional[str] = None):
    """
    Endpoint pro seznam dostupných pluginů s jejich metadaty.
    Podporuje filtrování podle OS typu (windows/linux).
    """
    plugins = []
    for plugin in AVAILABLE_PLUGINS.values():
        if os_type is None or os_type in plugin.supported_os:
            plugins.append({
                "name": plugin.name,
                "category": plugin.category,
                "description": plugin.description,
                "supported_os": plugin.supported_os,
                "accepts_pid": plugin.accepts_pid,
                "requires_pid": plugin.requires_pid,
            })
    
    categories = get_all_categories(os_type)
    
    return {
        "plugins": plugins,
        "categories": categories,
        "filtered_by_os": os_type
    }


@router.get("/plugins/categories/{category}")
async def get_plugins_by_category_endpoint(category: str):
    """
    Vrátí pluginy podle kategorie.
    """
    plugins = get_plugins_by_category(category)
    if not plugins:
        raise HTTPException(status_code=404, detail=f"Category '{category}' not found.")
    
    return {"category": category, "plugins": plugins}


@router.get("/analysis/{analysis_id}/plugins")
async def get_available_plugins_deprecated():
    """
    Deprecated: Použijte /plugins endpoint místo tohoto.
    Endpoint pro seznam dostupných pluginů.
    """
    return {"plugins": get_plugin_list()}

def _get_plugin_status(analysis_dir: Path, plugin_name: str, pid: int = None) -> dict:
    """Get the status of a single plugin, checking markers."""
    plugin_short = plugin_name.split('.')[-1].lower()
    suffix = f"_pid{pid}" if pid is not None else ""
    result_file = analysis_dir / f"{plugin_short}{suffix}.json"
    running_marker = analysis_dir / f"{plugin_short}{suffix}.running"
    error_file = analysis_dir / f"{plugin_short}{suffix}.error"

    if result_file.exists():
        return {"status": "completed"}
    elif running_marker.exists():
        try:
            info = json.loads(running_marker.read_text(encoding="utf-8"))
            return {"status": "running", "started_at": info.get("started_at")}
        except Exception:
            return {"status": "running"}
    elif error_file.exists():
        try:
            info = json.loads(error_file.read_text(encoding="utf-8"))
            return {
                "status": "failed",
                "error": info.get("stderr", "Unknown error")[:300],
                "exit_code": info.get("exit_code"),
                "failed_at": info.get("failed_at"),
            }
        except Exception:
            return {"status": "failed", "error": "Unknown error"}
    else:
        return {"status": "not_started"}


@router.get("/analysis/{analysis_id}/status")
async def get_analysis_status(analysis_id: str, plugin: Optional[str] = None, pid: Optional[int] = None):
    """
    Endpoint pro zjištění stavu analýzy.
    Stavy: not_started, running, completed, failed.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    if plugin:
        status_info = _get_plugin_status(analysis_dir, plugin, pid=pid)
        return {"plugin": plugin, "pid": pid, **status_info}
    
    # Vrátíme stav všech pluginů
    statuses = {}
    for plugin_name in get_plugin_list():
        statuses[plugin_name] = _get_plugin_status(analysis_dir, plugin_name)["status"]
    
    return {"analysis_id": analysis_id, "plugins": statuses}

@router.get("/analysis/{analysis_id}/results/{plugin}")
async def get_analysis_results(analysis_id: str, plugin: str, pid: Optional[int] = None):
    """
    Endpoint pro získání výsledků dokončené analýzy pro konkrétní plugin.
    Optional pid parameter returns per-PID results if available.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    plugin_name = plugin.split('.')[-1].lower()
    suffix = f"_pid{pid}" if pid is not None else ""
    result_file = analysis_dir / f"{plugin_name}{suffix}.json"

    if not result_file.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Analysis results not found for plugin '{plugin}'. Run the analysis first."
        )
        
    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    return data

@router.get("/analysis/{analysis_id}/results")
async def get_all_results(analysis_id: str):
    """
    Endpoint pro získání všech dostupných výsledků analýzy.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    results = {}
    for plugin_name in get_plugin_list():
        plugin_short = plugin_name.split('.')[-1].lower()
        result_file = analysis_dir / f"{plugin_short}.json"
        
        if result_file.exists():
            with open(result_file, "r", encoding="utf-8") as f:
                results[plugin_name] = json.load(f)
    
    if not results:
        raise HTTPException(
            status_code=404,
            detail="No analysis results found. Run analysis first."
        )
    
    return {"analysis_id": analysis_id, "results": results}


# ─── Plugin Presets ─────────────────────────────────────────────────────

@router.get("/plugins/presets")
async def get_plugin_presets(os_type: Optional[str] = None):
    """Return available plugin presets (Quick Triage, Malware Hunt, etc.)."""
    presets = {}
    for preset_name, preset_info in PLUGIN_PRESETS.items():
        plugins = preset_info["plugins"]
        if os_type:
            plugins = [p for p in plugins if os_type in AVAILABLE_PLUGINS.get(p, PluginInfo(name="", category="", description="", supported_os=[])).supported_os]
        if plugins:
            presets[preset_name] = {
                "description": preset_info["description"],
                "plugins": plugins,
            }
    return {"presets": presets, "filtered_by_os": os_type}


# ─── Export ─────────────────────────────────────────────────────────────

@router.get("/analysis/{analysis_id}/export/{plugin}")
async def export_plugin_results(
    analysis_id: str,
    plugin: str,
    format: str = Query("json", regex="^(json|csv)$"),
):
    """Export plugin results as JSON or CSV download."""
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    plugin_short = plugin.split('.')[-1].lower()
    result_file = analysis_dir / f"{plugin_short}.json"
    if not result_file.exists():
        raise HTTPException(status_code=404, detail="Results not found. Run the analysis first.")

    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    if format == "csv":
        if not isinstance(data, list) or len(data) == 0:
            raise HTTPException(status_code=400, detail="No tabular data to export.")
        
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        for row in data:
            writer.writerow(row)
        
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={plugin_short}_{analysis_id[:8]}.csv"},
        )
    else:
        return StreamingResponse(
            iter([json.dumps(data, indent=2, ensure_ascii=False)]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={plugin_short}_{analysis_id[:8]}.json"},
        )


# ─── Cross-plugin Correlation ──────────────────────────────────────────

@router.get("/analysis/{analysis_id}/correlate/{pid}")
async def correlate_by_pid(analysis_id: str, pid: int):
    """
    Correlate data across multiple plugin results for a given PID.
    Searches PsScan, CmdLine, DllList, NetScan, Envars, Handles, Malfind results.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    pid_fields = ["PID", "Pid", "pid"]
    correlation = {"pid": pid, "data": {}}

    # Files to search for PID references
    plugin_files = {
        "psscan": "Process Info",
        "pslist": "Process Info",
        "cmdline": "Command Line", 
        "dlllist": "Loaded DLLs",
        "netscan": "Network Connections",
        "netscan": "Network Connections",
        "envars": "Environment Variables",
        "handles": "Handles",
        "malfind": "Suspicious Memory",
        "privs": "Privileges",
    }

    for plugin_short, label in plugin_files.items():
        result_file = analysis_dir / f"{plugin_short}.json"
        if not result_file.exists():
            continue
        
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                continue
            
            matching_rows = []
            for row in data:
                for pid_field in pid_fields:
                    if row.get(pid_field) == pid:
                        matching_rows.append(row)
                        break
            
            if matching_rows:
                correlation["data"][label] = {
                    "plugin": plugin_short,
                    "count": len(matching_rows),
                    "rows": matching_rows[:100],  # Limit to 100 rows
                }
        except Exception:
            continue

    if not correlation["data"]:
        raise HTTPException(
            status_code=404,
            detail=f"No data found for PID {pid}. Make sure you have run relevant plugins."
        )

    return correlation