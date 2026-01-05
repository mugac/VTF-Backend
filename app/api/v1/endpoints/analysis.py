from pathlib import Path
import json
from typing import Optional, List, Dict

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.core.config import settings
from app.services.volatility_runner import run_volatility_analysis
from app.api.v1.plugins import (
    get_plugin_list,
    get_plugin_info,
    is_valid_plugin,
    get_all_categories,
    get_plugins_by_category,
    AVAILABLE_PLUGINS
)

router = APIRouter()


class RunAnalysisRequest(BaseModel):
    plugin: str

@router.post("/analysis/{analysis_id}/run")
async def run_analysis(analysis_id: str, request: RunAnalysisRequest, background_tasks: BackgroundTasks):
    """
    Endpoint pro spuštění analýzy konkrétním pluginem.
    Pro Linux dumpy automaticky použije matching symbol file pokud existuje.
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
    
    # Zkontrolujeme, jestli analýza již neexistuje
    plugin_name = request.plugin.split('.')[-1].lower()
    result_file = analysis_dir / f"{plugin_name}.json"
    
    if result_file.exists():
        return {
            "message": "Analysis already completed for this plugin.",
            "status": "completed",
            "plugin": request.plugin
        }
    
    # Pro Linux dumpy potřebujeme symbol file
    symbol_path = None
    if os_type == "linux":
        # Zkusíme najít matching symbol file v cache
        # TODO: Match podle kernel_version nebo hash
        # Pro teď použijeme první dostupný symbol
        symbol_cache = settings.SYMBOLS_CACHE
        if symbol_cache.exists():
            symbol_files = list(symbol_cache.glob("*.json"))
            # Odfiltrujeme metadata.json
            symbol_files = [f for f in symbol_files if f.name != "metadata.json"]
            if symbol_files:
                symbol_path = symbol_files[0]  # Použijeme první dostupný
                # TODO: V budoucnu matchovat podle kernel verze
    
    background_tasks.add_task(run_volatility_analysis, dump_path, request.plugin, symbol_path)
    
    return {
        "message": "Analysis started.",
        "analysis_id": analysis_id,
        "plugin": request.plugin,
        "status": "in_progress",
        "os_type": os_type,
        "symbols_used": str(symbol_path) if symbol_path else None
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
                "supported_os": plugin.supported_os
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

@router.get("/analysis/{analysis_id}/status")
async def get_analysis_status(analysis_id: str, plugin: Optional[str] = None):
    """
    Endpoint pro zjištění stavu analýzy.
    Pokud je zadán plugin, vrátí stav pro tento plugin.
    Jinak vrátí stav všech pluginů.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    if plugin:
        plugin_name = plugin.split('.')[-1].lower()
        result_file = analysis_dir / f"{plugin_name}.json"
        
        return {
            "plugin": plugin,
            "status": "completed" if result_file.exists() else "not_started"
        }
    
    # Vrátíme stav všech pluginů
    statuses = {}
    for plugin_name in get_plugin_list():
        plugin_short = plugin_name.split('.')[-1].lower()
        result_file = analysis_dir / f"{plugin_short}.json"
        statuses[plugin_name] = "completed" if result_file.exists() else "not_started"
    
    return {"analysis_id": analysis_id, "plugins": statuses}

@router.get("/analysis/{analysis_id}/results/{plugin}")
async def get_analysis_results(analysis_id: str, plugin: str):
    """
    Endpoint pro získání výsledků dokončené analýzy pro konkrétní plugin.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    plugin_name = plugin.split('.')[-1].lower()
    result_file = analysis_dir / f"{plugin_name}.json"

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