import hashlib
from pathlib import Path
import json

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.services.volatility_runner import run_volatility_analysis

router = APIRouter()

MVP_PLUGIN = "windows.psscan.PsScan"

@router.post("/upload")
async def upload_memory_dump(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """
    Endpoint pro nahrání memory dumpu a spuštění analýzy na pozadí.
    """

    file_content = await file.read()
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    analysis_dir = settings.STORAGE_PATH / sha256_hash
    analysis_dir.mkdir(parents=True, exist_ok=True)
    
    dump_path = analysis_dir / file.filename

    with open(dump_path, "wb") as buffer:
        buffer.write(file_content)
        
    background_tasks.add_task(run_volatility_analysis, dump_path, MVP_PLUGIN)
    
    return {"message": "Upload successful, analysis started.", "analysis_id": sha256_hash}

@router.get("/status/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    """
    Endpoint pro zjištění stavu analýzy.
    """
    plugin_name = MVP_PLUGIN.split('.')[-1].lower()
    result_file = settings.STORAGE_PATH / analysis_id / f"{plugin_name}.json"
    
    if result_file.exists():
        return {"status": "completed"}
    
    return {"status": "in_progress"}

@router.get("/results/{analysis_id}")
async def get_analysis_results(analysis_id: str):
    """
    Endpoint pro získání výsledků dokončené analýzy.
    """
    plugin_name = MVP_PLUGIN.split('.')[-1].lower()
    result_file = settings.STORAGE_PATH / analysis_id / f"{plugin_name}.json"

    if not result_file.exists():
        raise HTTPException(status_code=404, detail="Analysis results not found or not completed yet.")
        
    with open(result_file, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    return data