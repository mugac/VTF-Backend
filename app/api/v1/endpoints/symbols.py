"""
Symbols Management API Endpoints
Handles upload and management of vmlinux files and ISF symbol files.
"""

from fastapi import APIRouter, File, UploadFile, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from typing import Optional, List
from pathlib import Path
from pydantic import BaseModel
import uuid
import json
import logging
from datetime import datetime
import shutil

from app.core.config import settings
from app.services.symbol_generator import (
    generate_isf,
    get_vmlinux_hash,
    validate_vmlinux,
    get_or_generate_isf
)

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory job tracking (pro production by měla být databáze)
symbol_jobs = {}


class SymbolJob(BaseModel):
    """Model pro tracking ISF generation job"""
    job_id: str
    status: str  # "pending", "processing", "completed", "failed"
    vmlinux_hash: Optional[str] = None
    kernel_version: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None
    isf_size_bytes: Optional[int] = None
    duration_seconds: Optional[float] = None


class SymbolInfo(BaseModel):
    """Model pro info o cached symbolu"""
    symbol_id: str  # hash vmlinux
    kernel_version: Optional[str] = None
    size_bytes: int
    size_mb: float
    created_at: str
    file_path: str


def background_generate_isf(
    job_id: str,
    vmlinux_path: Path,
    system_map_path: Optional[Path] = None
):
    """
    Background task pro generování ISF.
    """
    try:
        logger.info(f"[Job {job_id}] Starting ISF generation")
        symbol_jobs[job_id]["status"] = "processing"
        
        # Generate ISF
        result = get_or_generate_isf(
            vmlinux_path,
            settings.SYMBOLS_CACHE,
            system_map_path
        )
        
        if result["success"]:
            symbol_jobs[job_id].update({
                "status": "completed",
                "completed_at": datetime.now().isoformat(),
                "vmlinux_hash": result.get("vmlinux_hash"),
                "isf_size_bytes": result["isf_path"].stat().st_size if result["isf_path"] else None,
                "error": None
            })
            logger.info(f"[Job {job_id}] ISF generation completed successfully")
        else:
            symbol_jobs[job_id].update({
                "status": "failed",
                "completed_at": datetime.now().isoformat(),
                "error": result["error"]
            })
            logger.error(f"[Job {job_id}] ISF generation failed: {result['error']}")
    
    except Exception as e:
        logger.error(f"[Job {job_id}] Unexpected error: {str(e)}")
        symbol_jobs[job_id].update({
            "status": "failed",
            "completed_at": datetime.now().isoformat(),
            "error": str(e)
        })
    
    finally:
        # Cleanup temporary files
        try:
            if vmlinux_path.exists():
                vmlinux_path.unlink()
            if system_map_path and system_map_path.exists():
                system_map_path.unlink()
            # Remove job directory if empty
            job_dir = vmlinux_path.parent
            if job_dir.exists() and not list(job_dir.iterdir()):
                job_dir.rmdir()
        except Exception as e:
            logger.warning(f"[Job {job_id}] Cleanup warning: {str(e)}")


@router.post("/upload-vmlinux", response_model=SymbolJob)
async def upload_vmlinux(
    background_tasks: BackgroundTasks,
    vmlinux: UploadFile = File(...),
    system_map: Optional[UploadFile] = File(None),
    kernel_version: Optional[str] = None
):
    """
    Upload vmlinux (a volitelně System.map) pro generování ISF symbolu.
    Vrací job_id pro tracking progress.
    """
    job_id = str(uuid.uuid4())
    logger.info(f"[Job {job_id}] Received vmlinux upload: {vmlinux.filename}")
    
    # Vytvoření dočasného adresáře pro tento job
    job_dir = settings.TEMP_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    
    vmlinux_path = job_dir / "vmlinux"
    system_map_path = job_dir / "System.map" if system_map else None
    
    try:
        # Uložení vmlinux
        with open(vmlinux_path, "wb") as f:
            shutil.copyfileobj(vmlinux.file, f)
        logger.info(f"[Job {job_id}] vmlinux saved: {vmlinux_path.stat().st_size / (1024*1024):.1f} MB")
        
        # Uložení System.map pokud je přítomen
        if system_map and system_map_path:
            with open(system_map_path, "wb") as f:
                shutil.copyfileobj(system_map.file, f)
            logger.info(f"[Job {job_id}] System.map saved")
        
        # Validace vmlinux
        validation = validate_vmlinux(vmlinux_path)
        if not validation["valid"]:
            # Cleanup
            shutil.rmtree(job_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=validation["error"])
        
        # Vytvoření job záznamu
        job = SymbolJob(
            job_id=job_id,
            status="pending",
            kernel_version=kernel_version,
            created_at=datetime.now().isoformat()
        )
        symbol_jobs[job_id] = job.dict()
        
        # Spuštění background task
        background_tasks.add_task(
            background_generate_isf,
            job_id,
            vmlinux_path,
            system_map_path
        )
        
        logger.info(f"[Job {job_id}] Background generation started")
        return job
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Job {job_id}] Upload failed: {str(e)}")
        # Cleanup
        shutil.rmtree(job_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.get("/job/{job_id}", response_model=SymbolJob)
async def get_symbol_job_status(job_id: str):
    """
    Získat status ISF generation job.
    """
    if job_id not in symbol_jobs:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return SymbolJob(**symbol_jobs[job_id])


@router.get("/", response_model=List[SymbolInfo])
async def list_available_symbols():
    """
    Seznam všech dostupných ISF symbolů v cache.
    """
    symbols = []
    cache_dir = settings.SYMBOLS_CACHE
    
    if not cache_dir.exists():
        return symbols
    
    # Načtení metadata
    metadata_file = cache_dir / "metadata.json"
    metadata = {}
    if metadata_file.exists():
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
        except:
            pass
    
    # Projít všechny .json soubory v cache
    for isf_file in cache_dir.glob("*.json"):
        if isf_file.name == "metadata.json":
            continue
        
        symbol_id = isf_file.stem  # hash without .json
        size_bytes = isf_file.stat().st_size
        
        meta = metadata.get(symbol_id, {})
        
        symbols.append(SymbolInfo(
            symbol_id=symbol_id,
            kernel_version=meta.get("kernel_version"),
            size_bytes=size_bytes,
            size_mb=round(size_bytes / (1024 * 1024), 2),
            created_at=meta.get("created_at", "unknown"),
            file_path=str(isf_file)
        ))
    
    return symbols


@router.post("/upload-isf")
async def upload_existing_isf(
    isf_file: UploadFile = File(...),
    kernel_version: Optional[str] = None
):
    """
    Upload již existujícího ISF souboru (např. staženého z community repository).
    """
    logger.info(f"Received ISF upload: {isf_file.filename}")
    
    # Generujeme symbol_id z názvu nebo času
    symbol_id = str(uuid.uuid4())
    isf_path = settings.SYMBOLS_CACHE / f"{symbol_id}.json"
    
    try:
        # Uložení ISF
        with open(isf_path, "wb") as f:
            shutil.copyfileobj(isf_file.file, f)
        
        size_bytes = isf_path.stat().st_size
        logger.info(f"ISF saved: {size_bytes / (1024*1024):.1f} MB")
        
        # Update metadata
        metadata_file = settings.SYMBOLS_CACHE / "metadata.json"
        metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except:
                metadata = {}
        
        metadata[symbol_id] = {
            "kernel_version": kernel_version,
            "created_at": datetime.now().isoformat(),
            "size_bytes": size_bytes,
            "uploaded": True,
            "original_filename": isf_file.filename
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return {
            "success": True,
            "symbol_id": symbol_id,
            "size_mb": round(size_bytes / (1024 * 1024), 2)
        }
    
    except Exception as e:
        logger.error(f"ISF upload failed: {str(e)}")
        if isf_path.exists():
            isf_path.unlink()
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@router.delete("/{symbol_id}")
async def delete_symbol(symbol_id: str):
    """
    Smazat cached symbol file.
    """
    isf_path = settings.SYMBOLS_CACHE / f"{symbol_id}.json"
    
    if not isf_path.exists():
        raise HTTPException(status_code=404, detail="Symbol not found")
    
    try:
        isf_path.unlink()
        
        # Update metadata
        metadata_file = settings.SYMBOLS_CACHE / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                if symbol_id in metadata:
                    del metadata[symbol_id]
                
                with open(metadata_file, 'w') as f:
                    json.dump(metadata, f, indent=2)
            except:
                pass
        
        logger.info(f"Deleted symbol: {symbol_id}")
        return {"success": True, "message": "Symbol deleted"}
    
    except Exception as e:
        logger.error(f"Failed to delete symbol {symbol_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Delete failed: {str(e)}")


@router.get("/{symbol_id}/download")
async def download_symbol(symbol_id: str):
    """
    Stáhnout ISF symbol file.
    """
    isf_path = settings.SYMBOLS_CACHE / f"{symbol_id}.json"
    
    if not isf_path.exists():
        raise HTTPException(status_code=404, detail="Symbol not found")
    
    return FileResponse(
        path=str(isf_path),
        media_type="application/json",
        filename=f"symbol_{symbol_id[:8]}.json"
    )
