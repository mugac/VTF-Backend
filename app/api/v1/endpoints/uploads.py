import hashlib
from pathlib import Path
from typing import List
from datetime import datetime

from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()


class UploadInfo(BaseModel):
    analysis_id: str
    filename: str
    size_bytes: int
    uploaded_at: str


class UploadResponse(BaseModel):
    message: str
    analysis_id: str
    filename: str
    size_bytes: int


@router.post("/upload", response_model=UploadResponse)
async def upload_memory_dump(file: UploadFile = File(...)):
    """
    Endpoint pro nahrání memory dumpu - pouze uloží soubor do storage.
    Vrátí analysis_id, které se použije pro další operace.
    """
    file_content = await file.read()
    file_size = len(file_content)
    sha256_hash = hashlib.sha256(file_content).hexdigest()

    analysis_dir = settings.STORAGE_PATH / sha256_hash
    analysis_dir.mkdir(parents=True, exist_ok=True)
    
    dump_path = analysis_dir / file.filename

    # Uložíme soubor
    with open(dump_path, "wb") as buffer:
        buffer.write(file_content)
    
    # Uložíme metadata
    metadata = {
        "filename": file.filename,
        "size_bytes": file_size,
        "sha256": sha256_hash,
        "uploaded_at": datetime.utcnow().isoformat(),
        "content_type": file.content_type
    }
    
    metadata_path = analysis_dir / "metadata.json"
    import json
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    
    return UploadResponse(
        message="Upload successful.",
        analysis_id=sha256_hash,
        filename=file.filename,
        size_bytes=file_size
    )


@router.get("/uploads", response_model=List[UploadInfo])
async def list_uploads():
    """
    Vrátí seznam všech nahraných memory dumpů.
    """
    if not settings.STORAGE_PATH.exists():
        return []
    
    uploads = []
    for analysis_dir in settings.STORAGE_PATH.iterdir():
        if not analysis_dir.is_dir():
            continue
        
        metadata_path = analysis_dir / "metadata.json"
        if metadata_path.exists():
            import json
            with open(metadata_path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
            
            uploads.append(UploadInfo(
                analysis_id=analysis_dir.name,
                filename=metadata.get("filename", "unknown"),
                size_bytes=metadata.get("size_bytes", 0),
                uploaded_at=metadata.get("uploaded_at", "")
            ))
    
    return sorted(uploads, key=lambda x: x.uploaded_at, reverse=True)


@router.get("/uploads/{analysis_id}")
async def get_upload_info(analysis_id: str):
    """
    Vrátí detailní informace o nahraném souboru.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    metadata_path = analysis_dir / "metadata.json"
    if not metadata_path.exists():
        raise HTTPException(status_code=404, detail="Metadata not found for this upload.")
    
    import json
    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    
    return metadata


@router.delete("/uploads/{analysis_id}")
async def delete_upload(analysis_id: str):
    """
    Smaže nahraný soubor a všechny související výsledky analýz.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    # Smažeme celou složku
    import shutil
    shutil.rmtree(analysis_dir)
    
    return {"message": "Upload and all analysis results deleted successfully.", "analysis_id": analysis_id}
