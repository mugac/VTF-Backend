import hashlib
from pathlib import Path
from typing import List, Optional
from datetime import datetime
import subprocess
import logging
import json
import platform

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


def detect_os_from_dump(dump_path: Path) -> dict:
    """
    Detekuje OS z memory dumpu pomocí banners.Banners pluginu.
    
    Returns:
        dict s keys: os_type, kernel_version, architecture, detected (bool), error
    """
    logger.info(f"Detecting OS for dump: {dump_path}")
    
    # Použijeme Python z konfigurace
    python_path = settings.PYTHON_PATH
    scripts_dir = python_path.parent
    vol_executable = "vol.exe" if platform.system() == "Windows" else "vol"
    vol_path = scripts_dir / vol_executable
    
    if not vol_path.exists():
        # Fallback na Python modul
        command = [
            str(python_path),
            "-m", "volatility3.cli",
            "-f", str(dump_path),
            "--renderer", "json",
            "banners.Banners"
        ]
    else:
        command = [
            str(vol_path),
            "-f", str(dump_path),
            "--renderer", "json",
            "banners.Banners"
        ]
    
    try:
        logger.info(f"Running OS detection command: {' '.join(command)}")
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=60,  # 1 minute timeout
            check=False
        )
        
        if result.returncode != 0:
            logger.warning(f"Banners plugin failed (exit code {result.returncode}): {result.stderr}")
            return {
                "detected": False,
                "error": "OS detection failed",
                "os_type": None,
                "kernel_version": None,
                "architecture": None
            }
        
        # Parse JSON output
        try:
            output_data = json.loads(result.stdout)
            
            # Banners vrací pole řádků s různými informacemi
            # Hledáme OS informace v banners
            os_type = None
            kernel_version = None
            architecture = None
            
            if isinstance(output_data, list) and len(output_data) > 0:
                for row in output_data:
                    banner = row.get("Banner", "").lower()
                    
                    # Detekce Windows
                    if "windows" in banner:
                        os_type = "windows"
                        # Pokus o extrakci verze
                        if "windows 10" in banner:
                            kernel_version = "10"
                        elif "windows 11" in banner:
                            kernel_version = "11"
                        elif "windows 7" in banner:
                            kernel_version = "7"
                    
                    # Detekce Linux
                    elif "linux" in banner:
                        os_type = "linux"
                        # Pokus o extrakci kernel verze
                        import re
                        version_match = re.search(r'(\d+\.\d+\.\d+[-\w]*)', banner)
                        if version_match:
                            kernel_version = version_match.group(1)
                    
                    # Detekce architektury
                    if "x64" in banner or "x86_64" in banner or "amd64" in banner:
                        architecture = "x64"
                    elif "x86" in banner or "i386" in banner or "i686" in banner:
                        architecture = "x86"
            
            if os_type:
                logger.info(f"OS detected: {os_type} {kernel_version or 'unknown version'} ({architecture or 'unknown arch'})")
                return {
                    "detected": True,
                    "os_type": os_type,
                    "kernel_version": kernel_version,
                    "architecture": architecture,
                    "error": None
                }
            else:
                logger.warning("Could not determine OS from banners output")
                return {
                    "detected": False,
                    "os_type": None,
                    "kernel_version": None,
                    "architecture": None,
                    "error": "OS type not identified in banners"
                }
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse banners output: {e}")
            return {
                "detected": False,
                "error": "Failed to parse OS detection output",
                "os_type": None,
                "kernel_version": None,
                "architecture": None
            }
    
    except subprocess.TimeoutExpired:
        logger.error("OS detection timed out")
        return {
            "detected": False,
            "error": "OS detection timed out",
            "os_type": None,
            "kernel_version": None,
            "architecture": None
        }
    except Exception as e:
        logger.error(f"OS detection failed with error: {str(e)}")
        return {
            "detected": False,
            "error": str(e),
            "os_type": None,
            "kernel_version": None,
            "architecture": None
        }


class UploadInfo(BaseModel):
    analysis_id: str
    filename: str
    size_bytes: int
    uploaded_at: str
    project_name: Optional[str] = None
    os_type: Optional[str] = None


class UploadResponse(BaseModel):
    message: str
    analysis_id: str
    filename: str
    size_bytes: int


class DetectOSResponse(BaseModel):
    success: bool
    os_type: Optional[str] = None
    kernel_version: Optional[str] = None
    architecture: Optional[str] = None
    banners_output: Optional[List[dict]] = None
    error: Optional[str] = None


@router.post("/upload", response_model=UploadResponse)
async def upload_memory_dump(
    file: UploadFile = File(...),
    project_name: Optional[str] = None
):
    """
    Endpoint pro nahrání memory dumpu - pouze uloží soubor do storage.
    Vrátí analysis_id, které se použije pro další operace.
    Volitelně lze zadat project_name.
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
    
    # Uložíme základní metadata (bez OS detekce)
    metadata = {
        "filename": file.filename,
        "size_bytes": file_size,
        "sha256": sha256_hash,
        "uploaded_at": datetime.utcnow().isoformat(),
        "content_type": file.content_type,
        "project_name": project_name or file.filename
    }
    
    metadata_path = analysis_dir / "metadata.json"
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"Upload completed: {sha256_hash}")
    
    return UploadResponse(
        message="Upload successful.",
        analysis_id=sha256_hash,
        filename=file.filename,
        size_bytes=file_size
    )


@router.post("/detect-os/{analysis_id}", response_model=DetectOSResponse)
async def detect_os(analysis_id: str):
    """
    Spustí banners plugin pro detekci OS z memory dumpu.
    Vrátí detekované informace a kompletní výstup z banners pluginu.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    metadata_path = analysis_dir / "metadata.json"
    if not metadata_path.exists():
        raise HTTPException(status_code=404, detail="Metadata not found.")
    
    # Najdeme memory dump soubor
    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    
    dump_filename = metadata.get("filename")
    dump_path = analysis_dir / dump_filename
    
    if not dump_path.exists():
        raise HTTPException(status_code=404, detail="Memory dump file not found.")
    
    # Spustíme detekci
    logger.info(f"Running OS detection for {analysis_id}")
    
    python_path = settings.PYTHON_PATH
    scripts_dir = python_path.parent
    vol_executable = "vol.exe" if platform.system() == "Windows" else "vol"
    vol_path = scripts_dir / vol_executable
    
    if not vol_path.exists():
        command = [
            str(python_path),
            "-m", "volatility3.cli",
            "-f", str(dump_path),
            "--renderer", "json",
            "banners.Banners"
        ]
    else:
        command = [
            str(vol_path),
            "-f", str(dump_path),
            "--renderer", "json",
            "banners.Banners"
        ]
    
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            timeout=60,
            check=False
        )
        
        if result.returncode != 0:
            logger.warning(f"Banners plugin failed: {result.stderr}")
            # I když selže, vraťíme response s chybou ale ne HTTP error
            return DetectOSResponse(
                success=False,
                error=f"Banners plugin vrátil chybu. Možná není správný profil nebo dump je poškozen.",
                banners_output=[]
            )
        
        # Parse JSON output
        try:
            output_data = json.loads(result.stdout)
        except json.JSONDecodeError:
            # Pokud není JSON, zkusíme vrátit raw output
            logger.warning(f"Non-JSON output from banners: {result.stdout[:200]}")
            return DetectOSResponse(
                success=False,
                error="Banners plugin nevrátil validní JSON",
                banners_output=[]
            )
        
        # Detekce OS z výstupu
        os_type = None
        kernel_version = None
        architecture = None
        
        if isinstance(output_data, list) and len(output_data) > 0:
            # Zkombinujeme všechny bannery do jednoho stringu pro lepší detekci
            all_banners = " ".join([row.get("Banner", "").lower() for row in output_data])
            
            # Detekce Windows - hledáme známé patterny
            if any(keyword in all_banners for keyword in ["windows", "microsoft", "nt kernel"]):
                os_type = "windows"
                
                # Detekce verze Windows
                if "windows 11" in all_banners or "10.0.22" in all_banners:
                    kernel_version = "11"
                elif "windows 10" in all_banners or "10.0.1" in all_banners or "10.0.2" in all_banners:
                    kernel_version = "10"
                elif "windows 8.1" in all_banners or "6.3" in all_banners:
                    kernel_version = "8.1"
                elif "windows 8" in all_banners or "6.2" in all_banners:
                    kernel_version = "8"
                elif "windows 7" in all_banners or "6.1" in all_banners:
                    kernel_version = "7"
                elif "vista" in all_banners or "6.0" in all_banners:
                    kernel_version = "Vista"
                elif "xp" in all_banners or "5.1" in all_banners:
                    kernel_version = "XP"
            
            # Detekce Linux
            elif any(keyword in all_banners for keyword in ["linux", "ubuntu", "debian", "centos", "rhel"]):
                os_type = "linux"
                import re
                version_match = re.search(r'(\d+\.\d+\.\d+[-\w]*)', all_banners)
                if version_match:
                    kernel_version = version_match.group(1)
            
            # Detekce architektury
            if any(keyword in all_banners for keyword in ["x64", "x86_64", "amd64"]):
                architecture = "x64"
            elif any(keyword in all_banners for keyword in ["x86", "i386", "i686"]):
                architecture = "x86"
        
        # Aktualizujeme metadata POUZE pokud byla detekce úspěšná
        # (pokud uživatel ručně nastavil OS, nechceme ho přepsat)
        if os_type and not metadata.get("os_type"):
            metadata["os_type"] = os_type
            metadata["kernel_version"] = kernel_version
            metadata["architecture"] = architecture
            metadata["os_detected"] = True
            
            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
        
        # Vrátíme výsledek detekce (i když je os_type None)
        return DetectOSResponse(
            success=True if os_type else False,
            os_type=os_type,
            kernel_version=kernel_version,
            architecture=architecture,
            banners_output=output_data,
            error="Nepodařilo se detekovat OS z výstupu banners" if not os_type else None
        )
        
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse banners output: {e}")
        return DetectOSResponse(
            success=False,
            error=f"Failed to parse banners output: {str(e)}"
        )
    except subprocess.TimeoutExpired:
        logger.error("OS detection timed out")
        return DetectOSResponse(
            success=False,
            error="OS detection timed out (60s)"
        )
    except Exception as e:
        logger.error(f"OS detection error: {str(e)}")
        return DetectOSResponse(
            success=False,
            error=str(e)
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
                uploaded_at=metadata.get("uploaded_at", ""),
                project_name=metadata.get("project_name"),
                os_type=metadata.get("os_type")
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


class UpdateProjectRequest(BaseModel):
    project_name: Optional[str] = None
    os_type: Optional[str] = None


@router.patch("/uploads/{analysis_id}")
async def update_project(analysis_id: str, request: UpdateProjectRequest):
    """
    Aktualizuje název projektu a/nebo OS typu.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    
    metadata_path = analysis_dir / "metadata.json"
    if not metadata_path.exists():
        raise HTTPException(status_code=404, detail="Metadata not found.")
    
    # Načteme a upravíme metadata
    with open(metadata_path, "r", encoding="utf-8") as f:
        metadata = json.load(f)
    
    if request.project_name is not None:
        metadata["project_name"] = request.project_name
    
    if request.os_type is not None:
        metadata["os_type"] = request.os_type
    
    # Uložíme zpět
    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    
    return {"message": "Project updated successfully", "metadata": metadata}


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
