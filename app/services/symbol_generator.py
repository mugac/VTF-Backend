"""
Symbol Generator Service
Handles generation of ISF (Intermediate Symbol Format) files from vmlinux using dwarf2json.
"""

import hashlib
import subprocess
import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime
import json

from app.core.config import settings

logger = logging.getLogger(__name__)


def get_vmlinux_hash(vmlinux_path: Path) -> str:
    """
    Calculate SHA256 hash of vmlinux file.
    Uses partial hashing for performance (first 50MB + last 10MB).
    
    Args:
        vmlinux_path: Path to vmlinux file
        
    Returns:
        SHA256 hash as hex string
    """
    sha256 = hashlib.sha256()
    file_size = vmlinux_path.stat().st_size
    
    with open(vmlinux_path, 'rb') as f:
        # Hash first 50MB or entire file if smaller
        chunk_size = min(50 * 1024 * 1024, file_size)
        sha256.update(f.read(chunk_size))
        
        # Hash last 10MB if file is large enough
        if file_size > 60 * 1024 * 1024:
            f.seek(-10 * 1024 * 1024, 2)  # Seek from end
            sha256.update(f.read())
    
    return sha256.hexdigest()


def validate_vmlinux(vmlinux_path: Path) -> Dict[str, any]:
    """
    Validate that the file is a valid ELF with debug info.
    
    Args:
        vmlinux_path: Path to vmlinux file
        
    Returns:
        Dict with validation result: {"valid": bool, "error": str|None}
    """
    if not vmlinux_path.exists():
        return {"valid": False, "error": "File does not exist"}
    
    # Check ELF magic bytes
    try:
        with open(vmlinux_path, 'rb') as f:
            magic = f.read(4)
            if magic != b'\x7fELF':
                return {"valid": False, "error": "Not a valid ELF file"}
    except Exception as e:
        return {"valid": False, "error": f"Cannot read file: {str(e)}"}
    
    # TODO: Could add more validation (check for debug sections)
    # For now, we'll rely on dwarf2json to report missing debug info
    
    return {"valid": True, "error": None}


def generate_isf(
    vmlinux_path: Path,
    output_path: Path,
    system_map_path: Optional[Path] = None,
    timeout: int = 600
) -> Dict[str, any]:
    """
    Generate ISF (Intermediate Symbol Format) file from vmlinux using dwarf2json.
    
    Args:
        vmlinux_path: Path to vmlinux ELF file with debug symbols
        output_path: Path where to save generated ISF JSON
        system_map_path: Optional path to System.map file
        timeout: Timeout in seconds (default 10 minutes)
        
    Returns:
        Dict with result:
        {
            "success": bool,
            "output_file": Path|None,
            "size_bytes": int|None,
            "duration_seconds": float|None,
            "error": str|None
        }
    """
    logger.info(f"Starting ISF generation for {vmlinux_path}")
    
    # Validate vmlinux first
    validation = validate_vmlinux(vmlinux_path)
    if not validation["valid"]:
        return {
            "success": False,
            "output_file": None,
            "size_bytes": None,
            "duration_seconds": None,
            "error": validation["error"]
        }
    
    # Find dwarf2json binary
    dwarf2json_exe = settings.BASE_DIR / "bin" / "dwarf2json.exe"
    if not dwarf2json_exe.exists():
        return {
            "success": False,
            "output_file": None,
            "size_bytes": None,
            "duration_seconds": None,
            "error": "dwarf2json.exe not found in bin/ directory"
        }
    
    # Build command
    cmd = [str(dwarf2json_exe), "linux", "--elf", str(vmlinux_path)]
    
    if system_map_path and system_map_path.exists():
        cmd.extend(["--system-map", str(system_map_path)])
        logger.info(f"Using System.map: {system_map_path}")
    
    start_time = datetime.now()
    
    try:
        logger.info(f"Running command: {' '.join(cmd)}")
        
        # Run dwarf2json
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=True
        )
        
        # Write output to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        
        duration = (datetime.now() - start_time).total_seconds()
        size = output_path.stat().st_size
        
        logger.info(f"ISF generation completed in {duration:.1f}s, size: {size / (1024*1024):.1f} MB")
        
        return {
            "success": True,
            "output_file": output_path,
            "size_bytes": size,
            "duration_seconds": duration,
            "error": None
        }
        
    except subprocess.TimeoutExpired:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"ISF generation timed out after {duration:.1f}s")
        return {
            "success": False,
            "output_file": None,
            "size_bytes": None,
            "duration_seconds": duration,
            "error": f"Generation timed out after {timeout} seconds"
        }
        
    except subprocess.CalledProcessError as e:
        duration = (datetime.now() - start_time).total_seconds()
        error_msg = e.stderr if e.stderr else str(e)
        logger.error(f"dwarf2json failed: {error_msg}")
        
        # Check for common errors
        if "Unable to find debug information" in error_msg or "no debug info" in error_msg.lower():
            error_msg = "vmlinux file does not contain debug information. Please use vmlinux with CONFIG_DEBUG_INFO=y"
        
        return {
            "success": False,
            "output_file": None,
            "size_bytes": None,
            "duration_seconds": duration,
            "error": f"dwarf2json error: {error_msg}"
        }
        
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Unexpected error during ISF generation: {str(e)}")
        return {
            "success": False,
            "output_file": None,
            "size_bytes": None,
            "duration_seconds": duration,
            "error": f"Unexpected error: {str(e)}"
        }


def get_or_generate_isf(
    vmlinux_path: Path,
    cache_dir: Path,
    system_map_path: Optional[Path] = None
) -> Dict[str, any]:
    """
    Get ISF from cache or generate new one if not cached.
    
    Args:
        vmlinux_path: Path to vmlinux file
        cache_dir: Directory for symbol cache
        system_map_path: Optional System.map file
        
    Returns:
        Dict with result:
        {
            "success": bool,
            "isf_path": Path|None,
            "cached": bool,
            "error": str|None
        }
    """
    # Calculate hash
    try:
        vmlinux_hash = get_vmlinux_hash(vmlinux_path)
        logger.info(f"vmlinux hash: {vmlinux_hash}")
    except Exception as e:
        return {
            "success": False,
            "isf_path": None,
            "cached": False,
            "error": f"Failed to hash vmlinux: {str(e)}"
        }
    
    # Check cache
    cache_file = cache_dir / f"{vmlinux_hash}.json"
    if cache_file.exists():
        logger.info(f"Found cached ISF: {cache_file}")
        return {
            "success": True,
            "isf_path": cache_file,
            "cached": True,
            "error": None,
            "vmlinux_hash": vmlinux_hash
        }
    
    # Generate new ISF
    logger.info(f"No cache found, generating new ISF")
    result = generate_isf(vmlinux_path, cache_file, system_map_path)
    
    if result["success"]:
        # Update cache metadata
        metadata_file = cache_dir / "metadata.json"
        metadata = {}
        if metadata_file.exists():
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except:
                metadata = {}
        
        metadata[vmlinux_hash] = {
            "created_at": datetime.now().isoformat(),
            "size_bytes": result["size_bytes"],
            "duration_seconds": result["duration_seconds"]
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return {
            "success": True,
            "isf_path": cache_file,
            "cached": False,
            "error": None,
            "vmlinux_hash": vmlinux_hash
        }
    else:
        return {
            "success": False,
            "isf_path": None,
            "cached": False,
            "error": result["error"],
            "vmlinux_hash": vmlinux_hash
        }
