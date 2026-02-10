"""
Annotations & Tagging API Endpoints.
Allows analysts to tag rows and add notes to plugin results.
"""

from pathlib import Path
import json
import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


class Annotation(BaseModel):
    """A single annotation/tag on a result row."""
    plugin: str             # Plugin name (short, e.g. "psscan")
    row_index: int          # Row number in results
    tag: str                # Tag: "suspicious", "benign", "ioc", "important", "reviewed"
    note: Optional[str] = None  # Free text note
    created_at: Optional[str] = None


class AnnotationCreate(BaseModel):
    """Request to create/update an annotation."""
    plugin: str
    row_index: int
    tag: str
    note: Optional[str] = None


class AnnotationsResponse(BaseModel):
    """Response with all annotations for a project."""
    analysis_id: str
    annotations: List[Annotation]
    total: int


def _get_annotations_path(analysis_id: str) -> Path:
    return settings.STORAGE_PATH / analysis_id / "annotations.json"


def _load_annotations(analysis_id: str) -> List[dict]:
    path = _get_annotations_path(analysis_id)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _save_annotations(analysis_id: str, annotations: List[dict]):
    path = _get_annotations_path(analysis_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(annotations, f, indent=2, ensure_ascii=False)


@router.get("/analysis/{analysis_id}/annotations", response_model=AnnotationsResponse)
async def get_annotations(analysis_id: str, plugin: Optional[str] = None):
    """Get all annotations for a project, optionally filtered by plugin."""
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    annotations = _load_annotations(analysis_id)
    
    if plugin:
        plugin_short = plugin.split('.')[-1].lower()
        annotations = [a for a in annotations if a.get("plugin") == plugin_short]

    return AnnotationsResponse(
        analysis_id=analysis_id,
        annotations=[Annotation(**a) for a in annotations],
        total=len(annotations),
    )


@router.post("/analysis/{analysis_id}/annotations")
async def add_annotation(analysis_id: str, annotation: AnnotationCreate):
    """Add or update an annotation on a result row."""
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    valid_tags = {"suspicious", "benign", "ioc", "important", "reviewed", "false_positive"}
    if annotation.tag not in valid_tags:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tag. Valid tags: {', '.join(valid_tags)}"
        )

    annotations = _load_annotations(analysis_id)
    plugin_short = annotation.plugin.split('.')[-1].lower()

    # Check if annotation already exists for this plugin + row
    existing_idx = None
    for i, a in enumerate(annotations):
        if a.get("plugin") == plugin_short and a.get("row_index") == annotation.row_index:
            existing_idx = i
            break

    new_annotation = {
        "plugin": plugin_short,
        "row_index": annotation.row_index,
        "tag": annotation.tag,
        "note": annotation.note,
        "created_at": datetime.utcnow().isoformat(),
    }

    if existing_idx is not None:
        annotations[existing_idx] = new_annotation
    else:
        annotations.append(new_annotation)

    _save_annotations(analysis_id, annotations)

    return {"message": "Annotation saved.", "annotation": new_annotation}


@router.delete("/analysis/{analysis_id}/annotations")
async def delete_annotation(analysis_id: str, plugin: str, row_index: int):
    """Delete an annotation from a result row."""
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    annotations = _load_annotations(analysis_id)
    plugin_short = plugin.split('.')[-1].lower()

    filtered = [a for a in annotations if not (
        a.get("plugin") == plugin_short and a.get("row_index") == row_index
    )]

    if len(filtered) == len(annotations):
        raise HTTPException(status_code=404, detail="Annotation not found.")

    _save_annotations(analysis_id, filtered)
    return {"message": "Annotation deleted."}


# ─── Dashboard / Summary ───────────────────────────────────────────────

@router.get("/analysis/{analysis_id}/dashboard")
async def get_dashboard(analysis_id: str):
    """
    Get a summary dashboard for a project.
    Aggregates data from all completed plugin results.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    # Load metadata
    metadata_path = analysis_dir / "metadata.json"
    metadata = {}
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)

    dashboard = {
        "analysis_id": analysis_id,
        "project_name": metadata.get("project_name", "Unknown"),
        "os_type": metadata.get("os_type"),
        "kernel_version": metadata.get("kernel_version"),
        "dump_size_mb": round(metadata.get("size_bytes", 0) / (1024 * 1024), 1),
        "completed_plugins": [],
        "failed_plugins": [],
        "summary": {},
    }

    # Scan for completed and failed plugins
    for f in analysis_dir.iterdir():
        if f.suffix == ".json" and f.name not in ("metadata.json", "annotations.json", "ioc_list.json"):
            dashboard["completed_plugins"].append(f.stem)
        elif f.suffix == ".error":
            dashboard["failed_plugins"].append(f.stem)

    # Process summary from known plugins
    summary = {}

    # Process count from psscan/pslist
    for pname in ["psscan", "pslist"]:
        pfile = analysis_dir / f"{pname}.json"
        if pfile.exists():
            try:
                data = json.load(open(pfile, "r", encoding="utf-8"))
                if isinstance(data, list):
                    summary["total_processes"] = len(data)
                    # Count unique process names
                    proc_names = set()
                    for row in data:
                        name = row.get("ImageFileName") or row.get("COMM") or row.get("Name")
                        if name:
                            proc_names.add(str(name))
                    summary["unique_process_names"] = len(proc_names)
                    summary["top_processes"] = sorted(
                        [(n, sum(1 for r in data if (r.get("ImageFileName") or r.get("COMM") or r.get("Name")) == n)) for n in list(proc_names)[:20]],
                        key=lambda x: x[1], reverse=True
                    )[:10]
                break
            except Exception:
                pass

    # Network connections from netscan/netstat
    for nname in ["netscan", "netstat"]:
        nfile = analysis_dir / f"{nname}.json"
        if nfile.exists():
            try:
                data = json.load(open(nfile, "r", encoding="utf-8"))
                if isinstance(data, list):
                    summary["total_connections"] = len(data)
                    # Unique foreign addresses
                    foreign_addrs = set()
                    for row in data:
                        addr = row.get("ForeignAddr") or row.get("Foreign Address")
                        if addr and str(addr) not in ("*", "0.0.0.0", "::", "-"):
                            foreign_addrs.add(str(addr))
                    summary["unique_foreign_addresses"] = len(foreign_addrs)
                    summary["foreign_addresses"] = list(foreign_addrs)[:50]
                break
            except Exception:
                pass

    # Malfind suspicious regions
    malfind_file = analysis_dir / "malfind.json"
    if malfind_file.exists():
        try:
            data = json.load(open(malfind_file, "r", encoding="utf-8"))
            if isinstance(data, list):
                summary["malfind_detections"] = len(data)
                # Unique PIDs with suspicious memory
                suspicious_pids = set()
                for row in data:
                    pid = row.get("PID") or row.get("Pid")
                    if pid is not None:
                        suspicious_pids.add(int(pid))
                summary["suspicious_process_count"] = len(suspicious_pids)
        except Exception:
            pass

    # File count from filescan
    filescan_file = analysis_dir / "filescan.json"
    if filescan_file.exists():
        try:
            data = json.load(open(filescan_file, "r", encoding="utf-8"))
            if isinstance(data, list):
                summary["total_files_in_memory"] = len(data)
        except Exception:
            pass

    # Annotations summary
    annotations = _load_annotations(analysis_id)
    if annotations:
        tag_counts = {}
        for a in annotations:
            tag = a.get("tag", "unknown")
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
        summary["annotations"] = {
            "total": len(annotations),
            "by_tag": tag_counts,
        }

    dashboard["summary"] = summary
    return dashboard
