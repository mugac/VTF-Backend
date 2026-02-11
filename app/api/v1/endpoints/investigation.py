"""
Investigation API Endpoints.
PID Watchlist / Tracked Processes + Registry Browser + Process Tree helpers.
"""

from pathlib import Path
import json
import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.core.config import settings
from app.api.v1.plugins import AVAILABLE_PLUGINS

router = APIRouter()
logger = logging.getLogger(__name__)


# ─── Models ─────────────────────────────────────────────────────────────

class TrackedProcess(BaseModel):
    """A process being tracked/watched by the analyst."""
    pid: int
    process_name: str = ""
    ppid: Optional[int] = None
    reason: str = ""                        # Why was it tracked
    tags: List[str] = []                    # e.g. ["suspicious", "malware", "interesting"]
    source_plugin: str = ""                 # Which plugin led to tracking
    notes: str = ""
    added_at: Optional[str] = None


class TrackProcessRequest(BaseModel):
    """Request to track a new process."""
    pid: int
    process_name: str = ""
    ppid: Optional[int] = None
    reason: str = ""
    tags: List[str] = []
    source_plugin: str = ""
    notes: str = ""


class UpdateTrackedProcessRequest(BaseModel):
    """Request to update a tracked process."""
    reason: Optional[str] = None
    tags: Optional[List[str]] = None
    notes: Optional[str] = None


VALID_TAGS = {
    "suspicious", "malware", "interesting", "cleared", "benign",
    "lateral_movement", "persistence", "exfiltration", "c2",
    "privilege_escalation", "injection", "rootkit"
}


# ─── Helpers ────────────────────────────────────────────────────────────

def _get_tracked_path(analysis_id: str) -> Path:
    return settings.STORAGE_PATH / analysis_id / "tracked_pids.json"


def _load_tracked(analysis_id: str) -> List[dict]:
    path = _get_tracked_path(analysis_id)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def _save_tracked(analysis_id: str, tracked: List[dict]):
    path = _get_tracked_path(analysis_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(tracked, f, indent=2, ensure_ascii=False)


def _validate_analysis(analysis_id: str) -> Path:
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")
    return analysis_dir


# ─── PID Watchlist Endpoints ────────────────────────────────────────────

@router.get("/analysis/{analysis_id}/tracked-pids")
async def get_tracked_pids(analysis_id: str, tag: Optional[str] = None):
    """Get all tracked PIDs, optionally filtered by tag."""
    _validate_analysis(analysis_id)
    tracked = _load_tracked(analysis_id)

    if tag:
        tracked = [t for t in tracked if tag in t.get("tags", [])]

    return {
        "analysis_id": analysis_id,
        "tracked_pids": tracked,
        "total": len(tracked),
    }


@router.post("/analysis/{analysis_id}/tracked-pids")
async def track_pid(analysis_id: str, request: TrackProcessRequest):
    """Add a PID to the watchlist."""
    _validate_analysis(analysis_id)
    tracked = _load_tracked(analysis_id)

    # Validate tags
    invalid_tags = set(request.tags) - VALID_TAGS
    if invalid_tags:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid tags: {', '.join(invalid_tags)}. Valid: {', '.join(sorted(VALID_TAGS))}"
        )

    # Check if already tracked
    for t in tracked:
        if t["pid"] == request.pid:
            raise HTTPException(
                status_code=409,
                detail=f"PID {request.pid} is already tracked. Use PATCH to update."
            )

    # Auto-fill process name from pslist/psscan if not provided
    process_name = request.process_name
    if not process_name:
        process_name = _lookup_process_name(analysis_id, request.pid)

    new_entry = {
        "pid": request.pid,
        "process_name": process_name,
        "ppid": request.ppid,
        "reason": request.reason,
        "tags": request.tags,
        "source_plugin": request.source_plugin,
        "notes": request.notes,
        "added_at": datetime.utcnow().isoformat(),
    }

    tracked.append(new_entry)
    _save_tracked(analysis_id, tracked)

    return {"message": f"PID {request.pid} tracked.", "tracked_process": new_entry}


@router.patch("/analysis/{analysis_id}/tracked-pids/{pid}")
async def update_tracked_pid(analysis_id: str, pid: int, request: UpdateTrackedProcessRequest):
    """Update a tracked PID's reason, tags, or notes."""
    _validate_analysis(analysis_id)
    tracked = _load_tracked(analysis_id)

    found = None
    for t in tracked:
        if t["pid"] == pid:
            found = t
            break

    if not found:
        raise HTTPException(status_code=404, detail=f"PID {pid} is not tracked.")

    if request.tags is not None:
        invalid_tags = set(request.tags) - VALID_TAGS
        if invalid_tags:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid tags: {', '.join(invalid_tags)}"
            )
        found["tags"] = request.tags

    if request.reason is not None:
        found["reason"] = request.reason
    if request.notes is not None:
        found["notes"] = request.notes

    _save_tracked(analysis_id, tracked)
    return {"message": f"PID {pid} updated.", "tracked_process": found}


@router.delete("/analysis/{analysis_id}/tracked-pids/{pid}")
async def untrack_pid(analysis_id: str, pid: int):
    """Remove a PID from the watchlist."""
    _validate_analysis(analysis_id)
    tracked = _load_tracked(analysis_id)

    new_list = [t for t in tracked if t["pid"] != pid]
    if len(new_list) == len(tracked):
        raise HTTPException(status_code=404, detail=f"PID {pid} is not tracked.")

    _save_tracked(analysis_id, new_list)
    return {"message": f"PID {pid} removed from watchlist."}


def _lookup_process_name(analysis_id: str, pid: int) -> str:
    """Try to find process name from existing plugin results."""
    analysis_dir = settings.STORAGE_PATH / analysis_id
    for pfile_name in ["pslist", "psscan", "pstree"]:
        pfile = analysis_dir / f"{pfile_name}.json"
        if pfile.exists():
            try:
                with open(pfile, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    for row in data:
                        row_pid = row.get("PID") or row.get("Pid")
                        if row_pid is not None and int(row_pid) == pid:
                            return (
                                row.get("ImageFileName")
                                or row.get("COMM")
                                or row.get("Name")
                                or ""
                            )
            except Exception:
                continue
    return ""


# ─── Process Tree Endpoint ──────────────────────────────────────────────

@router.get("/analysis/{analysis_id}/process-tree")
async def get_process_tree(analysis_id: str):
    """
    Get process tree data with tracking status merged in.
    Returns the pstree data with __children preserved, plus tracking info.
    """
    analysis_dir = _validate_analysis(analysis_id)
    tracked = _load_tracked(analysis_id)
    tracked_pids = {t["pid"]: t for t in tracked}

    # Try pstree first (has __children), fall back to pslist/psscan
    tree_file = analysis_dir / "pstree.json"
    if tree_file.exists():
        with open(tree_file, "r", encoding="utf-8") as f:
            # Re-read the raw file — we need __children which _clean_children may have removed
            raw_data = json.load(f)

        # Annotate tree with tracking info
        def annotate_tree(nodes):
            for node in nodes if isinstance(nodes, list) else [nodes]:
                pid = node.get("PID") or node.get("Pid")
                if pid is not None and int(pid) in tracked_pids:
                    node["_tracked"] = tracked_pids[int(pid)]
                children = node.get("__children", [])
                if children:
                    annotate_tree(children)

        annotate_tree(raw_data)
        return {"source": "pstree", "tree": raw_data}

    # Fallback: build flat process list from pslist/psscan
    for pname in ["pslist", "psscan"]:
        pfile = analysis_dir / f"{pname}.json"
        if pfile.exists():
            with open(pfile, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                # Build tree from PPID relationships
                tree = _build_tree_from_flat(data, tracked_pids)
                return {"source": pname, "tree": tree}

    raise HTTPException(
        status_code=404,
        detail="No process data available. Run pstree, pslist, or psscan first."
    )


def _build_tree_from_flat(processes: list, tracked_pids: dict) -> list:
    """Build a hierarchical tree from a flat process list using PID/PPID."""
    pid_map = {}
    for proc in processes:
        pid = proc.get("PID") or proc.get("Pid")
        if pid is not None:
            pid = int(pid)
            node = {**proc, "__children": []}
            if pid in tracked_pids:
                node["_tracked"] = tracked_pids[pid]
            pid_map[pid] = node

    roots = []
    for pid, node in pid_map.items():
        ppid = node.get("PPID") or node.get("PPid")
        if ppid is not None:
            ppid = int(ppid)
        if ppid in pid_map and ppid != pid:
            pid_map[ppid]["__children"].append(node)
        else:
            roots.append(node)

    return roots


# ─── Process Timeline Endpoint ──────────────────────────────────────────

@router.get("/analysis/{analysis_id}/process-timeline")
async def get_process_timeline(analysis_id: str):
    """
    Get process creation/exit timeline data.
    Returns processes with their CreateTime and ExitTime for timeline visualization.
    """
    analysis_dir = _validate_analysis(analysis_id)
    tracked = _load_tracked(analysis_id)
    tracked_pids = {t["pid"]: t for t in tracked}

    processes = []
    
    # Collect from psscan (includes terminated processes) or pslist
    for pname in ["psscan", "pslist", "pstree"]:
        pfile = analysis_dir / f"{pname}.json"
        if pfile.exists():
            try:
                with open(pfile, "r", encoding="utf-8") as f:
                    data = json.load(f)
                
                def extract_processes(items):
                    for row in items if isinstance(items, list) else [items]:
                        pid = row.get("PID") or row.get("Pid")
                        if pid is None:
                            continue
                        pid = int(pid)
                        
                        proc = {
                            "pid": pid,
                            "ppid": int(row.get("PPID") or row.get("PPid") or 0),
                            "name": row.get("ImageFileName") or row.get("COMM") or row.get("Name") or "?",
                            "create_time": row.get("CreateTime") or row.get("STARTTIME") or None,
                            "exit_time": row.get("ExitTime") or None,
                            "is_tracked": pid in tracked_pids,
                            "tracked_info": tracked_pids.get(pid),
                        }
                        processes.append(proc)
                        
                        # Recurse into __children for pstree
                        children = row.get("__children", [])
                        if children:
                            extract_processes(children)

                extract_processes(data)
                break  # Use first available source
            except Exception as e:
                logger.error(f"Error loading {pname}: {e}")
                continue

    if not processes:
        raise HTTPException(
            status_code=404,
            detail="No process data for timeline. Run psscan or pslist first."
        )

    # Add malfind info to timeline entries
    malfind_file = analysis_dir / "malfind.json"
    malfind_pids = set()
    if malfind_file.exists():
        try:
            with open(malfind_file, "r", encoding="utf-8") as f:
                mf_data = json.load(f)
            if isinstance(mf_data, list):
                for row in mf_data:
                    mpid = row.get("PID") or row.get("Pid")
                    if mpid is not None:
                        malfind_pids.add(int(mpid))
        except Exception:
            pass

    for proc in processes:
        proc["has_malfind"] = proc["pid"] in malfind_pids

    # Sort by create_time
    processes.sort(key=lambda p: p.get("create_time") or "")

    return {
        "analysis_id": analysis_id,
        "processes": processes,
        "total": len(processes),
        "tracked_count": sum(1 for p in processes if p["is_tracked"]),
        "malfind_count": sum(1 for p in processes if p["has_malfind"]),
    }


# ─── Registry Browser Endpoint ─────────────────────────────────────────

@router.get("/analysis/{analysis_id}/registry/hives")
async def get_registry_hives(analysis_id: str):
    """Get list of registry hives from hivelist plugin results."""
    analysis_dir = _validate_analysis(analysis_id)
    
    hivelist_file = analysis_dir / "hivelist.json"
    if not hivelist_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Registry hive list not available. Run windows.registry.hivelist.HiveList first."
        )
    
    with open(hivelist_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        return {"hives": []}
    
    hives = []
    for row in data:
        hive = {
            "offset": row.get("Offset"),
            "file_path": row.get("FileFullPath") or row.get("File output") or "",
        }
        # Extract short name from path
        full_path = hive["file_path"]
        if full_path:
            parts = full_path.replace("\\", "/").split("/")
            hive["short_name"] = parts[-1] if parts else full_path
        else:
            hive["short_name"] = f"Unnamed (0x{hive['offset']:x})" if hive["offset"] else "Unknown"
        hives.append(hive)
    
    return {"analysis_id": analysis_id, "hives": hives}


@router.get("/analysis/{analysis_id}/registry/keys")
async def get_registry_keys(analysis_id: str, hive_offset: Optional[int] = None, key_path: Optional[str] = None):
    """
    Get registry keys from printkey results.
    Can filter by hive_offset and/or key_path for browsing.
    """
    analysis_dir = _validate_analysis(analysis_id)
    
    printkey_file = analysis_dir / "printkey.json"
    if not printkey_file.exists():
        raise HTTPException(
            status_code=404,
            detail="Registry key data not available. Run windows.registry.printkey.PrintKey first."
        )
    
    with open(printkey_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    if not isinstance(data, list):
        return {"keys": [], "values": []}
    
    # Filter by hive offset if specified
    filtered = data
    if hive_offset is not None:
        filtered = [r for r in filtered if r.get("Hive Offset") == hive_offset]
    
    # Filter by key path if specified
    if key_path is not None:
        filtered = [r for r in filtered if r.get("Key") == key_path]
    
    # Separate keys and values
    keys = [r for r in filtered if r.get("Type") == "Key"]
    values = [r for r in filtered if r.get("Type") != "Key"]
    
    return {
        "key_path": key_path,
        "hive_offset": hive_offset,
        "keys": keys,
        "values": values,
        "total_keys": len(keys),
        "total_values": len(values),
    }


# ─── Investigation Summary ─────────────────────────────────────────────

@router.get("/analysis/{analysis_id}/investigation-summary")
async def get_investigation_summary(analysis_id: str):
    """
    Get a summary of the current investigation state — tracked PIDs,
    available data, suggestions for next steps.
    """
    analysis_dir = _validate_analysis(analysis_id)
    tracked = _load_tracked(analysis_id)

    # Check which plugins have results
    completed_plugins = []
    for f in analysis_dir.iterdir():
        if f.suffix == ".json" and f.name not in (
            "metadata.json", "annotations.json", "ioc_list.json", "tracked_pids.json"
        ):
            completed_plugins.append(f.stem)

    # Gather per-PID result availability
    pid_results = {}
    for t in tracked:
        pid = t["pid"]
        pid_data = {"pid": pid, "process_name": t["process_name"], "available_results": []}
        for plugin_short in completed_plugins:
            if f"_pid{pid}" in plugin_short:
                pid_data["available_results"].append(plugin_short.replace(f"_pid{pid}", ""))
        pid_results[pid] = pid_data

    # Suggest next actions
    suggestions = []
    if not tracked:
        suggestions.append("Start by tracking suspicious PIDs from malfind or psscan results.")
    
    has_pstree = "pstree" in completed_plugins
    has_psscan = "psscan" in completed_plugins
    has_malfind = "malfind" in completed_plugins
    
    if not has_pstree:
        suggestions.append("Run PsTree to see process parent-child relationships.")
    if not has_psscan:
        suggestions.append("Run PsScan to find all processes including terminated ones.")
    if not has_malfind:
        suggestions.append("Run Malfind to detect suspicious memory injections.")
    
    for t in tracked:
        pid = t["pid"]
        pid_name = t["process_name"]
        pid_short_results = pid_results.get(pid, {}).get("available_results", [])
        if "dlllist" not in pid_short_results:
            suggestions.append(f"Run DllList for PID {pid} ({pid_name}) to check loaded modules.")
        if "handles" not in pid_short_results:
            suggestions.append(f"Run Handles for PID {pid} ({pid_name}) to examine open handles.")

    return {
        "analysis_id": analysis_id,
        "tracked_pids": tracked,
        "tracked_count": len(tracked),
        "completed_plugins": completed_plugins,
        "pid_results": pid_results,
        "suggestions": suggestions[:10],  # Limit suggestions
    }
