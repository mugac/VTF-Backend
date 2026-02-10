"""
IOC (Indicators of Compromise) Scanner API Endpoints.
Allows uploading IOC lists and scanning plugin results for matches.
"""

from pathlib import Path
import json
import re
import logging
from typing import Optional, List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)


class IOCList(BaseModel):
    """IOC list to scan against plugin results."""
    ips: List[str] = []
    domains: List[str] = []
    hashes: List[str] = []          # MD5, SHA1, SHA256
    filenames: List[str] = []       # File name patterns
    process_names: List[str] = []   # Process name patterns
    registry_keys: List[str] = []   # Registry key patterns
    custom_patterns: List[str] = [] # Arbitrary regex patterns


class IOCMatch(BaseModel):
    """A single IOC match found in plugin results."""
    ioc_type: str       # e.g. "ip", "domain", "hash", "filename", "process", "custom"
    ioc_value: str      # The IOC value that matched
    plugin: str         # Which plugin result contained the match
    field: str          # Which field/column matched
    row_index: int      # Row number in plugin results
    row_data: dict      # The full row data


class IOCScanResponse(BaseModel):
    """Response from IOC scan."""
    total_matches: int
    matches_by_type: dict
    matches: List[IOCMatch]


@router.post("/analysis/{analysis_id}/ioc-scan", response_model=IOCScanResponse)
async def scan_for_iocs(analysis_id: str, ioc_list: IOCList):
    """
    Scan all available plugin results for Indicators of Compromise.
    Searches through all completed plugin results in the analysis directory.
    """
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    # Collect all result files
    result_files = list(analysis_dir.glob("*.json"))
    result_files = [f for f in result_files if f.name != "metadata.json"]

    matches: List[IOCMatch] = []

    for result_file in result_files:
        plugin_name = result_file.stem
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            if not isinstance(data, list):
                continue

            for row_idx, row in enumerate(data):
                if not isinstance(row, dict):
                    continue

                # Convert all values to strings for searching
                for field, value in row.items():
                    if field == "__children":
                        continue
                    str_value = str(value).lower() if value is not None else ""

                    # Check IPs
                    for ip in ioc_list.ips:
                        if ip.lower() in str_value:
                            matches.append(IOCMatch(
                                ioc_type="ip",
                                ioc_value=ip,
                                plugin=plugin_name,
                                field=field,
                                row_index=row_idx,
                                row_data=row,
                            ))

                    # Check domains
                    for domain in ioc_list.domains:
                        if domain.lower() in str_value:
                            matches.append(IOCMatch(
                                ioc_type="domain",
                                ioc_value=domain,
                                plugin=plugin_name,
                                field=field,
                                row_index=row_idx,
                                row_data=row,
                            ))

                    # Check hashes
                    for h in ioc_list.hashes:
                        if h.lower() in str_value:
                            matches.append(IOCMatch(
                                ioc_type="hash",
                                ioc_value=h,
                                plugin=plugin_name,
                                field=field,
                                row_index=row_idx,
                                row_data=row,
                            ))

                    # Check filenames
                    for fname in ioc_list.filenames:
                        if fname.lower() in str_value:
                            matches.append(IOCMatch(
                                ioc_type="filename",
                                ioc_value=fname,
                                plugin=plugin_name,
                                field=field,
                                row_index=row_idx,
                                row_data=row,
                            ))

                    # Check process names
                    for pname in ioc_list.process_names:
                        if pname.lower() in str_value:
                            matches.append(IOCMatch(
                                ioc_type="process",
                                ioc_value=pname,
                                plugin=plugin_name,
                                field=field,
                                row_index=row_idx,
                                row_data=row,
                            ))

                    # Check registry keys
                    for rkey in ioc_list.registry_keys:
                        if rkey.lower() in str_value:
                            matches.append(IOCMatch(
                                ioc_type="registry",
                                ioc_value=rkey,
                                plugin=plugin_name,
                                field=field,
                                row_index=row_idx,
                                row_data=row,
                            ))

                    # Check custom regex patterns
                    for pattern in ioc_list.custom_patterns:
                        try:
                            if re.search(pattern, str(value) if value else "", re.IGNORECASE):
                                matches.append(IOCMatch(
                                    ioc_type="custom",
                                    ioc_value=pattern,
                                    plugin=plugin_name,
                                    field=field,
                                    row_index=row_idx,
                                    row_data=row,
                                ))
                        except re.error:
                            pass  # Invalid regex — skip

        except Exception as e:
            logger.warning(f"Error scanning {result_file.name}: {e}")
            continue

    # Deduplicate matches (same row + same IOC)
    seen = set()
    unique_matches = []
    for m in matches:
        key = (m.ioc_type, m.ioc_value, m.plugin, m.row_index)
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)

    # Group by type
    matches_by_type = {}
    for m in unique_matches:
        matches_by_type.setdefault(m.ioc_type, 0)
        matches_by_type[m.ioc_type] += 1

    return IOCScanResponse(
        total_matches=len(unique_matches),
        matches_by_type=matches_by_type,
        matches=unique_matches[:500],  # Limit response size
    )


# ─── IOC List Management (save/load per project) ───────────────────────

@router.post("/analysis/{analysis_id}/ioc-list")
async def save_ioc_list(analysis_id: str, ioc_list: IOCList):
    """Save an IOC list for a project."""
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    ioc_path = analysis_dir / "ioc_list.json"
    with open(ioc_path, "w", encoding="utf-8") as f:
        json.dump(ioc_list.dict(), f, indent=2, ensure_ascii=False)

    return {"message": "IOC list saved.", "total_indicators": sum([
        len(ioc_list.ips), len(ioc_list.domains), len(ioc_list.hashes),
        len(ioc_list.filenames), len(ioc_list.process_names),
        len(ioc_list.registry_keys), len(ioc_list.custom_patterns),
    ])}


@router.get("/analysis/{analysis_id}/ioc-list")
async def get_ioc_list(analysis_id: str):
    """Get saved IOC list for a project."""
    analysis_dir = settings.STORAGE_PATH / analysis_id
    if not analysis_dir.exists():
        raise HTTPException(status_code=404, detail="Analysis ID not found.")

    ioc_path = analysis_dir / "ioc_list.json"
    if not ioc_path.exists():
        return IOCList().dict()

    with open(ioc_path, "r", encoding="utf-8") as f:
        return json.load(f)
