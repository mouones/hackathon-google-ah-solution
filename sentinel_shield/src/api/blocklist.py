"""
Sentinel Shield - Blocklist Management API
Admin interface for managing blocked senders, domains, and IPs
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List, Dict
from datetime import datetime
import re

# Import auth dependency
from .auth import get_current_user

router = APIRouter()


# In-memory blocklist storage (in production: use database)
BLOCKLIST = {
    "domains": [
        {"value": "paypa1-verify.tk", "reason": "Brand impersonation (PayPal)", "added_by": "system", "added_at": "2024-12-14T03:00:00Z", "hits": 15},
        {"value": "suppIier-payments.xyz", "reason": "Malware distribution", "added_by": "admin", "added_at": "2024-12-14T02:30:00Z", "hits": 8},
        {"value": "company-urgent.ml", "reason": "CEO fraud attempts", "added_by": "admin", "added_at": "2024-12-14T01:00:00Z", "hits": 3},
    ],
    "senders": [
        {"value": "security@paypa1-verify.tk", "reason": "Phishing sender", "added_by": "system", "added_at": "2024-12-14T03:00:00Z", "hits": 15},
        {"value": "invoice@suppIier-payments.xyz", "reason": "Malware sender", "added_by": "admin", "added_at": "2024-12-14T02:30:00Z", "hits": 8},
    ],
    "ips": [
        {"value": "192.168.100.50", "reason": "Known C2 server", "added_by": "threat_intel", "added_at": "2024-12-13T12:00:00Z", "hits": 42},
        {"value": "10.0.0.99", "reason": "Spam source", "added_by": "admin", "added_at": "2024-12-12T08:00:00Z", "hits": 127},
    ],
    "keywords": [
        {"value": "gift card", "reason": "Common in BEC scams", "added_by": "admin", "added_at": "2024-12-10T00:00:00Z", "hits": 5},
        {"value": "wire transfer urgent", "reason": "Financial fraud indicator", "added_by": "system", "added_at": "2024-12-09T00:00:00Z", "hits": 12},
    ]
}


# Pydantic Models
class BlocklistEntry(BaseModel):
    value: str
    reason: str
    entry_type: str  # domain, sender, ip, keyword


class BlocklistItem(BaseModel):
    value: str
    reason: str
    added_by: str
    added_at: str
    hits: int


class BlocklistStats(BaseModel):
    total_entries: int
    domains: int
    senders: int
    ips: int
    keywords: int
    total_blocks_24h: int


# API Endpoints

@router.get("/stats", response_model=BlocklistStats)
async def get_blocklist_stats(
    current_user: dict = Depends(get_current_user)
):
    """Get blocklist statistics"""
    
    return BlocklistStats(
        total_entries=sum(len(v) for v in BLOCKLIST.values()),
        domains=len(BLOCKLIST["domains"]),
        senders=len(BLOCKLIST["senders"]),
        ips=len(BLOCKLIST["ips"]),
        keywords=len(BLOCKLIST["keywords"]),
        total_blocks_24h=sum(item["hits"] for category in BLOCKLIST.values() for item in category)
    )


@router.get("/all")
async def get_all_blocklist(
    current_user: dict = Depends(get_current_user)
):
    """Get complete blocklist"""
    
    return {
        "domains": BLOCKLIST["domains"],
        "senders": BLOCKLIST["senders"],
        "ips": BLOCKLIST["ips"],
        "keywords": BLOCKLIST["keywords"]
    }


@router.get("/{entry_type}")
async def get_blocklist_by_type(
    entry_type: str,
    search: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Get blocklist entries by type (domains, senders, ips, keywords)"""
    
    if entry_type not in BLOCKLIST:
        raise HTTPException(status_code=400, detail=f"Invalid entry type. Use: domains, senders, ips, keywords")
    
    entries = BLOCKLIST[entry_type]
    
    if search:
        entries = [e for e in entries if search.lower() in e["value"].lower()]
    
    return {
        "type": entry_type,
        "count": len(entries),
        "entries": entries
    }


@router.post("/add")
async def add_to_blocklist(
    entry: BlocklistEntry,
    current_user: dict = Depends(get_current_user)
):
    """Add entry to blocklist"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    entry_type = entry.entry_type + "s"  # domain -> domains
    if entry_type not in BLOCKLIST:
        entry_type = entry.entry_type  # Try exact match
        if entry_type not in BLOCKLIST:
            raise HTTPException(status_code=400, detail=f"Invalid entry type")
    
    # Check if already exists
    for existing in BLOCKLIST[entry_type]:
        if existing["value"].lower() == entry.value.lower():
            raise HTTPException(status_code=400, detail="Entry already exists in blocklist")
    
    new_entry = {
        "value": entry.value.lower(),
        "reason": entry.reason,
        "added_by": current_user["email"],
        "added_at": datetime.utcnow().isoformat() + "Z",
        "hits": 0
    }
    
    BLOCKLIST[entry_type].append(new_entry)
    
    return {
        "message": "Entry added to blocklist",
        "entry": new_entry,
        "type": entry_type
    }


@router.delete("/{entry_type}/{value}")
async def remove_from_blocklist(
    entry_type: str,
    value: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove entry from blocklist"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if entry_type not in BLOCKLIST:
        raise HTTPException(status_code=400, detail="Invalid entry type")
    
    original_len = len(BLOCKLIST[entry_type])
    BLOCKLIST[entry_type] = [e for e in BLOCKLIST[entry_type] if e["value"].lower() != value.lower()]
    
    if len(BLOCKLIST[entry_type]) == original_len:
        raise HTTPException(status_code=404, detail="Entry not found in blocklist")
    
    return {
        "message": "Entry removed from blocklist",
        "value": value,
        "type": entry_type
    }


@router.post("/check")
async def check_against_blocklist(
    sender: Optional[str] = None,
    domain: Optional[str] = None,
    ip: Optional[str] = None,
    content: Optional[str] = None
):
    """Check if sender/domain/ip/content matches blocklist"""
    
    matches = []
    
    if sender:
        for entry in BLOCKLIST["senders"]:
            if entry["value"].lower() == sender.lower():
                matches.append({"type": "sender", "matched": entry["value"], "reason": entry["reason"]})
    
    if domain:
        for entry in BLOCKLIST["domains"]:
            if entry["value"].lower() in domain.lower():
                matches.append({"type": "domain", "matched": entry["value"], "reason": entry["reason"]})
    
    if ip:
        for entry in BLOCKLIST["ips"]:
            if entry["value"] == ip:
                matches.append({"type": "ip", "matched": entry["value"], "reason": entry["reason"]})
    
    if content:
        for entry in BLOCKLIST["keywords"]:
            if entry["value"].lower() in content.lower():
                matches.append({"type": "keyword", "matched": entry["value"], "reason": entry["reason"]})
    
    return {
        "is_blocked": len(matches) > 0,
        "matches": matches,
        "match_count": len(matches)
    }


@router.post("/import")
async def import_blocklist(
    entries: List[BlocklistEntry],
    current_user: dict = Depends(get_current_user)
):
    """Bulk import blocklist entries"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    added = 0
    skipped = 0
    
    for entry in entries:
        entry_type = entry.entry_type + "s"
        if entry_type not in BLOCKLIST:
            entry_type = entry.entry_type
        
        if entry_type not in BLOCKLIST:
            skipped += 1
            continue
        
        # Check if exists
        exists = any(e["value"].lower() == entry.value.lower() for e in BLOCKLIST[entry_type])
        if exists:
            skipped += 1
            continue
        
        BLOCKLIST[entry_type].append({
            "value": entry.value.lower(),
            "reason": entry.reason,
            "added_by": current_user["email"],
            "added_at": datetime.utcnow().isoformat() + "Z",
            "hits": 0
        })
        added += 1
    
    return {
        "message": f"Import complete: {added} added, {skipped} skipped",
        "added": added,
        "skipped": skipped
    }


@router.get("/export")
async def export_blocklist(
    entry_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Export blocklist in various formats"""
    
    if entry_type and entry_type in BLOCKLIST:
        data = {entry_type: BLOCKLIST[entry_type]}
    else:
        data = BLOCKLIST
    
    return {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "exported_by": current_user["email"],
        "data": data
    }
