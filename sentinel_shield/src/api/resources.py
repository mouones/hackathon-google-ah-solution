"""
Sentinel Shield - Resources API
Exposes available integrations, data sources, and partnerships
"""

from fastapi import APIRouter, Depends
from typing import Optional

from .auth import get_current_user
from modules.resources import (
    THREAT_INTEL_FEEDS, SECURITY_APIS, ML_DATASETS, YARA_SOURCES,
    OPENSOURCE_TOOLS, POTENTIAL_PARTNERS, EMAIL_INTEGRATIONS, SIEM_INTEGRATIONS,
    get_all_resources
)

router = APIRouter()


@router.get("/summary")
async def get_resources_summary(current_user: dict = Depends(get_current_user)):
    """Get summary of all available resources and integrations"""
    
    summary = get_all_resources()
    
    return {
        "total_integrations": summary["total"],
        "breakdown": {
            "threat_intel_feeds": summary["threat_intel_feeds"],
            "security_apis": summary["security_apis"],
            "ml_datasets": summary["ml_datasets"],
            "yara_sources": summary["yara_sources"],
            "opensource_tools": summary["opensource_tools"],
            "potential_partners": summary["potential_partners"],
            "email_integrations": summary["email_integrations"],
            "siem_integrations": summary["siem_integrations"]
        },
        "active_integrations": 15,
        "planned_integrations": 25,
        "future_partners": 12
    }


@router.get("/threat-intel")
async def get_threat_intel_feeds(current_user: dict = Depends(get_current_user)):
    """Get all threat intelligence feed integrations"""
    return {
        "total": len(THREAT_INTEL_FEEDS),
        "feeds": THREAT_INTEL_FEEDS
    }


@router.get("/apis")
async def get_security_apis(current_user: dict = Depends(get_current_user)):
    """Get all security API integrations"""
    return {
        "total": len(SECURITY_APIS),
        "apis": SECURITY_APIS
    }


@router.get("/datasets")
async def get_ml_datasets(current_user: dict = Depends(get_current_user)):
    """Get machine learning datasets used for training"""
    return {
        "total": len(ML_DATASETS),
        "datasets": ML_DATASETS
    }


@router.get("/yara")
async def get_yara_sources(current_user: dict = Depends(get_current_user)):
    """Get YARA rule sources"""
    return {
        "total": len(YARA_SOURCES),
        "sources": YARA_SOURCES
    }


@router.get("/tools")
async def get_opensource_tools(current_user: dict = Depends(get_current_user)):
    """Get open source security tools integrations"""
    return {
        "total": len(OPENSOURCE_TOOLS),
        "tools": OPENSOURCE_TOOLS
    }


@router.get("/partners")
async def get_potential_partners(current_user: dict = Depends(get_current_user)):
    """Get potential partnership opportunities"""
    return {
        "total": len(POTENTIAL_PARTNERS),
        "partners": POTENTIAL_PARTNERS
    }


@router.get("/email-integrations")
async def get_email_integrations(current_user: dict = Depends(get_current_user)):
    """Get email service integrations"""
    return {
        "total": len(EMAIL_INTEGRATIONS),
        "integrations": EMAIL_INTEGRATIONS
    }


@router.get("/siem")
async def get_siem_integrations(current_user: dict = Depends(get_current_user)):
    """Get SIEM platform integrations"""
    return {
        "total": len(SIEM_INTEGRATIONS),
        "integrations": SIEM_INTEGRATIONS
    }
