"""
Sentinel Shield - Plugin Marketplace API
Extensible architecture for third-party security plugins
"""

from fastapi import APIRouter, HTTPException, Depends, UploadFile, File
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

from .auth import get_current_user

router = APIRouter()


# Plugin catalog
PLUGINS = [
    {
        "id": "plugin_hibp",
        "name": "Have I Been Pwned Integration",
        "author": "Sentinel Shield",
        "category": "breach_detection",
        "description": "Real-time breach checking via HIBP API",
        "version": "2.1.0",
        "downloads": 15420,
        "rating": 4.8,
        "price": "free",
        "installed": True,
        "enabled": True,
        "official": True
    },
    {
        "id": "plugin_vt",
        "name": "VirusTotal Scanner",
        "author": "Sentinel Shield",
        "category": "malware_analysis",
        "description": "Scan files and URLs with 70+ antivirus engines",
        "version": "3.0.1",
        "downloads": 12850,
        "rating": 4.9,
        "price": "free",
        "installed": True,
        "enabled": True,
        "official": True
    },
    {
        "id": "plugin_slack",
        "name": "Slack Notifications",
        "author": "Sentinel Shield",
        "category": "integrations",
        "description": "Send security alerts to Slack channels",
        "version": "1.5.0",
        "downloads": 8920,
        "rating": 4.7,
        "price": "free",
        "installed": False,
        "enabled": False,
        "official": True
    },
    {
        "id": "plugin_teams",
        "name": "Microsoft Teams Alerts",
        "author": "Sentinel Shield",
        "category": "integrations",
        "description": "Security notifications for MS Teams",
        "version": "1.3.2",
        "downloads": 7650,
        "rating": 4.6,
        "price": "free",
        "installed": False,
        "enabled": False,
        "official": True
    },
    {
        "id": "plugin_healthcare",
        "name": "Healthcare Compliance Pack",
        "author": "MedSec Solutions",
        "category": "compliance",
        "description": "HIPAA-specific threat detection and PHI protection",
        "version": "2.0.0",
        "downloads": 3240,
        "rating": 4.5,
        "price": "$99/month",
        "installed": False,
        "enabled": False,
        "official": False
    },
    {
        "id": "plugin_finance",
        "name": "Financial Services Shield",
        "author": "FinSecure Inc",
        "category": "compliance",
        "description": "PCI-DSS compliance and financial fraud detection",
        "version": "1.8.0",
        "downloads": 2890,
        "rating": 4.4,
        "price": "$149/month",
        "installed": False,
        "enabled": False,
        "official": False
    },
    {
        "id": "plugin_siem",
        "name": "SIEM Connector",
        "author": "Sentinel Shield",
        "category": "integrations",
        "description": "Export events to Splunk, QRadar, or Elastic SIEM",
        "version": "2.2.1",
        "downloads": 5430,
        "rating": 4.7,
        "price": "free",
        "installed": False,
        "enabled": False,
        "official": True
    },
    {
        "id": "plugin_o365",
        "name": "Office 365 Integration",
        "author": "Sentinel Shield",
        "category": "email_gateway",
        "description": "Deep integration with Microsoft 365 email",
        "version": "3.1.0",
        "downloads": 11200,
        "rating": 4.8,
        "price": "free",
        "installed": True,
        "enabled": True,
        "official": True
    },
    {
        "id": "plugin_gsuite",
        "name": "Google Workspace Shield",
        "author": "Sentinel Shield",
        "category": "email_gateway",
        "description": "Gmail and Google Workspace protection",
        "version": "2.9.0",
        "downloads": 9870,
        "rating": 4.7,
        "price": "free",
        "installed": False,
        "enabled": False,
        "official": True
    }
]

CATEGORIES = [
    {"id": "breach_detection", "name": "Breach Detection", "count": 1},
    {"id": "malware_analysis", "name": "Malware Analysis", "count": 1},
    {"id": "integrations", "name": "Integrations", "count": 3},
    {"id": "compliance", "name": "Compliance", "count": 2},
    {"id": "email_gateway", "name": "Email Gateway", "count": 2},
]


class PluginConfig(BaseModel):
    api_key: Optional[str] = None
    webhook_url: Optional[str] = None
    channel: Optional[str] = None
    enabled_features: List[str] = []


# API Endpoints

@router.get("/catalog")
async def get_plugin_catalog(
    category: Optional[str] = None,
    search: Optional[str] = None,
    installed_only: bool = False,
    current_user: dict = Depends(get_current_user)
):
    """Get available plugins from marketplace"""
    
    plugins = PLUGINS.copy()
    
    if category:
        plugins = [p for p in plugins if p["category"] == category]
    
    if search:
        plugins = [p for p in plugins if search.lower() in p["name"].lower() or search.lower() in p["description"].lower()]
    
    if installed_only:
        plugins = [p for p in plugins if p["installed"]]
    
    return {
        "total": len(plugins),
        "plugins": plugins,
        "categories": CATEGORIES
    }


@router.get("/installed")
async def get_installed_plugins(current_user: dict = Depends(get_current_user)):
    """Get list of installed plugins"""
    
    installed = [p for p in PLUGINS if p["installed"]]
    
    return {
        "total": len(installed),
        "enabled": len([p for p in installed if p["enabled"]]),
        "plugins": installed
    }


@router.get("/{plugin_id}")
async def get_plugin_details(
    plugin_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get detailed information about a plugin"""
    
    plugin = next((p for p in PLUGINS if p["id"] == plugin_id), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    # Add extra details
    details = plugin.copy()
    details["changelog"] = [
        {"version": plugin["version"], "date": "2024-12-01", "changes": ["Bug fixes", "Performance improvements"]},
        {"version": "Previous", "date": "2024-11-15", "changes": ["New features", "Security updates"]}
    ]
    details["requirements"] = ["Sentinel Shield v1.0+", "API key (for premium features)"]
    details["permissions"] = ["Read emails", "Access threat data", "Send notifications"]
    
    return details


@router.post("/{plugin_id}/install")
async def install_plugin(
    plugin_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Install a plugin from marketplace"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    plugin = next((p for p in PLUGINS if p["id"] == plugin_id), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    if plugin["installed"]:
        raise HTTPException(status_code=400, detail="Plugin already installed")
    
    # Simulate installation
    plugin["installed"] = True
    
    return {
        "message": f"Plugin '{plugin['name']}' installed successfully",
        "plugin_id": plugin_id,
        "requires_configuration": True,
        "next_step": f"Configure the plugin at /api/v1/plugins/{plugin_id}/configure"
    }


@router.post("/{plugin_id}/uninstall")
async def uninstall_plugin(
    plugin_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Uninstall a plugin"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    plugin = next((p for p in PLUGINS if p["id"] == plugin_id), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    if not plugin["installed"]:
        raise HTTPException(status_code=400, detail="Plugin not installed")
    
    plugin["installed"] = False
    plugin["enabled"] = False
    
    return {
        "message": f"Plugin '{plugin['name']}' uninstalled",
        "plugin_id": plugin_id
    }


@router.post("/{plugin_id}/enable")
async def enable_plugin(
    plugin_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Enable an installed plugin"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    plugin = next((p for p in PLUGINS if p["id"] == plugin_id), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    if not plugin["installed"]:
        raise HTTPException(status_code=400, detail="Plugin must be installed first")
    
    plugin["enabled"] = True
    
    return {"message": f"Plugin '{plugin['name']}' enabled", "plugin_id": plugin_id}


@router.post("/{plugin_id}/disable")
async def disable_plugin(
    plugin_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Disable a plugin"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    plugin = next((p for p in PLUGINS if p["id"] == plugin_id), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    plugin["enabled"] = False
    
    return {"message": f"Plugin '{plugin['name']}' disabled", "plugin_id": plugin_id}


@router.post("/{plugin_id}/configure")
async def configure_plugin(
    plugin_id: str,
    config: PluginConfig,
    current_user: dict = Depends(get_current_user)
):
    """Configure plugin settings"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    plugin = next((p for p in PLUGINS if p["id"] == plugin_id), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    return {
        "message": f"Plugin '{plugin['name']}' configured successfully",
        "plugin_id": plugin_id,
        "config_saved": True
    }


@router.get("/{plugin_id}/status")
async def get_plugin_status(
    plugin_id: str,
    current_user: dict = Depends(get_current_user)
):
    """Get plugin status and health"""
    
    plugin = next((p for p in PLUGINS if p["id"] == plugin_id), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    return {
        "plugin_id": plugin_id,
        "name": plugin["name"],
        "installed": plugin["installed"],
        "enabled": plugin["enabled"],
        "health": "healthy" if plugin["enabled"] else "inactive",
        "last_activity": datetime.utcnow().isoformat() + "Z" if plugin["enabled"] else None,
        "stats": {
            "events_processed": 1250 if plugin["enabled"] else 0,
            "errors": 0,
            "uptime": "99.9%" if plugin["enabled"] else "N/A"
        }
    }
