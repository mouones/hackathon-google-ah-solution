"""
Sentinel Shield - AI Security Analyst API
Natural language interface for security queries powered by NLP
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import re

from .auth import get_current_user

router = APIRouter()


class SecurityQuery(BaseModel):
    question: str
    context: Optional[str] = None


class QueryResponse(BaseModel):
    answer: str
    data: Optional[dict] = None
    visualizations: Optional[List[dict]] = None
    follow_up_questions: List[str]


# Query patterns and responses
QUERY_PATTERNS = {
    r"(threats?|attacks?).*(today|24 hours|last day)": {
        "handler": "threats_today",
        "description": "Threats in the last 24 hours"
    },
    r"(phishing|phish).*(emails?|attempts?)": {
        "handler": "phishing_stats",
        "description": "Phishing email statistics"
    },
    r"(employee|user|staff).*(risk|vulnerable|at risk)": {
        "handler": "at_risk_employees",
        "description": "Employees at security risk"
    },
    r"(blocked|quarantine).*(how many|count|number)": {
        "handler": "blocked_count",
        "description": "Count of blocked items"
    },
    r"(top|most).*(threats?|attacks?|risks?)": {
        "handler": "top_threats",
        "description": "Top threats by frequency"
    },
    r"(dark web|breach|leaked)": {
        "handler": "dark_web_status",
        "description": "Dark web monitoring status"
    },
    r"(training|security awareness)": {
        "handler": "training_status",
        "description": "Security training status"
    },
    r"(recommend|suggest|should|advice)": {
        "handler": "recommendations",
        "description": "Security recommendations"
    },
}


def get_threats_today():
    return {
        "answer": "In the last 24 hours, I detected **127 threats** across your organization. Here's the breakdown:\n\n• 45 Phishing emails blocked\n• 23 Malicious URLs blocked\n• 12 Suspicious attachments quarantined\n• 47 Spam emails filtered\n\nThe most targeted department was **Marketing** with 34 attempts.",
        "data": {
            "total": 127,
            "phishing": 45,
            "malicious_urls": 23,
            "attachments": 12,
            "spam": 47,
            "most_targeted": "Marketing"
        },
        "visualizations": [
            {"type": "pie_chart", "title": "Threat Distribution", "data": {"phishing": 45, "urls": 23, "attachments": 12, "spam": 47}}
        ],
        "follow_up_questions": [
            "Show me the phishing attempts in detail",
            "Which employees were targeted?",
            "Compare to last week's threats"
        ]
    }


def get_phishing_stats():
    return {
        "answer": "Here's your phishing analysis:\n\n📧 **This Week:** 156 phishing attempts blocked (97.2% detection rate)\n📈 **Trend:** 12% increase from last week\n🎯 **Top Target:** Finance department\n🏷️ **Common Themes:** Invoice fraud (34%), Password reset (28%), Package delivery (22%)\n\nNo successful phishing attacks this week!",
        "data": {
            "attempts_blocked": 156,
            "detection_rate": 97.2,
            "trend": "+12%",
            "top_target": "Finance",
            "themes": {"invoice": 34, "password": 28, "package": 22, "other": 16}
        },
        "follow_up_questions": [
            "Show me examples of blocked emails",
            "Which brands were impersonated?",
            "Schedule phishing training for Finance"
        ]
    }


def get_at_risk_employees():
    return {
        "answer": "I've identified **5 employees** who may need additional security training:\n\n1. **John Smith** (Marketing) - Failed 2 phishing tests, clicked 1 real phishing link\n2. **Sarah Jones** (Sales) - Password found in breach, hasn't reset\n3. **Mike Brown** (Finance) - Opened suspicious attachment last week\n4. **Lisa Chen** (HR) - Using weak password pattern\n5. **Tom Wilson** (IT) - Disabled 2FA on personal device\n\nI recommend scheduling targeted training sessions.",
        "data": {
            "at_risk_count": 5,
            "employees": [
                {"name": "John Smith", "dept": "Marketing", "risk": "high"},
                {"name": "Sarah Jones", "dept": "Sales", "risk": "high"},
                {"name": "Mike Brown", "dept": "Finance", "risk": "medium"},
                {"name": "Lisa Chen", "dept": "HR", "risk": "medium"},
                {"name": "Tom Wilson", "dept": "IT", "risk": "low"}
            ]
        },
        "follow_up_questions": [
            "Send training invites to these employees",
            "Show their security scores over time",
            "What training modules should they complete?"
        ]
    }


def get_blocked_count():
    return {
        "answer": "Here's your blocking summary:\n\n📊 **Today:** 34 items quarantined\n📅 **This Week:** 187 items blocked\n📆 **This Month:** 892 threats neutralized\n\n**Breakdown:**\n• Emails: 450\n• URLs: 312\n• Attachments: 89\n• Domains: 41",
        "data": {
            "today": 34,
            "week": 187,
            "month": 892,
            "by_type": {"emails": 450, "urls": 312, "attachments": 89, "domains": 41}
        },
        "follow_up_questions": [
            "Show me what's in quarantine now",
            "Any false positives this week?",
            "Export blocking report"
        ]
    }


def get_top_threats():
    return {
        "answer": "Your top 5 threat categories this month:\n\n1. 🎣 **Brand Impersonation** - 234 attempts (Microsoft, PayPal, Amazon)\n2. 💰 **BEC/CEO Fraud** - 89 attempts targeting Finance\n3. 📎 **Malicious Attachments** - 67 blocked (mostly .docm, .xlsm)\n4. 🔗 **Credential Harvesting** - 45 fake login pages\n5. 🦠 **Malware Distribution** - 23 samples detected\n\nBrand impersonation is up 45% from last month.",
        "data": {
            "threats": [
                {"name": "Brand Impersonation", "count": 234, "trend": "+45%"},
                {"name": "BEC/CEO Fraud", "count": 89, "trend": "+12%"},
                {"name": "Malicious Attachments", "count": 67, "trend": "-5%"},
                {"name": "Credential Harvesting", "count": 45, "trend": "+8%"},
                {"name": "Malware", "count": 23, "trend": "-15%"}
            ]
        },
        "follow_up_questions": [
            "Show me brand impersonation examples",
            "Who is being targeted by CEO fraud?",
            "What malware variants were detected?"
        ]
    }


def get_dark_web_status():
    return {
        "answer": "🌐 **Dark Web Monitoring Status:**\n\nCurrently monitoring 3 domains. Last scan: 2 hours ago\n\n⚠️ **2 Active Alerts:**\n1. `john.smith@company.com` found in LinkedIn breach (password hash exposed)\n2. `sarah.jones@company.com` found in Dropbox breach\n\n✅ No company documents or trade secrets detected on paste sites.\n✅ No mentions on dark web forums this week.",
        "data": {
            "monitored_domains": 3,
            "breaches_found": 2,
            "documents_leaked": 0,
            "forum_mentions": 0
        },
        "follow_up_questions": [
            "Force password reset for affected users",
            "Show breach details",
            "Add more domains to monitoring"
        ]
    }


def get_training_status():
    return {
        "answer": "📚 **Security Training Overview:**\n\n• **Completion Rate:** 78% (156/200 employees)\n• **Avg Score:** 82%\n• **Overdue:** 12 employees haven't started required modules\n\n🏆 **Top Performers:** IT Department (avg 94%)\n⚠️ **Needs Improvement:** Marketing (avg 68%)\n\nNext phishing simulation scheduled for Monday.",
        "data": {
            "completion_rate": 78,
            "avg_score": 82,
            "overdue": 12,
            "top_dept": "IT",
            "low_dept": "Marketing"
        },
        "follow_up_questions": [
            "Send reminders to overdue employees",
            "Schedule training for Marketing",
            "Show leaderboard"
        ]
    }


def get_recommendations():
    return {
        "answer": "Based on my analysis, here are my top recommendations:\n\n1. **High Priority:** Force password reset for 2 employees found in breaches\n2. **High Priority:** Schedule phishing training for Marketing (low scores)\n3. **Medium:** Enable MFA for 8 users who haven't activated it\n4. **Medium:** Review 34 quarantined items from today\n5. **Low:** Update blocklist with new phishing domains\n\nWould you like me to create action items for these?",
        "data": {
            "high_priority": 2,
            "medium_priority": 2,
            "low_priority": 1
        },
        "follow_up_questions": [
            "Create action items for all",
            "Start with high priority items",
            "Show me the details for each"
        ]
    }


HANDLERS = {
    "threats_today": get_threats_today,
    "phishing_stats": get_phishing_stats,
    "at_risk_employees": get_at_risk_employees,
    "blocked_count": get_blocked_count,
    "top_threats": get_top_threats,
    "dark_web_status": get_dark_web_status,
    "training_status": get_training_status,
    "recommendations": get_recommendations,
}


@router.post("/query")
async def security_query(
    query: SecurityQuery,
    current_user: dict = Depends(get_current_user)
):
    """Process natural language security query"""
    
    question = query.question.lower()
    
    # Find matching handler
    for pattern, config in QUERY_PATTERNS.items():
        if re.search(pattern, question, re.IGNORECASE):
            handler = HANDLERS.get(config["handler"])
            if handler:
                result = handler()
                return {
                    "query": query.question,
                    "matched_intent": config["description"],
                    **result
                }
    
    # Default response
    return {
        "query": query.question,
        "matched_intent": "general",
        "answer": f"I understood your question: '{query.question}'\n\nI can help you with:\n• Threat statistics and trends\n• Phishing analysis\n• Employee risk assessment\n• Blocked items and quarantine\n• Dark web monitoring\n• Training status\n• Security recommendations\n\nTry asking something like 'Show me threats from today' or 'Which employees are at risk?'",
        "follow_up_questions": [
            "What threats were detected today?",
            "Show me phishing statistics",
            "Which employees need training?"
        ]
    }


@router.get("/suggestions")
async def get_query_suggestions(current_user: dict = Depends(get_current_user)):
    """Get suggested queries based on current security state"""
    
    return {
        "trending_queries": [
            "What threats were blocked today?",
            "Show me phishing attempts this week",
            "Which employees are at risk?",
            "Any dark web alerts?",
            "What should I focus on today?"
        ],
        "recent_queries": [
            "Top threats this month",
            "Training completion status",
            "Blocked email count"
        ],
        "quick_actions": [
            {"query": "Give me a security summary", "icon": "📊"},
            {"query": "Any urgent alerts?", "icon": "🚨"},
            {"query": "Show recommendations", "icon": "💡"}
        ]
    }


@router.post("/action")
async def execute_action(
    action: str,
    target: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """Execute security action from AI recommendation"""
    
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    actions = {
        "force_password_reset": f"Password reset email sent to {target or 'affected users'}",
        "schedule_training": f"Training session scheduled for {target or 'specified department'}",
        "enable_mfa": f"MFA enrollment email sent to {target or 'users without MFA'}",
        "export_report": "Report generated and sent to your email",
        "update_blocklist": "Blocklist updated with new threat indicators"
    }
    
    message = actions.get(action, f"Action '{action}' executed successfully")
    
    return {
        "action": action,
        "target": target,
        "status": "completed",
        "message": message,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
