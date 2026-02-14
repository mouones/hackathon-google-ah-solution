"""
Sentinel Shield - Gamified Security Training Module
Interactive security awareness training with leaderboards and challenges
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import random

from .auth import get_current_user

router = APIRouter()


# Training data
PHISHING_SIMULATIONS = [
    {
        "id": "sim_001",
        "type": "email",
        "difficulty": "easy",
        "subject": "Your Password Expires Tomorrow!",
        "sender": "it-support@c0mpany.com",
        "red_flags": ["Typo in domain (c0mpany)", "Urgency", "Password link"],
        "points": 10
    },
    {
        "id": "sim_002",
        "type": "email",
        "difficulty": "medium",
        "subject": "Invoice #12345 - Payment Required",
        "sender": "invoices@vendor-payments.xyz",
        "red_flags": ["Unknown sender", "Generic subject", ".xyz TLD"],
        "points": 25
    },
    {
        "id": "sim_003",
        "type": "email",
        "difficulty": "hard",
        "subject": "RE: Project Update - Action Needed",
        "sender": "mike.johnson@company.co", 
        "red_flags": ["Reply to non-existent thread", ".co instead of .com", "Attachment request"],
        "points": 50
    }
]

TRAINING_MODULES = [
    {"id": "mod_001", "name": "Phishing 101", "duration": 15, "points": 100, "required": True},
    {"id": "mod_002", "name": "Password Security", "duration": 10, "points": 75, "required": True},
    {"id": "mod_003", "name": "Social Engineering", "duration": 20, "points": 150, "required": False},
    {"id": "mod_004", "name": "Safe Browsing", "duration": 12, "points": 80, "required": True},
    {"id": "mod_005", "name": "Data Protection", "duration": 18, "points": 120, "required": False},
    {"id": "mod_006", "name": "Mobile Security", "duration": 10, "points": 75, "required": False},
]

BADGES = [
    {"id": "badge_spotter", "name": "Phishing Spotter", "description": "Identified 10 phishing emails", "icon": "🎣"},
    {"id": "badge_learner", "name": "Quick Learner", "description": "Completed 3 training modules", "icon": "📚"},
    {"id": "badge_champion", "name": "Security Champion", "description": "Top 10 in leaderboard", "icon": "🏆"},
    {"id": "badge_perfect", "name": "Perfect Score", "description": "100% on phishing test", "icon": "💯"},
    {"id": "badge_streak", "name": "On Fire", "description": "7-day training streak", "icon": "🔥"},
]

LEADERBOARD = [
    {"rank": 1, "name": "David Lee", "dept": "IT", "points": 2450, "badges": 5},
    {"rank": 2, "name": "Emily Brown", "dept": "HR", "points": 2180, "badges": 4},
    {"rank": 3, "name": "Mike Williams", "dept": "Finance", "points": 1920, "badges": 4},
    {"rank": 4, "name": "Lisa Chen", "dept": "Engineering", "points": 1750, "badges": 3},
    {"rank": 5, "name": "John Smith", "dept": "Marketing", "points": 1580, "badges": 3},
]


class SimulationResponse(BaseModel):
    simulation_id: str
    is_phishing: bool
    confidence: str  # certain, probably, unsure
    red_flags_identified: List[str] = []


class ModuleProgress(BaseModel):
    module_id: str
    completed: bool
    score: Optional[int] = None


# API Endpoints

@router.get("/dashboard")
async def get_training_dashboard(current_user: dict = Depends(get_current_user)):
    """Get user's training dashboard"""
    
    user_stats = {
        "total_points": 1250,
        "rank": 8,
        "badges_earned": 3,
        "modules_completed": 4,
        "modules_total": len(TRAINING_MODULES),
        "phishing_tests_passed": 12,
        "phishing_tests_failed": 2,
        "current_streak": 5,
        "next_badge": {"name": "Security Champion", "progress": "80%"}
    }
    
    return {
        "user": current_user["email"],
        "stats": user_stats,
        "recent_activity": [
            {"action": "Completed Phishing 101", "points": 100, "date": "2024-12-13"},
            {"action": "Identified phishing email", "points": 25, "date": "2024-12-12"},
            {"action": "Earned Perfect Score badge", "points": 50, "date": "2024-12-11"},
        ],
        "badges": BADGES[:3]
    }


@router.get("/leaderboard")
async def get_leaderboard(
    department: Optional[str] = None,
    time_period: str = "all_time",  # all_time, monthly, weekly
    current_user: dict = Depends(get_current_user)
):
    """Get security training leaderboard"""
    
    board = LEADERBOARD
    if department:
        board = [e for e in board if e["dept"].lower() == department.lower()]
    
    return {
        "period": time_period,
        "leaderboard": board,
        "your_position": 8,
        "department_ranking": [
            {"dept": "IT", "avg_score": 2100},
            {"dept": "HR", "avg_score": 1850},
            {"dept": "Finance", "avg_score": 1720},
            {"dept": "Engineering", "avg_score": 1650},
            {"dept": "Marketing", "avg_score": 1480},
        ]
    }


@router.get("/modules")
async def get_training_modules(current_user: dict = Depends(get_current_user)):
    """Get available training modules"""
    
    modules_with_status = []
    for mod in TRAINING_MODULES:
        mod_copy = mod.copy()
        mod_copy["status"] = random.choice(["completed", "in_progress", "not_started"])
        mod_copy["score"] = random.randint(70, 100) if mod_copy["status"] == "completed" else None
        modules_with_status.append(mod_copy)
    
    return {
        "total_modules": len(TRAINING_MODULES),
        "completed": len([m for m in modules_with_status if m["status"] == "completed"]),
        "required_completed": True,
        "modules": modules_with_status
    }


@router.get("/simulation/next")
async def get_next_simulation(current_user: dict = Depends(get_current_user)):
    """Get next phishing simulation for user"""
    
    sim = random.choice(PHISHING_SIMULATIONS)
    
    return {
        "simulation_id": sim["id"],
        "type": sim["type"],
        "difficulty": sim["difficulty"],
        "potential_points": sim["points"],
        "content": {
            "from": sim["sender"],
            "subject": sim["subject"],
            "body": f"Dear Employee,\n\nThis is a test simulation email about '{sim['subject']}'.\n\nPlease click the link below or review the attachment.\n\nBest regards,\nIT Department"
        },
        "question": "Is this email legitimate or a phishing attempt?",
        "options": ["Legitimate - Safe to proceed", "Phishing - Report and delete"]
    }


@router.post("/simulation/answer")
async def submit_simulation_answer(
    response: SimulationResponse,
    current_user: dict = Depends(get_current_user)
):
    """Submit answer for phishing simulation"""
    
    sim = next((s for s in PHISHING_SIMULATIONS if s["id"] == response.simulation_id), None)
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found")
    
    # All simulations are phishing in this demo
    correct = response.is_phishing
    
    points_earned = 0
    if correct:
        points_earned = sim["points"]
        if response.confidence == "certain":
            points_earned += 10
        
        # Bonus for identifying red flags
        flags_correct = len([f for f in response.red_flags_identified if f in sim["red_flags"]])
        points_earned += flags_correct * 5
    
    return {
        "correct": correct,
        "points_earned": points_earned,
        "explanation": f"This was a phishing email. Red flags: {', '.join(sim['red_flags'])}",
        "actual_red_flags": sim["red_flags"],
        "your_red_flags": response.red_flags_identified,
        "new_total_points": 1250 + points_earned
    }


@router.get("/badges")
async def get_badges(current_user: dict = Depends(get_current_user)):
    """Get all badges and user's earned badges"""
    
    earned = ["badge_spotter", "badge_learner", "badge_streak"]
    
    badges_with_status = []
    for badge in BADGES:
        badge_copy = badge.copy()
        badge_copy["earned"] = badge["id"] in earned
        badge_copy["earned_date"] = "2024-12-10" if badge_copy["earned"] else None
        badges_with_status.append(badge_copy)
    
    return {
        "total_badges": len(BADGES),
        "earned_count": len(earned),
        "badges": badges_with_status
    }


@router.get("/challenges/weekly")
async def get_weekly_challenges(current_user: dict = Depends(get_current_user)):
    """Get current weekly challenges"""
    
    return {
        "week": "Dec 9-15, 2024",
        "challenges": [
            {"name": "Phishing Hunter", "goal": "Identify 5 phishing emails", "progress": 3, "reward": 100},
            {"name": "Learning Streak", "goal": "Complete 1 module per day for 7 days", "progress": 5, "reward": 200},
            {"name": "Quick Response", "goal": "Report suspicious email within 1 minute", "progress": 1, "reward": 50},
        ],
        "team_challenge": {
            "name": "Department Defense",
            "goal": "Highest dept average score wins",
            "your_dept": "IT",
            "your_dept_rank": 1
        }
    }


@router.post("/modules/{module_id}/complete")
async def complete_module(
    module_id: str,
    progress: ModuleProgress,
    current_user: dict = Depends(get_current_user)
):
    """Mark training module as completed"""
    
    module = next((m for m in TRAINING_MODULES if m["id"] == module_id), None)
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    
    points = module["points"]
    if progress.score and progress.score >= 90:
        points += 25  # Bonus for high score
    
    return {
        "message": f"Module '{module['name']}' completed!",
        "points_earned": points,
        "score": progress.score,
        "certificate_available": progress.score >= 80 if progress.score else False
    }
