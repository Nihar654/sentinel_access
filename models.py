from pydantic import BaseModel
from typing import Optional, List

class User(BaseModel):
    user_id: str
    name: str
    rank: str
    clearance_level: int        # 1-5, 5 = highest
    assigned_missions: List[str]
    roles: List[str]

class AccessRequest(BaseModel):
    user_id: str
    prompt: str
    mission_context: Optional[str] = None
    resource: Optional[str] = None

class AccessDecision(BaseModel):
    user_id: str
    decision: str               # "ALLOW" | "DENY" | "ESCALATE"
    explanation: str
    risk_score: int             # 0-100
    confidence: int             # 0-100
    audit_flags: List[str]