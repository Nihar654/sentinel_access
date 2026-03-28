from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from models import AccessRequest, AccessDecision
from policy_engine import evaluate_access
from self_audit import audit_decision
from database import get_db
from db_models import AuditLogDB

router = APIRouter(prefix="/access", tags=["access"])

@router.post("/evaluate", response_model=None)
def evaluate(request: AccessRequest, db: Session = Depends(get_db)):
    decision = evaluate_access(db, request)
    audit    = audit_decision(db, request, decision)
    return {
        "decision": decision,
        "self_audit": audit
    }

@router.get("/logs")
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(AuditLogDB).order_by(AuditLogDB.created_at.desc()).limit(50).all()
    return [
        {
            "id":                 l.id,
            "user_id":            l.user_id,
            "prompt":             l.prompt,
            "resource":           l.resource,
            "mission_context":    l.mission_context,
            "decision":           l.decision,
            "explanation":        l.explanation,
            "risk_score":         l.risk_score,
            "confidence":         l.confidence,
            "audit_flags":        l.audit_flags,
            "self_audit_result":  l.self_audit_result,  # ← explicit
            "created_at":         l.created_at.isoformat() if l.created_at else None
        }
        for l in logs
    ]