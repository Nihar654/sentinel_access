from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from models import AccessRequest, AccessDecision
from policy_engine import evaluate_access
from self_audit import audit_decision
from database import get_db
from db_models import AuditLogDB, BlacklistDB

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
def get_logs(
    db:           Session = Depends(get_db),
    user_id:      str     = None,
    decision:     str     = None,
    audit_verdict: str    = None
):
    query = db.query(AuditLogDB)

    if user_id:
        query = query.filter(AuditLogDB.user_id == user_id)

    if decision:
        query = query.filter(AuditLogDB.decision == decision.upper())

    logs = query.order_by(AuditLogDB.created_at.desc()).limit(50).all()

    # filter by audit verdict in Python since it's nested JSON
    if audit_verdict:
        logs = [
            l for l in logs
            if l.self_audit_result and
               l.self_audit_result.get("audit_verdict") == audit_verdict.upper()
        ]

    return [
        {
            "id":                 l.id,
            "user_id":            l.user_id,
            "prompt":             l.prompt,
            "resource":           l.resource,
            "mission_context":    l.mission_context,
            "decision":           l.decision,
            "expected_decision":  l.expected_decision,
            "explanation":        l.explanation,
            "risk_score":         l.risk_score,
            "confidence":         l.confidence,
            "audit_flags":        l.audit_flags,
            "self_audit_result":  l.self_audit_result,
            "created_at":         l.created_at.isoformat() if l.created_at else None
        }
        for l in logs
    ]

@router.get("/blacklist")
def get_blacklist(db: Session = Depends(get_db)):
    entries = db.query(BlacklistDB).all()
    return [
        {
            "user_id":      e.user_id,
            "strike_count": e.strike_count,
            "blacklisted":  bool(e.blacklisted),
            "updated_at":   e.updated_at.isoformat() if e.updated_at else None
        }
        for e in entries
    ]