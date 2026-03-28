from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from models import AccessRequest, AccessDecision
from policy_engine import evaluate_access
from database import get_db
from db_models import AuditLogDB

router = APIRouter(prefix="/access", tags=["access"])

@router.post("/evaluate", response_model=AccessDecision)
def evaluate(request: AccessRequest, db: Session = Depends(get_db)):
    return evaluate_access(db, request)

@router.get("/logs")
def get_logs(db: Session = Depends(get_db)):
    logs = db.query(AuditLogDB).order_by(AuditLogDB.created_at.desc()).limit(50).all()
    return logs