from sqlalchemy.orm import Session
from db_models import UserDB, PolicyDB, AuditLogDB
from models import User, AccessRequest, AccessDecision
import json

RISK_KEYWORDS = {
    "high":   ["launch", "strike", "destroy", "override", "disable", "bypass"],
    "medium": ["access", "retrieve", "coordinates", "location", "identity"],
    "low":    ["list", "show", "summarize", "explain", "status"]
}

def get_user(db: Session, user_id: str) -> UserDB | None:
    return db.query(UserDB).filter(UserDB.user_id == user_id).first()

def get_policy(db: Session, resource: str) -> PolicyDB | None:
    return db.query(PolicyDB).filter(PolicyDB.resource == resource).first()

def score_prompt_risk(prompt: str) -> tuple[int, list[str]]:
    prompt_lower = prompt.lower()
    flags, score = [], 0
    for kw in RISK_KEYWORDS["high"]:
        if kw in prompt_lower:
            score += 30
            flags.append(f"High-risk keyword detected: '{kw}'")
    for kw in RISK_KEYWORDS["medium"]:
        if kw in prompt_lower:
            score += 15
            flags.append(f"Medium-risk keyword: '{kw}'")
    for kw in RISK_KEYWORDS["low"]:
        if kw in prompt_lower:
            score += 5
    return min(score, 100), flags

def log_decision(db: Session, request: AccessRequest, decision: AccessDecision):
    entry = AuditLogDB(
        user_id=request.user_id,
        prompt=request.prompt,
        resource=request.resource,
        mission_context=request.mission_context,
        decision=decision.decision,
        explanation=decision.explanation,
        risk_score=decision.risk_score,
        confidence=decision.confidence,
        audit_flags=decision.audit_flags
    )
    db.add(entry)
    db.commit()

def evaluate_access(db: Session, request: AccessRequest) -> AccessDecision:
    audit_flags = []
    user = get_user(db, request.user_id)

    if not user:
        decision = AccessDecision(
            user_id=request.user_id,
            decision="DENY",
            explanation="User not found in system.",
            risk_score=100,
            confidence=99,
            audit_flags=["Unknown user ID"]
        )
        log_decision(db, request, decision)
        return decision

    risk_score, prompt_flags = score_prompt_risk(request.prompt)
    audit_flags.extend(prompt_flags)

    if request.resource:
        policy = get_policy(db, request.resource)

        if not policy:
            audit_flags.append(f"Unknown resource: {request.resource}")

        else:
            if user.clearance_level < policy.min_clearance:
                decision = AccessDecision(
                    user_id=user.user_id,
                    decision="DENY",
                    explanation=(
                        f"Clearance level {user.clearance_level} insufficient. "
                        f"Resource '{request.resource}' requires level {policy.min_clearance}."
                    ),
                    risk_score=risk_score,
                    confidence=95,
                    audit_flags=audit_flags
                )
                log_decision(db, request, decision)
                return decision

            if not any(r in user.roles for r in policy.required_roles):
                decision = AccessDecision(
                    user_id=user.user_id,
                    decision="DENY",
                    explanation=(
                        f"User lacks required role for '{request.resource}'. "
                        f"Required: {policy.required_roles}."
                    ),
                    risk_score=risk_score,
                    confidence=95,
                    audit_flags=audit_flags
                )
                log_decision(db, request, decision)
                return decision

            if policy.required_mission and (
                not request.mission_context or
                request.mission_context not in user.assigned_missions
            ):
                decision = AccessDecision(
                    user_id=user.user_id,
                    decision="DENY",
                    explanation=(
                        f"User is not assigned to mission '{request.mission_context}' "
                        f"required for this resource."
                    ),
                    risk_score=risk_score,
                    confidence=90,
                    audit_flags=audit_flags + ["Mission context mismatch"]
                )
                log_decision(db, request, decision)
                return decision

    if risk_score >= 60:
        decision = AccessDecision(
            user_id=user.user_id,
            decision="ESCALATE",
            explanation=(
                f"Request flagged for human review. "
                f"User clearance is valid but prompt risk score is {risk_score}/100."
            ),
            risk_score=risk_score,
            confidence=80,
            audit_flags=audit_flags
        )
        log_decision(db, request, decision)
        return decision

    decision = AccessDecision(
        user_id=user.user_id,
        decision="ALLOW",
        explanation=f"Access granted. '{user.name}' meets all policy requirements.",
        risk_score=risk_score,
        confidence=95,
        audit_flags=audit_flags
    )
    log_decision(db, request, decision)
    return decision