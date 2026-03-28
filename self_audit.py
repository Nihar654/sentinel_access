from sqlalchemy.orm import Session
from db_models import UserDB, PolicyDB, AuditLogDB
from models import AccessDecision, AccessRequest
from policy_engine import get_user, get_policy, score_prompt_risk


AUDIT_PASS   = "PASS"
AUDIT_WARN   = "WARN"
AUDIT_FAIL   = "FAIL"


def audit_decision(
    db: Session,
    request: AccessRequest,
    decision: AccessDecision
) -> dict:

    flags   = []
    checks  = []
    verdict = AUDIT_PASS

    user   = get_user(db, request.user_id)
    policy = get_policy(db, request.resource) if request.resource else None

    # ── Check 1: Re-derive risk score independently ──────────────────────────
    recomputed_risk, _ = score_prompt_risk(request.prompt)
    if recomputed_risk != decision.risk_score:
        flags.append(
            f"Risk score mismatch — engine reported {decision.risk_score}, "
            f"audit recomputed {recomputed_risk}."
        )
        verdict = AUDIT_FAIL
        checks.append({"check": "risk_score_consistency", "status": AUDIT_FAIL})
    else:
        checks.append({"check": "risk_score_consistency", "status": AUDIT_PASS})


    # ── Check 2: ALLOW despite insufficient clearance ────────────────────────
    if decision.decision == "ALLOW" and policy:
        if user and user.clearance_level < policy.min_clearance:
            flags.append(
                f"ALLOW granted but clearance level {user.clearance_level} "
                f"is below required {policy.min_clearance}. Possible policy bypass."
            )
            verdict = AUDIT_FAIL
            checks.append({"check": "clearance_gate", "status": AUDIT_FAIL})
        else:
            checks.append({"check": "clearance_gate", "status": AUDIT_PASS})


    # ── Check 3: ALLOW despite missing required role ─────────────────────────
    if decision.decision == "ALLOW" and policy and user:
        if not any(r in user.roles for r in policy.required_roles):
            flags.append(
                f"ALLOW granted but user has none of the required roles: "
                f"{policy.required_roles}."
            )
            verdict = AUDIT_FAIL
            checks.append({"check": "role_gate", "status": AUDIT_FAIL})
        else:
            checks.append({"check": "role_gate", "status": AUDIT_PASS})


    # ── Check 4: ALLOW on unassigned mission ─────────────────────────────────
    if decision.decision == "ALLOW" and policy and policy.required_mission:
        if user and request.mission_context not in user.assigned_missions:
            flags.append(
                f"ALLOW granted but user is not assigned to mission "
                f"'{request.mission_context}'."
            )
            verdict = AUDIT_FAIL
            checks.append({"check": "mission_gate", "status": AUDIT_FAIL})
        else:
            checks.append({"check": "mission_gate", "status": AUDIT_PASS})


    # ── Check 5: High risk score but decision is ALLOW ───────────────────────
    if decision.decision == "ALLOW" and decision.risk_score >= 60:
        flags.append(
            f"ALLOW granted despite high risk score of {decision.risk_score}/100. "
            f"Should have been ESCALATE or DENY."
        )
        verdict = AUDIT_FAIL
        checks.append({"check": "risk_threshold_gate", "status": AUDIT_FAIL})
    else:
        checks.append({"check": "risk_threshold_gate", "status": AUDIT_PASS})


    # ── Check 6: DENY with low risk and valid clearance (over-denial) ────────
    if decision.decision == "DENY" and decision.risk_score < 20:
        if user and policy and user.clearance_level >= policy.min_clearance:
            flags.append(
                f"DENY issued despite valid clearance and low risk score "
                f"({decision.risk_score}/100). Possible over-restriction."
            )
            if verdict != AUDIT_FAIL:
                verdict = AUDIT_WARN
            checks.append({"check": "over_denial_check", "status": AUDIT_WARN})
        else:
            checks.append({"check": "over_denial_check", "status": AUDIT_PASS})
    else:
        checks.append({"check": "over_denial_check", "status": AUDIT_PASS})


    # ── Check 7: Confidence too high on ambiguous decisions ──────────────────
    if decision.decision == "ESCALATE" and decision.confidence > 90:
        flags.append(
            f"Confidence {decision.confidence}% is unusually high for an ESCALATE "
            f"decision — escalations imply ambiguity."
        )
        if verdict != AUDIT_FAIL:
            verdict = AUDIT_WARN
        checks.append({"check": "confidence_calibration", "status": AUDIT_WARN})
    else:
        checks.append({"check": "confidence_calibration", "status": AUDIT_PASS})


    # ── Check 8: Unknown user still received ALLOW ───────────────────────────
    if not user and decision.decision == "ALLOW":
        flags.append("ALLOW granted to an unrecognized user ID. Critical failure.")
        verdict = AUDIT_FAIL
        checks.append({"check": "unknown_user_gate", "status": AUDIT_FAIL})
    else:
        checks.append({"check": "unknown_user_gate", "status": AUDIT_PASS})


    # ── Persist audit result to audit_log ────────────────────────────────────
    log = db.query(AuditLogDB).filter(
        AuditLogDB.user_id == request.user_id,
        AuditLogDB.prompt  == request.prompt
    ).order_by(AuditLogDB.created_at.desc()).first()

    if log:
        existing_flags = log.audit_flags or []
        log.audit_flags = existing_flags + [f"[SELF-AUDIT] {f}" for f in flags]
        log.self_audit_result = {
        "audit_verdict": verdict,
        "checks_run":    len(checks),
        "checks_passed": sum(1 for c in checks if c["status"] == AUDIT_PASS),
        "checks_warned": sum(1 for c in checks if c["status"] == AUDIT_WARN),
        "checks_failed": sum(1 for c in checks if c["status"] == AUDIT_FAIL),
        "flags":         flags,
        "detail":        checks
    }
        db.commit()

    return {
        "audit_verdict":  verdict,
        "checks_run":     len(checks),
        "checks_passed":  sum(1 for c in checks if c["status"] == AUDIT_PASS),
        "checks_warned":  sum(1 for c in checks if c["status"] == AUDIT_WARN),
        "checks_failed":  sum(1 for c in checks if c["status"] == AUDIT_FAIL),
        "flags":          flags,
        "detail":         checks
    }