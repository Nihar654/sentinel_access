from sqlalchemy import Column, String, Integer, JSON, DateTime, func
from database import Base

class UserDB(Base):
    __tablename__ = "users"

    user_id         = Column(String, primary_key=True, index=True)
    name            = Column(String, nullable=False)
    rank            = Column(String, nullable=False)
    clearance_level = Column(Integer, nullable=False)
    assigned_missions = Column(JSON, default=[])   # stored as JSON array
    roles           = Column(JSON, default=[])     # stored as JSON array


class PolicyDB(Base):
    __tablename__ = "policies"

    resource        = Column(String, primary_key=True, index=True)
    min_clearance   = Column(Integer, nullable=False)
    required_roles  = Column(JSON, default=[])
    required_mission = Column(Integer, default=0)  # 0 = False, 1 = True


class AuditLogDB(Base):
    __tablename__ = "audit_log"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    user_id         = Column(String, nullable=False)
    prompt          = Column(String, nullable=False)
    resource        = Column(String, nullable=True)
    mission_context = Column(String, nullable=True)
    decision        = Column(String, nullable=False)   # ALLOW / DENY / ESCALATE
    explanation     = Column(String, nullable=False)
    risk_score      = Column(Integer, nullable=False)
    confidence      = Column(Integer, nullable=False)
    audit_flags     = Column(JSON, default=[])
    created_at      = Column(DateTime, server_default=func.now())
    self_audit_result = Column(JSON, nullable = True)
    expected_decision = Column(String, nullable = True)

class BlacklistDB(Base):
    __tablename__ = "blacklist"

    user_id     = Column(String, primary_key=True, index=True)
    strike_count = Column(Integer, default=0)
    blacklisted = Column(Integer, default=0)  # 0 = False, 1 = True
    updated_at  = Column(DateTime, server_default=func.now(), onupdate=func.now())