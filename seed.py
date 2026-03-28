from database import engine, SessionLocal
from db_models import Base, UserDB, PolicyDB

def seed():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    # Clear existing data
    db.query(UserDB).delete()
    db.query(PolicyDB).delete()

    # --- Users ---
    users = [
        UserDB(
            user_id="U001",
            name="Col. Arjun Mehta",
            rank="Colonel",
            clearance_level=4,
            assigned_missions=["OPERATION_SKYWATCH", "OPERATION_DAWNSTRIKE"],
            roles=["commander", "intel_viewer"]
        ),
        UserDB(
            user_id="U002",
            name="Lt. Priya Nair",
            rank="Lieutenant",
            clearance_level=2,
            assigned_missions=["OPERATION_SKYWATCH"],
            roles=["field_agent"]
        ),
        UserDB(
            user_id="U003",
            name="Civ. Ravi Shankar",
            rank="Civilian",
            clearance_level=1,
            assigned_missions=[],
            roles=["analyst"]
        ),
    ]

    # --- Policies ---
    policies = [
        PolicyDB(
            resource="classified_intel",
            min_clearance=3,
            required_roles=["intel_viewer", "commander"],
            required_mission=1
        ),
        PolicyDB(
            resource="strike_orders",
            min_clearance=4,
            required_roles=["commander"],
            required_mission=1
        ),
        PolicyDB(
            resource="personnel_records",
            min_clearance=2,
            required_roles=["commander", "analyst"],
            required_mission=0
        ),
    ]

    db.add_all(users + policies)
    db.commit()
    db.close()
    print("Database seeded successfully.")

if __name__ == "__main__":
    seed()