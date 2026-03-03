"""Generate artificial HoursLog data.

Creates N artificial users and random log entries directly via psycopg2,
compatible with the Prisma-managed PostgreSQL schema.

Usage:
    pip install psycopg2-binary bcrypt python-dotenv
    python generate_artificial_data.py

By default, this seeds the database specified by DATABASE_URL in .env.
"""

from __future__ import annotations

import argparse
import os
import random
import string
from dataclasses import dataclass
from datetime import date, timedelta

import bcrypt
import psycopg2
from dotenv import load_dotenv

load_dotenv()


DEFAULT_CATEGORIES: list[tuple[str, str, str]] = [
    ("Service Delivery", "Providing service delivery such as first aid events, night-time economy, hospital volunteering, logistics and community advocacy", "#007bff"),
    ("Community Service", "Participating in organised community activities such as visiting hospitals or care homes or supporting the elderly or disabled", "#28a745"),
    ("Badger Support", "Helping with Badgers as a Badger Helper", "#28a745"),
    ("Event Planning", "Planning, delivering, or supporting internal competitions as an organiser, steward, or judge", "#ffc107"),
    ("Cadet Events", "Helping to organise events for other cadets and young people", "#ffc107"),
    ("Training Delivery", "Planning and delivering training inside or outside a unit, such as running courses or helping with Grand Prior subjects", "#17a2b8"),
    ("Unit Support", "Planning and delivering additional activities for a unit such as games, tuck-shops, or activity sessions", "#6c757d"),
    ("Youth Representation", "Representing young people through platforms such as Youth Forums or Regional Youth Team meetings", "#6c757d"),
    ("Maintenance & Cleaning", "Involvement in cleaning or maintaining St John buildings or property", "#795548"),
    ("Fundraising", "Fundraising activities for St John Ambulance, the Order of St John, or St John Eye Hospital", "#dc3545"),
    ("Ceremonial Participation", "Taking part in formal parades or acting as a lining (flag) party", "#9c27b0"),
    ("Competitions", "Involvement or competition in external or inter-unit competitions", "#3f51b5"),
    ("Public Representation", "Involvement in external representation events outside of unit hours", "#00bcd4"),
    ("Travel", "Travel time to and from qualifying cadet volunteer activities", "#8bc34a"),
]

DEFAULT_ROLES: list[tuple[str, str]] = [
    ("Cadet Logistics Role", "Any Cadet volunteering in logistics"),
    ("Cadet Event Manager", "Any Cadet volunteering in Event Management Roles such as Bronze Officer or Treatment Center Manager"),
    ("Cadet Emergency Responder", "Cadet Operational role for CER"),
    ("Cadet Community First Aider", "Cadet Operational role for CCFA"),
    ("Cadet", "Cadet Operational role for 10HrFA"),
    ("Cadet of the Year Team", "Any activities undertaken as a Cadet of the Year"),
    ("Cadet Non-Commissioned Officer", "Any activities undertaken as a Corporal, Sergeant, or Leading Cadet"),
    ("Cadet Leadership Roles", "Any other leadership roles, such as Youth Operations or St John Assembly Member"),
]


@dataclass(frozen=True)
class SeedResult:
    users_created: int
    entries_created: int
    password_used: str


def _get_connection():
    """Create a psycopg2 connection from DATABASE_URL."""
    url = os.environ.get("DATABASE_URL", "")
    # Strip SQLAlchemy dialect prefix if present
    url = url.replace("postgresql+psycopg2://", "postgresql://")
    if not url:
        raise RuntimeError("DATABASE_URL not set. Check your .env file.")
    return psycopg2.connect(url)


def _hash_password(password: str) -> str:
    """Hash a password using bcrypt (compatible with bcryptjs)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(12)).decode("utf-8")


def _ensure_defaults_exist(cur) -> None:
    """Ensure at least one active category and role exists."""
    cur.execute("SELECT COUNT(*) FROM categories")
    if cur.fetchone()[0] == 0:
        for name, description, color in DEFAULT_CATEGORIES:
            cur.execute(
                "INSERT INTO categories (name, description, color, is_active) VALUES (%s, %s, %s, true) ON CONFLICT (name) DO NOTHING",
                (name, description, color),
            )

    cur.execute("SELECT COUNT(*) FROM roles")
    if cur.fetchone()[0] == 0:
        for name, description in DEFAULT_ROLES:
            cur.execute(
                "INSERT INTO roles (name, description, is_active) VALUES (%s, %s, true) ON CONFLICT (name) DO NOTHING",
                (name, description),
            )


def _quarter_hour(min_hours: float, max_hours: float) -> float:
    min_q = int(round(min_hours * 4))
    max_q = int(round(max_hours * 4))
    return random.randint(min_q, max_q) / 4.0


def _random_activity_title(cat_name: str, role_name: str) -> str:
    verb = random.choice(["Shift", "Session", "Support", "Coverage", "Assistance", "Planning", "Coordination", "Training"])
    suffix = "".join(random.choice(string.ascii_uppercase) for _ in range(3))
    return f"{cat_name} {verb} ({role_name}) {suffix}"


def _purge_existing(cur, prefix: str) -> int:
    cur.execute("SELECT id FROM users WHERE username LIKE %s", (f"{prefix}_%",))
    user_ids = [row[0] for row in cur.fetchall()]
    if not user_ids:
        return 0
    # Delete secondary role associations
    cur.execute(
        "DELETE FROM \"_SecondaryRoles\" WHERE \"A\" IN (SELECT id FROM log_entries WHERE user_id = ANY(%s))",
        (user_ids,),
    )
    cur.execute("DELETE FROM log_entries WHERE user_id = ANY(%s)", (user_ids,))
    cur.execute("DELETE FROM audit_logs WHERE user_id = ANY(%s)", (user_ids,))
    cur.execute("DELETE FROM users WHERE id = ANY(%s)", (user_ids,))
    return len(user_ids)


def seed_artificial_data(
    *,
    user_count: int,
    min_entries: int,
    max_entries: int,
    prefix: str,
    password: str,
    days_back: int,
    purge: bool,
    secondary_role_max: int,
) -> SeedResult:
    if user_count <= 0:
        raise ValueError("user_count must be > 0")
    if not (0 < min_entries <= max_entries):
        raise ValueError("min_entries must be > 0 and <= max_entries")
    if days_back <= 0:
        raise ValueError("days_back must be > 0")

    conn = _get_connection()
    cur = conn.cursor()

    try:
        _ensure_defaults_exist(cur)
        conn.commit()

        if purge:
            deleted = _purge_existing(cur, prefix)
            conn.commit()
            print(f"Purged {deleted} existing users with prefix '{prefix}_'")

        # Fetch categories and roles
        cur.execute("SELECT id, name FROM categories WHERE is_active = true ORDER BY name")
        categories = cur.fetchall()  # list of (id, name)
        cur.execute("SELECT id, name FROM roles WHERE is_active = true ORDER BY name")
        roles = cur.fetchall()  # list of (id, name)

        if not categories:
            raise RuntimeError("No categories exist; cannot create log entries")
        if not roles:
            raise RuntimeError("No roles exist; cannot create log entries")

        password_hash = _hash_password(password)
        entries_created = 0
        users_created = 0
        today = date.today()

        for idx in range(1, user_count + 1):
            username = f"{prefix}_{idx:03d}"
            email = f"{username}@example.com"

            # Check uniqueness
            cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            if cur.fetchone():
                continue

            cur.execute(
                """INSERT INTO users (username, email, password_hash, first_name, last_name,
                   display_name, permission_level, email_verified, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, 1, true, NOW()) RETURNING id""",
                (username, email, password_hash, f"Artificial{idx}", "User", f"Artificial User {idx}"),
            )
            user_id = cur.fetchone()[0]
            users_created += 1

            # Per-user random weighting
            cat_weights = [random.expovariate(1) for _ in categories]
            role_weights = [random.expovariate(1) for _ in roles]
            user_min_hours = round(random.uniform(0.5, 3.0), 2)
            user_max_hours = round(random.uniform(user_min_hours + 0.5, 12.0), 2)
            user_travel_max = round(random.uniform(0.0, 4.0), 2)
            weekend_bias = random.random()

            entry_count = random.randint(min_entries, max_entries)
            for _ in range(entry_count):
                cat_id, cat_name = random.choices(categories, weights=cat_weights, k=1)[0]
                role_id, role_name = random.choices(roles, weights=role_weights, k=1)[0]

                activity_hours = _quarter_hour(user_min_hours, user_max_hours)
                travel_hours = _quarter_hour(0.0, user_travel_max)

                raw_day = random.randint(0, days_back - 1)
                entry_date = today - timedelta(days=raw_day)
                is_weekend = entry_date.weekday() >= 5
                if is_weekend and random.random() > weekend_bias:
                    raw_day = random.randint(0, days_back - 1)
                    entry_date = today - timedelta(days=raw_day)
                elif not is_weekend and random.random() < weekend_bias * 0.4:
                    offset = (5 - entry_date.weekday()) % 7 or 7
                    entry_date = entry_date + timedelta(days=offset)
                    if entry_date > today:
                        entry_date = today

                cur.execute(
                    """INSERT INTO log_entries (user_id, category_id, role_id, title, description,
                       hours, travel_hours, date, review_status, created_at, updated_at)
                       VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active', NOW(), NOW()) RETURNING id""",
                    (user_id, cat_id, role_id, _random_activity_title(cat_name, role_name),
                     f"Auto-generated activity in {cat_name}.", activity_hours, travel_hours, entry_date),
                )
                entry_id = cur.fetchone()[0]

                # Secondary roles
                if secondary_role_max > 0:
                    candidates = [r for r in roles if r[0] != role_id]
                    count = random.randint(0, min(secondary_role_max, len(candidates)))
                    if count > 0:
                        random.shuffle(candidates)
                        for sr_id, _ in candidates[:count]:
                            cur.execute(
                                'INSERT INTO "_SecondaryRoles" ("A", "B") VALUES (%s, %s) ON CONFLICT DO NOTHING',
                                (entry_id, sr_id),
                            )

                entries_created += 1

        conn.commit()

        # Count total with prefix
        cur.execute("SELECT COUNT(*) FROM users WHERE username LIKE %s", (f"{prefix}_%",))
        total_users = cur.fetchone()[0]

        return SeedResult(users_created=total_users, entries_created=entries_created, password_used=password)

    finally:
        cur.close()
        conn.close()


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed HoursLog with artificial users + log entries")
    parser.add_argument("--users", type=int, default=70, help="Number of artificial users to create")
    parser.add_argument("--min-entries", type=int, default=1, help="Minimum log entries per user")
    parser.add_argument("--max-entries", type=int, default=50, help="Maximum log entries per user")
    parser.add_argument("--prefix", type=str, default="artificial", help="Username prefix (e.g. artificial_001)")
    parser.add_argument("--password", type=str, default="TestPassword123!", help="Password assigned to all generated users")
    parser.add_argument("--days-back", type=int, default=365, help="Randomize entry dates in the last N days")
    parser.add_argument("--purge", action="store_true", help="Delete existing generated users (by prefix) before seeding")
    parser.add_argument("--secondary-role-max", type=int, default=2, help="Max number of secondary roles per entry (0 to disable)")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    result = seed_artificial_data(
        user_count=args.users,
        min_entries=args.min_entries,
        max_entries=args.max_entries,
        prefix=args.prefix,
        password=args.password,
        days_back=args.days_back,
        purge=args.purge,
        secondary_role_max=args.secondary_role_max,
    )

    print("Seed complete")
    print(f"Users now present with prefix '{args.prefix}_': {result.users_created}")
    print(f"Log entries created this run: {result.entries_created}")
    print(f"Password for generated users: {result.password_used}")


if __name__ == "__main__":
    main()
