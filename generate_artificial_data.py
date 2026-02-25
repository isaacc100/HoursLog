"""Generate artificial HoursLog data.

Creates N artificial users and random log entries compatible with the existing
SQLAlchemy models in this repo.

Usage (PowerShell):
    ./venv/Scripts/python.exe ./generate_artificial_data.py

By default, this seeds the configured database (see config.py / DATABASE_URL).
"""

from __future__ import annotations

import argparse
import random
import string
from dataclasses import dataclass
from datetime import date, timedelta

from app import create_app, db
from app.models import Category, LogEntry, Role, User


DEFAULT_CATEGORIES: list[tuple[str, str, str]] = [
    ("Tutoring", "Educational tutoring activities", "#007bff"),
    ("Food Service", "Food preparation and distribution", "#28a745"),
    ("Event Planning", "Organizing and managing events", "#ffc107"),
    ("Administrative", "Office and administrative work", "#6c757d"),
    ("Outreach", "Community outreach programs", "#17a2b8"),
    ("Fundraising", "Fundraising activities", "#dc3545"),
]

DEFAULT_ROLES: list[tuple[str, str]] = [
    ("Volunteer", "General volunteer role"),
    ("Team Lead", "Leading a team of volunteers"),
    ("Coordinator", "Coordinating activities"),
    ("Trainer", "Training other volunteers"),
    ("Supervisor", "Supervising activities"),
]


@dataclass(frozen=True)
class SeedResult:
    users_created: int
    entries_created: int
    password_used: str


def _ensure_defaults_exist() -> None:
    """Ensure at least one active category and role exists."""
    if not Category.query.first():
        for name, description, color in DEFAULT_CATEGORIES:
            db.session.add(Category(name=name, description=description, color=color, is_active=True))

    if not Role.query.first():
        for name, description in DEFAULT_ROLES:
            db.session.add(Role(name=name, description=description, is_active=True))

    db.session.commit()


def _quarter_hour(min_hours: float, max_hours: float) -> float:
    """Random quarter-hour increment between bounds (inclusive)."""
    min_q = int(round(min_hours * 4))
    max_q = int(round(max_hours * 4))
    return random.randint(min_q, max_q) / 4.0


def _random_activity_title(category: Category, role: Role) -> str:
    verb = random.choice(
        [
            "Shift",
            "Session",
            "Support",
            "Coverage",
            "Assistance",
            "Planning",
            "Coordination",
            "Training",
        ]
    )
    suffix = "".join(random.choice(string.ascii_uppercase) for _ in range(3))
    return f"{category.name} {verb} ({role.name}) {suffix}"


def _maybe_secondary_roles(primary: Role, all_roles: list[Role], max_count: int) -> list[Role]:
    candidates = [r for r in all_roles if r.id != primary.id]
    if not candidates:
        return []

    count = random.randint(0, max_count)
    if count <= 0:
        return []

    random.shuffle(candidates)
    return candidates[:count]


def _purge_existing(prefix: str) -> int:
    """Delete users created by this generator (and their cascading log entries)."""
    users = User.query.filter(User.username.like(f"{prefix}_%"))  # noqa: E712
    deleted = 0
    for user in users.all():
        db.session.delete(user)
        deleted += 1
    db.session.commit()
    return deleted


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

    _ensure_defaults_exist()

    if purge:
        _purge_existing(prefix)

    categories = Category.query.filter_by(is_active=True).all() or Category.query.all()
    roles = Role.query.filter_by(is_active=True).all() or Role.query.all()

    if not categories:
        raise RuntimeError("No categories exist; cannot create log entries")
    if not roles:
        raise RuntimeError("No roles exist; cannot create log entries")

    entries_created = 0
    today = date.today()

    for idx in range(1, user_count + 1):
        username = f"{prefix}_{idx:03d}"
        email = f"{username}@example.com"

        # Ensure uniqueness if the script is run without purge.
        if User.query.filter((User.username == username) | (User.email == email)).first():
            continue

        user = User(
            username=username,
            email=email,
            first_name=f"Artificial{idx}",
            last_name="User",
            display_name=f"Artificial User {idx}",
            is_admin=False,
            is_active=True,
            email_verified=True,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.flush()  # assign user.id for FK usage

        entry_count = random.randint(min_entries, max_entries)
        for _ in range(entry_count):
            category = random.choice(categories)
            role = random.choice(roles)

            activity_hours = _quarter_hour(1.0, 12.0)
            travel_hours = _quarter_hour(0.0, 8.0)
            entry_date = today - timedelta(days=random.randint(0, days_back - 1))

            entry = LogEntry(
                user_id=user.id,
                category_id=category.id,
                role_id=role.id,
                title=_random_activity_title(category, role),
                description=f"Auto-generated activity in {category.name}.",
                notes=None,
                hours=activity_hours,
                travel_hours=travel_hours,
                date=entry_date,
            )

            if secondary_role_max > 0:
                entry.secondary_roles = _maybe_secondary_roles(role, roles, secondary_role_max)

            db.session.add(entry)
            entries_created += 1

    db.session.commit()

    # Count users actually created in this run by prefix, for reporting.
    created_users = User.query.filter(User.username.like(f"{prefix}_%"))  # noqa: E712
    return SeedResult(users_created=created_users.count(), entries_created=entries_created, password_used=password)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Seed HoursLog with artificial users + log entries")
    parser.add_argument("--users", type=int, default=70, help="Number of artificial users to create")
    parser.add_argument("--min-entries", type=int, default=1, help="Minimum log entries per user")
    parser.add_argument("--max-entries", type=int, default=50, help="Maximum log entries per user")
    parser.add_argument("--prefix", type=str, default="artificial", help="Username prefix (e.g. artificial_001)")
    parser.add_argument(
        "--password",
        type=str,
        default="TestPassword123!",
        help="Password assigned to all generated users",
    )
    parser.add_argument(
        "--days-back",
        type=int,
        default=365,
        help="Randomize entry dates in the last N days",
    )
    parser.add_argument(
        "--purge",
        action="store_true",
        help="Delete existing generated users (by prefix) before seeding",
    )
    parser.add_argument(
        "--secondary-role-max",
        type=int,
        default=2,
        help="Max number of secondary roles per entry (0 to disable)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    app = create_app()
    with app.app_context():
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
