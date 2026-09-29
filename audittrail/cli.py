"""Operator CLI for bootstrap tasks."""

from __future__ import annotations

import argparse

from audittrail.db.session import SessionLocal
from audittrail.services.api_keys import generate_api_key


def create_api_key(name: str) -> int:
    db = SessionLocal()
    try:
        raw, record = generate_api_key(db, name)
        print(f"id={record.id}")
        print(f"name={record.name}")
        print(f"prefix={record.key_prefix}")
        print(f"api_key={raw}")
        return 0
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser(prog="audittrail")
    sub = parser.add_subparsers(dest="command", required=True)

    key_cmd = sub.add_parser("create-api-key", help="Create a REST API key in the database")
    key_cmd.add_argument("--name", required=True, help="Human-readable key name")

    args = parser.parse_args()
    if args.command == "create-api-key":
        return create_api_key(args.name)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
