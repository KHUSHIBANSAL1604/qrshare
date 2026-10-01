"""Small maintenance CLI that works without the Flask CLI environment.

    python manage.py keygen     # print fresh secrets for .env
    python manage.py cleanup    # run one cleanup sweep (suitable for cron)
    python manage.py init-db    # create tables
    python manage.py stats      # counts, for a quick health check
"""
from __future__ import annotations

import secrets
import sys

from app import create_app
from app.config import generate_master_key
from app.extensions import db


def cmd_keygen() -> int:
    print("# Paste these into your .env file")
    print(f"SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"MASTER_ENCRYPTION_KEY={generate_master_key()}")
    print("\n# Changing MASTER_ENCRYPTION_KEY makes existing files unreadable.")
    return 0


def cmd_cleanup() -> int:
    app = create_app()
    with app.app_context():
        report = app.extensions["qrshare"].cleanup.run()
    for key, value in report.as_dict().items():
        print(f"{key:18} {value}")
    return 0


def cmd_init_db() -> int:
    app = create_app()
    with app.app_context():
        db.create_all()
    print("Database ready.")
    return 0


def cmd_stats() -> int:
    from app.models import AuditLog, Share, StoredFile

    app = create_app()
    with app.app_context():
        shares = db.session.query(Share).all()
        print(f"files          {db.session.query(StoredFile).count()}")
        print(f"shares         {len(shares)}")
        print(f"  active       {sum(1 for s in shares if s.status.value == 'active')}")
        print(f"  expired      {sum(1 for s in shares if s.status.value == 'expired')}")
        print(f"  used         {sum(1 for s in shares if s.status.value == 'used')}")
        print(f"  deleted      {sum(1 for s in shares if s.status.value == 'deleted')}")
        print(f"audit events   {db.session.query(AuditLog).count()}")
    return 0


COMMANDS = {
    "keygen": cmd_keygen,
    "cleanup": cmd_cleanup,
    "init-db": cmd_init_db,
    "stats": cmd_stats,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print(__doc__)
        print("Commands: " + ", ".join(COMMANDS))
        return 1
    return COMMANDS[argv[1]]()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
