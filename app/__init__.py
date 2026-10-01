"""QRShare application factory."""
from __future__ import annotations

import logging
import os
import sys
from logging.config import dictConfig

from flask import Flask

from app.config import Config, generate_master_key, get_config
from app.errors import init_errors
from app.extensions import csrf, db, limiter
from app.security import init_security
from app.services import build_services
from app.services.cleanup_service import start_background_cleanup
from app.utils.formatting import human_duration, human_size

__version__ = "1.0.0"

logger = logging.getLogger(__name__)


def configure_logging(debug: bool) -> None:
    dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "[%(asctime)s] %(levelname)-8s %(name)s: %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "stream": "ext://sys.stdout",
                }
            },
            "root": {"level": "DEBUG" if debug else "INFO", "handlers": ["console"]},
            "loggers": {"werkzeug": {"level": "WARNING"}},
        }
    )


def _check_secrets(app: Flask) -> None:
    """Refuse to start without real secrets.

    Generating a throwaway key at boot would silently invalidate every
    existing share and every session cookie on restart, so outside
    development this is a hard failure.
    """
    problems = []
    if not app.config.get("SECRET_KEY"):
        problems.append("SECRET_KEY")
    if not app.config.get("MASTER_ENCRYPTION_KEY"):
        problems.append("MASTER_ENCRYPTION_KEY")

    if not problems:
        try:
            Config.master_key_bytes(app.config["MASTER_ENCRYPTION_KEY"])
        except ValueError as exc:
            raise RuntimeError(f"Invalid MASTER_ENCRYPTION_KEY: {exc}") from exc
        return

    if app.config["ENV_NAME"] != "development":
        raise RuntimeError(
            "Missing required secrets: "
            + ", ".join(problems)
            + ". Copy .env.example to .env and fill them in "
            "(see the README, or run: python manage.py keygen)."
        )

    # Development convenience only, and loudly announced.
    import secrets as _secrets

    if "SECRET_KEY" in problems:
        app.config["SECRET_KEY"] = _secrets.token_urlsafe(48)
    if "MASTER_ENCRYPTION_KEY" in problems:
        app.config["MASTER_ENCRYPTION_KEY"] = generate_master_key()
    logger.warning(
        "DEVELOPMENT ONLY: generated ephemeral %s. Existing shares will not "
        "survive a restart. Create a .env file before doing anything real.",
        " and ".join(problems),
    )


def create_app(config_name: str | None = None, **overrides) -> Flask:
    config_class = get_config(config_name)
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_class)
    app.config.update(overrides)

    configure_logging(app.config["DEBUG"])
    _check_secrets(app)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["STORAGE_PATH"], exist_ok=True)

    # -- extensions --------------------------------------------------------
    db.init_app(app)
    csrf.init_app(app)
    # Flask-Limiter reads its RATELIMIT_* keys during init_app, so translate
    # our own config names across first.
    app.config["RATELIMIT_STORAGE_URI"] = app.config["RATE_LIMIT_STORAGE_URI"]
    app.config["RATELIMIT_DEFAULT"] = ";".join(app.config["RATE_LIMIT_DEFAULT"])
    app.config["RATELIMIT_HEADERS_ENABLED"] = True
    app.config["RATELIMIT_ENABLED"] = app.config["RATE_LIMIT_ENABLED"]
    limiter.init_app(app)

    init_security(app)

    # -- services ----------------------------------------------------------
    app.extensions["qrshare"] = build_services(app)

    # -- models must be imported before create_all -------------------------
    from app import models  # noqa: F401

    # -- blueprints --------------------------------------------------------
    from app.routes.api import api_bp
    from app.routes.main import main_bp
    from app.routes.share import share_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(share_bp)
    app.register_blueprint(api_bp)

    # The default limit exists to catch scripted abuse of the HTML routes.
    # Counting stylesheets, scripts and the favicon against it would exhaust a
    # normal visitor's budget in a handful of page loads, and a health probe
    # must never be throttled.
    limiter.exempt(app.view_functions["static"])
    limiter.exempt(app.view_functions["main.healthz"])

    init_errors(app)

    # -- template helpers --------------------------------------------------
    app.jinja_env.filters["human_size"] = human_size
    app.jinja_env.filters["human_duration"] = human_duration
    app.jinja_env.globals["app_version"] = __version__

    with app.app_context():
        db.create_all()

    _register_cli(app)

    # Werkzeug's reloader imports the module in a supervisor process *and* in
    # the child that actually serves. Only the child sets WERKZEUG_RUN_MAIN, so
    # without this check the sweeper would run twice in development.
    reloader_child = os.environ.get("WERKZEUG_RUN_MAIN") == "true"
    if not app.config["TESTING"] and (reloader_child or not app.debug):
        start_background_cleanup(app, app.config["CLEANUP_INTERVAL_SECONDS"])

    logger.info("QRShare %s started in %s mode", __version__, app.config["ENV_NAME"])
    return app


def _register_cli(app: Flask) -> None:
    import click

    @app.cli.command("cleanup")
    def cleanup_command() -> None:
        """Run one cleanup sweep and print what it removed."""
        report = app.extensions["qrshare"].cleanup.run()
        click.echo(report.as_dict())

    @app.cli.command("keygen")
    def keygen_command() -> None:
        """Print a fresh SECRET_KEY and MASTER_ENCRYPTION_KEY."""
        import secrets as _secrets

        click.echo(f"SECRET_KEY={_secrets.token_urlsafe(48)}")
        click.echo(f"MASTER_ENCRYPTION_KEY={generate_master_key()}")

    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create any missing tables."""
        db.create_all()
        click.echo("Database ready.", file=sys.stdout)
