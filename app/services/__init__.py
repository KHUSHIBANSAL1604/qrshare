"""Service layer.

Routes stay thin by delegating here. A single :class:`ServiceRegistry` is
built once per application and stashed on ``app.extensions["qrshare"]``, which
keeps wiring explicit and makes services trivial to swap in tests.
"""
from __future__ import annotations

from dataclasses import dataclass

from flask import Flask, current_app

from app.services.audit_service import AuditService
from app.services.cleanup_service import CleanupService
from app.services.encryption_service import EncryptionService
from app.services.file_service import FileService
from app.services.qr_service import QRCodeService
from app.services.share_service import ShareError, ShareService
from app.services.storage import (
    DatabaseStorageBackend,
    LocalStorageBackend,
    S3StorageBackend,
    StorageBackend,
    StorageError,
)


@dataclass(frozen=True)
class ServiceRegistry:
    storage: StorageBackend
    encryption: EncryptionService
    files: FileService
    shares: ShareService
    qr: QRCodeService
    cleanup: CleanupService
    audit: type[AuditService]


def build_storage(app: Flask) -> StorageBackend:
    """Pick the storage backend named by configuration.

    Share and file logic never sees this choice -- it only ever talks to the
    :class:`StorageBackend` interface -- so swapping local for S3 changes
    where bytes live and nothing else.
    """
    kind = app.config.get("STORAGE_BACKEND", "local")
    if kind == "database":
        # Blobs live beside the application's own tables. Keeps a hosted
        # deployment durable without requiring a separate storage provider.
        return DatabaseStorageBackend(app.config["SQLALCHEMY_DATABASE_URI"])
    if kind == "s3":
        return S3StorageBackend(
            app.config["S3_BUCKET"],
            endpoint_url=app.config["S3_ENDPOINT_URL"],
            access_key=app.config["S3_ACCESS_KEY_ID"],
            secret_key=app.config["S3_SECRET_ACCESS_KEY"],
            region=app.config["S3_REGION"],
            prefix=app.config["S3_PREFIX"],
        )
    if kind != "local":
        raise RuntimeError(
            f"unknown STORAGE_BACKEND: {kind!r} (expected 'local', 'database' or 's3')"
        )
    return LocalStorageBackend(app.config["STORAGE_PATH"])


def build_services(app: Flask) -> ServiceRegistry:
    """Instantiate every service from application config."""
    from app.config import Config

    master_key = Config.master_key_bytes(app.config["MASTER_ENCRYPTION_KEY"])
    storage = build_storage(app)
    encryption = EncryptionService(master_key, chunk_size=app.config["ENCRYPTION_CHUNK_SIZE"])
    files = FileService(storage, encryption)
    return ServiceRegistry(
        storage=storage,
        encryption=encryption,
        files=files,
        shares=ShareService(
            app.config["SECRET_KEY"], ticket_ttl=app.config["DOWNLOAD_TICKET_TTL_SECONDS"]
        ),
        qr=QRCodeService(),
        cleanup=CleanupService(files, grace_minutes=app.config["CLEANUP_GRACE_MINUTES"]),
        audit=AuditService,
    )


def services() -> ServiceRegistry:
    """The registry for the current application."""
    return current_app.extensions["qrshare"]


__all__ = [
    "ServiceRegistry",
    "build_services",
    "build_storage",
    "services",
    "ShareError",
    "StorageError",
    "AuditService",
]
