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
from app.services.storage import LocalStorageBackend, StorageBackend, StorageError


@dataclass(frozen=True)
class ServiceRegistry:
    storage: StorageBackend
    encryption: EncryptionService
    files: FileService
    shares: ShareService
    qr: QRCodeService
    cleanup: CleanupService
    audit: type[AuditService]


def build_services(app: Flask) -> ServiceRegistry:
    """Instantiate every service from application config."""
    from app.config import Config

    master_key = Config.master_key_bytes(app.config["MASTER_ENCRYPTION_KEY"])
    storage = LocalStorageBackend(app.config["STORAGE_PATH"])
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
    "services",
    "ShareError",
    "StorageError",
    "AuditService",
]
