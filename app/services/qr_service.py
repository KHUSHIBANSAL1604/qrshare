"""QR code rendering.

The QR encodes the share **URL** and nothing else. It carries no file data, no
key material and no metadata -- it is simply a convenient way to move a bearer
URL from one screen to another camera.
"""
from __future__ import annotations

import base64
from io import BytesIO

import qrcode
from qrcode.constants import ERROR_CORRECT_M
from qrcode.image.pil import PilImage

#: pixels per QR module; 10 gives a ~330-490px image that phones read reliably
#: from a laptop screen without the PNG becoming large.
DEFAULT_BOX_SIZE = 10
DEFAULT_BORDER = 4


class QRCodeService:
    """Renders share URLs as PNG QR codes."""

    def __init__(self, box_size: int = DEFAULT_BOX_SIZE, border: int = DEFAULT_BORDER) -> None:
        self.box_size = box_size
        self.border = border

    def render_png(self, url: str, box_size: int | None = None) -> bytes:
        """Return a PNG of ``url`` as raw bytes.

        Error correction level M (~15%) keeps the code readable when a phone
        camera catches a reflection, without inflating the module count.
        """
        qr = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_M,
            box_size=box_size or self.box_size,
            border=self.border,
        )
        qr.add_data(url)
        qr.make(fit=True)
        image: PilImage = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
        buffer = BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def render_data_uri(self, url: str) -> str:
        """Inline PNG, so the share page shows the QR with no extra request."""
        encoded = base64.b64encode(self.render_png(url)).decode()
        return f"data:image/png;base64,{encoded}"
