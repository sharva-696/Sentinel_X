import os
import uuid
import tempfile
from pathlib import Path
from typing import Tuple
from backend.app.config import settings, UPLOADS_DIR


class ValidationError(Exception):
    """Custom exception raised when an input file violates upload or format constraints."""
    pass


def validate_file_size(size_bytes: int) -> None:
    if size_bytes == 0:
        raise ValidationError("Uploaded file is empty (0 bytes). Valid firmware must contain binary data.")
    if size_bytes > settings.max_upload_size_bytes:
        raise ValidationError(
            f"File size ({size_bytes} bytes) exceeds the maximum allowed limit of "
            f"{settings.max_upload_size_bytes} bytes (32 MB)."
        )


def save_upload_safely(file_bytes: bytes, original_filename: str = "firmware.bin") -> Tuple[Path, str]:
    """
    Validates and stores binary payload safely in UPLOADS_DIR using a sanitized UUID-based filename.
    Returns: (Path to saved file, generated assessment_id)
    """
    validate_file_size(len(file_bytes))

    assessment_id = str(uuid.uuid4())
    safe_filename = f"{assessment_id}.bin"
    target_path = UPLOADS_DIR / safe_filename

    # Ensure uploads directory exists
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    with open(target_path, "wb") as f:
        f.write(file_bytes)

    return target_path, assessment_id


def cleanup_file(file_path: Path) -> None:
    """Safely removes a file from disk if it exists."""
    try:
        if file_path and file_path.is_file():
            file_path.unlink(missing_ok=True)
    except Exception:
        pass
