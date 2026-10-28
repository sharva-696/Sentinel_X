import hashlib
from pathlib import Path
from typing import Tuple


def compute_hashes(file_path: Path, chunk_size: int = 65536) -> Tuple[str, str]:
    """
    Computes SHA-256 and MD5 hashes using chunked streaming.
    Ensures bounded memory utilization even for large binaries.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)

    return sha256.hexdigest(), md5.hexdigest()


def compute_bytes_hashes(data: bytes) -> Tuple[str, str]:
    """
    Computes SHA-256 and MD5 hashes for an in-memory bytes object.
    """
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return sha256, md5
