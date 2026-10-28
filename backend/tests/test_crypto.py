import hashlib
from pathlib import Path
from backend.app.utils.crypto import compute_hashes, compute_bytes_hashes


def test_compute_bytes_hashes():
    data = b"Sentinel-X ESP32 Test Payload 2026"
    expected_sha256 = hashlib.sha256(data).hexdigest()
    expected_md5 = hashlib.md5(data).hexdigest()

    sha256, md5 = compute_bytes_hashes(data)

    assert sha256 == expected_sha256
    assert md5 == expected_md5
    assert len(sha256) == 64
    assert len(md5) == 32


def test_compute_hashes_file(tmp_path: Path):
    test_file = tmp_path / "firmware_sample.bin"
    content = b"\xe9\x04\x02\x20" + (b"A" * 1024)
    test_file.write_bytes(content)

    expected_sha256 = hashlib.sha256(content).hexdigest()
    expected_md5 = hashlib.md5(content).hexdigest()

    sha256, md5 = compute_hashes(test_file, chunk_size=256)

    assert sha256 == expected_sha256
    assert md5 == expected_md5


def test_empty_file_hashes(tmp_path: Path):
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")

    sha256, md5 = compute_hashes(empty_file)

    assert sha256 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert md5 == "d41d8cd98f00b204e9800998ecf8427e"
