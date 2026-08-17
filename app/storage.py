import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

STORAGE_ROOT = Path(os.getenv("REPORT_STORAGE_PATH", "/data/reports"))


def save_report(content: bytes, scanner: str) -> str:
    now = datetime.now(timezone.utc)
    digest = hashlib.sha256(content).hexdigest()[:16]

    directory = STORAGE_ROOT / now.strftime("%Y/%m/%d")
    directory.mkdir(parents=True, exist_ok=True)

    filename = f"{now.strftime('%H%M%S')}-{scanner}-{digest}.json"
    path = directory / filename
    path.write_bytes(content)

    return str(path)


def load_report(path: str) -> bytes:
    file_path = Path(path)
    if not file_path.is_relative_to(STORAGE_ROOT):
        raise ValueError("Chemin hors du repertoire de stockage")
    return file_path.read_bytes()
