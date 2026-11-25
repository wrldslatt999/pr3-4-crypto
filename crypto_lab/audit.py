"""Події операцій у JSONL: без ключів, паролів, plaintext та назв файлів."""
import json
import logging
from datetime import datetime, timezone
from pathlib import Path


class JsonFormatter(logging.Formatter):
    def format(self, record):
        obj = {"ts_utc": datetime.now(timezone.utc).isoformat(),
               "level": record.levelname, "event": record.getMessage()}
        for name in ("operation", "algorithm", "key_bits", "bytes", "elapsed_ms", "status", "error"):
            if hasattr(record, name):
                obj[name] = getattr(record, name)
        return json.dumps(obj, ensure_ascii=False)


def get_logger(path=".crypto-lab/logs/operations.jsonl"):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch(mode=0o600)
    log = logging.getLogger("lab34.crypto")
    log.setLevel(logging.INFO)
    for handler in list(log.handlers):
        log.removeHandler(handler)
        handler.close()
    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setFormatter(JsonFormatter())
    log.addHandler(fh)
    log.propagate = False
    return log
