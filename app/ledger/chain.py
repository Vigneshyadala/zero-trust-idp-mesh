import hashlib
import json
import os
import threading
import time
from pathlib import Path

GENESIS_PREVIOUS = "0" * 64


class AlreadyAnchored(Exception):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_hash(index: int, timestamp: int, entry: dict, previous_hash: str) -> str:
    return sha256_hex(
        canonical(
            {
                "index": index,
                "timestamp": timestamp,
                "entry": entry,
                "previous_hash": previous_hash,
            }
        )
    )


class Ledger:
    """Append-only, hash-chained ledger persisted to a JSON file."""

    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.blocks: list[dict] = []
        if self.path.exists():
            self.blocks = json.loads(self.path.read_text(encoding="utf-8"))
        if not self.blocks:
            self._append({"type": "genesis"})

    def _append(self, entry: dict) -> dict:
        index = len(self.blocks)
        previous = self.blocks[-1]["hash"] if self.blocks else GENESIS_PREVIOUS
        timestamp = int(time.time())
        block = {
            "index": index,
            "timestamp": timestamp,
            "entry": entry,
            "previous_hash": previous,
            "hash": compute_hash(index, timestamp, entry, previous),
        }
        self.blocks.append(block)
        self._save()
        return block

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.blocks, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def find(self, did: str) -> dict | None:
        for block in reversed(self.blocks):
            if block["entry"].get("did") == did:
                return block
        return None

    def anchor(self, did: str, document_hash: str) -> dict:
        with self._lock:
            if self.find(did) is not None:
                raise AlreadyAnchored(did)
            return self._append(
                {"type": "did_anchor", "did": did, "did_document_hash": document_hash}
            )

    def validate(self) -> bool:
        previous = GENESIS_PREVIOUS
        for position, block in enumerate(self.blocks):
            if block["index"] != position or block["previous_hash"] != previous:
                return False
            expected = compute_hash(
                block["index"], block["timestamp"], block["entry"], block["previous_hash"]
            )
            if block["hash"] != expected:
                return False
            previous = block["hash"]
        return True
