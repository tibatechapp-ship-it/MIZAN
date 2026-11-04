"""Append-only engineering collaboration ledger."""

import json
from datetime import datetime, timezone
from pathlib import Path


def add_entry(message: str, actor: str, ledger_path=".mizan/ledger.jsonl"):
    if not message.strip():
        raise ValueError("Entry message cannot be empty.")

    if actor not in {"human", "chatgpt", "joint"}:
        raise ValueError("Actor must be human, chatgpt, or joint.")

    path = Path(ledger_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "message": message.strip(),
        "verification": "not_verified",
    }

    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, ensure_ascii=False) + "\n")

    return entry
