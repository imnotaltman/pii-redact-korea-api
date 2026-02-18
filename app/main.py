from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Tuple

from flask import Flask, jsonify, request

app = Flask(__name__)

PatternName = Literal["rrn", "phone", "email", "account", "address"]
MaskMode = Literal["full", "partial", "token"]


@dataclass
class Detector:
    name: PatternName
    regex: re.Pattern


DETECTORS: List[Detector] = [
    Detector("rrn", re.compile(r"\b\d{6}-?[1-4]\d{6}\b")),
    Detector("phone", re.compile(r"\b01[0-9]-?\d{3,4}-?\d{4}\b")),
    Detector("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    Detector("account", re.compile(r"\b\d{2,6}-\d{2,6}-\d{2,6}\b|\b\d{10,14}\b")),
    Detector("address", re.compile(r"\b([가-힣]+(시|도)\s+[가-힣]+(시|군|구)\s+[가-힣0-9]+(로|길)\s*\d+[\-\d]*)")),
]


def find_entities(text: str, include_types: Optional[List[PatternName]] = None) -> List[Dict]:
    wanted = set(include_types or [d.name for d in DETECTORS])
    found: List[Dict] = []
    for detector in DETECTORS:
        if detector.name not in wanted:
            continue
        for match in detector.regex.finditer(text):
            found.append(
                {
                    "type": detector.name,
                    "start": match.start(),
                    "end": match.end(),
                    "value": match.group(0),
                }
            )
    return sorted(found, key=lambda e: (e["start"], e["end"]))


def mask_value(value: str, mode: MaskMode) -> str:
    if mode == "full":
        return "*" * len(value)
    if mode == "token":
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        return f"<PII_{digest}>"
    if len(value) <= 4:
        return "*" * len(value)
    keep = 2
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]


def apply_redaction(text: str, entities: List[Dict], mode: MaskMode) -> Tuple[str, Dict[str, int]]:
    if not entities:
        return text, {}

    chunks: List[str] = []
    cursor = 0
    stats: Dict[str, int] = {}

    for entity in entities:
        chunks.append(text[cursor : entity["start"]])
        chunks.append(mask_value(entity["value"], mode))
        stats[entity["type"]] = stats.get(entity["type"], 0) + 1
        cursor = entity["end"]

    chunks.append(text[cursor:])
    return "".join(chunks), stats


@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    text = str(payload.get("text", "")).strip()
    if not text:
        return jsonify({"message": "text is required"}), 400

    entities = find_entities(text)
    return jsonify({"count": len(entities), "entities": entities})


@app.post("/redact")
def redact():
    payload = request.get_json(silent=True) or {}
    text = str(payload.get("text", "")).strip()
    mode = str(payload.get("mode", "partial"))
    include_types = payload.get("include_types")

    if not text:
        return jsonify({"message": "text is required"}), 400
    if mode not in {"full", "partial", "token"}:
        return jsonify({"message": "mode must be one of full|partial|token"}), 400

    entities = find_entities(text, include_types if isinstance(include_types, list) else None)
    redacted_text, stats = apply_redaction(text, entities, mode)  # type: ignore[arg-type]

    return jsonify(
        {
            "count": len(entities),
            "stats": stats,
            "redacted_text": redacted_text,
            "entities": entities,
            "mode": mode,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8017, debug=True)
