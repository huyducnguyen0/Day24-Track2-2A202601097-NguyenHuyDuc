"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_PHONE_RE = re.compile(r"(?<!\d)0(?:[\s.-]?\d){9,10}(?!\d)")
_BANK_RE = re.compile(
    r"(?:stk|số\s+tài\s+khoản)\s*[:#-]?\s*(\d{8,16})(?!\d)",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"
)


def _entity(entity_type: str, match: re.Match[str], group: int = 0) -> dict:
    start, end = match.span(group)
    return {"type": entity_type, "start": start, "end": end}


def detect(text: str) -> list[dict]:
    entities: list[dict] = []

    entities.extend(_entity("VN_CCCD", m) for m in _CCCD_RE.finditer(text))

    for match in _PHONE_RE.finditer(text):
        context = text[max(0, match.start() - 24) : match.start()].lower()
        if re.search(r"(?:stk|tài\s+khoản)\s*$", context):
            continue
        entities.append(_entity("VN_PHONE", match))

    entities.extend(_entity("VN_BANK_ACCOUNT", m, 1) for m in _BANK_RE.finditer(text))
    entities.extend(_entity("EMAIL", m) for m in _EMAIL_RE.finditer(text))

    # Stable ordering makes callers and redaction deterministic.  Remove any
    # accidental duplicate while preserving the most specific span.
    unique = {(e["type"], e["start"], e["end"]): e for e in entities}
    return sorted(unique.values(), key=lambda e: (e["start"], e["end"], e["type"]))


def redact(text: str) -> str:
    entities = sorted(detect(text), key=lambda e: (e["start"], e["end"]))
    for entity in reversed(entities):
        start, end = entity["start"], entity["end"]
        replacement = f"[REDACTED_{entity['type']}]"
        text = text[:start] + replacement + text[end:]
    return text
