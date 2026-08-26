"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


GENESIS_HASH = "0" * 64


def _content_hash(entry: dict) -> str:
    content = {key: value for key, value in entry.items() if key != "hash"}
    canonical = json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    previous_hash = GENESIS_HASH
    if path.exists() and path.stat().st_size:
        lines = path.read_text(encoding="utf-8").splitlines()
        if lines:
            previous = json.loads(lines[-1])
            previous_hash = previous.get("hash", GENESIS_HASH)

    recorded = dict(entry)
    recorded["prev_hash"] = previous_hash
    recorded["hash"] = _content_hash(recorded)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(recorded, ensure_ascii=False, sort_keys=True) + "\n")
    return recorded


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return True

    expected_previous = GENESIS_HASH
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            if not line.strip():
                return False
            entry = json.loads(line)
            if not entry.get("reason"):
                return False
            if entry.get("prev_hash") != expected_previous:
                return False
            if not entry.get("hash") or entry["hash"] != _content_hash(entry):
                return False
            expected_previous = entry["hash"]
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
        return False
    return True
