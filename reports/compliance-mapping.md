# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade; giữ nguyên ledger khi xoá là stretch goal | `Guide.md` §Stretch goals #3 |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM/API và egress | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Per-agent identity, run identity, owner và TTL 300 giây được ghi trong ledger | `agent/runner.py` (`agent_id`, `run_id`, `agent_owner`, `ttl_seconds`); `reports/ledger.jsonl:1` |
| ASI01 — goal hijack | Trifecta split; customer chỉ được map từ trusted `related_tickets` | `agent/runner.py`; `reports/attack-after.log` (rỗng); `reports/ledger.jsonl:23` |
| ISO 42001 Clause 5-6 | Policy-as-code được kiểm thử và version-control | `agent/policy.py`; `git log --oneline -- agent/policy.py` |
