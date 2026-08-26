"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng biến
thể 5, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


def _args_hash(args: object) -> str:
    encoded = json.dumps(args, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _ticket_id(document_id: str) -> int | None:
    match = re.match(r"^ticket-(\d+)", document_id, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _ledger_entry(
    *,
    agent_id: str,
    run_id: str,
    agent_owner: str,
    tool_name: str,
    args: object,
    context: policy.PolicyContext,
    decision: str,
    reason: str,
) -> dict:
    issued_at = datetime.now(timezone.utc)
    return {
        "ts": issued_at.isoformat(),
        "ttl_seconds": 300,
        "expires_at": (issued_at + timedelta(seconds=300)).isoformat(),
        "agent_id": agent_id,
        "run_id": run_id,
        "agent_owner": agent_owner,
        "tool": tool_name,
        "args_hash": _args_hash(args),
        "classification": context.data_classification,
        "decision": decision,
        "reason": reason,
    }


def _authorize(
    *,
    agent_id: str,
    run_id: str,
    agent_owner: str,
    tool_name: str,
    args: object,
    context: policy.PolicyContext,
    ledger_path: Path,
) -> bool:
    allow, reason = policy.check(context)
    decision = "allow" if allow else "deny"
    ledger.append(
        _ledger_entry(
            agent_id=agent_id,
            run_id=run_id,
            agent_owner=agent_owner,
            tool_name=tool_name,
            args=args,
            context=context,
            decision=decision,
            reason=reason,
        ),
        ledger_path,
    )
    return allow


def _trusted_customer_ids(ticket_ids: list[int]) -> list[str]:
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    ticket_set = set(ticket_ids)
    customer_ids: list[str] = []
    for customer in customers:
        related = {int(ticket) for ticket in customer.get("related_tickets", [])}
        if ticket_set.intersection(related):
            customer_ids.append(str(customer["customer_id"]))
    return customer_ids


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    log_path = Path(log_dir) if log_dir is not None else REPORTS_DIR
    ledger_path = log_path / "ledger.jsonl"
    agent_id = f"lab24-agent-{uuid.uuid4().hex[:12]}"
    root_run_id = uuid.uuid4().hex

    run_a_context = policy.PolicyContext(
        data_classification="internal",
        request_purpose="search-and-summarize-tickets",
        agent_owner=f"{agent_id}:run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    if _authorize(
        agent_id=agent_id,
        run_id=f"{root_run_id}:run-a",
        agent_owner=run_a_context.agent_owner,
        tool_name="search_docs",
        args={"query": message},
        context=run_a_context,
        ledger_path=ledger_path,
    ):
        docs = tools.search_docs(message)
    else:
        docs = []

    # PII is redacted before any document text enters the model context.
    sanitized_docs = [
        {"id": document["id"], "text": pii.redact(document["text"])}
        for document in docs
    ]
    combined_text = "\n\n".join(document["text"] for document in sanitized_docs)
    injected = llm.find_injection(combined_text)

    # This is the only data crossing the Run A -> Run B boundary: typed IDs
    # derived from filenames, never document text or LLM-extracted IDs.
    ticket_ids = sorted(
        {ticket_id for ticket_id in (_ticket_id(d["id"]) for d in docs) if ticket_id is not None}
    )

    run_b_context = policy.PolicyContext(
        data_classification="restricted",
        request_purpose="reconciliation",
        agent_owner=f"{agent_id}:run-b",
        delegation_depth=1,
        egress_enabled=False,
    )
    collected: list[dict] = []
    for customer_id in _trusted_customer_ids(ticket_ids):
        if not _authorize(
            agent_id=agent_id,
            run_id=f"{root_run_id}:run-b",
            agent_owner=run_b_context.agent_owner,
            tool_name="read_customer",
            args={"customer_id": customer_id},
            context=run_b_context,
            ledger_path=ledger_path,
        ):
            continue
        try:
            collected.append(tools.read_customer(customer_id))
        except tools.ToolError:
            continue

    if injected is not None:
        # The policy decision itself is the evidence required by the lab.
        # No private record is sent because a denied call never reaches the
        # actual http_post tool.
        egress_context = policy.PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation-egress",
            agent_owner=f"{agent_id}:run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        if _authorize(
            agent_id=agent_id,
            run_id=f"{root_run_id}:run-b",
            agent_owner=egress_context.agent_owner,
            tool_name="http_post",
            args={"url": injected.target_url, "record_count": len(collected)},
            context=egress_context,
            ledger_path=ledger_path,
        ):
            tools.http_post(injected.target_url, {"records": collected})

    return llm.summarize(sanitized_docs)
