# DPIA-lite (1 trang)

## 1. Dữ liệu gì

`search_docs` đọc nội dung ticket không tin cậy, trong đó có thể chứa tên,
CCCD, số điện thoại, STK và email. Nội dung được redact bằng PII gate trước
khi đi vào LLM context. `read_customer` đọc hồ sơ private gồm
`customer_id`, tên, CCCD, phone, bank account, email và `related_tickets`.
Ledger chỉ lưu hash của arguments, không lưu nguyên PII.

## 2. Mục đích gì

Agent cần đọc ticket để tổng hợp yêu cầu hỗ trợ. Chỉ khi ticket ID đến từ
filename và khớp `related_tickets` trong data store tin cậy, Run B mới đọc
hồ sơ khách hàng để phục vụ đối soát. Nội dung tự do của ticket không được
dùng để chọn `customer_id`.

## 3. Chảy đi đâu

Luồng dữ liệu là `corpus/` → `search_docs` → PII redaction → LLM context;
ticket ID dạng số đi qua boundary Run A → Run B → lookup `related_tickets` →
`read_customer`. Hồ sơ private không được đưa vào `summarize` và không được
POST ra sink khi policy deny. `http_post` chỉ được xem xét tại policy gate;
với `restricted + egress_enabled`, request bị deny trước khi tool chạy.

Khi dùng `--mock`, không có model provider bên ngoài; dữ liệu chỉ đi vào
local context và ledger metadata. Khi dùng `--model`, ticket text có thể đi
tới Anthropic API; nếu provider ở nước ngoài, đây là luồng xuyên biên giới
cần đánh giá/lưu hồ sơ theo NĐ 356/2025. Egress control của runner vẫn chặn
đường POST dữ liệu private không cần thiết tới sink.
