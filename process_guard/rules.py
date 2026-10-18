"""Transparent heuristic checks; these are triage signals, not verdicts."""
from __future__ import annotations


def evaluate_rules(record: dict, features: dict[str, float]) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    if features["name_similarity_risk"]:
        score += 0.35
        reasons.append("Tên gần giống tiến trình hệ thống")
    if features["path_is_temp"]:
        score += 0.25
        reasons.append("Chạy từ thư mục tạm")
    elif features["path_is_user_writable"] and not features["path_is_missing"]:
        score += 0.12
        reasons.append("Đường dẫn ngoài thư mục hệ thống/ứng dụng")
    if features["parent_is_script_host"]:
        score += 0.18
        reasons.append("Tiến trình con của Office/script host")
    if features.get("registry_run_persistence", 0):
        score += 0.25
        reasons.append("Đường dẫn executable xuất hiện trong Registry Run/RunOnce")
    if features.get("scheduled_task_persistence", 0):
        score += 0.25
        reasons.append("Có Scheduled Task action trỏ tới executable này; cần xác minh ngữ cảnh")
    if features.get("sysmon_registry_run_hint", 0):
        score += 0.3
        reasons.append("Sysmon ghi nhận thay đổi Registry Run/RunOnce bởi tiến trình này")
    if features.get("sysmon_remote_memory_access_hint", 0):
        score += 0.35
        reasons.append("Sysmon ghi nhận quyền truy cập bộ nhớ tiến trình từ xa; cần xác minh")
    if features.get("sysmon_remote_thread_hint", 0):
        score += 0.4
        reasons.append("Sysmon ghi nhận tạo remote thread; cần xác minh khả năng injection")
    if features.get("sysmon_process_tampering_hint", 0):
        score += 0.45
        reasons.append("Sysmon ghi nhận process tampering; cần điều tra thêm")
    if (features.get("sysmon_file_create_events", 0) >= 20
            and (features["path_is_temp"] or features["path_is_user_writable"])):
        score += 0.10
        reasons.append("Nhiều sự kiện tạo file gần đây từ executable ở đường dẫn có thể ghi")
    if features.get("sysmon_dns_query_events", 0) >= 12 and features["connection_count"] >= 5:
        score += 0.08
        reasons.append("Nhiều truy vấn DNS Sysmon gần đây cùng nhiều kết nối; cần xem xét ngữ cảnh")
    if features["connection_count"] >= 12:
        score += 0.12
        reasons.append("Nhiều kết nối mạng đồng thời")
    if features.get("cpu_peak_percent", features["cpu_percent"]) >= 85 and features["file_write_rate_kbps"] >= 1024:
        score += 0.12
        reasons.append("CPU đỉnh cao kèm tốc độ ghi file cao")
    if features.get("unsigned_hint", 0):
        score += 0.12
        reasons.append("Chữ ký số thiếu hoặc không hợp lệ (đã kiểm tra)")
    return min(score, 1.0), reasons
