# Kiểm tra thay đổi ngày 29/10/2026

## Cập nhật ngày 01/11/2026

Chạy `python scripts/verify_project.py`: **21/21 test đạt**, compile Python và kiểm tra cú pháp code trong hai notebook đạt. JSON thực thi lưu ở `artifacts/reports/software_validation/latest.json` cùng phiên bản thư viện. Notebook PID chưa chạy train bằng dữ liệu thật vì chưa có VM/dataset lab.

Các test bổ sung kiểm tra tính lại điểm thay vì tin điểm lịch sử; metric rule/ML/kết hợp; null khi mẫu số bằng 0; process instance trong từng CSV; chặn file trùng nội dung nguồn train hoặc process instance đã thấy; fingerprint model/summary/manifest; không điền thiếu cột giữa hai CSV; không ghi đè đầu ra và báo cáo chỉnh thủ công. EDA, năm biểu đồ train và báo cáo tổng hợp cũng đã được kiểm tra bằng fixture phần mềm. Đã xem trực quan ảnh confusion matrix tạo từ fixture; không dùng ảnh này làm minh chứng phát hiện trong VM.

Benchmark ngắn của **collector CLI** đã chạy thực tế 20 giây, 20 snapshot, không lỗi thu thập; CSV/JSON ở `artifacts/reports/development_checks/collector_20261101_020535.*`. Môi trường thực thi bị giới hạn truy cập tiến trình/kết nối nên không đại diện toàn bộ máy hoặc ứng dụng desktop/web. Kết quả này kiểm tra cơ chế đo và ghi file, không thay thế benchmark VM dài hạn.

CLI `analyze_pid_data.py`, `evaluate_pid_sessions.py`, `train_pid_models.py` hiển thị help đúng. `build_project_report.py` tạo được báo cáo tổng hợp từ kết quả Cardiff lưu sẵn và ghi rõ PID lab chưa có artifact. Chưa thực hiện kịch bản tấn công, Atomic Red Team hoặc thu thập dữ liệu có nhãn trên máy phát triển.

Các mục dưới đây giữ lại biên bản lần kiểm tra trước.

## Môi trường

Windows, Python 3.11.9, `.venv` cài từ `requirements.txt`. Phiên bản chính: psutil 7.2.2, pandas 3.1.0, NumPy 2.4.6, scikit-learn 1.9.1, joblib 1.6.0. Môi trường thực thi có giới hạn truy cập hệ thống nên snapshot không đại diện toàn bộ tiến trình trên host.

## Kết quả

`python -m unittest discover -s tests -v`: **9/9 test đạt**.

| Kiểm tra | Kết quả |
|---|---|
| Bounds phiên thu thập: NaN, interval bằng 0/vượt duration | Từ chối trước khi truy vấn PID |
| Phiên thu thập với telemetry giả lập | Có CSV feature, PID/create-time, provenance và JSON completed |
| Truyền cùng source CSV hai lần | Từ chối |
| Huấn luyện bốn model với fixture có nguồn riêng | Có artifact và confusion matrix đúng với score/threshold live |
| Thiếu lớp hoặc executable độc lập | Từ chối |
| Nhãn sai, nguồn/path trống, feature không số/NaN/inf | Từ chối trước khi ghi model |
| Phân tập theo executable | Không giao nhóm giữa train/validation/test, mỗi tập có hai lớp |
| PID tái sử dụng | Không ghi mẫu với nhãn cũ; JSON ghi trạng thái kết thúc |
| Windows từ chối truy vấn TCP bằng RuntimeError | Collector tiếp tục trả snapshot, không có dữ liệu kết nối |

`python -m compileall -q process_guard scripts apps tests`: đạt.

Kiểm tra khởi tạo thực: collector trả snapshot và `DashboardData(initial_mode='demo')` khởi tạo thành công. Hai CLI mới/cập nhật hiển thị `--help` thành công. Đây là kiểm tra khởi tạo, không phải kiểm tra giao diện trình duyệt hoặc desktop bằng ảnh.

## Phạm vi

Fixture test tạo trong thư mục tạm và được dọn sau test, không thêm vào dataset quan sát. Các test không tạo malware, persistence hay injection; không dùng metric fixture làm kết quả nghiên cứu. Chưa chạy benchmark 8 giờ, kịch bản Atomic Red Team, thu thập dataset PID có nhãn được nhóm xác minh hoặc đo detection/false-positive trong VM. Kết quả Cardiff có sẵn không được huấn luyện lại trong lượt này.
