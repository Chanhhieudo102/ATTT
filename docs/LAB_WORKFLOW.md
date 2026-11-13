# Quy trình hoàn thiện thực nghiệm PID

## 1. Chuẩn bị phiên thử

Chạy trong VM lab và ghi mã VM, hệ điều hành, CPU/RAM, snapshot VM, phiên bản thư viện, thời điểm, kịch bản và người xác minh nhãn. Lưu nguồn nhãn tham chiếu tới log kịch bản. Nhãn `0` là quan sát benign đã kiểm chứng, `1` là tiến trình thuộc kịch bản simulated malicious đã kiểm chứng. Không suy nhãn từ điểm rule/ML, CPU cao, tên đáng ngờ hoặc chỉ vì tiến trình được tạo bởi safe workload.

```powershell
python -m pip install -r requirements.txt
python main.py
# Terminal khác, trong VM: stimulus an toàn, không phải malware/injection
python scripts/safe_behavior_lab.py --duration 15
```

Safe workload chỉ có CPU, file tạm và loopback. Để đáp ứng yêu cầu hành vi cụ thể, nhóm cần thêm kịch bản được duyệt và xác minh riêng; công cụ không tự xác nhận VM isolation.

## 2. Thu thập theo phiên

Thay PID ví dụ bằng PID thật. Mỗi lệnh chỉ dùng một nhãn cho toàn bộ PID được chỉ định:

```powershell
python scripts/collect_pid_samples.py --pid 1234 --label 0 --label-source "VM01/benign-browser/run01" --duration 60 --interval 3 --output data/observations/benign_browser_01.csv
python scripts/collect_pid_samples.py --pid 5678 --label 1 --label-source "VM01/approved-scenario/run02/evidence.json" --duration 60 --interval 3 --output data/observations/simulated_02.csv
```

CSV chứa feature, PID/create-time, path, nhãn, nguồn, thời gian UTC và điểm triage. JSON cùng tên chứa cấu hình, danh tính PID ban đầu, trạng thái, số mẫu và số cảnh báo ML/kết hợp. Quét đầu làm nóng CPU/I/O và không lưu thành mẫu. Tool dừng khi hết thời lượng hoặc mọi PID không còn truy cập được/đổi danh tính. Ctrl+C giữ các hàng đã flush và đánh dấu interrupted. Không append hoặc ghi đè phiên cũ. Enrichment chữ ký/Sysmon/persistence không được CLI tự truy vấn; các cờ checked phản ánh giới hạn này.

Thu ít nhất 3 executable path độc lập cho mỗi lớp, cùng nhiều bối cảnh/lần chạy. Đây chỉ là mức tối thiểu cho chia tập, không đủ chứng minh khả năng tổng quát. Python chạy nhiều script vẫn là cùng executable. Không copy một binary thành nhiều path để đáp ứng điều kiện. Desktop vẫn có thể lưu từng quan sát vào `collected_samples.csv`.

## 3. Huấn luyện và kiểm tra dữ liệu

Chạy EDA trên các file huấn luyện đã chọn trước; không đưa file dành cho đánh giá phiên mới vào train:

```powershell
python scripts/analyze_pid_data.py --source data/observations/benign_browser_01.csv data/observations/simulated_02.csv
```

EDA xuất thống kê feature, phân bố nhãn/executable, feature hằng, số path có hai nhãn và biểu đồ runtime. Thư mục mặc định có timestamp và không ghi đè. Không tự xóa feature giống nhau vì có thể là snapshot idle hợp lệ. Có thể làm EDA/train/đánh giá bằng `notebooks/pid_lab_eda_training.ipynb`; notebook cần kernel Python có các thư viện trong requirements và IPython, chưa có kết quả thực nghiệm điền sẵn.

Truyền tường minh các CSV đã xác minh, có thể kết hợp dữ liệu desktop và các phiên CLI:

```powershell
python scripts/train_pid_models.py --source data/observations/collected_samples.csv data/observations/benign_browser_01.csv data/observations/simulated_02.csv
```

Không truyền cùng file hai lần hoặc gộp lại cùng dữ liệu qua nhiều file. Tool từ chối nhãn ngoài 0/1, nguồn/path trống, feature thiếu/không hữu hạn và thiếu executable. Toàn bộ snapshot của cùng normalized path thuộc cùng một tập. Chọn model bằng validation F1; giữ test để báo cáo. Bốn model: Decision Tree, Random Forest, Extra Trees, Isolation Forest (chỉ fit benign train).

Đầu ra ở `artifacts/reports/pid_live/`: `dataset_summary.json`, `split_manifest.csv`, `label_source_audit.csv`, `model_comparison.csv`, các confusion JSON và feature importance. Model ở `artifacts/models/pid_live/`. Xem partition và nguồn nhãn để phát hiện nhầm/thiếu/thiên lệch dữ liệu trước khi diễn giải metric. `active_model.txt` chọn model supervised theo validation. Khởi động lại monitor sau train để nạp model mới.

CLI train tạo thêm biểu đồ so sánh, confusion matrix của 4 model và top feature importance. Dùng `--model-dir`/`--report-dir` để lưu một lượt riêng. Model mới giữ fingerprint summary/manifest để công cụ đánh giá kiểm tra đúng provenance. Với model cũ thiếu fingerprint cần train lại trước khi đánh giá phiên.

## 4. Đo hệ thống tích hợp

Chạy các phiên mới ngoài dữ liệu train/validation/test và lưu JSON thu thập để đối chiếu ML-only với `max(rule, ML)`. Nếu chưa có model, JSON ghi `ml_available=false`; không diễn giải số ML alert bằng 0 là không bỏ sót. Thu thập riêng ứng dụng hợp lệ như browser/Office/IDE và tình huống mô phỏng có nguồn nhãn.

```powershell
python scripts/evaluate_pid_sessions.py --source data/observations/test_benign_new.csv data/observations/test_simulated_new.csv
```

Công cụ tính lại điểm từ feature, không tin cột điểm lịch sử; xuất `predictions.csv`, `detection_metrics.csv`, `evaluation.json` và `process_instances.csv` khi đủ PID/create-time. Có metric riêng rule, ML và kết hợp; nếu chưa có model thì chỉ báo rule. Mẫu số bằng 0 được ghi null. Thư mục output phải mới, không ghi đè kết quả cũ.

Khi có model, công cụ yêu cầu training summary/manifest khớp fingerprint, từ chối CSV có cùng hash với nguồn train/validation/test và process instance đã xuất hiện trong manifest khi đủ metadata. Nó báo số hàng có executable path đã biết; phiên mới dùng executable đã biết không chứng minh khái quát sang executable chưa từng thấy. Audit không độc lập xác minh nhãn, VM hay việc cùng binary ở nhiều path.

Trong báo cáo ghi TP/FN cho simulated, FP/TN cho benign; Precision = TP/(TP+FP), Recall = TP/(TP+FN), FPR = FP/(FP+TN). Ghi rõ tính theo snapshot, process instance hay phiên; không trộn đơn vị. Không dùng hàng loạt snapshot tương quan để phóng đại số thử nghiệm độc lập. Ghi tỷ lệ không thu thập được do quyền/quá trình kết thúc.

```powershell
# Thay 1234 bằng PID desktop/web monitor thực tế
python scripts/benchmark_monitor.py --target-pid 1234 --duration-hours 8 --interval-seconds 3
python -m unittest discover -s tests -v
```

Giữ CSV/JSON benchmark, log detection JSONL, ảnh bảng/cây/cảnh báo, hồ sơ VM và log kịch bản. Với ProcMon, gắn PML/CSV với đúng phiên và thời gian tạo PID; PID có thể được tái sử dụng giữa hai phiên. Không công bố telemetry chứa dữ liệu cá nhân trong bộ nộp.

## 5. Tiêu chí nghiệm thu còn cần thực hiện trong VM

- Dataset PID hai lớp được nhóm xác minh với nguồn nhãn và executable độc lập.
- Metric bốn model cùng confusion matrix, audit và phân tích false positive.
- Phát hiện kịch bản mô phỏng khi chạy monitor, có log và ảnh minh chứng.
- Benchmark monitor dài hạn trên VM; báo cáo thời gian quét và CPU/RAM.
- Báo cáo phân biệt kết quả Cardiff, synthetic, unit test và thực nghiệm PID.

Code/test tự động không thay thế bằng chứng thực nghiệm. Hiện chưa có kết quả PID lab đủ căn cứ để kết luận độ chính xác phát hiện thực tế.

## 6. Cập nhật báo cáo và kiểm tra phần mềm

```powershell
python scripts/verify_project.py
python scripts/build_project_report.py
```

`verify_project.py` chạy test, kiểm tra cú pháp Python/notebook và lưu JSON cùng phiên bản thư viện trong `artifacts/reports/software_validation/`. Notebook được kiểm tra cú pháp, không tự chạy train khi thiếu dữ liệu. `build_project_report.py` tổng hợp artifact hiện có vào `docs/BAO_CAO_TONG_HOP.md`; phần thiếu ghi rõ chưa có kết quả. File có marker generated có thể cập nhật; bản báo cáo chỉnh thủ công bỏ marker cần dùng tên output khác để tránh ghi đè.
