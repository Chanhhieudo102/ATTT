# Dataset Cardiff trong project

Tài liệu này mô tả cách mã nguồn và báo cáo hiện có sử dụng dữ liệu; số liệu được dẫn từ `BAO_CAO_DATASET_MODEL_KET_QUA.md`, không phải một lượt huấn luyện mới.

## Nguồn

- Dataset 2: *Behavioural machine activity for benign and malicious Win7 64-bit executables*, [DOI](https://doi.org/10.17035/d.2018.0050524986).
- Paper tham khảo: Rhode, Burnap, Jones (2018), *Early-stage malware prediction using recurrent neural networks*, [DOI](https://doi.org/10.1016/j.cose.2018.05.010).
- Script tải: `scripts/download_cardiff_dataset.py`, đọc metadata Figshare và giải nén `data_2.csv` vào `data/raw/cardiff_data_2.csv`.

## Ngữ nghĩa và tiền xử lý

Đơn vị mẫu là lần chạy executable trong sandbox, còn feature là telemetry toàn máy. Nhãn của lần chạy không phải nhãn cho mọi PID trên máy. Các trường dùng: CPU system/user, memory, swap, total_processes, max_pid, RX/TX bytes và packets.

`process_guard/cardiff.py` chuẩn hóa tên cột, chuyển số, loại hàng thiếu; loại sample ID có nhãn hoặc cờ split mâu thuẫn. Dùng `test_set` công bố theo sample, không random split các hàng thời gian. Với cửa sổ 5 giây, dữ liệu thành 5 × 10 = 50 feature; giây thiếu được điền theo quy tắc trong `make_sequences`. GRU dùng tensor chuỗi, các model dạng bảng dùng vector phẳng.

Báo cáo hiện có ghi 4.620 mẫu sau khi loại 11 sample ID mâu thuẫn: 4.099 train, 521 test. Các kết quả và hạn chế đầy đủ ở [báo cáo dataset/model](../BAO_CAO_DATASET_MODEL_KET_QUA.md). Không dùng các số này để công bố độ chính xác PID live hoặc làm nhãn tự động cho dữ liệu lab.

## Tái lập

```powershell
python scripts/prepare_cardiff_dataset.py
python scripts/eda.py
python scripts/train_cardiff_models.py --help
python scripts/plot_cardiff_results.py
```

Đọc `--help` trước khi chạy train để chọn model/cấu hình và tránh ghi đè đầu ra ổn định. Các checkpoint theo lượt nằm trong `artifacts/models/cardiff/runs/`; báo cáo theo lượt trong `artifacts/reports/cardiff/runs/`. Muốn tái lập chính xác cần giữ phiên bản thư viện, cấu hình và dataset gốc; không kỳ vọng latency giống nhau giữa các máy.
