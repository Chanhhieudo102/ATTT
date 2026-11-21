# ProcessGuard — giám sát tiến trình và nhận diện hành vi đáng ngờ

Đồ án **Ứng dụng học máy trong nhận diện các tiến trình mã độc đang hoạt động trong máy**. Dự án có ứng dụng desktop và dashboard web để xem tiến trình, cây cha-con, tín hiệu rule-based và cảnh báo. Phần ML gồm hai luồng:

- **Cardiff Dataset 2** (telemetry toàn máy khi chạy executable trong sandbox): tái lập thí nghiệm của bài báo Rhode et al. (2018) và đề xuất hai mô hình nhẹ.
- **Dữ liệu PID tự thu thập** (30.202 snapshot, 141 file thực thi, 5 chương trình mô phỏng vô hại): huấn luyện mô hình chấm điểm từng tiến trình, tích hợp vào chương trình giám sát live.

> **Tài liệu nộp:** báo cáo [22Nh15-ATTT-BAOCAO-10222022-102220016.docx](22Nh15-ATTT-BAOCAO-10222022-102220016.docx) và slide [ProcessGuard_22Nh15_Slide.pptx](ProcessGuard_22Nh15_Slide.pptx).
>
> **Phạm vi kết quả:** số liệu Cardiff là đánh giá offline trên tập test công bố. Số liệu PID đo trên máy phát triển với chương trình mô phỏng vô hại (không phải malware thật, không chạy trong VM cô lập); nhãn do script điều phối gán. Số liệu synthetic chỉ dùng kiểm tra demo.

## Cấu trúc thư mục

Mã nguồn ứng dụng, dữ liệu và đầu ra được tách riêng để dễ tìm, cập nhật và nộp đồ án:

```text
apps/
  desktop/app.py           Giao diện desktop Tkinter
  web/server.py            HTTP server và API dashboard
  web/static/              HTML, CSS, JavaScript
process_guard/             Collector, feature, rule, ML và tích hợp hệ điều hành
scripts/                   EDA, huấn luyện, demo, lab và benchmark
data/
  raw/                     Dataset gốc Cardiff
  processed/               Dataset đã tiền xử lý
  fixtures/                Dữ liệu demo tổng hợp
  observations/            PID observations do nhóm thu thập
  reference/               Blocklist hash cục bộ
artifacts/
  models/                  Model Cardiff, demo và PID live
  reports/                 Metric, EDA, ProcMon, lab và benchmark
  logs/                    Detection log
  quarantine/              File cách ly và metadata khôi phục
docs/requirements/          Đề bài gốc huongdan.txt
docs/                       Tài liệu kiến trúc và dataset
notebooks/                  Notebook EDA/huấn luyện
main.py, web_app.py         Launcher tương thích ở thư mục gốc
```

`python main.py`, `python web_app.py` và các script trong `scripts/` vẫn được giữ nguyên cách gọi. Các đường dẫn dữ liệu/đầu ra trong ứng dụng được neo theo thư mục dự án, vì vậy không phụ thuộc thư mục làm việc hiện tại.

## Tiến độ đối chiếu với [đề bài gốc](docs/requirements/huongdan.txt)

| Giai đoạn/yêu cầu | Trạng thái | Đã triển khai và phần còn thiếu |
|---|---|---|
| 1. Cơ sở lý thuyết, chọn dataset/paper | **Đã làm phần kỹ thuật** | Chọn Cardiff Dataset 2 và paper về early malware prediction bằng RNN; [docs/DATASET_CARDIFF.md](docs/DATASET_CARDIFF.md) ghi dataset/paper, [docs/ARCHITECTURE_AND_THEORY.md](docs/ARCHITECTURE_AND_THEORY.md) mô tả kiến trúc, MITRE ATT&CK, Sysinternals, tín hiệu và giới hạn. Nhóm vẫn cần đưa nội dung vào mẫu báo cáo/trình bày theo yêu cầu lớp. |
| 2. Thu thập và hiển thị tiến trình live | **Đã làm một phần** | Desktop và web thu thập PID/PPID, tên/đường dẫn/command line, thời gian chạy, CPU/RAM, threads, handles, kết nối, cây tiến trình và cập nhật mỗi 3 giây. Đã bổ sung trung bình/đỉnh CPU-RAM trên 5 lần quét gần nhất và tốc độ byte/I/O operation. Desktop có kiểm tra Authenticode/hash/Run keys/Scheduled Tasks, ProcMon CSV và memory metadata. Có capture ProcMon tự động tối đa 60 giây/256 MiB rồi export CSV. Sysmon Event ID 1/3/8/10/11/12/13/14/22/25 được đọc thủ công. Chưa thu thập API/system call trực tiếp, chưa so sánh nội dung vùng nhớ với file/module, chưa theo dõi tự động mọi thao tác file/Registry. |
| 3. Dataset và feature engineering | **Đã làm** | Cardiff: tải, làm sạch, EDA đầy đủ (`scripts/eda_cardiff_full.py`, [docs/DATASET_CARDIFF.md](docs/DATASET_CARDIFF.md)). PID: 30.202 snapshot (26.716 benign, 3.486 mô phỏng) từ 141 file thực thi qua 11 phiên huấn luyện và 3 phiên đánh giá; nhãn có `label_source` và `scenario_manifest.json`; 5 chương trình C# mô phỏng vô hại trong [lab/simulations/](lab/simulations/README.md); 40 đặc trưng runtime/đường dẫn/quan hệ cha-con. Chưa chạy Atomic Red Team hay mã độc thật; chưa chạy trong VM cô lập. |
| 4. Huấn luyện và so sánh ML | **Đã làm** | Cardiff: 11 mô hình cửa sổ 5 giây, tái lập bài báo (9 baseline + GRU A/B/C + ensemble), 2 mô hình nhẹ đề xuất (LiteSE-BiLSTM-Attn, Hybrid CNN-SE + XGBoost), validation 15% và tinh chỉnh siêu tham số. PID: 7 mô hình (DT, RF, ET, XGBoost, Isolation Forest, LiteSE, Hybrid), kiểm định chéo theo nhóm, tinh chỉnh, leave-one-out theo kỹ thuật và phát hiện sớm theo số snapshot. |
| 5. Tích hợp và kiểm thử hệ thống | **Đã làm** | Extra Trees + rule (max) chấm điểm live; phiên đánh giá với tiến trình mới: recall 0,75, precision 1,0, FPR 0%. Có ảnh dashboard/desktop, `detections.jsonl`, benchmark 15 phút (quét ~127 ms, CPU ~11% một lõi, RAM ~160 MB) và 21 unit test. Model Cardiff chỉ phục vụ nghiên cứu, **không** chấm từng PID. Chưa xác minh trong VM. |

Xem [kiến trúc và cơ sở lý thuyết](docs/ARCHITECTURE_AND_THEORY.md) để biết luồng module, cách diễn giải tín hiệu và danh sách giới hạn kỹ thuật.

## Chạy chương trình

### Cài đặt

    py -m venv .venv
    .\.venv\Scripts\Activate.ps1
    python -m pip install -r requirements.txt

### Dashboard web

    python web_app.py
    # Mở http://127.0.0.1:8765

    # Khởi động ở chế độ demo an toàn
    python web_app.py --demo

Dashboard có bảng/cây tiến trình, tìm kiếm và lọc, chi tiết tiến trình, biểu đồ CPU/RAM, cảnh báo gần đây, log local và trang metric Cardiff. Mặc định giao diện làm mới khoảng 3 giây. Server chỉ bind vào 127.0.0.1; web dashboard chỉ đọc/hiển thị và ghi log cảnh báo, không điều khiển hoặc kết thúc tiến trình. Cảnh báo được ghi ở `artifacts/logs/detections.jsonl`. Nút **Tải báo cáo hiệu năng** xuất tối đa 1.200 snapshot gần nhất (thời gian quét, số process, CPU/RAM của monitor và host) thành CSV để đo theo thời gian.

### Ứng dụng desktop

    python main.py
    python main.py --demo

Desktop hiển thị PID/PPID, tên/đường dẫn, CPU/RAM, threads, handles, kết nối mạng, tiến trình con, I/O và điểm rule/model riêng. Điểm cảnh báo kết hợp là giá trị lớn hơn giữa rule và ML, không cộng hai điểm. Kiểm tra chữ ký/hash/Registry/Scheduled Tasks/Sysmon, quét memory metadata, VirusTotal, cách ly/khôi phục và ProcMon được gọi thủ công. Kết thúc process, tra cứu hash và cách ly đều cần xác nhận; nút bỏ qua ẩn cảnh báo cho process identity đó đến khi tiến trình kết thúc hoặc ứng dụng khởi động lại.

**ProcMon:** bấm **Capture ProcMon 60 giây…**, chọn `procmon.exe` từ Microsoft Sysinternals và xác nhận capture trong VM. Ứng dụng chỉ chạy file có Authenticode hợp lệ của Microsoft Corporation; tự dừng/export PML sang CSV khi đủ 60 giây hoặc 256 MiB. PML/CSV nằm trong `artifacts/reports/procmon/`. Có thể nhập CSV qua **Nhập thống kê ProcMon CSV…** để đếm `ReadFile`, `WriteFile` và Run/RunOnce theo PID + tên ảnh. Trace có thể chứa đường dẫn/hoạt động riêng tư; chỉ dùng trong VM lab. Số liệu ProcMon chỉ để đối chiếu, chưa là feature ML; PID cũ có thể bị tái sử dụng. Capture yêu cầu Windows, driver/quyền phù hợp và chưa được chạy xác minh trong VM.

**VirusTotal và quarantine:** chọn process → **Tra cứu VirusTotal SHA-256…** để gửi hash SHA-256 tới API v3 (không tải file), hoặc **Cách ly executable…** để sao chép, xác minh hash, rồi xóa file gốc. API key chỉ nhập qua hộp thoại hoặc biến môi trường `VIRUSTOTAL_API_KEY`, không ghi vào project/log. Kết quả VirusTotal là reputation để triage, không verdict chắc chắn. Hash tra cứu qua dịch vụ công khai có thể được ghi vào dataset dịch vụ; không truy vấn hash nhạy cảm. Cách ly từ chối thư mục Windows và chính executable ProcessGuard, tạo metadata khôi phục trong `artifacts/quarantine/`; khôi phục cần xác nhận, kiểm tra hash và không ghi đè file đang có. Cách ly file đang chạy có thể bị Windows từ chối; ứng dụng không tự kết thúc process.

**Memory triage (Windows):** chọn process thật và bấm **Quét vùng nhớ executable (read-only)**. Chương trình liệt kê metadata vùng executable `MEM_PRIVATE` ngoài dải địa chỉ image modules được PSAPI nhận diện; không đọc/sửa bytes bộ nhớ. JIT/runtime có thể tạo vùng như vậy; kết quả không chứng minh injection. Chức năng phụ thuộc quyền truy cập và chưa được xác minh trong VM.

### Demo nhanh

    python scripts/run_demo.py

Demo dùng fixture tiến trình giả lập như trình duyệt, Office và svch0st.exe giả ở đường dẫn tạm. **Không tạo tiến trình độc hại hay chạy payload.** Đây là demo pipeline/giao diện, không phải kiểm thử malware thật.

Lần chạy demo an toàn gần nhất: fixture `svch0st.exe` đạt rule 100%, synthetic ML 100% và điểm kết hợp 100%; các fixture benign có điểm ML 0–5,9%. Đây là xác nhận luồng fixture → feature → rule/model → cảnh báo hoạt động, không phải phép đo độ chính xác trên process hoặc malware thật.

### Kịch bản quan sát lab an toàn

Chỉ chạy trong VM lab cô lập. Mở ProcessGuard trước, rồi chạy ở terminal khác:

    python scripts/safe_behavior_lab.py --duration 10 --write-mb 8

Script tạo một process con có tải CPU giới hạn, ghi tối đa 8 MiB dữ liệu giả vào thư mục tạm (tự xóa khi kết thúc) và trao đổi dữ liệu chỉ qua loopback `127.0.0.1`. Thời lượng tối đa 15 giây, dung lượng tối đa 16 MiB. Script không kết nối ra ngoài, không sửa Registry/Scheduled Tasks, không injection, không chạy payload. Chọn PID con đang hoạt động trong ProcessGuard để quan sát và chỉ gán nhãn simulated malicious nếu nhóm xác định kịch bản này phù hợp cho nhãn đó. Kịch bản này tạo một số hành vi runtime để thử pipeline, không đại diện cho malware hoặc Atomic Red Team. Chưa chạy trong VM nên chưa có metric/ảnh minh chứng từ script.

## Dataset và paper tham chiếu

**Dataset:** *Behavioural machine activity for benign and malicious Win7 64-bit executables*, Cardiff University Figshare, [DOI 10.17035/d.2018.0050524986](https://doi.org/10.17035/d.2018.0050524986), giấy phép CC BY 4.0. Pipeline sử dụng Dataset 2, ban đầu khoảng 2.345 mẫu benign và 2.286 mẫu malicious. Mỗi mẫu là telemetry toàn máy ghi trong khi một executable chạy trong VirtualBox/Cuckoo Sandbox Windows 7 64-bit, tối đa khoảng 20 giây. Xem [mô tả dataset của Cardiff](https://research-data.cardiff.ac.uk/articles/dataset/Behavioural_machine_activity_for_benign_and_malicious_Win7_64-bit_executables/27052333).

**Paper:** Matilda Rhode, Pete Burnap, Kevin Jones, “Early-stage malware prediction using recurrent neural networks”, *Computers & Security*, 77 (2018), 578–594, [DOI 10.1016/j.cose.2018.05.010](https://doi.org/10.1016/j.cose.2018.05.010), [bản PDF](https://orca.cardiff.ac.uk/id/eprint/111627/8/1-s2.0-S0167404818305546-main.pdf). Paper nghiên cứu dự đoán sớm từ chuỗi telemetry và dùng GRU/RNN ensemble. Paper báo cáo khoảng 94% accuracy ở mốc 5 giây trong cấu hình của nghiên cứu đó; đây không phải kết quả có thể so sánh trực tiếp một-một với pipeline hiện tại.

**Giới hạn quan trọng:** dataset ghi hoạt động toàn máy trong lúc chạy một executable, không cung cấp telemetry riêng cho từng PID đang chạy trên máy của nhóm. Vì vậy Cardiff dùng để nghiên cứu phát hiện ở cấp mẫu executable/sandbox; không dùng model Cardiff để gán nhãn tiến trình live.

## EDA, huấn luyện và kết quả Cardiff

Báo cáo đầy đủ về nguồn và lọc dataset, cấu hình model, kết quả và giới hạn: [BAO_CAO_DATASET_MODEL_KET_QUA.md](BAO_CAO_DATASET_MODEL_KET_QUA.md).

### Chạy pipeline

    python scripts/download_cardiff_dataset.py
    python scripts/eda.py
    python -m pip install -r requirements-modern-ml.txt  # tùy chọn: thêm XGBoost và LightGBM
    python scripts/train_models.py --seconds 5

Nếu tải dataset thủ công, đặt data_2.csv tại data/raw/cardiff_data_2.csv hoặc truyền nguồn theo hướng dẫn của script. Notebook: [notebooks/cardiff_eda_training.ipynb](notebooks/cardiff_eda_training.ipynb).

Pipeline làm sạch theo sample_id, sắp xếp theo thời gian, loại bản ghi xung đột, giữ cửa sổ thời gian đầu và dùng `test_set` Cardiff công bố để chia train/test theo mẫu. Ở kết quả mới nhất: **4.620 mẫu** sau làm sạch, **4.099 train**, **521 test**; đánh giá chính dùng cửa sổ **5 giây**. Có 8 mô hình supervised (gồm XGBoost, LightGBM) và 1 baseline unsupervised. XGBoost/LightGBM là dependencies tùy chọn; nếu chưa cài, pipeline vẫn chạy các model khác và ghi model bị bỏ qua vào log.

### So sánh mô hình — Cardiff, cửa sổ 5 giây

| Mô hình | Accuracy | Balanced acc. | Precision | Recall | F1 | FPR | ROC AUC | PR AUC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Decision Tree | 0.8714 | 0.8735 | 0.9189 | 0.8635 | 0.8903 | 0.1165 | 0.8909 | 0.9213 |
| Random Forest | 0.9060 | 0.9105 | 0.9524 | **0.8889** | 0.9195 | 0.0680 | 0.9595 | 0.9778 |
| Extra Trees | 0.9079 | 0.9163 | 0.9684 | 0.8762 | 0.9200 | 0.0437 | 0.9713 | 0.9833 |
| Gradient Boosting | 0.8253 | 0.8178 | 0.8567 | 0.8540 | 0.8553 | 0.2184 | 0.9272 | 0.9588 |
| XGBoost | **0.9194** | **0.9283** | 0.9789 | **0.8857** | **0.9300** | 0.0291 | **0.9785** | **0.9876** |
| LightGBM | 0.9136 | 0.9244 | **0.9821** | 0.8730 | 0.9244 | **0.0243** | 0.9768 | 0.9862 |
| Logistic Regression | 0.8714 | 0.8710 | 0.9106 | 0.8730 | 0.8914 | 0.1311 | 0.9314 | 0.9344 |
| RBF SVM | 0.9002 | 0.9074 | 0.9582 | 0.8730 | 0.9136 | 0.0583 | 0.9643 | 0.9775 |
| Isolation Forest (unsupervised) | 0.4012 | 0.5031 | 0.7143 | 0.0159 | 0.0311 | 0.0097 | 0.4146 | 0.5795 |

**Thời gian chạy trên máy huấn luyện hiện tại:**

| Mô hình | Fit (giây) | Inference (ms/mẫu)* |
|---|---:|---:|
| Decision Tree | 0.1039 | 0.0019 |
| Random Forest | 0.6380 | 0.3911 |
| Extra Trees | 0.4519 | 0.3912 |
| Gradient Boosting | 3.6074 | 0.0036 |
| XGBoost | 0.3121 | 0.0067 |
| LightGBM | 0.2628 | 0.0107 |
| Logistic Regression | 0.0361 | 0.0026 |
| RBF SVM | 0.4426 | 0.1237 |
| Isolation Forest (unsupervised) | 0.2876 | 0.1805 |

Trong lượt chạy này, XGBoost có F1, ROC AUC và PR AUC cao nhất; LightGBM có FPR thấp nhất trong các model supervised; Random Forest có recall cao nhất. Isolation Forest gần như bỏ sót toàn bộ mẫu malicious. `Inference ms/mẫu` là thời gian gọi `predict` sau warm-up trên batch tối đa 128 mẫu; không gồm collector, feature extraction hay giao diện. Thời gian phụ thuộc CPU và threading.

**Lưu ý đánh giá:** bảng dùng test split chính thức của Cardiff để so sánh mô hình. Chọn XGBoost theo F1 của cùng test split có thể lạc quan; test này không còn là ước lượng độc lập cho model đã chọn. Kết quả vẫn là offline trên Cardiff, không phải tỷ lệ phát hiện trên máy của nhóm.

Với XGBoost, confusion matrix trên test là [[200, 6], [36, 279]] theo thứ tự nhãn [benign, malicious]: 279 mẫu malicious được nhận diện đúng, 36 mẫu bị bỏ sót, 6 mẫu benign bị báo nhầm và 200 mẫu benign được nhận đúng. Đây là phép đánh giá offline trên Cardiff, không phải tỷ lệ phát hiện trên máy của nhóm.

### Phát hiện sớm theo cửa sổ thời gian — Random Forest

| Thời gian telemetry | Accuracy | Precision | Recall | F1 | False-positive rate | Inference ms/mẫu* |
|---:|---:|---:|---:|---:|---:|---:|
| 1 giây | 0.7889 | 0.8154 | 0.8413 | 0.8281 | 0.2913 | 0.3168 |
| 2 giây | 0.8292 | 0.8645 | 0.8508 | 0.8576 | 0.2039 | 0.3890 |
| 3 giây | 0.8599 | 0.8903 | 0.8762 | 0.8832 | 0.1650 | 0.3105 |
| 4 giây | 0.8848 | 0.9236 | 0.8825 | 0.9026 | 0.1117 | 0.3078 |
| 5 giây | **0.9098** | **0.9558** | **0.8921** | **0.9228** | **0.0631** | 0.3131 |

Bảng cửa sổ thời gian dùng cấu hình Random Forest riêng cho bài toán early-window; do đó số tại 5 giây khác một chút so với Random Forest trong bảng so sánh mô hình chính. Kết quả thể hiện trade-off: cửa sổ ngắn phản hồi sớm hơn nhưng false positive cao hơn.

### EDA và feature importance

Sau khi loại 11 sample ID mâu thuẫn, phân bố còn 2.340 benign và 2.280 malicious (gần cân bằng). Biểu đồ EDA 5 giây dùng trung bình theo từng sample, nên mỗi executable có cùng trọng số: benign có CPU system, memory, số tiến trình và RX bytes trung bình cao hơn; malicious có CPU user trung bình cao hơn từ giây 1. Đây là telemetry toàn máy trong sandbox, không phải dấu hiệu đủ để phân loại một executable riêng lẻ. Trong XGBoost, các đặc trưng đứng đầu theo file importance hiện có gồm t0_tx_packets, t0_rx_bytes, t3_rx_bytes, t2_rx_bytes và t0_rx_packets. Đây là thứ hạng theo mô hình/dataset cụ thể; feature importance không tự nó chứng minh quan hệ nhân quả hay đảm bảo tổng quát sang máy khác.

Kết quả nằm trong `artifacts/reports/cardiff/`:

- cardiff_class_balance.csv, cardiff_eda_class_balance.png, cardiff_eda_by_label.csv, cardiff_eda_by_sample_5s.csv, cardiff_eda_*.png: EDA; by_label là thống kê theo observation trên full trace, by_sample_5s lấy 1 sample làm một đơn vị.
- cardiff_model_comparison.csv, cardiff_early_window_metrics.csv: bảng metric của 9 mô hình.
- cardiff_*_confusion.json: confusion matrix và classification report.
- cardiff_*_feature_importance.csv: feature importance.
- Biểu đồ train: `cardiff_model_comparison.png`, `cardiff_detection_metrics.png`, `cardiff_confusion_matrices.png`, `cardiff_roc_curves.png`, `cardiff_precision_recall_curves.png`, `cardiff_early_window_metrics.png`, `cardiff_training_time.png`, `cardiff_inference_latency.png` và feature importance.
- Có thể tạo lại các biểu đồ từ CSV/JSON đã có mà không huấn luyện lại: `python scripts/plot_cardiff_results.py`.
- Mỗi lượt train có log JSONL trong `artifacts/logs/cardiff_training_<run_id>.jsonl`, checkpoint từng mô hình và `checkpoint.json` trong `artifacts/models/cardiff/runs/<run_id>/`; báo cáo theo lượt nằm trong `artifacts/reports/cardiff/runs/<run_id>/`. Các file mới nhất cũng được sao chép vào đường dẫn ổn định phía trên.

### Tái lập bài báo và mô hình nhẹ đề xuất

Thiết lập giống bài báo: dùng tập test công bố (521 mẫu: 206 benign, 315 malicious), tách thêm **15% train làm validation** phân tầng theo nhãn (3.484 train / 615 validation), đánh giá tại từng giây t = 0..19 (giây t dùng t+1 snapshot). Baseline (RF, J48, GBDT, SVM, NB, KNN, MLP, AdaBoost, XGBoost) được huấn luyện lại tại mỗi giây và chạy 10-fold CV trên train; GRU A/B/C theo Table 13 của bài báo, ensemble lấy max xác suất, ngưỡng 0,5. Mô hình học sâu chạy 3 seed (42/43/44), early stopping (patience 15) và ReduceLROnPlateau.

Hai mô hình nhẹ đề xuất:

- **LiteSE-BiLSTM-Attn:** Conv1D + BatchNorm + Squeeze-and-Excitation → BiLSTM → multi-head attention pooling (~35 nghìn tham số, ít hơn GRU-B ~23 lần).
- **Hybrid CNN-SE + XGBoost:** embedding 64 chiều từ LiteSE + 40 thống kê chuỗi (last/mean/max/slope) → XGBoost.

| Mô hình (test, trung bình 3 seed) | Acc 1 giây | Acc 5 giây | FPR 5 giây | FNR 5 giây | Acc cao nhất (giây) | Tham số | Train (giây) |
|---|---:|---:|---:|---:|---:|---:|---:|
| Random Forest | 83,3% | 91,6% | 6,3% | 9,8% | **96,7% (13)** | — | — |
| XGBoost | 83,3% | 92,9% | 2,9% | 9,8% | 96,2% (16) | — | — |
| GRU-A (bài báo) | 75,5% | 91,2% | 4,0% | 11,9% | 93,5% (18) | 237.245 | 174 |
| GRU-B (bài báo) | 77,6% | 92,1% | 3,6% | 10,7% | 94,8% (19) | 795.477 | 378 |
| GRU-C (bài báo) | 75,5% | 89,4% | 3,7% | 15,0% | 94,8% (13) | 350.611 | 78 |
| Ensemble GRU max(A,B,C) | 77,2% | **93,3%** | 7,3% | **6,3%** | 95,9% (13) | 1.383.333 | 630 |
| **Hybrid CNN-SE + XGBoost** (đề xuất) | 83,2% | 93,1% | **2,8%** | 9,6% | 95,6% (15) | 35.273 | 41 |
| LiteSE-BiLSTM-Attn (đề xuất) | 77,5% | 89,7% | 3,6% | 14,7% | 93,9% (19) | 35.273 | 24 |

- Ensemble GRU tái lập đạt 93,3% ở giây 5, sát mức ~94% của bài báo. Các baseline cổ điển của nhóm cao hơn bài báo (RF 96,7% so với 92,05% trong Table 6) do pipeline làm sạch và cách tính khác.
- Hybrid đề xuất vượt ensemble của bài báo ở các giây đầu (1/2/3 giây: 83,2/88,6/91,2% so với 79,5/83,7/88,5%) với FPR chỉ 2,8% ở giây 5, trong khi nhẹ hơn ~39 lần và huấn luyện nhanh hơn ~15 lần.
- **Tinh chỉnh** (random search 30 cấu hình LiteSE + 20 cấu hình đầu XGBoost, chọn theo validation): cấu hình tinh chỉnh nhỏ hơn (15.533 tham số) và tốt hơn trên validation nhưng **không tốt hơn trên test** (Hybrid 91,9% ở giây 5), nên giữ cấu hình mặc định.

Chạy lại (cần PyTorch CPU: `python -m pip install -r requirements-rnn.txt`):

    python scripts/cardiff_paper_benchmark.py            # baseline + GRU + mô hình đề xuất (--group classical|deep)
    python scripts/tune_cardiff_best.py                  # tinh chỉnh siêu tham số
    python scripts/plot_cardiff_paper.py                 # bảng so sánh với bài báo và biểu đồ

Kết quả ghi vào `artifacts/reports/cardiff_paper/` (CSV được gitignore, chạy lại để tạo). Script cũ `scripts/train_cardiff_gru.py` vẫn giữ để tham khảo.

## Giám sát PID và dữ liệu nhóm tự thu thập

Chương trình lưu quan sát tiến trình live với nhãn benign hoặc simulated malicious và bắt buộc nhập `label_source` (mã VM lab/kịch bản/log/căn cứ), PID, executable, thời điểm và `create_time`. Nguồn nhập tay giúp truy vết nhưng không phải chứng thực ground-truth độc lập. Nhóm cần xác minh hành vi trong VM trước khi gán nhãn; không suy ra nhãn chỉ từ tên file hay điểm rule. Dataset Cardiff không thể thay thế bước này.

Quy trình thu thập trong desktop: chạy `python main.py` trong VM lab, chọn tiến trình, tùy chọn kiểm tra chữ ký/hash/Run keys/Scheduled Tasks và Sysmon, rồi lưu quan sát benign hoặc simulated malicious kèm nguồn gán nhãn. Collector lấy rolling average/peak từ tối đa 5 lần quét gần nhất; lưu nhiều snapshot khi kịch bản đang chạy để ghi nhận diễn biến. Safe workload hiện tại dùng Python child process nên một executable path không đủ cho grouped split; cần executable riêng đã xác minh cho **mỗi lớp** hoặc thêm tình huống/ứng dụng khác. Không sao chép cùng binary sang nhiều đường dẫn để giả tạo tính độc lập. Chỉ gán nhãn simulated malicious cho tiến trình thuộc kịch bản mô phỏng đã xác minh; workload safe không phải malware hay injection.

Có thể thu thập tự động nhiều snapshot cho PID được chỉ định bằng `python scripts/collect_pid_samples.py --pid 1234 --label 0 --label-source "VM01/benign/run01" --duration 60`. Tool lưu mỗi phiên vào CSV và JSON riêng trong `data/observations/`, kiểm tra PID/create-time và không tự xác nhận nhãn. Xem [quy trình lab](docs/LAB_WORKFLOW.md) để thu thập, huấn luyện và nghiệm thu.

Sau khi có `data/observations/collected_samples.csv` đủ dữ liệu, chạy:

    python scripts/train_pid_models.py

Hoặc truyền nhiều CSV phiên đã xác minh bằng `--source session_benign.csv session_simulated.csv ...`. Mỗi file chỉ truyền một lần, không gộp trùng cùng dữ liệu qua nhiều file.

Pipeline PID yêu cầu cả hai nhãn, `label_source` không rỗng và tối thiểu ba executable path khác nhau mỗi nhãn; chia train/validation/test theo process_path để tránh cùng executable lọt vào nhiều tập, chọn model theo F1 validation. Pipeline so sánh Decision Tree, Random Forest, Extra Trees, Isolation Forest, xuất Accuracy/Precision/Recall/F1/FPR, confusion matrix, feature importance, `label_source_audit.csv`, `split_manifest.csv` và `dataset_summary.json` vào `artifacts/reports/pid_live/`; model vào `artifacts/models/pid_live/`. Model chỉ có ý nghĩa tương ứng với chất lượng nhãn/độ đa dạng tập thu thập. CSV cũ cần bổ sung nguồn nhãn hoặc thu thập lại; thiếu các cột feature mới thì cũng cần thu thập lại.

Metric PID sử dụng cùng hàm score và ngưỡng 0,65 với live; Isolation Forest dùng điểm sigmoid (không phải xác suất). Chọn model supervised bằng validation, test chỉ để báo cáo. Metric ML-only không thay thế đánh giá cảnh báo kết hợp rule+ML. Pipeline từ chối feature thiếu/không hữu hạn thay vì âm thầm bỏ hàng hoặc điền 0.

### Bộ dữ liệu PID và kết quả mô hình

Bộ dữ liệu cuối gồm **30.202 snapshot** (26.716 benign, 3.486 mô phỏng) của 496 instance tiến trình từ **141 file thực thi** (136 có snapshot lành tính, 6 có snapshot mô phỏng; `powershell.exe` thuộc cả hai lớp vì vừa chạy bình thường vừa được Word giả sinh ra), thu bằng `scripts/run_pid_lab_experiment.py`. Tập được chia theo file thực thi, không file nào nằm ở hai tập:

| Tập | File lành tính | File mô phỏng | Snapshot |
|---|---:|---:|---:|
| Train | 69 | 2 (invoice_viewer, powershell) | 11.176 |
| Validation | 34 | 1 (winupdater) | 4.285 |
| Test | 33 | 3 (svch0st, expl0rer, WINWORD) | 14.741 |

Ngoài 4 mô hình gốc, `scripts/pid_model_benchmark.py` bổ sung XGBoost và hai mô hình chuỗi trên **cửa sổ 8 snapshot gần nhất** của mỗi tiến trình (log1p + z-score, `pos_weight` cho lớp hiếm): LiteSE-BiLSTM-Attn và Hybrid CNN-SE + XGBoost. Vì validation chỉ có 1 file độc hại, việc chọn và tinh chỉnh mô hình dùng **kiểm định chéo theo nhóm** (StratifiedGroupKFold 3 fold trên train + validation) với mục tiêu average precision (AP).

| Mô hình (test, ngưỡng 0,65) | Precision | Recall | F1 | FPR | Leave-one-out: phát hiện / FPR |
|---|---:|---:|---:|---:|---:|
| Decision Tree | 0,007 | 0,001 | 0,002 | 2,30% | — |
| Random Forest | 0,000 | 0,000 | 0,000 | 0% | — |
| **Extra Trees** (mô hình live) | **1,000** | 0,637 | 0,778 | **0%** | 42,8% / **0%** |
| XGBoost | 0,020 | 0,001 | 0,002 | 0,74% | 33,3% / 1,1% |
| Isolation Forest (không giám sát) | 0,000 | 0,000 | 0,000 | 0,72% | — |
| LiteSE-BiLSTM-Attn (3 seed) | 0,990 | 0,637 | 0,775 | 0,08% | 33,3% / 0,1% |
| Hybrid CNN-SE + XGBoost (3 seed) | 0,931 | **0,879** | **0,890** | 1,04% | **50,0%** / 1,0% |

- Hybrid bắt được nhiều kỹ thuật nhất, kể cả `expl0rer.exe` (sinh tiến trình con liên tục) mà mọi mô hình một snapshot đều bỏ sót, nhưng FPR ~1% (≈4 báo nhầm mỗi lần quét ~390 tiến trình) và dao động theo seed.
- Phát hiện sớm: mô hình nào bắt được một chương trình thì bắt ngay từ snapshot đầu tiên, vì các dấu hiệu mạnh (đường dẫn Temp, tên giả, cha là Office) có sẵn từ đầu.
- Tinh chỉnh (25 cấu hình ET, 15 XGBoost, 6 LiteSE, 15 đầu Hybrid) tăng AP kiểm định chéo nhưng không cải thiện test, do train + validation chỉ có 3 kỹ thuật độc hại.
- Chấm offline phiên đánh giá mới: Extra Trees và Hybrid cùng bắt 3/4 tiến trình mô phỏng, 0 báo nhầm; LiteSE và XGBoost bắt 2/4.

**Kết luận:** hệ thống live giữ **Extra Trees** kết hợp rule theo max(rule, ML) vì FPR 0% trên test, leave-one-out và phiên mới; Hybrid phù hợp làm tín hiệu thứ hai để ưu tiên điều tra.

    python scripts/pid_model_benchmark.py --stage all    # base | tune | extra | all; --quick để chạy thử
    python scripts/plot_pid_models.py

Kết quả ghi vào `artifacts/reports/pid_paper/`. Kiểm thử tích hợp trên phiên mới (`scripts/evaluate_pid_sessions.py`, kết quả trong `artifacts/reports/pid_eval_final/`): riêng rule recall 0,25; ML và kết hợp recall 0,75, precision 1,0, FPR 0% (snapshot và instance).

### Kết quả synthetic demo — chỉ minh họa

Fixture synthetic hiện có metric held-out trong `artifacts/reports/synthetic_demo/`:

| Mô hình | Accuracy | Precision | Recall | F1 | False-positive rate | Inference ms/mẫu* |
|---|---:|---:|---:|---:|---:|---:|
| Decision Tree | 0.9886 | 0.9886 | 0.9886 | 0.9886 | 0.0114 | 0.0054 |
| Random Forest | 0.9971 | 0.9943 | 1.0000 | 0.9972 | 0.0057 | 0.2607 |
| Extra Trees | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.3122 |
| Isolation Forest | 0.8686 | 0.7919 | 1.0000 | 0.8838 | 0.2629 | 0.1042 |

Các mẫu được tạo theo luật của demo nên dễ phân tách và không đại diện cho malware hay dữ liệu máy thật. Điểm số cao ở đây chỉ xác nhận luồng minh họa/model chạy được; không dùng để tuyên bố độ chính xác phát hiện thực tế.

## Tính năng đã triển khai và giới hạn

| Thành phần | Hiện trạng |
|---|---|
| Thu thập process | PID/PPID, tên/đường dẫn, command line, thời gian chạy, CPU/RAM hiện tại và trung bình/đỉnh trên 5 snapshot gần nhất, threads, handles, kết nối mạng, tiến trình con, tốc độ byte và I/O operation (một số trường phụ thuộc quyền hệ điều hành). Đây là counter I/O của process, không ghi lại từng file được truy cập. |
| Process tree và giao diện | Có ở desktop và dashboard web; web lọc/tìm kiếm, chi tiết PID, CPU/RAM chart, cảnh báo gần đây. |
| Feature engineering | Có path category dạng one-hot (Windows, Program Files, Temp, other, missing), name similarity/entropy, command length, chữ ký đã kiểm tra/hợp lệ, CPU/RAM snapshot và rolling average/peak, handles, kết nối, child count, byte/I/O rates, parent script host, Run-key/Scheduled Task persistence, Sysmon hint, số Event ID 11 FileCreate và Event ID 22 DNS query khớp PID trong cửa sổ event truy vấn. |
| Rule-based | Đường dẫn/temp bất thường, tên gần giống tên hệ thống, parent/script host, Run-key/Scheduled Task persistence, chữ ký thiếu/lỗi và tín hiệu Sysmon. Điểm rule là tín hiệu triage, không phải kết luận malware. |
| Chữ ký/hash | Desktop có thao tác kiểm tra Authenticode trên Windows, SHA-256 và blocklist cục bộ tùy chọn. Kết quả chữ ký được giữ theo đường dẫn executable và đưa vào feature/rule sau khi kiểm tra. |
| Persistence | Có kiểm tra Registry Run/RunOnce và action của Scheduled Tasks theo executable được chọn; kết quả được đưa vào rule/feature nếu truy vấn được. Task matching là kiểm tra action trỏ tới đúng executable, không chứng minh task đã khởi chạy PID hiện tại. Lần kiểm tra trong môi trường hiện tại bị Windows từ chối quyền truy cập, nên chưa có kết quả task thực tế để báo cáo. |
| Sysmon | Có đọc Event ID 1, 3, 8, 10, 11, 12, 13, 14, 22, 25 nếu Sysmon đã cài/cấu hình và người dùng chọn truy vấn. Event ID 8/10/25 tạo heuristic triage cho remote thread, quyền truy cập bộ nhớ và process tampering; Event ID 12/13/14 được kiểm tra với Run/RunOnce; Event ID 11/22 cung cấp số đếm tạo file/DNS trong tối đa 200 event mới nhất lấy được. Đây là cửa sổ event bị giới hạn, Event ID 11 không ghi nhận mọi lần đọc file và các sự kiện này không tự chứng minh injection. |
| Cảnh báo và hành động | Cảnh báo được ghi vào `artifacts/logs/detections.jsonl` với PID, tên, đường dẫn, điểm rule, điểm ML, model và lý do; desktop yêu cầu xác nhận trước khi kết thúc tiến trình, có thể bỏ qua cảnh báo cho PID đó trong phiên hiện tại. Web dashboard không điều khiển tiến trình. |
| API/system call và injection | Chưa thu thập trực tiếp API/system call. Có memory metadata scan read-only thủ công để liệt kê vùng executable riêng tư, nhưng chưa so sánh nội dung với file/module, chưa kết luận injection và chưa xác minh trong VM. Sysmon 8/10/25 chỉ cung cấp tín hiệu để điều tra thêm. |
| ProcMon | Desktop capture tự động tối đa 60 giây/256 MiB, dừng và export PML/CSV; có nhập CSV thủ công, giới hạn 64 MiB/1.000.000 dòng/100.000 nhóm PID-tên, đếm ReadFile/WriteFile và Run/RunOnce. Chưa chạy xác minh trong VM; chưa đưa số đếm vào model; trace cũ có thể trùng PID sau khi tái sử dụng. |
| Đo hiệu năng và kiểm thử lab | Có script `scripts/benchmark_monitor.py` ghi CSV từng snapshot và metadata JSON trong thời lượng cấu hình; web vẫn có export 1.200 snapshot. Chưa có báo cáo benchmark dài hạn đã chạy trong VM hoặc kết quả kiểm thử Atomic Red Team đã xác minh. |
| Hash reputation và quarantine | Có VirusTotal SHA-256 lookup (API key, hash-only, không upload file); cách ly/khôi phục có hash verification, metadata và xác nhận thủ công. Chưa truy vấn hash thật hoặc xác minh thao tác quarantine trong VM. |

Các thao tác lab và dịch vụ bên ngoài chưa được thực thi trên máy phát triển. Hash lookup dùng endpoint file report của VirusTotal; tài liệu API cảnh báo chỉ báo cáo hash công khai và không truy vấn indicator nhạy cảm. ProcMon capture cần quyền/driver hoạt động trên Windows và phải được chạy trong VM. CSV/JSON/PML lab và thư mục quarantine được gitignore mặc định vì có thể chứa telemetry hoặc file nhạy cảm; khi nộp bài, chọn lọc và làm sạch bản minh chứng cần thiết.

## Hạn chế và hướng phát triển

- Dữ liệu PID thu trên máy phát triển, chưa chạy trong VM cô lập; lớp độc hại chỉ có 6 file thực thi mô phỏng nên kết quả leave-one-out còn dao động lớn.
- Chưa chạy Atomic Red Team hay mã độc thật; chưa mô phỏng persistence và injection thật (cố ý tránh để an toàn).
- Hướng tiếp theo: đưa Hybrid CNN-SE + XGBoost vào luồng live như tín hiệu thứ hai trên chuỗi snapshot của từng tiến trình; hiệu chuẩn ngưỡng và chia validation theo thời gian khi có thêm dữ liệu độc hại.

## Quy trình lab và kiểm thử

Các công cụ bổ sung cho phần PID: `scripts/analyze_pid_data.py` tạo EDA; `scripts/train_pid_models.py` huấn luyện và xuất biểu đồ; `scripts/evaluate_pid_sessions.py` so sánh rule/ML/kết hợp trên phiên mới. Notebook tương ứng: `notebooks/pid_lab_eda_training.ipynb`. Chạy `python scripts/verify_project.py` để lưu kết quả kiểm thử phần mềm, sau đó `python scripts/build_project_report.py` để cập nhật [báo cáo tổng hợp](docs/BAO_CAO_TONG_HOP.md) từ artifact có thật. Xem [quy trình lab](docs/LAB_WORKFLOW.md) cho lệnh và giới hạn đánh giá.

Quy trình thao tác đầy đủ ở [docs/LAB_WORKFLOW.md](docs/LAB_WORKFLOW.md). Kiểm tra các thay đổi mới bằng `python -m unittest discover -s tests -v`; xem [biên bản kiểm tra](docs/VALIDATION.md) để biết phạm vi đã xác minh.

1. Chạy `python scripts/safe_behavior_lab.py` trong VM; JSON log tự lưu vào `artifacts/reports/lab_runs/`. Chạy thêm kịch bản Atomic Red Team hoặc kịch bản khác đã được duyệt và lưu log/ảnh màn hình thủ công cùng hồ sơ VM. Safe script chỉ tạo CPU/I/O giới hạn và loopback, không thay thế Atomic Red Team.
2. Thu thập PID benign/simulated trong VM với nguồn nhãn và nhiều executable path riêng cho từng lớp; chạy `python scripts/train_pid_models.py`; đính kèm metric, confusion matrix, `label_source_audit.csv` và phân tích false positive.
3. Chạy desktop/web monitor trong VM, lấy PID của tiến trình Python đó từ Task Manager, rồi chạy `python scripts/benchmark_monitor.py --target-pid 1234 --duration-hours 8 --interval-seconds 3` (thay `1234` bằng PID thật). CSV được flush sau mỗi sample; JSON ghi cấu hình máy, PID/create-time được theo dõi, thời lượng/số mẫu, trạng thái và mean/min/max cho scan time, CPU/RAM monitor và CPU/RAM host. Bỏ `--target-pid` để đo collector CLI thay vì giao diện monitor. Kèm hồ sơ VM và phân tích số liệu.
4. Trong desktop chạy **Capture ProcMon 60 giây…**, gắn trace với phiên thử nghiệm, xem CSV và lưu ảnh minh chứng. Chưa capture trực tiếp API/system call; ProcMon ghi event hệ thống thay cho API call-level trace.
5. Nếu cần capture API/system call hoặc theo dõi memory instruction, bổ sung telemetry chuyên dụng. Không xem Event ID 8/10/25 hoặc vùng executable riêng tư là bằng chứng injection.

## Mã nguồn chính

| File/thư mục | Vai trò |
|---|---|
| apps/web/server.py, apps/web/static/ | Web dashboard local, API snapshot và xuất CSV hiệu năng. |
| apps/desktop/app.py | Ứng dụng desktop giám sát live/demo. |
| process_guard/collector.py | Thu thập thông tin tiến trình và rolling runtime/I/O stats. |
| process_guard/features.py, rules.py | Trích xuất feature và rule triage. |
| process_guard/sysmon.py, scheduled_tasks.py, signature.py | Đọc Sysmon, tra action Scheduled Task và kiểm tra chữ ký/hash. |
| process_guard/memory_inspection.py, procmon.py, procmon_capture.py | Truy vấn metadata vùng executable read-only trên Windows; capture ProcMon giới hạn và nhập/tổng hợp CSV. |
| process_guard/virustotal.py, quarantine.py | Lookup reputation theo SHA-256 và cách ly/khôi phục file có xác minh hash. |
| process_guard/ml.py, pid_ml.py, benchmark.py | Pipeline model telemetry/PID và đo latency estimator. |
| process_guard/cardiff.py | Tiền xử lý dữ liệu Cardiff. |
| process_guard/demo.py, scripts/run_demo.py | Fixture và demo an toàn. |
| scripts/eda.py, train_models.py, train_cardiff_models.py | EDA và huấn luyện Cardiff. |
| scripts/train_pid_models.py | Huấn luyện từ quan sát PID có nhãn/nguồn và xuất metric, confusion matrix, audit nhãn. |
| process_guard/cardiff_deep.py | Mô hình PyTorch: GRU theo bài báo, LiteSE-BiLSTM-Attn, các biến thể ablation; huấn luyện có early stopping và trích embedding cho Hybrid. |
| scripts/cardiff_paper_benchmark.py, tune_cardiff_best.py, plot_cardiff_paper.py | Tái lập thí nghiệm bài báo trên Cardiff, tinh chỉnh mô hình đề xuất, bảng/biểu đồ đối chiếu. |
| process_guard/pid_sequence.py | Tạo cửa sổ k snapshot theo từng instance tiến trình (PID + create_time). |
| scripts/pid_model_benchmark.py, plot_pid_models.py | So sánh 7 mô hình trên dữ liệu PID, tinh chỉnh theo kiểm định chéo nhóm, leave-one-out, chấm phiên đánh giá mới. |
| scripts/run_pid_lab_experiment.py, lab/simulations/ | Điều phối phiên thu thập và 5 chương trình C# mô phỏng hành vi vô hại. |
| scripts/evaluate_pid_sessions.py, filter_new_instances.py, pid_leave_one_out.py | Đánh giá rule/ML/kết hợp trên phiên mới và leave-one-executable-out. |
| scripts/safe_behavior_lab.py | Tạo child process tải CPU/I/O giới hạn và loopback; ghi JSON run log, không có payload/injection/persistence. |
| scripts/benchmark_monitor.py | Benchmark collector dài hạn ra CSV + metadata JSON; script chưa được chạy trong VM. |
| notebooks/cardiff_eda_training.ipynb | Notebook EDA/huấn luyện. |
| docs/ARCHITECTURE_AND_THEORY.md | Kiến trúc, cơ sở lý thuyết, mapping ATT&CK và giới hạn kỹ thuật. |
| docs/DATASET_CARDIFF.md | Ghi chú về dataset và paper. |
| docs/requirements/huongdan.txt | Bản yêu cầu đồ án gốc. |

## Tài liệu tham khảo

- [Cardiff Dataset 2](https://doi.org/10.17035/d.2018.0050524986) và [mô tả dữ liệu](https://research-data.cardiff.ac.uk/articles/dataset/Behavioural_machine_activity_for_benign_and_malicious_Win7_64-bit_executables/27052333).
- [Rhode, Burnap, Jones (2018), Early-stage malware prediction using recurrent neural networks](https://doi.org/10.1016/j.cose.2018.05.010).
- [psutil documentation](https://psutil.readthedocs.io/), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Sysinternals Suite](https://learn.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite), [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon).
- [VirusTotal file report API](https://docs.virustotal.com/reference/file-info), [VirusTotal API data-sharing notice](https://docs.virustotal.com/reference/api-search).
- [MITRE ATT&CK](https://attack.mitre.org/), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (chỉ chạy test phù hợp trong VM lab theo quy trình được duyệt).
- [XGBoost scikit-learn interface](https://xgboost.readthedocs.io/en/stable/python/python_intro.html), [LightGBM Python API](https://lightgbm.readthedocs.io/en/stable/Python-API.html).
- [scikit-learn outlier detection](https://scikit-learn.org/stable/modules/outlier_detection.html).
