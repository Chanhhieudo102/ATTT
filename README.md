# ProcessGuard — giám sát tiến trình và nhận diện hành vi đáng ngờ

Đồ án **Ứng dụng học máy trong nhận diện các tiến trình mã độc đang hoạt động trong máy**. Dự án hiện có ứng dụng desktop và dashboard web để xem tiến trình, cây cha-con, tín hiệu rule-based và cảnh báo. Phần nghiên cứu ML dùng dataset telemetry Cardiff ở cấp **lần chạy executable**; phần chấm điểm PID live là luồng riêng, chỉ dùng được sau khi nhóm thu thập và gán nhãn dữ liệu tiến trình trong lab.

> **Phạm vi kết quả:** số liệu Cardiff bên dưới là đánh giá offline trên split test của dataset. Số liệu synthetic chỉ dùng kiểm tra demo. Chưa có bộ dữ liệu PID malware/simulation được nhóm thu thập và xác minh để kết luận hiệu năng phát hiện trên máy thật.

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
| 3. Dataset và feature engineering | **Đã làm một phần** | Có pipeline tải/EDA/huấn luyện Cardiff; desktop lưu PID observations kèm nguồn gán nhãn do người vận hành nhập, fixture synthetic và safe workload giới hạn có JSON run log. Feature PID gồm nhóm đường dẫn, signature/autorun/Scheduled Task/Sysmon khi đã kiểm tra, runtime rolling stats, I/O, network và parent/process tree. ProcMon CSV được tổng hợp để đối chiếu, chưa đưa vào model. **Chưa có dataset PID lab thật đã thu thập, nhãn được nhóm xác minh hoặc metric live**; provenance nhập tay không phải ground-truth độc lập. |
| 4. Huấn luyện và so sánh ML | **Đã làm cho Cardiff** | Đã đánh giá Decision Tree, Random Forest, Extra Trees và Isolation Forest; có metric, confusion matrix, feature importance và đánh giá cửa sổ 1–5 giây. Có pipeline riêng cho PID, nhưng cần dữ liệu thật do nhóm thu thập. Script GRU theo hướng paper là tùy chọn, chưa có kết quả GRU được báo cáo ở đây. |
| 5. Tích hợp và kiểm thử hệ thống | **Đã làm một phần** | Dashboard web và desktop chạy live/demo; có nút tra cứu SHA-256 VirusTotal (không upload file), cách ly file có xác minh hash và khôi phục, kèm xác nhận người dùng. Rule và PID model lab được tích hợp vào chấm điểm live; desktop xác nhận trước khi kết thúc PID. Model Cardiff chỉ phục vụ nghiên cứu telemetry, **không** chấm từng PID. Đã có code cho safe lab JSON evidence, capture ProcMon và benchmark dài hạn; chưa chạy trong VM, chưa có ảnh chụp/metric/false-positive thực nghiệm hoặc xác nhận Atomic Red Team. |

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

### GRU theo paper

Có mã tùy chọn để thử mô hình GRU và notebook, nhưng kết quả GRU chưa được đưa vào bảng trên. Khi cài PyTorch:

    python -m pip install -r requirements-rnn.txt
    python scripts/train_cardiff_gru.py --seconds 5

Đây là triển khai lại theo mô tả paper, không phải mã chính thức của tác giả. Chỉ thêm kết quả GRU vào báo cáo sau khi chạy được trên dataset và lưu metric/artifact tương ứng.

## Giám sát PID và dữ liệu nhóm tự thu thập

Chương trình lưu quan sát tiến trình live với nhãn benign hoặc simulated malicious và bắt buộc nhập `label_source` (mã VM lab/kịch bản/log/căn cứ), PID, executable, thời điểm và `create_time`. Nguồn nhập tay giúp truy vết nhưng không phải chứng thực ground-truth độc lập. Nhóm cần xác minh hành vi trong VM trước khi gán nhãn; không suy ra nhãn chỉ từ tên file hay điểm rule. Dataset Cardiff không thể thay thế bước này.

Quy trình thu thập trong desktop: chạy `python main.py` trong VM lab, chọn tiến trình, tùy chọn kiểm tra chữ ký/hash/Run keys/Scheduled Tasks và Sysmon, rồi lưu quan sát benign hoặc simulated malicious kèm nguồn gán nhãn. Collector lấy rolling average/peak từ tối đa 5 lần quét gần nhất; lưu nhiều snapshot khi kịch bản đang chạy để ghi nhận diễn biến. Safe workload hiện tại dùng Python child process nên một executable path không đủ cho grouped split; cần executable riêng đã xác minh cho **mỗi lớp** hoặc thêm tình huống/ứng dụng khác. Không sao chép cùng binary sang nhiều đường dẫn để giả tạo tính độc lập. Chỉ gán nhãn simulated malicious cho tiến trình thuộc kịch bản mô phỏng đã xác minh; workload safe không phải malware hay injection.

Sau khi có `data/observations/collected_samples.csv` đủ dữ liệu, chạy:

    python scripts/train_pid_models.py

Pipeline PID yêu cầu cả hai nhãn, `label_source` không rỗng và tối thiểu hai executable path khác nhau mỗi nhãn; chia train/test theo process_path để tránh cùng executable lọt vào hai phía. Pipeline so sánh Decision Tree, Random Forest, Extra Trees, Isolation Forest, xuất Accuracy/Precision/Recall/F1/FPR, confusion matrix, feature importance, `label_source_audit.csv` và `dataset_summary.json` vào `artifacts/reports/pid_live/`; model vào `artifacts/models/pid_live/`. Model chỉ có ý nghĩa tương ứng với chất lượng nhãn/độ đa dạng tập thu thập. CSV cũ cần bổ sung nguồn nhãn hoặc thu thập lại; thiếu các cột feature mới thì cũng cần thu thập lại.

**Trạng thái hiện tại:** chức năng thu thập và pipeline đã có, nhưng chưa có metric PID lab nào được báo cáo ở README vì chưa có dataset PID nhóm xác minh. Không dùng metric Cardiff hay synthetic để thay thế kết quả đó.

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

## Các bước còn lại để hoàn thiện đồ án

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
