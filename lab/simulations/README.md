# Kịch bản mô phỏng hành vi mã độc (an toàn)

Các chương trình .NET nhỏ trong thư mục này **không phải mã độc**. Mỗi chương trình chỉ tái tạo
*dấu hiệu runtime* của một kỹ thuật tấn công để ProcessGuard có tiến trình mô phỏng (nhãn 1) mà
không gây hại:

| Thư mục | Executable triển khai | Mô phỏng (MITRE ATT&CK) | Hành vi thật sự |
|---|---|---|---|
| `beacon` | `%TEMP%\pg_lab\svch0st\svch0st.exe` | T1036.005 Masquerading + T1071 C2 beaconing | Tên giả `svchost`, chạy từ Temp, mở 16 kết nối TCP **chỉ tới 127.0.0.1** và gửi beacon mỗi giây |
| `miner` | `%APPDATA%\pg_lab\winupdater\winupdater.exe` | T1496 Resource Hijacking | Băm SHA-256 liên tục trên một nửa số lõi CPU |
| `locker` | `%TEMP%\pg_lab\invoice_viewer\invoice_viewer.exe` | T1486 Data Encrypted for Impact | Tạo 120 file giả trong thư mục tạm riêng, XOR rồi ghi đè `.locked` lặp lại; xóa toàn bộ khi kết thúc |
| `dropper` | `%LOCALAPPDATA%\pg_lab\expl0rer\expl0rer.exe` | T1036.005 + T1106 tạo nhiều tiến trình con | Tên giả `explorer`, sinh 6 tiến trình con `cmd.exe /c ping 127.0.0.1` |
| `officeshell` | `%TEMP%\pg_lab\office\WINWORD.EXE` | T1204/T1059.001 Office spawn PowerShell | Tên giả Word, chạy `powershell.exe -EncodedCommand` beacon loopback |

Ràng buộc chung: thời lượng 10–600 giây, mạng chỉ loopback, không sửa Registry/Scheduled Task, không
injection, không tải/thực thi payload. Script `scripts/run_pid_lab_experiment.py` build, triển khai,
chạy, thu thập dữ liệu và dọn dẹp toàn bộ thư mục `pg_lab`.
