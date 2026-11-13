# Dashboard ProcessGuard

Giao diện web sử dụng sidebar navy, điểm nhấn xanh, các surface sáng/tối và SVG nội bộ. Bảng tiến trình nằm trước biểu đồ tài nguyên để ưu tiên điều tra. Trang nghiên cứu và nhật ký sử dụng cùng hệ thống màu, khoảng cách và typography.

## Mở giao diện

```powershell
python web_app.py --demo
# Mở http://127.0.0.1:8765
```

`python web_app.py` chạy chế độ live. Chế độ demo dùng các bản ghi tổng hợp; banner, thẻ dữ liệu và file CSV thể hiện rõ nguồn demo. CPU/RAM hệ thống vẫn là tài nguyên host do collector cung cấp.

## Thao tác

- Tìm theo tên, PID, PPID, đường dẫn và command line; dùng Ctrl+K để về trang giám sát và đặt con trỏ vào ô tìm kiếm.
- Lọc tất cả, cần xem xét, CPU cao hoặc có kết nối. Đặt lại khôi phục bộ lọc, tìm kiếm và thứ tự cây.
- Sắp xếp theo cây, điểm tín hiệu, CPU, RAM hoặc tên. Khi sắp xếp/phân lọc, thụt lề cây được bỏ để tránh thể hiện sai quan hệ cha-con.
- Xuất CSV chỉ lấy các dòng đang hiển thị và giữ thứ tự sắp xếp, chế độ dữ liệu, timestamp, điểm rule/ML và thông tin tiến trình. Chuỗi có thể bị bảng tính diễn giải thành công thức được thêm dấu nháy bảo vệ.
- Chọn dòng bằng chuột hoặc Enter/Space để mở bảng điều tra; Escape đóng. Bảng có focus trap, phục hồi focus và nền inert khi mở.
- Nút mặt trăng/mặt trời đổi giao diện; lựa chọn lưu trên trình duyệt local.
- Tạm dừng đóng băng cập nhật trình duyệt; collector trên server tiếp tục chạy. Nút làm mới lấy snapshot thủ công.

Ngưỡng màu cần xem xét là 0,65, theo cùng ngưỡng cảnh báo. Điểm tín hiệu phục vụ điều tra; không phải kết luận malware. Lịch sử biểu đồ được xóa khi đổi nguồn dữ liệu để tránh trộn hai chế độ.

## Kiểm tra giao diện

Đã kiểm tra bằng trình duyệt trên dữ liệu demo: sắp xếp giảm dần theo điểm, lọc còn một PID cần xem xét, tìm kiếm không có kết quả và nút xuất bị vô hiệu hóa, mở/đóng bảng chi tiết bằng bàn phím, đổi sáng/tối, trang nghiên cứu với 9 dòng model và xuất CSV một dòng sau khi tìm Chrome. Đã kiểm tra responsive ở viewport 390 × 844, không có tràn ngang toàn trang; bảng tiến trình cho phép cuộn ngang riêng. Ảnh giao diện demo dùng để kiểm tra thiết kế, không thay thế ảnh thử nghiệm PID trong VM.

Tệp giao diện: `apps/web/static/index.html`, `styles.css`, `app.js`. Dashboard tiếp tục dùng API local hiện có và không cần tải font/icon từ bên ngoài. Ứng dụng Tkinter desktop chưa được thay đổi trong lượt thiết kế web này.
