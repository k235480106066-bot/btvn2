# BÀI TẬP LỚN MÔN HỌC: AN TOÀN VÀ BẢO MẬT THÔNG TIN

## 👤 THÔNG TIN SINH VIÊN
- **Họ và tên:** **Mông Chí Thành**
- **MSSV:** **k235480106066**
- **Môn học:** **AN TOÀN BẢO MẬT THÔNG TIN**
- **Repository:** [https://github.com/k235480106066-bot/btvn2](https://github.com/k235480106066-bot/btvn2)

---

## 📖 GIỚI THIỆU DỰ ÁN
Dự án thực hiện đầy đủ các yêu cầu thực nghiệm mật mã học theo đề bài:
1. **Bài 1: Mã hóa đối xứng AES**:
   - Sinh khóa AES 128/192/256-bit, xuất khóa ra file `.key`, import khóa từ file.
   - Mã hóa và giải mã đoạn văn bản (hiển thị IV, Ciphertext Base64).
   - Mã hóa và giải mã file dung lượng lớn (hàng trăm MB - GB), đo thời gian, tốc độ thông lượng (Throughput MB/s).
   - Đối chiếu theo bytes (Compare Bytes): so sánh mã băm SHA-256 và từng byte nhị phân của file nguồn vs file giải mã.
2. **Bài 2: Mã hóa bất đối xứng RSA**:
   - Sinh cặp khóa RSA 2048-bit, xuất cặp khóa ra file `.pem` (SPKI / PKCS#8).
   - **View PEM**: Bóc tách chi tiết từng byte ASN.1 DER (Tag, Length, Offset, Value) và ý nghĩa toán học của các trường: $n, e, d, p, q, dp, dq, qinv$.
   - Mã hóa mảng byte giới hạn $\le 190$ bytes (mã hóa khóa AES 256-bit 32 bytes) $\rightarrow$ Lưu file Base64 $\rightarrow$ Giải mã và đối chiếu tính toàn vẹn 100%.
   - **Bài 2.7: Benchmark tốc độ**: So sánh Public Key ($e = 65537$ bé) vs Private Key ($d \approx 2048\text{ bit}$ to đùng), giải thích toán học thuật toán Square-and-Multiply.
   - **Bài 2.8: Băm SHA-256 & Hiệu ứng thác lũ (Avalanche Effect)**: Ma trận 256 ô bit, chứng minh khi đổi 1 bit đầu vào có $\approx 50\%$ bit đầu ra bị đảo lật (chuẩn SAC).
   - **Bài 2.9: Chữ ký số**: Đề xuất và demo phương pháp **RSA-PSS** (với Random Salt 32 bytes) và **Nonce/Timestamp Envelope** giúp cùng 1 dữ liệu, cùng 1 private key sinh ra chữ ký số khác nhau giữa các lần ký nhưng vẫn xác thực hợp lệ 100%.

---

## 🚀 HƯỚNG DẪN CHẠY CHƯƠNG TRÌNH

### 1. Ứng dụng Web (Khuyến nghị)
- **Cách 1:** Nhấp đúp chuột vào file `run_web.bat` trên Windows để tự động mở trình duyệt tại `http://localhost:8080`.
- **Cách 2:** Chạy lệnh:
  ```bash
  python server.py
  ```
- **Cách 3:** Mở trực tiếp file `index.html` bằng bất kỳ trình duyệt nào (Chrome, Edge, Firefox).

### 2. Ứng dụng Console .NET 10.0
- Mở terminal tại thư mục dự án và chạy:
  ```bash
  cd dotnet_app
  dotnet run
  ```

---

## 📂 CẤU TRÚC THƯ MỤC
```
├── index.html              # Giao diện Web App chính (5 Tab thực hành)
├── styles.css              # File định dạng giao diện hiện đại, responsive
├── app.js                  # Điều phối sự kiện và giao diện người dùng
├── crypto-aes.js           # Module xử lý mã hóa đối xứng AES (GCM/CBC)
├── crypto-rsa.js           # Module xử lý mã hóa bất đối xứng RSA
├── crypto-asn1.js          # Module phân tích cú pháp ASN.1 DER của file PEM
├── crypto-benchmark.js     # Module đo lường và đánh giá hiệu năng RSA
├── crypto-sha.js           # Module băm SHA-256 & Hiệu ứng thác lũ
├── crypto-signature.js     # Module chữ ký số RSA-PSS & PKCS#1 v1.5
├── server.py               # Máy chủ Web cục bộ Python
├── run_web.bat             # File khởi chạy nhanh 1-click trên Windows
├── BAO_CAO_BAI_TAP.md      # Báo cáo học thuật chi tiết kèm 5 hình ảnh minh chứng
├── AES_RSA_BAITAP.txt      # Đề bài gốc
├── images/                 # Thư mục chứa 5 ảnh chụp thực nghiệm
│   ├── 1_aes_text.png
│   ├── 2_aes_file.png
│   ├── 3_rsa_pem_asn1.png
│   ├── 4_rsa_benchmark.png
│   └── 5_sha256_avalanche.png
└── dotnet_app/             # Dự án C# .NET 10.0 Console App
    ├── dotnet_app.csproj
    └── Program.cs
```

---
*Bản quyền thuộc về sinh viên: **Mông Chí Thành** - MSSV: **k235480106066**.*
