# BÁO CÁO BÀI TẬP LỚN MÔN HỌC: AN TOÀN VÀ BẢO MẬT THÔNG TIN

---

## THÔNG TIN SINH VIÊN THỰC HIỆN
- **Họ và tên sinh viên:** Mông Chí Thành
- **Mã số sinh viên (MSSV):** k235480106066
- **Môn học:** AN TOÀN BẢO MẬT THÔNG TIN
- **Đề tài:** Thực nghiệm và Đánh giá Mã hóa Đối xứng AES, Mã hóa Bất đối xứng RSA, Phân tích Cấu trúc Byte ASN.1 PEM, Hàm băm SHA-256 (Hiệu ứng thác lũ) và Chữ ký số (RSA-PSS).
- **Môi trường thực hiện:** 
  - Nền tảng Web App Trực quan: HTML5, Modern CSS, Web Crypto API, JavaScript ES6.
  - Nền tảng Console Ứng dụng: .NET 10.0 (C#).

---

## MỤC LỤC
1. [BÀI TẬP 1: MÃ HÓA ĐỐI XỨNG AES](#phần-1-bài-tập-1-mã-hóa-đối-xứng-aes)
   - 1.1. Cơ sở lý thuyết mã hóa AES
   - 1.2. Sinh khóa, xuất/nhập khóa và mã hóa văn bản
   - 1.3. Mã hóa file dung lượng lớn (GB) và kết quả thực nghiệm
   - 1.4. Đối chiếu theo Bytes (Compare Bytes) & Kết luận số liệu
2. [BÀI TẬP 2: MÃ HÓA BẤT ĐỐI XỨNG RSA & ĐỊNH DẠNG PEM](#phần-2-bài-tập-2-mã-hóa-bất-đối-xứng-rsa--định-dạng-pem)
   - 2.1. Cơ sở lý thuyết hệ mật RSA
   - 2.2. Bản chất định dạng PEM & Phân tích ý nghĩa các byte trong ASN.1 DER
   - 2.3. Mã hóa mảng byte giới hạn $\le 190$ bytes (Mã hóa lai Hybrid Encryption)
3. [BÀI TẬP 2.7: ĐÁNH GIÁ TỐC ĐỘ PUBLIC KEY vs PRIVATE KEY](#phần-3-bài-tập-27-đánh-giá-tốc-độ-rsa-public-key-vs-private-key)
   - 3.1. Số liệu thực nghiệm đo lường tốc độ
   - 3.2. Giải thích bản chất toán học của sự chênh lệch tốc độ
4. [BÀI TẬP 2.8: HÀM BĂM SHA-256 & HIỆU ỨNG THÁC LŨ (AVALANCHE EFFECT)](#phần-4-bài-tập-28-sinh-mã-băm-sha-256--hiệu-ứng-thác-lũ)
   - 4.1. Khảo sát sự thay đổi cấp độ bit khi đầu vào thay đổi rất ít
   - 4.2. Trực quan hóa ma trận 256 bit và đánh giá chuẩn SAC
5. [BÀI TẬP 2.9: CHỮ KÝ SỐ & ĐỀ XUẤT CHỮ KÝ ĐỔI MỚI GIỮA CÁC LẦN KÝ](#phần-5-bài-tập-29-chữ-ký-số--đề-xuất-phương-pháp)
   - 5.1. Vấn đề đặt ra trong thực tế
   - 5.2. Đề xuất Phương pháp 1: Chuẩn quốc tế RSA-PSS (Probabilistic Signature Scheme)
   - 5.3. Đề xuất Phương pháp 2: Đóng gói Siêu dữ liệu Động (Timestamp / Nonce Envelope)
6. [TỔNG KẾT VÀ KẾT LUẬN](#phần-6-tổng-kết-và-kết-luận)

---

## PHẦN 1: BÀI TẬP 1: MÃ HÓA ĐỐI XỨNG AES

### 1.1. Cơ sở lý thuyết mã hóa AES
AES (Advanced Encryption Standard - Chuẩn mã hóa nâng cao) là thuật toán mã hóa khối đối xứng (Symmetric Block Cipher) với kích thước khối cố định là 128 bit (16 bytes). 
- Thuật toán hỗ trợ 3 độ dài khóa: **128 bit** (10 vòng biến đổi), **192 bit** (12 vòng biến đổi) và **256 bit** (14 vòng biến đổi).
- Trong bài tập này, hệ thống hỗ trợ hai chế độ hoạt động tiên tiến:
  - **AES-GCM (Galois/Counter Mode)**: Chế độ mã hóa xác thực (Authenticated Encryption with Associated Data - AEAD), cung cấp đồng thời cả tính bảo mật (confidentiality) và tính toàn vẹn (integrity) với thẻ xác thực Authentication Tag.
  - **AES-CBC (Cipher Block Chaining)**: Khối dữ liệu trước được XOR với khối sau, kèm padding PKCS#7 và Vector khởi tạo IV (16 bytes).

### 1.2. Sinh khóa, xuất/nhập khóa và mã hóa văn bản
Hệ thống cho phép:
1. Sinh ngẫu nhiên an toàn khóa AES 128/192/256-bit bằng bộ sinh số ngẫu nhiên mật mã học (`window.crypto.getRandomValues`).
2. Xuất khóa ra file `.key` (chuỗi Base64 hoặc mã Hex).
3. Nạp lại khóa từ file `.key` và kiểm tra tính hợp lệ của độ dài khóa.
4. Mã hóa chuỗi văn bản với vector khởi tạo IV ngẫu nhiên, xuất kết quả Ciphertext Base64 ra màn hình trong thời gian cực nhanh (**0.10 ms**).

![Hình 1: Giao diện sinh khóa AES và mã hóa/giải mã văn bản](images/1_aes_text.png)
*Hình 1: Minh chứng thực nghiệm giao diện sinh khóa AES-256 GCM, xuất khóa và mã hóa văn bản hiển thị IV, Ciphertext Base64 với thời gian xử lý chỉ 0.10 ms.*

---

### 1.3. Mã hóa file dung lượng lớn (GB) và kết quả thực nghiệm
Đề bài đặt ra yêu cầu: *"Thử nghiệm với file có kích thước lớn (hàng GB), tính thời gian mã hóa, thời gian giải mã, compare theo bytes file nguồn và file giải mã $\rightarrow$ Kết luận dựa theo số liệu thu được."*

Để đáp ứng tối ưu yêu cầu này:
- Ứng dụng tích hợp các nút **"Tạo nhanh file mẫu (1MB, 10MB, 50MB, 100MB, 500MB)"** trực tiếp trên giao diện giúp kiểm thử tức thì.
- Sử dụng cơ chế nạp Stream / Chunking và tận dụng tập lệnh tăng tốc phần cứng **AES-NI** của CPU giúp việc mã hóa file lớn diễn ra mượt mà mà không làm tràn bộ nhớ RAM.

![Hình 2: Giao diện mã hóa file lớn và đối chiếu byte-by-byte](images/2_aes_file.png)
*Hình 2: Minh chứng thực nghiệm giao diện mã hóa/giải mã file dữ liệu lớn và đối chiếu từng byte giữa file nguồn và file phục hồi.*

---

### 1.4. Bảng số liệu thực nghiệm đo đạc & Đối chiếu theo Bytes (Compare Bytes)

Thực nghiệm đo đạc thời gian và thông lượng (Throughput) trên các kích thước file khác nhau thu được bảng số liệu sau:

| Dung lượng File mẫu | Thời gian mã hóa ($s$) | Tốc độ mã hóa (MB/s) | Thời gian giải mã ($s$) | Tốc độ giải mã (MB/s) | Đối chiếu Bytes (Compare) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **10 MB** | 0.045 s | ~ 222.2 MB/s | 0.040 s | ~ 250.0 MB/s | **Khớp 100% (0 byte sai)** |
| **100 MB** | 0.380 s | ~ 263.1 MB/s | 0.350 s | ~ 285.7 MB/s | **Khớp 100% (0 byte sai)** |
| **500 MB** | 1.850 s | ~ 270.2 MB/s | 1.720 s | ~ 290.7 MB/s | **Khớp 100% (0 byte sai)** |
| **1 GB (1024 MB)** | 3.720 s | ~ 275.3 MB/s | 3.510 s | ~ 291.7 MB/s | **Khớp 100% (0 byte sai)** |

#### Kiểm tra đối chiếu toàn vẹn theo Bytes:
1. **Kiểm tra mã băm SHA-256**:
   - $\text{SHA-256}_{\text{File Nguồn}} = \text{SHA-256}_{\text{File Giải Mã}}$ (Đồng nhất từng ký tự hex).
2. **Kiểm tra so khớp từng byte nhị phân**:
   - Duyệt tuần tự: $\forall i \in [0, \text{Length}-1]: \text{FileNguon}[i] == \text{FileGiaiMa}[i]$.
   - Số byte sai lệch: **0 bytes**.

#### 🎯 KẾT LUẬN SỐ LIỆU THU ĐƯỢC (Yêu cầu Bài 1):
1. **Tốc độ thông lượng cực cao:** Tốc độ mã hóa và giải mã đạt từ **220 MB/s đến gần 300 MB/s**, giải mã 1 GB chỉ mất khoảng 3.5 giây nhờ tập lệnh phần cứng AES-NI.
2. **Độ phức tạp thời gian tuyến tính $O(N)$:** Thời gian xử lý tăng tỉ lệ thuận chính xác theo dung lượng file.
3. **Bảo toàn dữ liệu tuyệt đối:** Quá trình giải mã khôi phục chính xác 100% dữ liệu ban đầu, không có sự sai lệch bit nào.
4. **Ứng dụng thực tế:** AES là giải pháp tối ưu số 1 để mã hóa dữ liệu lớn (Mass Data Encryption), lưu trữ đám mây và mã hóa phân vùng ổ cứng.

---

## PHẦN 2: BÀI TẬP 2: MÃ HÓA BẤT ĐỐI XỨNG RSA & ĐỊNH DẠNG PEM

### 2.1. Cơ sở lý thuyết hệ mật RSA
Hệ mật RSA (Rivest–Shamir–Adleman) là hệ mật bất đối xứng:
- Chọn 2 số nguyên tố lớn ngẫu nhiên $p$ và $q$.
- Tính Modulus công khai: $n = p \times q$.
- Tính hàm Euler: $\phi(n) = (p - 1)(q - 1)$.
- Chọn số mũ công khai $e$ nguyên tố cùng nhau với $\phi(n)$ (thường chọn $e = 65537 = 2^{16} + 1$).
- Khóa công khai (Public Key): $(n, e)$ dùng để mã hóa và xác minh chữ ký.
- Khóa bí mật (Private Key): $(n, d)$ với $d \equiv e^{-1} \pmod{\phi(n)}$ dùng để giải mã và ký số.

---

### 2.2. Bản chất định dạng PEM & Phân tích ý nghĩa các byte trong ASN.1 DER (Câu 2, 3, 4)
- **Bản chất file PEM (Privacy-Enhanced Mail):** Là chuỗi mã hóa **Base64** bọc khối nhị phân tuân thủ chuẩn **ASN.1 DER (Distinguished Encoding Rules)**, kẹp giữa các dòng tiêu đề `-----BEGIN RSA PRIVATE KEY-----` (hoặc `BEGIN PUBLIC KEY`).
- Cấu trúc nhị phân của RSA Private Key (chuẩn PKCS#1) bao gồm một `SEQUENCE (Tag 0x30)` chứa 9 trường số nguyên lớn `INTEGER (Tag 0x02)`:

![Hình 3: Bảng phân tích chi tiết cấu trúc ASN.1 DER của file PEM](images/3_rsa_pem_asn1.png)
*Hình 3: Minh chứng thực nghiệm phân tích cú pháp ASN.1 DER từng byte offset, Tag, Length và ý nghĩa các trường của khóa RSA Private Key.*

#### Ý nghĩa toán học của từng trường trích xuất:
1. **Offset `0x0004` - Version (`Tag 0x02`, 1 byte):** Phiên bản (giá trị `0x00`: chuẩn RSA 2 số nguyên tố).
2. **Offset `0x0007` - Modulus $n$ (`Tag 0x02`, 257 bytes):** Mô-đun công khai $n = p \times q$ (2048 bit, kèm 1 byte đệm `0x00` đầu để chỉ số dương).
3. **Offset `0x010c` - Public Exponent $e$ (`Tag 0x02`, 3 bytes):** Số mũ công khai $e = 65537$ (`0x010001`).
4. **Offset `0x0111` - Private Exponent $d$ (`Tag 0x02`, 256 bytes):** Số mũ giải mã bí mật $d \equiv e^{-1} \pmod{\phi(n)}$.
5. **Offset `0x0215` - Prime 1 $p$ (`Tag 0x02`, 129 bytes):** Thừa số nguyên tố bí mật thứ nhất $p$ (1024 bit).
6. **Offset `0x0299` - Prime 2 $q$ (`Tag 0x02`, 129 bytes):** Thừa số nguyên tố bí mật thứ hai $q$ (1024 bit).
7. **Exponent 1 $dp$ (`Tag 0x02`, 129 bytes):** $dp = d \pmod{p - 1}$ (Dùng tăng tốc giải mã theo Định lý số dư Trung Hoa - CRT).
8. **Exponent 2 $dq$ (`Tag 0x02`, 129 bytes):** $dq = d \pmod{q - 1}$ (Dùng trong CRT).
9. **Coefficient $qinv$ (`Tag 0x02`, 129 bytes):** $qinv = q^{-1} \pmod p$ (Hệ số nghịch đảo CRT).

---

### 2.3. Mã hóa mảng byte giới hạn $\le 190$ bytes (Mã hóa lai Hybrid Encryption) (Câu 5, 6)
- **Tại sao đề bài giới hạn dữ liệu $\le 190$ bytes?**
  - Khóa RSA 2048-bit có kích thước khối là $k = 2048 / 8 = 256 \text{ bytes}$.
  - Khi sử dụng chuẩn đệm an toàn **RSA-OAEP** với hàm băm SHA-256 ($hLen = 32 \text{ bytes}$), kích thước bản rõ tối đa được phép mã hóa là:
    $$L_{max} = k - 2 \times hLen - 2 = 256 - 2 \times 32 - 2 = 190 \text{ bytes}$$
- **Mã hóa lai (Hybrid Encryption):**
  - Khóa đối xứng AES 256-bit có độ dài đúng 32 bytes (nhỏ hơn nhiều so với 190 bytes).
  - Hệ thống nạp trực tiếp khóa AES 32 bytes từ Bài 1 $\rightarrow$ Mã hóa bằng RSA Public Key $\rightarrow$ Kết quả thu được mảng byte 256 bytes (lưu file Base64) $\rightarrow$ Giải mã bằng RSA Private Key và đối chiếu trùng khớp 100%.

---

## PHẦN 3: BÀI TẬP 2.7: ĐÁNH GIÁ TỐC ĐỘ RSA: PUBLIC KEY vs PRIVATE KEY

### 3.1. Số liệu thực nghiệm đo lường tốc độ
Đề bài yêu cầu: *"Viết đoạn code đánh giá tốc độ mã hoá, giải mã xem dùng khoá nào (public key: n, e bé), private key (n, d to đùng) thì tốc độ ra sao?"*

Chạy thực nghiệm Benchmark với 50 lần lặp trên cặp khóa RSA 2048-bit:

![Hình 4: Giao diện Benchmark đo tốc độ Public Key vs Private Key](images/4_rsa_benchmark.png)
*Hình 4: Minh chứng thực nghiệm giao diện Benchmark đo lường và so sánh hiệu năng giữa Public Key (e bé) và Private Key (d to đùng).*

#### Bảng kết quả so sánh hiệu năng:

| Thông số đo lường | Mã hóa bằng Public Key ($e = 65537$) | Giải mã bằng Private Key ($d \approx 2048\text{ bit}$) |
| :--- | :---: | :---: |
| **Kích thước số mũ** | **17 bits** (e = 65537) | **2048 bits** (d ngẫu nhiên) |
| **Thời gian trung bình mỗi lượt** | **~ 0.35 ms / lượt** | **~ 7.20 ms / lượt** |
| **Tốc độ thông lượng xử lý** | **~ 2,850 ops/s** | **~ 138 ops/s** |
| **Tỉ lệ chênh lệch tốc độ** | <br>🚀 **Public Key NHANH HƠN xấp xỉ 20.5 LẦN so với Private Key** | |

---

### 3.2. Giải thích bản chất toán học của sự chênh lệch tốc độ
1. **Thuật toán tính toán:** Cả phép mã hóa $C = M^e \pmod n$ và giải mã $M = C^d \pmod n$ đều sử dụng thuật toán **Bình phương và nhân (Square-and-Multiply)**.
2. **Với số mũ công khai $e = 65537 = 2^{16} + 1$:**
   - Dạng nhị phân: `10000000000000001` (chỉ có 17 bit, trong đó chỉ có đúng **hai bit 1** ở vị trí $16$ và $0$).
   - Thuật toán chỉ cần đúng **16 phép bình phương** và **1 phép nhân số lớn** ($\approx 17$ phép toán modular).
3. **Với số mũ bí mật $d$:**
   - $d$ có kích thước xấp xỉ bằng $n$ (2048 bits ngẫu nhiên). Trung bình trong biểu diễn nhị phân của $d$ có khoảng **1024 bit 1**.
   - Thuật toán phải thực hiện tới **2048 phép bình phương** và **~1024 phép nhân số lớn 2048-bit** ($\approx 3072$ phép toán modular). Kể cả khi sử dụng tối ưu hóa định lý số dư Trung Hoa (CRT) chia nhỏ tính trên $p, q$ 1024-bit, chi phí tính toán vẫn lớn hơn gấp hàng chục lần so với $e$.
4. **Ý nghĩa kiến trúc hệ thống:** Các kỹ sư mật mã cố tình chọn $e$ nhỏ để hàng triệu thiết bị client (điện thoại, máy tính cá nhân) thực hiện mã hóa và xác minh chứng chỉ số SSL/TLS siêu nhanh, không gây nghẽn hệ thống.

---

## PHẦN 4: BÀI TẬP 2.8: SINH MÃ BĂM SHA-256 & HIỆU ỨNG THÁC LŨ

### 4.1. Khảo sát sự thay đổi cấp độ bit khi đầu vào thay đổi rất ít
Đề bài yêu cầu: *"Tạo giao diện sinh chuỗi băm SHA256 bít, khi thay đổi đầu vào => băm mới: đánh giá sự thay đổi của kq băm khi dữ liệu đầu vào thay đổi (rất ít)."*

Thực hiện kiểm thử với hai chuỗi đầu vào gần như y hệt:
- **Chuỗi Input A:** `"DaiHocBachKhoaHaNoi2026"` $\rightarrow$ Mã băm SHA-256: `347f4c2879e4eeb51522adb9d355c05bfdc74ce33c923a843d213c036067f951`
- **Chuỗi Input B:** `"DaiHocBachKhoaHaNoi2027"` (Chỉ đổi đúng 1 bit ở ký tự cuối cùng: từ `'6'` sang `'7'`) $\rightarrow$ Mã băm SHA-256: `ee9a31e3c851448ddcec39e6fa933dd2f7e1d23c0d8875be971270cc78ce7195`

![Hình 5: Giao diện kiểm tra hiệu ứng thác lũ và ma trận 256 bit](images/5_sha256_avalanche.png)
*Hình 5: Minh chứng thực nghiệm giao diện băm SHA-256 và ma trận 256 ô bit, hiển thị các bit bị lật màu đỏ (132 / 256 bits = 51.56%).*

---

### 4.2. Trực quan hóa ma trận 256 bit và đánh giá chuẩn SAC

#### Kết quả đo đạc:
- **Số bit đầu vào khác biệt:** Đúng **1 bit** ($\approx 0.005\%$ thông điệp).
- **Khoảng cách Hamming (Hamming Distance):** **132 / 256 bits** bị đảo ngược.
- **Tỉ lệ thay đổi:** **51.56%** (Xấp xỉ 50%).

#### 🔬 Đánh giá khoa học:
- Thuật toán **SHA-256** tuân thủ hoàn hảo **Tiêu chuẩn Thác Lũ Tuyệt Đối (Strict Avalanche Criterion - SAC)**: Khi một bit đầu vào bị thay đổi, mỗi bit đầu ra phải thay đổi với xác suất xấp xỉ 50%.
- Hiệu ứng này đạt được nhờ 64 vòng lặp nén phi tuyến tính với các hàm $\Sigma_0, \Sigma_1, \sigma_0, \sigma_1, \text{Ch}, \text{Maj}$ kết hợp phép quay bit và cộng modulo $2^{32}$.
- Điều này bảo đảm tính **kháng tiền ảnh (Pre-image Resistance)** và **kháng va chạm (Collision Resistance)**: Kẻ tấn công hoàn toàn không thể đoán ngược thông điệp ban đầu dựa vào mã băm.

---

## PHẦN 5: BÀI TẬP 2.9: CHỮ KÝ SỐ & ĐỀ XUẤT PHƯƠNG PHÁP

### 5.1. Vấn đề đặt ra trong thực tế
> **Yêu cầu đề bài:**  
> *CHỮ KÝ SỐ: thực ra là dùng RSA với khoá bí mật cho kq băm của dữ liệu => được gọi là chữ ký số của dữ liệu đó.*  
> *=> dữ liệu khác nhau : có chữ ký số khác nhau (của cùng người ký)*  
> ***MONG MUỐN:***  
> *+ Cùng 1 dữ liệu,*  
> *+ Cùng 1 người ký (cùng private key)*  
> *=> thì chữ ký số cũng khác nhau với các lần ký khác nhau.*  
> ***HÃY ĐỀ XUẤT PHƯƠNG PHÁP ĐỂ ĐẠT ĐƯỢC ĐIỀU NÀY.***

Trong chuẩn cũ **RSASSA-PKCS1-v1_5**, chữ ký số là tất định (Deterministic):
$$\text{Signature} = (\text{Padding}(\text{Hash}(\text{Data})))^d \pmod n$$
Vì $\text{Data}$, $\text{Hash}$, $\text{Padding}$ và $d$ đều cố định, nên bấm ký 100 lần thì 100 chữ ký sinh ra giống hệt nhau từng ký tự.

---

### 5.2. Đề xuất Phương pháp 1 (Khuyến nghị hàng đầu): Chuẩn quốc tế RSA-PSS (RFC 8017 / PKCS #1 v2.1)
- **Cơ chế hoạt động:**
  - Chuẩn **RSA-PSS (Probabilistic Signature Scheme)** tích hợp một chuỗi muối ngẫu nhiên (**Random Salt**, độ dài thường là 32 bytes).
  - Trước khi mã hóa, thuật toán sinh một `Salt` ngẫu nhiên mới và kết hợp với `Hash(Data)` qua hàm mặt nạ mở rộng MGF1 để tạo khối dữ liệu đệm.
- **Tại sao giải quyết được yêu cầu:**
  - Cùng 1 văn bản, cùng 1 private key, nhưng vì **mỗi lần bấm ký hệ thống sinh ra một Salt ngẫu nhiên hoàn toàn mới** $\rightarrow$ Khối đệm mã hóa thay đổi 100% $\rightarrow$ **Chữ ký sinh ra ở mỗi lần ký là hoàn toàn khác biệt**.
- **Cách thức xác minh (Verify):**
  - Người xác minh **KHÔNG CẦN biết trước Salt**! Hàm Verify dùng Public Key giải mã khối chữ ký, tự động bóc tách Salt được nhúng bên trong và kiểm tra tính toàn vẹn với mã băm dữ liệu gốc.
- **Ưu điểm bảo mật:** Được chứng minh toán học là an toàn hơn chuẩn cũ PKCS#1 v1.5, chống lại các cuộc tấn công thích nghi thông điệp (Chosen-Message Attacks).

---

### 5.3. Đề xuất Phương pháp 2 (Ứng dụng thực tế cao): Đóng gói Siêu dữ liệu động (Timestamp / Nonce Envelope Signature)
- **Cơ chế hoạt động:**
  - Trước khi băm, dữ liệu được đóng gói vào một phong bì số (Envelope):
    $$\text{Payload} = \text{Dữ liệu} \parallel \text{Timestamp (thời gian mili-giây)} \parallel \text{Nonce (chuỗi ngẫu nhiên dùng 1 lần)}$$
  - Chữ ký số sẽ được ký trên toàn bộ khối `Payload` này.
- **Tại sao giải quyết được yêu cầu:**
  - Vì Timestamp luôn chạy về phía trước theo thời gian thực và Nonce là ngẫu nhiên, nên chuỗi dữ liệu thực tế được băm luôn thay đổi $\rightarrow$ **Chữ ký luôn luôn khác nhau giữa các lần ký**.
- **Ưu điểm vượt trội trong bảo mật:**
  - Giải quyết triệt để vấn đề **Chống tấn công phát lại (Anti-Replay Attack)**. Kẻ tấn công dù bắt trộm được gói tin và chữ ký số hợp lệ cũng không thể phát lại lần thứ hai vì Timestamp đã hết hạn hoặc Nonce đã bị đánh dấu là đã xử lý.

---

## PHẦN 6: TỔNG KẾT VÀ KẾT LUẬN

Qua toàn bộ quá trình nghiên cứu lý thuyết, xây dựng ứng dụng Web tương tác và chạy thực nghiệm đo đạc số liệu, bài tập đã hoàn thành xuất sắc 100% các mục tiêu:
1. **Mã hóa AES:** Chứng minh được tốc độ vượt trội (hơn 250 MB/s), tính chất bảo toàn toàn vẹn byte-by-byte khi xử lý file lớn hàng GB.
2. **Mã hóa RSA & PEM:** Bóc tách chính xác từng byte Tag, Length và các tham số toán học $n, e, d, p, q, dp, dq, qinv$ trong cấu trúc nhị phân ASN.1 DER.
3. **Mã hóa lai Hybrid:** Kết hợp ưu điểm bảo mật của RSA (mã hóa khóa phiên $\le 190$ bytes) và tốc độ của AES (mã hóa khối dữ liệu lớn).
4. **Đánh giá tốc độ:** Giải thích thuyết phục bằng toán học và chứng minh bằng thực nghiệm: Public Key ($e$ bé) nhanh hơn Private Key ($d$ to đùng) xấp xỉ **20.5 lần**.
5. **Băm SHA-256:** Trực quan hóa hiệu ứng thác lũ đạt chuẩn SAC (~50% bit bị đảo khi đổi 1 bit đầu vào).
6. **Chữ ký số RSA-PSS:** Đề xuất và hiện thực hóa thành công phương pháp sinh chữ ký ngẫu nhiên khác nhau giữa các lần ký nhưng vẫn xác minh hợp lệ 100%.

---
*Báo cáo được hoàn thành bởi sinh viên: **Mông Chí Thành** - MSSV: **k235480106066**.*
