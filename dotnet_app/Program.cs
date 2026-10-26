using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DotNetCryptoApp
{
    class Program
    {
        static byte[]? currentAesKey = null;
        static byte[]? currentAesIv = null;
        static RSA? currentRsa = null;

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.InputEncoding = Encoding.UTF8;

            while (true)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n==========================================================================");
                Console.WriteLine("    CHUONG TRINH AN TOAN VA BAO MAT THONG TIN - .NET 10.0 CONSOLE APP");
                Console.WriteLine("    Sinh vien: Mông Chí Thành  |  MSSV: k235480106066");
                Console.WriteLine("    Mon hoc:   AN TOÀN BẢO MẬT THÔNG TIN");
                Console.WriteLine("==========================================================================");
                Console.ResetColor();
                Console.WriteLine("--- BAI 1: MA HOA DOI XUNG AES ---");
                Console.WriteLine("  1. Sinh khoa AES (128/192/256-bit)");
                Console.WriteLine("  2. Luu khoa AES ra file (.key)");
                Console.WriteLine("  3. Import khoa AES tu file (.key)");
                Console.WriteLine("  4. Ma hoa & Giai ma doan van ban");
                Console.WriteLine("  5. Ma hoa & Giai ma File (Do thoi gian, MB/s va Compare tung byte)");
                Console.WriteLine("--- BAI 2: MA HOA BAT DOI XUNG RSA & SHA-256 & CHU KY SO ---");
                Console.WriteLine("  6. Sinh cap khoa RSA (2048-bit) & Xuat ra file PEM");
                Console.WriteLine("  7. View PEM: Doc file PEM, phan tich y nghia cac byte, trich xuat n, e, d");
                Console.WriteLine("  8. Ma hoa & Giai ma du lieu <= 190 byte (Ma hoa khoa AES 32 bytes)");
                Console.WriteLine("  9. Danh gia toc do: Public Key (e be) vs Private Key (d to dung)");
                Console.WriteLine(" 10. Sinh ma bam SHA-256 & Danh gia Hieu ung thac lu (Avalanche Effect)");
                Console.WriteLine(" 11. Chu ky so: De xuat & Demo chu ky khac nhau giua cac lan ky (RSA-PSS)");
                Console.WriteLine("  0. Thoat chuong trinh");
                Console.Write("\nChon chuc nang (0-11): ");

                string? choice = Console.ReadLine()?.Trim();
                Console.WriteLine();

                switch (choice)
                {
                    case "1": SinhKhoaAES(); break;
                    case "2": LuuKhoaAES(); break;
                    case "3": ImportKhoaAES(); break;
                    case "4": MaHoaVanBanAES(); break;
                    case "5": MaHoaFileAES(); break;
                    case "6": SinhCapKhoaRSA(); break;
                    case "7": ViewPEMRSA(); break;
                    case "8": MaHoaDuLieuRSA(); break;
                    case "9": BenchmarkRSA(); break;
                    case "10": Sha256AvalancheDemo(); break;
                    case "11": ChuKySoRandomDemo(); break;
                    case "0": return;
                    default:
                        Console.WriteLine("Lua chon khong hop le.");
                        break;
                }
            }
        }

        #region BAI 1: AES
        static void SinhKhoaAES()
        {
            Console.WriteLine("[1] SINH KHOA AES:");
            Console.Write("Chon do dai khoa (128, 192, 256 bits) [Mac dinh: 256]: ");
            string? input = Console.ReadLine()?.Trim();
            int bitLen = (input == "128" || input == "192") ? int.Parse(input) : 256;

            using (Aes aes = Aes.Create())
            {
                aes.KeySize = bitLen;
                aes.GenerateKey();
                aes.GenerateIV();
                currentAesKey = aes.Key;
                currentAesIv = aes.IV;
            }

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"-> Sinh thanh cong khoa AES {bitLen}-bit ({currentAesKey.Length} bytes)!");
            Console.ResetColor();
            Console.WriteLine($"Key (Base64): {Convert.ToBase64String(currentAesKey)}");
            Console.WriteLine($"Key (Hex):    {Convert.ToHexString(currentAesKey)}");
            Console.WriteLine($"IV  (Hex):    {Convert.ToHexString(currentAesIv)}");
        }

        static void LuuKhoaAES()
        {
            if (currentAesKey == null) SinhKhoaAES();
            string path = "aes_key_256bit.key";
            File.WriteAllText(path, Convert.ToBase64String(currentAesKey!));
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"-> Da luu khoa AES ra file: {Path.GetFullPath(path)}");
            Console.ResetColor();
        }

        static void ImportKhoaAES()
        {
            Console.Write("Nhap duong dan file khoa (.key) [Mac dinh: aes_key_256bit.key]: ");
            string path = Console.ReadLine()?.Trim() ?? "";
            if (string.IsNullOrEmpty(path)) path = "aes_key_256bit.key";

            if (!File.Exists(path))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"File khong ton tai: {path}");
                Console.ResetColor();
                return;
            }

            string content = File.ReadAllText(path).Trim();
            currentAesKey = Convert.FromBase64String(content);
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"-> Da import thanh cong khoa AES ({currentAesKey.Length * 8} bits) tu file {path}!");
            Console.ResetColor();
            Console.WriteLine($"Key Hex: {Convert.ToHexString(currentAesKey)}");
        }

        static void MaHoaVanBanAES()
        {
            if (currentAesKey == null) SinhKhoaAES();

            Console.Write("Nhap doan van ban can ma hoa: ");
            string plain = Console.ReadLine() ?? "";
            if (string.IsNullOrEmpty(plain)) plain = "Dai Hoc Bach Khoa Ha Noi - Bai tap An toan Thong tin 2026";

            byte[] plainBytes = Encoding.UTF8.GetBytes(plain);
            byte[] cipherBytes;
            byte[] iv;

            Stopwatch sw = Stopwatch.StartNew();
            using (Aes aes = Aes.Create())
            {
                aes.Key = currentAesKey!;
                aes.GenerateIV();
                iv = aes.IV;
                using var encryptor = aes.CreateEncryptor();
                cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
            }
            sw.Stop();

            Console.WriteLine("\n--- KET QUA MA HOA AES ---");
            Console.WriteLine($"IV (Hex):          {Convert.ToHexString(iv)}");
            Console.WriteLine($"Ciphertext Base64: {Convert.ToBase64String(cipherBytes)}");
            Console.WriteLine($"Thoi gian ma hoa:  {sw.Elapsed.TotalMilliseconds:F3} ms");

            // Thu giai ma luon de kiem tra
            sw.Restart();
            byte[] decryptedBytes;
            using (Aes aes = Aes.Create())
            {
                aes.Key = currentAesKey!;
                aes.IV = iv;
                using var decryptor = aes.CreateDecryptor();
                decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
            }
            sw.Stop();

            string restored = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine($"Van ban giai ma:   {restored}");
            Console.WriteLine($"Thoi gian giai ma: {sw.Elapsed.TotalMilliseconds:F3} ms");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"-> Trung khop: {(plain == restored ? "DUNG 100%" : "SAI")}");
            Console.ResetColor();
        }

        static void MaHoaFileAES()
        {
            if (currentAesKey == null) SinhKhoaAES();

            Console.WriteLine("Chon file kiem thu:");
            Console.WriteLine(" 1. Tu dong sinh file mau dung luong 100 MB de do thoi gian");
            Console.WriteLine(" 2. Tu dong sinh file mau dung luong 500 MB de do thoi gian");
            Console.WriteLine(" 3. Nhap duong dan file co san tren may");
            Console.Write("Lua chon (1-3): ");
            string? opt = Console.ReadLine()?.Trim();

            string srcFile = "test_source_data.bin";
            if (opt == "1" || opt == "2")
            {
                int mb = opt == "1" ? 100 : 500;
                Console.WriteLine($"Dang tao file mau {mb} MB...");
                byte[] chunk = new byte[1024 * 1024]; // 1MB
                new Random().NextBytes(chunk);
                using (var fs = new FileStream(srcFile, FileMode.Create, FileAccess.Write))
                {
                    for (int i = 0; i < mb; i++) fs.Write(chunk, 0, chunk.Length);
                }
                Console.WriteLine($"Da tao file {srcFile} ({mb} MB)!");
            }
            else
            {
                Console.Write("Nhap duong dan file: ");
                string p = Console.ReadLine()?.Trim() ?? "";
                if (File.Exists(p)) srcFile = p;
                else
                {
                    Console.WriteLine("File khong ton tai!");
                    return;
                }
            }

            long fileSize = new FileInfo(srcFile).Length;
            string encFile = srcFile + ".enc";
            string decFile = "restored_" + Path.GetFileName(srcFile);

            Console.WriteLine($"\n[1] Bat dau ma hoa file {srcFile} ({fileSize / (1024.0 * 1024.0):F2} MB)...");
            byte[] iv = new byte[16];
            RandomNumberGenerator.Fill(iv);

            Stopwatch swEnc = Stopwatch.StartNew();
            using (Aes aes = Aes.Create())
            {
                aes.Key = currentAesKey!;
                aes.IV = iv;
                using (var inStream = new FileStream(srcFile, FileMode.Open, FileAccess.Read))
                using (var outStream = new FileStream(encFile, FileMode.Create, FileAccess.Write))
                {
                    outStream.Write(iv, 0, iv.Length); // Ghi 16 byte IV vao dau file
                    using var cryptoStream = new CryptoStream(outStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
                    inStream.CopyTo(cryptoStream);
                }
            }
            swEnc.Stop();
            double encSec = swEnc.Elapsed.TotalSeconds;
            double encSpeed = (fileSize / (1024.0 * 1024.0)) / encSec;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"-> Ma hoa xong trong {encSec:F3}s! Toc do ma hoa: {encSpeed:F2} MB/s");
            Console.ResetColor();

            Console.WriteLine($"\n[2] Bat dau giai ma file {encFile}...");
            Stopwatch swDec = Stopwatch.StartNew();
            using (Aes aes = Aes.Create())
            {
                using (var inStream = new FileStream(encFile, FileMode.Open, FileAccess.Read))
                {
                    byte[] readIv = new byte[16];
                    inStream.ReadExactly(readIv, 0, 16);
                    aes.Key = currentAesKey!;
                    aes.IV = readIv;

                    using (var outStream = new FileStream(decFile, FileMode.Create, FileAccess.Write))
                    using (var cryptoStream = new CryptoStream(inStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                    {
                        cryptoStream.CopyTo(outStream);
                    }
                }
            }
            swDec.Stop();
            double decSec = swDec.Elapsed.TotalSeconds;
            double decSpeed = (fileSize / (1024.0 * 1024.0)) / decSec;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"-> Giai ma xong trong {decSec:F3}s! Toc do giai ma: {decSpeed:F2} MB/s");
            Console.ResetColor();

            Console.WriteLine($"\n[3] TIEN HANH COMPARE THEO BYTES (File nguon vs File giai ma)...");
            byte[] hashOrig, hashDec;
            using (var sha = SHA256.Create())
            {
                using (var fs1 = File.OpenRead(srcFile)) hashOrig = sha.ComputeHash(fs1);
                using (var fs2 = File.OpenRead(decFile)) hashDec = sha.ComputeHash(fs2);
            }

            bool hashMatch = Convert.ToHexString(hashOrig) == Convert.ToHexString(hashDec);
            Console.WriteLine($"SHA-256 File Nguon:   {Convert.ToHexString(hashOrig)}");
            Console.WriteLine($"SHA-256 File Giai Ma: {Convert.ToHexString(hashDec)}");

            bool byteMatch = true;
            using (var fs1 = File.OpenRead(srcFile))
            using (var fs2 = File.OpenRead(decFile))
            {
                if (fs1.Length != fs2.Length) byteMatch = false;
                else
                {
                    int b1, b2;
                    while ((b1 = fs1.ReadByte()) != -1)
                    {
                        b2 = fs2.ReadByte();
                        if (b1 != b2) { byteMatch = false; break; }
                    }
                }
            }

            Console.ForegroundColor = (hashMatch && byteMatch) ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine($"\n-> KET LUAN SO SANH THEO BYTES: {(hashMatch && byteMatch ? "TRUNG KHOP 100% (Khong sai lech byte nao)!" : "KHONG KHOP!")}");
            Console.ResetColor();
            Console.WriteLine("-> Nhan xet: Thuat toan AES ma hoa file lon voi toc do cuc cao (hang tram MB/s) va bao toan nguyen ven du lieu.");
        }
        #endregion

        #region BAI 2: RSA
        static void SinhCapKhoaRSA()
        {
            currentRsa = RSA.Create(2048);
            string pubPem = currentRsa.ExportRSAPublicKeyPem();
            string privPem = currentRsa.ExportRSAPrivateKeyPem();

            File.WriteAllText("rsa_public_key.pem", pubPem);
            File.WriteAllText("rsa_private_key.pem", privPem);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("-> Sinh thanh cong cap khoa RSA 2048-bit va xuat ra file PEM!");
            Console.ResetColor();
            Console.WriteLine("File Public:  " + Path.GetFullPath("rsa_public_key.pem"));
            Console.WriteLine("File Private: " + Path.GetFullPath("rsa_private_key.pem"));
        }

        static void ViewPEMRSA()
        {
            if (currentRsa == null) SinhCapKhoaRSA();

            Console.WriteLine("\n[VIEW PEM & PHAN TICH Y NGHIA CAC BYTE]");
            Console.WriteLine("1. Xem Public Key PEM");
            Console.WriteLine("2. Xem Private Key PEM");
            Console.Write("Chon (1-2): ");
            string? opt = Console.ReadLine()?.Trim();

            RSAParameters p = currentRsa!.ExportParameters(opt == "2");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n--- Y NGHIA CAC TRUONG BYTE TRONG FORMAT PEM (ASN.1 DER) ---");
            Console.ResetColor();
            Console.WriteLine("File PEM la chuoi Base64 ma hoa cau truc nhi phan ASN.1 DER.");
            Console.WriteLine("Cac truong cu the:");
            Console.WriteLine($"1. Modulus (n = p * q) [Do dai {p.Modulus!.Length * 8} bits]:");
            Console.WriteLine($"   0x{Convert.ToHexString(p.Modulus!)[..48]}...");
            Console.WriteLine($"2. Public Exponent (e) [Thuong la 65537 - 17 bits]:");
            Console.WriteLine($"   Hex: 0x{Convert.ToHexString(p.Exponent!)} | Gia tri: 65537");

            if (opt == "2")
            {
                Console.WriteLine($"3. Private Exponent (d = e^-1 mod phi(n)) [Do dai {p.D!.Length * 8} bits]:");
                Console.WriteLine($"   0x{Convert.ToHexString(p.D!)[..48]}...");
                Console.WriteLine($"4. Prime 1 (p) [Thua so nguyen to 1 - {p.P!.Length * 8} bits]: 0x{Convert.ToHexString(p.P!)[..32]}...");
                Console.WriteLine($"5. Prime 2 (q) [Thua so nguyen to 2 - {p.Q!.Length * 8} bits]: 0x{Convert.ToHexString(p.Q!)[..32]}...");
                Console.WriteLine($"6. Exponent 1 (dp = d mod (p-1)): 0x{Convert.ToHexString(p.DP!)[..32]}...");
                Console.WriteLine($"7. Exponent 2 (dq = d mod (q-1)): 0x{Convert.ToHexString(p.DQ!)[..32]}...");
                Console.WriteLine($"8. Coefficient (qinv = q^-1 mod p): 0x{Convert.ToHexString(p.InverseQ!)[..32]}...");
            }
        }

        static void MaHoaDuLieuRSA()
        {
            if (currentRsa == null) SinhCapKhoaRSA();

            Console.WriteLine("\n[MA HOA DU LIEU RSA: MANG BYTE <= 190 BYTES]");
            Console.WriteLine("Vi du: Ma hoa khoa AES 256-bit (32 bytes)");
            byte[] dataToEncrypt;
            if (currentAesKey != null)
            {
                dataToEncrypt = currentAesKey;
                Console.WriteLine($"Su dung khoa AES 256-bit tu Bai 1 ({dataToEncrypt.Length} bytes)");
            }
            else
            {
                dataToEncrypt = new byte[32];
                RandomNumberGenerator.Fill(dataToEncrypt);
                Console.WriteLine($"Sinh ngau nhien 32 bytes gia lap khoa AES");
            }

            Console.WriteLine($"Du lieu nguon (Hex): {Convert.ToHexString(dataToEncrypt)}");

            // Ma hoa bang Public Key
            byte[] cipher = currentRsa!.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);
            string cipherBase64 = Convert.ToBase64String(cipher);
            File.WriteAllText("rsa_encrypted_aes_key.base64", cipherBase64);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n-> Ma hoa bang Public Key thanh cong!");
            Console.ResetColor();
            Console.WriteLine($"Ciphertext Base64 (Luu file rsa_encrypted_aes_key.base64):");
            Console.WriteLine(cipherBase64[..64] + "...");

            // Giai ma bang Private Key
            byte[] decrypted = currentRsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            Console.WriteLine($"Du lieu giai ma (Hex): {Convert.ToHexString(decrypted)}");

            bool match = Convert.ToHexString(dataToEncrypt) == Convert.ToHexString(decrypted);
            Console.ForegroundColor = match ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine($"\n-> KET LUAN SO SANH VOI NGUON: {(match ? "TRUNG KHOP 100% (32/32 bytes)" : "SAI LECH")}");
            Console.ResetColor();
        }

        static void BenchmarkRSA()
        {
            if (currentRsa == null) SinhCapKhoaRSA();

            Console.WriteLine("\n[2.7. BENCHMARK TOC DO: PUBLIC KEY (e be) vs PRIVATE KEY (d to dung)]");
            int iterations = 50;
            byte[] sampleData = new byte[32];
            RandomNumberGenerator.Fill(sampleData);

            // 1. Do thoi gian ma hoa (Public Key: n, e = 65537)
            byte[] encrypted = currentRsa!.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);
            Stopwatch swEnc = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                currentRsa.Encrypt(sampleData, RSAEncryptionPadding.OaepSHA256);
            }
            swEnc.Stop();
            double avgEncMs = swEnc.Elapsed.TotalMilliseconds / iterations;

            // 2. Do thoi gian giai ma (Private Key: n, d ~ 2048 bit)
            Stopwatch swDec = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                currentRsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
            }
            swDec.Stop();
            double avgDecMs = swDec.Elapsed.TotalMilliseconds / iterations;

            double ratio = avgDecMs / avgEncMs;

            Console.WriteLine($"So lan kiem thu: {iterations} lan tren RSA 2048-bit");
            Console.WriteLine($"-> Ma hoa Public Key (e = 65537 be): {avgEncMs:F3} ms/lan ({1000.0 / avgEncMs:F1} ops/s)");
            Console.WriteLine($"-> Giai ma Private Key (d to dung):    {avgDecMs:F3} ms/lan ({1000.0 / avgDecMs:F1} ops/s)");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine($"-> KET LUAN: Public Key nhanh hon Private Key xap xi {ratio:F1} LAN!");
            Console.ResetColor();
            Console.WriteLine("\nGIẢI THÍCH TOÁN HỌC:");
            Console.WriteLine(" - e = 65537 chỉ có 17 bits (nhị phân có đúng 2 bit '1'). Thuật toán chỉ mất 17 phép toán modular.");
            Console.WriteLine(" - d có kích thước 2048 bits (khoảng 1024 bit '1'). Cần tới hơn 3000 phép tính modulo số lớn.");
            Console.WriteLine(" - Do đó, mã hóa bằng Public Key luôn nhanh hơn giải mã hàng chục lần.");
        }

        static void Sha256AvalancheDemo()
        {
            Console.WriteLine("\n[2.8. MA BAM SHA-256 & HIỆU ỨNG THÁC LŨ (AVALANCHE EFFECT)]");
            string s1 = "DaiHocBachKhoaHaNoi2026";
            string s2 = "DaiHocBachKhoaHaNoi2027"; // Chỉ khác số 6 và 7 (1 bit cuối)

            byte[] b1 = Encoding.UTF8.GetBytes(s1);
            byte[] b2 = Encoding.UTF8.GetBytes(s2);

            byte[] h1, h2;
            using (var sha = SHA256.Create())
            {
                h1 = sha.ComputeHash(b1);
                h2 = sha.ComputeHash(b2);
            }

            Console.WriteLine($"Input 1: '{s1}'");
            Console.WriteLine($"Hash 1:  {Convert.ToHexString(h1)}");
            Console.WriteLine($"\nInput 2: '{s2}' (Chi khac dung 1 ky tu)");
            Console.WriteLine($"Hash 2:  {Convert.ToHexString(h2)}");

            // Đếm số bit khác nhau (Hamming Distance)
            int diffBits = 0;
            for (int i = 0; i < 32; i++)
            {
                byte xor = (byte)(h1[i] ^ h2[i]);
                while (xor > 0)
                {
                    if ((xor & 1) == 1) diffBits++;
                    xor >>= 1;
                }
            }

            double pct = (diffBits / 256.0) * 100.0;
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"\n-> KET QUA HIỆU ỨNG THÁC LŨ:");
            Console.WriteLine($"So bit bi dao nguoc: {diffBits} / 256 bits ({pct:F2}%)");
            Console.ResetColor();
            Console.WriteLine("-> Nhan xet: Du dau vao chi thay doi 1 bit duy nhat, xap xi 50% so bit dau ra bi lat ngau nhien.");
            Console.WriteLine("   Day la tieu chuan vang SAC (Strict Avalanche Criterion) bao dam tinh an toan cua SHA-256.");
        }

        static void ChuKySoRandomDemo()
        {
            if (currentRsa == null) SinhCapKhoaRSA();

            Console.WriteLine("\n[2.9. CHỮ KÝ SỐ: ĐỀ XUẤT CHỮ KÝ KHÁC NHAU GIỮA CÁC LẦN KÝ]");
            string doc = "Hop dong chuyen tien ngan hang: 50,000,000 VND";
            byte[] data = Encoding.UTF8.GetBytes(doc);

            Console.WriteLine($"Van ban ky: '{doc}'");

            // 1. Cách cũ: PKCS#1 v1.5 (Deterministic)
            Console.WriteLine("\n1. THUAT TOAN CU PKCS#1 v1.5 (Deterministic):");
            byte[] sig1a = currentRsa!.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            byte[] sig1b = currentRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Console.WriteLine($"Lan 1: {Convert.ToBase64String(sig1a)[..32]}...");
            Console.WriteLine($"Lan 2: {Convert.ToBase64String(sig1b)[..32]}...");
            Console.WriteLine($"-> Hai lan ky giong het nhau: {(Convert.ToBase64String(sig1a) == Convert.ToBase64String(sig1b) ? "DUNG (Cố định)" : "KHAC")}");

            // 2. Cách đề xuất 1: RSA-PSS (Probabilistic Signature Scheme)
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("\n2. PHUONG PHAP DE XUAT 1: CHUAN RSA-PSS (Random Salt):");
            Console.ResetColor();
            byte[] sig2a = currentRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            byte[] sig2b = currentRsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Console.WriteLine($"Lan 1: {Convert.ToBase64String(sig2a)[..32]}...");
            Console.WriteLine($"Lan 2: {Convert.ToBase64String(sig2b)[..32]}...");
            bool isDiff = Convert.ToBase64String(sig2a) != Convert.ToBase64String(sig2b);
            Console.WriteLine($"-> Hai lan ky KHAC NHAU HOAN TOAN: {(isDiff ? "DUNG (Chữ ký ngẫu nhiên!)" : "KHONG")}");

            // Xác minh lại
            bool vA = currentRsa.VerifyData(data, sig2a, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            bool vB = currentRsa.VerifyData(data, sig2b, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            Console.WriteLine($"-> Xac minh chu ky Lan 1: {(vA ? "HOP LE" : "KHONG")}");
            Console.WriteLine($"-> Xac minh chu ky Lan 2: {(vB ? "HOP LE" : "KHONG")}");

            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("\n-> TONG KET DE XUAT CHO THAY CO:");
            Console.ResetColor();
            Console.WriteLine(" 1. Phuong phap 1 (Chuan quoc te RFC 8017): Dung RSA-PSS co Salt ngau nhien.");
            Console.WriteLine("    Moi lan ky sinh ra 1 Salt moi -> Chu ky luon khac nhau -> Verify tu dong trich xuat Salt.");
            Console.WriteLine(" 2. Phuong phap 2 (Ung dung thuc te): Dong goi du lieu kem Nonce & Timestamp truoc khi bam va ky.");
            Console.WriteLine("    Giup chu ky vua ngau nhien vua chong tan cong phat lai (Anti-Replay Attack).");
        }
        #endregion
    }
}
