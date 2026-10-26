/**
 * Module Đánh Giá Tốc Độ (Benchmark) RSA: Public Key (e bé) vs Private Key (d to)
 * Trực quan hóa số liệu thực nghiệm, tính toán tỉ số chênh lệch và giải thích toán học chi tiết.
 */

class RSABenchmark {
  constructor(cryptoRSA) {
    this.cryptoRSA = cryptoRSA;
    this.isRunning = false;
  }

  /**
   * Chạy bài đo lường tốc độ với số lần lặp iterations
   */
  async runBenchmark(iterations = 30, onProgress = null) {
    if (this.isRunning) return;
    this.isRunning = true;

    // Đảm bảo đã có cặp khoá
    if (!this.cryptoRSA.importedPublicKey || !this.cryptoRSA.importedPrivateKey) {
      if (onProgress) onProgress(5, 'Đang tự động khởi tạo cặp khoá RSA 2048-bit...');
      await this.cryptoRSA.generateKeyPair(2048);
    }

    const testData = new Uint8Array(32); // Giả lập khoá AES 256-bit (32 bytes)
    window.crypto.getRandomValues(testData);

    // 1. Đo tốc độ Mã hoá (Public Key: n, e = 65537)
    const encDurations = [];
    let encryptedSample = null;

    for (let i = 0; i < iterations; i++) {
      if (onProgress) {
        const pct = Math.round(((i + 1) / (iterations * 2)) * 50);
        onProgress(pct, `Đang đo mã hoá Public Key (Lần ${i + 1}/${iterations})...`);
      }

      const t0 = performance.now();
      const res = await window.crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        this.cryptoRSA.importedPublicKey,
        testData
      );
      const t1 = performance.now();
      encDurations.push(t1 - t0);
      if (i === 0) encryptedSample = res;
    }

    // 2. Đo tốc độ Giải mã (Private Key: n, d ~ 2048 bit)
    const decDurations = [];
    for (let i = 0; i < iterations; i++) {
      if (onProgress) {
        const pct = 50 + Math.round(((i + 1) / (iterations * 2)) * 50);
        onProgress(pct, `Đang đo giải mã Private Key (Lần ${i + 1}/${iterations})...`);
      }

      const t0 = performance.now();
      await window.crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        this.cryptoRSA.importedPrivateKey,
        encryptedSample
      );
      const t1 = performance.now();
      decDurations.push(t1 - t0);
    }

    this.isRunning = false;

    // Thống kê số liệu
    const totalEncTime = encDurations.reduce((a, b) => a + b, 0);
    const avgEncTime = totalEncTime / iterations;
    const encOpsPerSec = avgEncTime > 0 ? (1000 / avgEncTime).toFixed(1) : 0;

    const totalDecTime = decDurations.reduce((a, b) => a + b, 0);
    const avgDecTime = totalDecTime / iterations;
    const decOpsPerSec = avgDecTime > 0 ? (1000 / avgDecTime).toFixed(1) : 0;

    const speedupRatio = (avgDecTime / avgEncTime).toFixed(2);

    return {
      iterations,
      keySize: this.cryptoRSA.keySize || 2048,
      avgEncTimeMs: avgEncTime.toFixed(3),
      avgDecTimeMs: avgDecTime.toFixed(3),
      totalEncTimeMs: totalEncTime.toFixed(2),
      totalDecTimeMs: totalDecTime.toFixed(2),
      encOpsPerSec,
      decOpsPerSec,
      speedupRatio,
      explanation: this.getMathematicalExplanation(speedupRatio)
    };
  }

  getMathematicalExplanation(ratio) {
    return {
      title: 'GIẢI THÍCH TOÁN HỌC: TẠI SAO PUBLIC KEY NHANH HƠN PRIVATE KEY NHIỀU LẦN?',
      summary: `Thực nghiệm cho thấy: Mã hoá bằng Public Key (e bé) nhanh hơn Giải mã bằng Private Key (d lớn) xấp xỉ ${ratio} lần!`,
      details: [
        {
          param: 'Public Exponent (e)',
          size: '17 bits (e = 65537 = 0x10001)',
          binary: '10000000000000001 (chỉ có đúng 2 bit "1")',
          complexity: 'Theo thuật toán Square-and-Multiply (Bình phương và nhân), tính C = M^e mod n chỉ cần đúng 16 phép bình phương và 1 phép nhân số lớn!',
          cost: 'Rất nhỏ (~17 phép toán modular)'
        },
        {
          param: 'Private Exponent (d)',
          size: '2048 bits (số nguyên cực lớn ngẫu nhiên)',
          binary: 'Xấp xỉ 1024 bit "1" và 1024 bit "0" ngẫu nhiên',
          complexity: 'Tính M = C^d mod n cần tới 2048 phép bình phương và ~1024 phép nhân số lớn 2048-bit (ngay cả khi tối ưu hoá CRT - Chinese Remainder Theorem, vẫn cần hàng trăm phép nhân trên số 1024-bit).',
          cost: 'Rất lớn (~3072 phép toán modular)'
        }
      ],
      conclusion: 'Trong thực tế ứng dụng, người ta cố tình chọn e nhỏ (như 65537 hoặc 3) để các thao tác mã hoá và xác thực chữ ký (thực hiện bởi hàng triệu client / thiết bị yếu) diễn ra siêu nhanh, trong khi việc giải mã và tạo chữ ký (Private key) chỉ do server hoặc chủ sở hữu thực hiện.'
    };
  }
}

window.RSABenchmark = RSABenchmark;
