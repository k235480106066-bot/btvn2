/**
 * Module Chữ Ký Số RSA & Đề Xuất Chữ Ký Khác Nhau Giữa Các Lần Ký
 * Hỗ trợ RSASSA-PKCS1-v1_5 (Deterministic) và RSA-PSS (Probabilistic với Salt ngẫu nhiên)
 * cùng phương pháp Gắn Nonce/Timestamp chống tấn công phát lại (Anti-Replay).
 */

class CryptoSignature {
  constructor(cryptoRSA) {
    this.cryptoRSA = cryptoRSA;
    this.pssPrivateKey = null;
    this.pssPublicKey = null;
    this.pkcs1PrivateKey = null;
    this.pkcs1PublicKey = null;
    this.signatureHistory = [];
  }

  /**
   * Khởi tạo hoặc chuyển đổi cặp khoá sang các thuật toán ký số
   */
  async ensureSigningKeys() {
    if (!this.cryptoRSA.publicKeyDer || !this.cryptoRSA.privateKeyDer) {
      await this.cryptoRSA.generateKeyPair(2048);
    }

    const pubDer = this.cryptoRSA.publicKeyDer;
    const privDer = this.cryptoRSA.privateKeyDer;

    // 1. Khởi tạo khoá RSA-PSS (Ký ngẫu nhiên với Salt)
    try {
      this.pssPublicKey = await window.crypto.subtle.importKey(
        'spki',
        pubDer,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['verify']
      );
      this.pssPrivateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        privDer,
        { name: 'RSA-PSS', hash: 'SHA-256' },
        true,
        ['sign']
      );
    } catch (e) {
      console.warn('Lỗi import khoá RSA-PSS:', e);
    }

    // 2. Khởi tạo khoá RSASSA-PKCS1-v1_5 (Ký cố định Deterministic)
    try {
      this.pkcs1PublicKey = await window.crypto.subtle.importKey(
        'spki',
        pubDer,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        true,
        ['verify']
      );
      this.pkcs1PrivateKey = await window.crypto.subtle.importKey(
        'pkcs8',
        privDer,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        true,
        ['sign']
      );
    } catch (e) {
      console.warn('Lỗi import khoá RSASSA-PKCS1-v1_5:', e);
    }
  }

  /**
   * Ký số bằng thuật toán RSA-PSS (Mỗi lần ký tạo ra chữ ký HOÀN TOÀN KHÁC NHAU)
   */
  async signWithPSS(messageText, saltLength = 32) {
    await this.ensureSigningKeys();
    if (!this.pssPrivateKey) throw new Error('Không thể nạp khoá bí mật RSA-PSS.');

    const dataBytes = new TextEncoder().encode(messageText);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataBytes);
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    const tStart = performance.now();
    const sigBuffer = await window.crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: saltLength // Salt ngẫu nhiên 32 bytes (256 bits)
      },
      this.pssPrivateKey,
      dataBytes
    );
    const tEnd = performance.now();

    const sigBytes = new Uint8Array(sigBuffer);
    const sigBase64 = this.bytesToBase64(sigBytes);
    const sigHex = this.bytesToHex(sigBytes);

    const record = {
      id: Date.now() + Math.random().toString(16).slice(2, 6),
      scheme: 'RSA-PSS (Salt ngẫu nhiên)',
      time: new Date().toLocaleTimeString(),
      durationMs: (tEnd - tStart).toFixed(2),
      hashHex,
      signatureBase64: sigBase64,
      signatureHex: sigHex,
      messageText,
      saltLength
    };

    this.signatureHistory.unshift(record);
    return record;
  }

  /**
   * Ký số bằng thuật toán RSASSA-PKCS1-v1_5 (Deterministic: Luôn cho cùng 1 chữ ký)
   */
  async signWithPKCS1(messageText) {
    await this.ensureSigningKeys();
    if (!this.pkcs1PrivateKey) throw new Error('Không thể nạp khoá bí mật PKCS#1 v1.5.');

    const dataBytes = new TextEncoder().encode(messageText);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', dataBytes);
    const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    const tStart = performance.now();
    const sigBuffer = await window.crypto.subtle.sign(
      { name: 'RSASSA-PKCS1-v1_5' },
      this.pkcs1PrivateKey,
      dataBytes
    );
    const tEnd = performance.now();

    const sigBytes = new Uint8Array(sigBuffer);
    const sigBase64 = this.bytesToBase64(sigBytes);
    const sigHex = this.bytesToHex(sigBytes);

    const record = {
      id: Date.now() + Math.random().toString(16).slice(2, 6),
      scheme: 'PKCS#1 v1.5 (Cố định - Deterministic)',
      time: new Date().toLocaleTimeString(),
      durationMs: (tEnd - tStart).toFixed(2),
      hashHex,
      signatureBase64: sigBase64,
      signatureHex: sigHex,
      messageText,
      saltLength: 0
    };

    this.signatureHistory.unshift(record);
    return record;
  }

  /**
   * Ký số bằng phương pháp Gắn Nonce / Timestamp (Envelope Signature)
   */
  async signWithTimestampNonce(messageText) {
    const timestamp = Date.now();
    const nonce = Math.random().toString(36).substring(2, 10);
    const envelope = JSON.stringify({
      data: messageText,
      timestamp: timestamp,
      timestampISO: new Date(timestamp).toISOString(),
      nonce: nonce
    });

    const sigRecord = await this.signWithPSS(envelope);
    sigRecord.scheme = 'Metadata Nonce/Timestamp + RSA-PSS';
    sigRecord.envelope = envelope;
    return sigRecord;
  }

  /**
   * Xác minh chữ ký số bằng Public Key
   */
  async verifySignature(messageText, signatureBase64, scheme = 'RSA-PSS', saltLength = 32) {
    await this.ensureSigningKeys();

    const sigBytes = this.base64ToBytes(signatureBase64);
    const dataBytes = new TextEncoder().encode(messageText);

    let isValid = false;
    const tStart = performance.now();

    if (scheme.includes('PSS')) {
      if (!this.pssPublicKey) throw new Error('Chưa có khoá công khai PSS để xác minh.');
      isValid = await window.crypto.subtle.verify(
        {
          name: 'RSA-PSS',
          saltLength: saltLength
        },
        this.pssPublicKey,
        sigBytes,
        dataBytes
      );
    } else {
      if (!this.pkcs1PublicKey) throw new Error('Chưa có khoá công khai PKCS#1 để xác minh.');
      isValid = await window.crypto.subtle.verify(
        { name: 'RSASSA-PKCS1-v1_5' },
        this.pkcs1PublicKey,
        sigBytes,
        dataBytes
      );
    }
    const tEnd = performance.now();

    return {
      isValid,
      durationMs: (tEnd - tStart).toFixed(2),
      scheme,
      message: isValid
        ? 'Chữ ký số HỢP LỆ VÀ NGUYÊN VẸN! (Dữ liệu chưa bị chỉnh sửa và đúng người ký).'
        : 'CẢNH BÁO: Chữ ký số KHÔNG HỢP LỆ! (Dữ liệu bị thay đổi hoặc khoá ký không đúng).'
    };
  }

  /**
   * Báo cáo đề xuất phương pháp đạt được chữ ký khác nhau giữa các lần ký
   */
  getProposalReport() {
    return {
      problemStatement: 'Cùng 1 dữ liệu, cùng 1 người ký (cùng private key) => Chữ ký số khác nhau giữa các lần ký.',
      solutions: [
        {
          id: 1,
          name: 'Phương pháp 1: Chuẩn RSA-PSS (Probabilistic Signature Scheme - RFC 8017 / PKCS #1 v2.1)',
          status: 'Khuyến nghị hàng đầu (Chuẩn mật mã học quốc tế hiện đại)',
          mechanism: 'Trong thuật toán RSA-PSS, trước khi thực hiện phép băm mở rộng (MGF1) và mã hoá RSA, một chuỗi muối ngẫu nhiên (Random Salt, độ dài thường là 32 bytes) được tự động sinh ra và ghép vào khối dữ liệu cần ký.',
          advantages: [
            'Mỗi lần gọi hàm ký, một giá trị Salt ngẫu nhiên mới được tạo ra -> Khối đệm mã hoá thay đổi 100% -> Chữ ký mỗi lần hoàn toàn khác nhau.',
            'Người xác minh (Verify) KHÔNG CẦN biết trước Salt: Giải thuật RSA-PSS dùng Public Key giải mã khối chữ ký, trích xuất lại Salt được nhúng bên trong để tự động kiểm tra tính toàn vẹn.',
            'Bảo mật vượt trội so với PKCS#1 v1.5: Đã được chứng minh toán học là kháng lại các cuộc tấn công thích nghi bản rõ (Chosen-message attacks) và giả mạo chữ ký.'
          ]
        },
        {
          id: 2,
          name: 'Phương pháp 2: Gắn Siêu Dữ Liệu Động (Timestamp / Nonce / Salt) vào thông điệp (Envelope Signature)',
          status: 'Ứng dụng thực tế cao (Chuẩn JWT / TLS / Blockchain / API Gateway)',
          mechanism: 'Trước khi băm, người ký đóng gói dữ liệu thành một Envelope: Payload = { data: D, timestamp: T, nonce: R }. Chữ ký sẽ được tạo trên toàn bộ Payload này.',
          advantages: [
            'Vì trường Thời gian (Timestamp) hoặc Chuỗi ngẫu nhiên (Nonce) luôn thay đổi theo từng mili-giây, giá trị băm SHA-256 của Payload luôn mới 100% -> Chữ ký luôn luôn khác nhau.',
            'Chống tấn công phát lại (Anti-Replay Attack): Kẻ xấu chặn bắt chữ ký cũng không thể phát lại gói tin vì Timestamp hoặc Nonce đã bị hết hạn hoặc bị đánh dấu đã xử lý.',
            'Có thể kiểm tra thời điểm chính xác khi giao dịch hoặc văn bản được ký.'
          ]
        }
      ]
    };
  }

  bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  base64ToBytes(base64) {
    const binary = atob(base64.replace(/\s+/g, ''));
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

window.CryptoSignature = CryptoSignature;
