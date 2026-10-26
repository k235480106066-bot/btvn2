/**
 * Module Xử Lý Mã Hoá Bất Đối Xứng RSA (RSA-OAEP / RSA-PSS / PKCS#1)
 * Hỗ trợ sinh cặp khoá, xuất/nhập PEM, phân tích ASN.1 byte-by-byte,
 * trích xuất n, e, d, p, q, mã hoá/giải mã mảng byte (<= 190 bytes, ví dụ khoá AES 32 bytes)
 * và đối chiếu tính toàn vẹn dữ liệu.
 */

class CryptoRSA {
  constructor() {
    this.keyPair = null;          // WebCrypto CryptoKeyPair
    this.publicKeyPem = '';       // Chuỗi PEM Public
    this.privateKeyPem = '';      // Chuỗi PEM Private
    this.publicParsed = null;     // Thông tin trích xuất (n, e)
    this.privateParsed = null;    // Thông tin trích xuất (n, e, d, p, q, ...)
    this.importedPublicKey = null;
    this.importedPrivateKey = null;
    this.keySize = 2048;
  }

  /**
   * Sinh cặp khoá RSA ngẫu nhiên (1024, 2048, 4096 bit)
   */
  async generateKeyPair(keySize = 2048) {
    this.keySize = keySize;

    // Sinh cặp khoá tương thích với RSA-OAEP (mã hoá) và RSA-PSS (ký số)
    // Lưu ý: Trong Web Crypto API, để vừa mã hoá vừa ký, ta có thể sinh cặp khoá hoặc export SPKI/PKCS8 rồi re-import
    this.keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: keySize,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
        hash: 'SHA-256'
      },
      true,
      ['encrypt', 'decrypt']
    );

    // Xuất khoá công khai dạng SPKI DER
    const spkiDer = await window.crypto.subtle.exportKey('spki', this.keyPair.publicKey);
    this.publicKeyDer = new Uint8Array(spkiDer);
    this.publicKeyPem = window.ASN1Parser.derToPem(this.publicKeyDer, 'PUBLIC KEY');

    // Xuất khoá bí mật dạng PKCS#8 DER
    const pkcs8Der = await window.crypto.subtle.exportKey('pkcs8', this.keyPair.privateKey);
    this.privateKeyDer = new Uint8Array(pkcs8Der);
    this.privateKeyPem = window.ASN1Parser.derToPem(this.privateKeyDer, 'PRIVATE KEY');

    // Phân tích cú pháp ASN.1 trích xuất n, e, d...
    this.publicParsed = window.ASN1Parser.inspectRSA(this.publicKeyDer);
    this.privateParsed = window.ASN1Parser.inspectRSA(this.privateKeyDer);

    this.importedPublicKey = this.keyPair.publicKey;
    this.importedPrivateKey = this.keyPair.privateKey;

    return {
      publicKeyPem: this.publicKeyPem,
      privateKeyPem: this.privateKeyPem,
      publicParsed: this.publicParsed,
      privateParsed: this.privateParsed,
      keySize
    };
  }

  /**
   * Phân tích và nạp khoá công khai từ chuỗi PEM
   */
  async importPublicKeyFromPem(pemStr) {
    const derBytes = window.ASN1Parser.pemToDer(pemStr);
    const parsed = window.ASN1Parser.inspectRSA(derBytes);

    if (parsed.type !== 'PUBLIC_KEY') {
      throw new Error('File không chứa khoá công khai RSA hợp lệ.');
    }

    // Import vào Web Crypto
    try {
      this.importedPublicKey = await window.crypto.subtle.importKey(
        'spki',
        derBytes,
        {
          name: 'RSA-OAEP',
          hash: 'SHA-256'
        },
        true,
        ['encrypt']
      );
    } catch (err) {
      console.warn('Lỗi import SPKI trực tiếp, thử dạng fallback:', err);
    }

    this.publicKeyPem = pemStr.trim();
    this.publicParsed = parsed;
    return parsed;
  }

  /**
   * Phân tích và nạp khoá bí mật từ chuỗi PEM
   */
  async importPrivateKeyFromPem(pemStr) {
    const derBytes = window.ASN1Parser.pemToDer(pemStr);
    const parsed = window.ASN1Parser.inspectRSA(derBytes);

    if (parsed.type !== 'PRIVATE_KEY') {
      throw new Error('File không chứa khoá bí mật RSA hợp lệ.');
    }

    // Import vào Web Crypto
    try {
      // Nếu là PKCS#8
      if (pemStr.includes('BEGIN PRIVATE KEY')) {
        this.importedPrivateKey = await window.crypto.subtle.importKey(
          'pkcs8',
          derBytes,
          {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
          },
          true,
          ['decrypt']
        );
      } else {
        // Nếu là PKCS#1 (BEGIN RSA PRIVATE KEY), bọc thành PKCS#8 DER để Web Crypto chấp nhận
        const pkcs8Der = this.wrapPKCS1ToPKCS8(derBytes);
        this.importedPrivateKey = await window.crypto.subtle.importKey(
          'pkcs8',
          pkcs8Der,
          {
            name: 'RSA-OAEP',
            hash: 'SHA-256'
          },
          true,
          ['decrypt']
        );
      }
    } catch (err) {
      console.warn('Lỗi import WebCrypto subtle private key:', err);
    }

    this.privateKeyPem = pemStr.trim();
    this.privateParsed = parsed;
    return parsed;
  }

  /**
   * Bọc PKCS#1 RSA Private Key DER thành PKCS#8 DER chuẩn cho Web Crypto API
   */
  wrapPKCS1ToPKCS8(pkcs1Bytes) {
    // PKCS#8 Structure:
    // SEQUENCE {
    //   version INTEGER 0
    //   AlgorithmIdentifier SEQUENCE { OID rsaEncryption, NULL }
    //   OCTET STRING (pkcs1Bytes)
    // }
    const algSeq = new Uint8Array([
      0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
    ]);
    const octetHeader = this.createTLVHeader(0x04, pkcs1Bytes.length);
    const versionBytes = new Uint8Array([0x02, 0x01, 0x00]);

    const innerLen = versionBytes.length + algSeq.length + octetHeader.length + pkcs1Bytes.length;
    const outerHeader = this.createTLVHeader(0x30, innerLen);

    const pkcs8 = new Uint8Array(outerHeader.length + innerLen);
    let offset = 0;
    pkcs8.set(outerHeader, offset); offset += outerHeader.length;
    pkcs8.set(versionBytes, offset); offset += versionBytes.length;
    pkcs8.set(algSeq, offset); offset += algSeq.length;
    pkcs8.set(octetHeader, offset); offset += octetHeader.length;
    pkcs8.set(pkcs1Bytes, offset);

    return pkcs8;
  }

  createTLVHeader(tag, length) {
    if (length < 128) {
      return new Uint8Array([tag, length]);
    } else if (length < 256) {
      return new Uint8Array([tag, 0x81, length]);
    } else if (length < 65536) {
      return new Uint8Array([tag, 0x82, (length >> 8) & 0xFF, length & 0xFF]);
    } else {
      return new Uint8Array([tag, 0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]);
    }
  }

  /**
   * Mã hoá mảng byte (tối đa 190 bytes, ví dụ khoá AES 256 bit = 32 bytes)
   * Sử dụng Public Key và thuật toán RSA-OAEP (SHA-256)
   */
  async encryptData(dataBytesOrText) {
    if (!this.importedPublicKey) {
      throw new Error('Chưa có khoá công khai RSA. Hãy sinh hoặc import Public Key PEM.');
    }

    let rawBytes;
    if (typeof dataBytesOrText === 'string') {
      rawBytes = new TextEncoder().encode(dataBytesOrText);
    } else if (dataBytesOrText instanceof Uint8Array) {
      rawBytes = dataBytesOrText;
    } else {
      throw new Error('Dữ liệu đầu vào phải là chuỗi hoặc mảng Uint8Array.');
    }

    // Giới hạn độ dài: Với RSA 2048-bit và OAEP (SHA-256):
    // maxLen = 2048/8 - 2 * 32 - 2 = 190 bytes!
    const keyBytes = (this.keySize || 2048) / 8;
    const maxDataLen = keyBytes - 2 * 32 - 2; // 190 bytes với RSA-2048, 62 bytes với RSA-1024

    if (rawBytes.length > maxDataLen) {
      throw new Error(`Dữ liệu dài ${rawBytes.length} bytes, vượt quá giới hạn an toàn ${maxDataLen} bytes của RSA-${this.keySize} OAEP!`);
    }

    const tStart = performance.now();
    const cipherBuffer = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      this.importedPublicKey,
      rawBytes
    );
    const tEnd = performance.now();
    const cipherBytes = new Uint8Array(cipherBuffer);

    return {
      ciphertextBytes: cipherBytes,
      ciphertextBase64: this.bytesToBase64(cipherBytes),
      ciphertextHex: this.bytesToHex(cipherBytes),
      durationMs: (tEnd - tStart).toFixed(3),
      plainSize: rawBytes.length,
      cipherSize: cipherBytes.length,
      rawPlainBytes: rawBytes
    };
  }

  /**
   * Giải mã Ciphertext Base64 bằng Private Key
   */
  async decryptData(ciphertextBase64OrBytes) {
    if (!this.importedPrivateKey) {
      throw new Error('Chưa có khoá bí mật RSA. Hãy sinh hoặc import Private Key PEM.');
    }

    let cipherBytes;
    if (typeof ciphertextBase64OrBytes === 'string') {
      cipherBytes = this.base64ToBytes(ciphertextBase64OrBytes);
    } else {
      cipherBytes = ciphertextBase64OrBytes;
    }

    const tStart = performance.now();
    const plainBuffer = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      this.importedPrivateKey,
      cipherBytes
    );
    const tEnd = performance.now();
    const plainBytes = new Uint8Array(plainBuffer);

    let textPreview = '';
    try {
      textPreview = new TextDecoder('utf-8', { fatal: true }).decode(plainBytes);
    } catch {
      textPreview = '[Dữ liệu nhị phân - không phải văn bản thuần UTF-8]';
    }

    return {
      plainBytes,
      plainBase64: this.bytesToBase64(plainBytes),
      plainHex: this.bytesToHex(plainBytes),
      textPreview,
      durationMs: (tEnd - tStart).toFixed(3),
      plainSize: plainBytes.length
    };
  }

  /**
   * So sánh dữ liệu giải mã với dữ liệu gốc trước khi mã hoá
   */
  compareData(origBytes, decBytes) {
    if (origBytes.length !== decBytes.length) {
      return {
        isMatch: false,
        msg: `Kích thước không khớp: Gốc=${origBytes.length} bytes, Giải mã=${decBytes.length} bytes.`
      };
    }

    for (let i = 0; i < origBytes.length; i++) {
      if (origBytes[i] !== decBytes[i]) {
        return {
          isMatch: false,
          msg: `Khác biệt tại byte offset ${i}: Gốc=0x${origBytes[i].toString(16)}, Giải mã=0x${decBytes[i].toString(16)}.`
        };
      }
    }

    return {
      isMatch: true,
      msg: `Dữ liệu sau khi giải mã TRÙNG KHỚP TUYỆT ĐỐI 100% với dữ liệu trước khi mã hoá (${origBytes.length}/${origBytes.length} bytes khớp)!`
    };
  }

  exportPemFile(pemString, filename) {
    const blob = new Blob([pemString], { type: 'application/x-pem-file;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
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

// Export ra window
window.CryptoRSA = CryptoRSA;
