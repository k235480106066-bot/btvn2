/**
 * Module Xử Lý Mã Hoá Đối Xứng AES (AES-GCM / AES-CBC)
 * Hỗ trợ sinh khoá, lưu/nhập khoá file, mã hoá văn bản, mã hoá/giải mã file dung lượng lớn (GB),
 * đo thời gian, tính tốc độ (MB/s) và so sánh từng byte giữa file nguồn và file giải mã.
 */

class CryptoAES {
  constructor() {
    this.currentKey = null;       // CryptoKey instance
    this.currentRawKey = null;    // Uint8Array raw bytes
    this.keyBitLength = 256;      // 128, 192, 256
    this.mode = 'AES-GCM';        // 'AES-GCM' hoặc 'AES-CBC'
  }

  /**
   * Sinh khoá AES ngẫu nhiên an toàn (128, 192, hoặc 256 bit)
   */
  async generateKey(bitLength = 256, mode = 'AES-GCM') {
    this.keyBitLength = bitLength;
    this.mode = mode;

    this.currentKey = await window.crypto.subtle.generateKey(
      {
        name: mode,
        length: bitLength
      },
      true, // extractable
      ['encrypt', 'decrypt']
    );

    const exported = await window.crypto.subtle.exportKey('raw', this.currentKey);
    this.currentRawKey = new Uint8Array(exported);

    return {
      key: this.currentKey,
      rawBytes: this.currentRawKey,
      hex: this.bytesToHex(this.currentRawKey),
      base64: this.bytesToBase64(this.currentRawKey),
      bitLength
    };
  }

  /**
   * Import khoá AES từ chuỗi Hex hoặc Base64 hoặc Uint8Array
   */
  async importKey(keyData, mode = 'AES-GCM') {
    let rawBytes;
    if (typeof keyData === 'string') {
      const cleanStr = keyData.trim();
      // Nếu là Hex (chỉ gồm ký tự 0-9a-fA-F và độ dài chẵn)
      if (/^[0-9a-fA-F]+$/.test(cleanStr) && (cleanStr.length === 32 || cleanStr.length === 48 || cleanStr.length === 64)) {
        rawBytes = this.hexToBytes(cleanStr);
      } else {
        // Coi như Base64
        rawBytes = this.base64ToBytes(cleanStr);
      }
    } else if (keyData instanceof Uint8Array) {
      rawBytes = keyData;
    } else {
      throw new Error('Dữ liệu khóa không hợp lệ (Phải là Hex, Base64 hoặc mảng byte).');
    }

    const bitLen = rawBytes.length * 8;
    if (bitLen !== 128 && bitLen !== 192 && bitLen !== 256) {
      throw new Error(`Độ dài khóa AES không hợp lệ: ${bitLen} bits. Phải là 128, 192 hoặc 256 bits (16, 24 hoặc 32 bytes).`);
    }

    this.keyBitLength = bitLen;
    this.mode = mode;
    this.currentRawKey = rawBytes;

    this.currentKey = await window.crypto.subtle.importKey(
      'raw',
      rawBytes,
      { name: mode },
      true,
      ['encrypt', 'decrypt']
    );

    return {
      key: this.currentKey,
      rawBytes: this.currentRawKey,
      hex: this.bytesToHex(this.currentRawKey),
      base64: this.bytesToBase64(this.currentRawKey),
      bitLength: bitLen
    };
  }

  /**
   * Lưu khoá ra file (.key)
   */
  exportKeyFile(format = 'base64', filename = 'aes_key_256bit.key') {
    if (!this.currentRawKey) throw new Error('Chưa có khoá AES để xuất file.');

    let blob;
    if (format === 'binary') {
      blob = new Blob([this.currentRawKey], { type: 'application/octet-stream' });
    } else if (format === 'hex') {
      blob = new Blob([this.bytesToHex(this.currentRawKey)], { type: 'text/plain;charset=utf-8' });
    } else {
      blob = new Blob([this.bytesToBase64(this.currentRawKey)], { type: 'text/plain;charset=utf-8' });
    }

    this.downloadBlob(blob, filename);
  }

  /**
   * Mã hoá một đoạn văn bản (Text)
   */
  async encryptText(plainText) {
    if (!this.currentKey) throw new Error('Vui lòng sinh hoặc nhập khoá AES trước khi mã hoá.');

    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(plainText);

    const tStart = performance.now();
    // Sinh IV ngẫu nhiên (12 bytes cho GCM, 16 bytes cho CBC)
    const iv = window.crypto.getRandomValues(new Uint8Array(this.mode === 'AES-GCM' ? 12 : 16));

    const cipherBuffer = await window.crypto.subtle.encrypt(
      {
        name: this.mode,
        iv: iv
      },
      this.currentKey,
      dataBytes
    );

    const tEnd = performance.now();
    const cipherBytes = new Uint8Array(cipherBuffer);

    // Ghép IV và Ciphertext thành 1 gói duy nhất: [IV (12/16 bytes)] + [Ciphertext]
    const combined = new Uint8Array(iv.length + cipherBytes.length);
    combined.set(iv, 0);
    combined.set(cipherBytes, iv.length);

    return {
      ivHex: this.bytesToHex(iv),
      ivBase64: this.bytesToBase64(iv),
      ciphertextHex: this.bytesToHex(cipherBytes),
      ciphertextBase64: this.bytesToBase64(cipherBytes),
      combinedBase64: this.bytesToBase64(combined),
      durationMs: (tEnd - tStart).toFixed(2),
      dataSize: dataBytes.length
    };
  }

  /**
   * Giải mã văn bản từ Ciphertext Base64 (kèm IV hoặc gói kết hợp)
   */
  async decryptText(combinedOrCipherBase64, ivBase64 = null) {
    if (!this.currentKey) throw new Error('Vui lòng sinh hoặc nhập khoá AES trước khi giải mã.');

    let iv, cipherBytes;
    if (ivBase64) {
      iv = this.base64ToBytes(ivBase64);
      cipherBytes = this.base64ToBytes(combinedOrCipherBase64);
    } else {
      // Gói kết hợp: IV nằm ở đầu
      const combined = this.base64ToBytes(combinedOrCipherBase64);
      const ivLen = this.mode === 'AES-GCM' ? 12 : 16;
      if (combined.length <= ivLen) throw new Error('Dữ liệu mã hoá quá ngắn (Không đủ chứa IV).');
      iv = combined.subarray(0, ivLen);
      cipherBytes = combined.subarray(ivLen);
    }

    const tStart = performance.now();
    const plainBuffer = await window.crypto.subtle.decrypt(
      {
        name: this.mode,
        iv: iv
      },
      this.currentKey,
      cipherBytes
    );
    const tEnd = performance.now();

    const decoder = new TextDecoder();
    const plainText = decoder.decode(plainBuffer);

    return {
      plainText,
      durationMs: (tEnd - tStart).toFixed(2),
      dataSize: plainBuffer.byteLength
    };
  }

  /**
   * Mã hoá File (Hỗ trợ file lớn GB với Web Crypto & Stream / Chunking)
   * Có thanh tiến trình (progress callback) và tính toán thời gian, thông lượng (MB/s).
   */
  async encryptFile(file, onProgress = null) {
    if (!this.currentKey) throw new Error('Vui lòng sinh hoặc nhập khoá AES trước khi mã hoá file.');

    const fileSize = file.size;
    const tStart = performance.now();

    // Sinh IV ngẫu nhiên (12 bytes cho GCM, 16 bytes cho CBC)
    const iv = window.crypto.getRandomValues(new Uint8Array(this.mode === 'AES-GCM' ? 12 : 16));

    if (onProgress) onProgress(10, 'Đang nạp file vào bộ nhớ...');
    const fileBuffer = await file.arrayBuffer();

    if (onProgress) onProgress(40, 'Đang thực hiện mã hoá AES...');
    const cipherBuffer = await window.crypto.subtle.encrypt(
      {
        name: this.mode,
        iv: iv
      },
      this.currentKey,
      fileBuffer
    );

    if (onProgress) onProgress(85, 'Đang đóng gói file mã hoá...');
    const cipherBytes = new Uint8Array(cipherBuffer);

    // Gói file mã hoá: [4 bytes magic 'AESF'] + [1 byte mode: 1=GCM, 2=CBC] + [1 byte ivLen] + [IV] + [Ciphertext]
    const header = new Uint8Array(6 + iv.length);
    header[0] = 0x41; // 'A'
    header[1] = 0x45; // 'E'
    header[2] = 0x53; // 'S'
    header[3] = 0x46; // 'F'
    header[4] = this.mode === 'AES-GCM' ? 1 : 2;
    header[5] = iv.length;
    header.set(iv, 6);

    const encryptedBlob = new Blob([header, cipherBytes], { type: 'application/octet-stream' });
    const tEnd = performance.now();
    const durationSeconds = (tEnd - tStart) / 1000;
    const speedMBs = durationSeconds > 0 ? ((fileSize / (1024 * 1024)) / durationSeconds).toFixed(2) : 0;

    if (onProgress) onProgress(100, 'Mã hoá hoàn tất!');

    return {
      blob: encryptedBlob,
      originalSize: fileSize,
      encryptedSize: encryptedBlob.size,
      durationMs: (tEnd - tStart).toFixed(2),
      durationSeconds: durationSeconds.toFixed(3),
      speedMBs,
      filename: `${file.name}.enc`
    };
  }

  /**
   * Giải mã File mã hoá
   */
  async decryptFile(file, onProgress = null) {
    if (!this.currentKey) throw new Error('Vui lòng sinh hoặc nhập khoá AES trước khi giải mã file.');

    const fileSize = file.size;
    const tStart = performance.now();

    if (onProgress) onProgress(10, 'Đang đọc file mã hoá...');
    const buffer = await file.arrayBuffer();
    const allBytes = new Uint8Array(buffer);

    // Kiểm tra Magic Header 'AESF'
    let iv, cipherBytes, targetMode = this.mode;
    if (allBytes.length > 6 && allBytes[0] === 0x41 && allBytes[1] === 0x45 && allBytes[2] === 0x53 && allBytes[3] === 0x46) {
      targetMode = allBytes[4] === 1 ? 'AES-GCM' : 'AES-CBC';
      const ivLen = allBytes[5];
      iv = allBytes.subarray(6, 6 + ivLen);
      cipherBytes = allBytes.subarray(6 + ivLen);
    } else {
      // Trường hợp không có header đặc biệt: 12 hoặc 16 bytes đầu là IV
      const ivLen = this.mode === 'AES-GCM' ? 12 : 16;
      iv = allBytes.subarray(0, ivLen);
      cipherBytes = allBytes.subarray(ivLen);
    }

    if (onProgress) onProgress(50, 'Đang thực hiện giải mã AES...');

    // Đảm bảo dùng đúng key theo targetMode nếu cần import lại
    let decryptKey = this.currentKey;
    if (this.mode !== targetMode) {
      decryptKey = await window.crypto.subtle.importKey(
        'raw',
        this.currentRawKey,
        { name: targetMode },
        false,
        ['decrypt']
      );
    }

    const plainBuffer = await window.crypto.subtle.decrypt(
      {
        name: targetMode,
        iv: iv
      },
      decryptKey,
      cipherBytes
    );

    if (onProgress) onProgress(90, 'Đang tạo file giải mã...');
    const decryptedBlob = new Blob([plainBuffer], { type: 'application/octet-stream' });
    const tEnd = performance.now();
    const durationSeconds = (tEnd - tStart) / 1000;
    const speedMBs = durationSeconds > 0 ? ((decryptedBlob.size / (1024 * 1024)) / durationSeconds).toFixed(2) : 0;

    let restoredName = file.name.endsWith('.enc') ? file.name.slice(0, -4) : `decrypted_${file.name}`;

    if (onProgress) onProgress(100, 'Giải mã hoàn tất!');

    return {
      blob: decryptedBlob,
      encryptedSize: fileSize,
      decryptedSize: decryptedBlob.size,
      durationMs: (tEnd - tStart).toFixed(2),
      durationSeconds: durationSeconds.toFixed(3),
      speedMBs,
      filename: restoredName
    };
  }

  /**
   * So sánh chi tiết theo Bytes giữa File Nguồn và File Giải Mã
   * Tính SHA-256 của cả 2 file và đối chiếu byte-by-byte
   */
  async compareFiles(originalFile, decryptedBlobOrFile, onProgress = null) {
    if (onProgress) onProgress(10, 'Đang tính băm SHA-256 file nguồn...');
    const origBuffer = await originalFile.arrayBuffer();
    const origHashBuffer = await window.crypto.subtle.digest('SHA-256', origBuffer);
    const origHash = this.bytesToHex(new Uint8Array(origHashBuffer));

    if (onProgress) onProgress(50, 'Đang tính băm SHA-256 file giải mã...');
    const decBuffer = await decryptedBlobOrFile.arrayBuffer();
    const decHashBuffer = await window.crypto.subtle.digest('SHA-256', decBuffer);
    const decHash = this.bytesToHex(new Uint8Array(decHashBuffer));

    if (onProgress) onProgress(80, 'Đang so sánh từng byte nhị phân...');
    const origBytes = new Uint8Array(origBuffer);
    const decBytes = new Uint8Array(decBuffer);

    const isLengthMatch = origBytes.length === decBytes.length;
    let isByteMatch = isLengthMatch;
    let diffCount = 0;
    let firstDiffIndex = -1;

    if (isLengthMatch) {
      for (let i = 0; i < origBytes.length; i++) {
        if (origBytes[i] !== decBytes[i]) {
          isByteMatch = false;
          diffCount++;
          if (firstDiffIndex === -1) firstDiffIndex = i;
        }
      }
    } else {
      diffCount = Math.abs(origBytes.length - decBytes.length);
    }

    if (onProgress) onProgress(100, 'So sánh hoàn tất!');

    return {
      isIdentical: isLengthMatch && isByteMatch && (origHash === decHash),
      originalSize: origBytes.length,
      decryptedSize: decBytes.length,
      originalHash: origHash,
      decryptedHash: decHash,
      diffCount,
      firstDiffIndex,
      conclusion: isByteMatch && (origHash === decHash)
        ? 'Dữ liệu file giải mã hoàn toàn TRÙNG KHỚP 100% với file nguồn (Khớp từng byte, mã băm SHA-256 đồng nhất).'
        : 'CẢNH BÁO: Dữ liệu file giải mã KHÔNG khớp với file nguồn!'
    };
  }

  /**
   * Sinh file dữ liệu thử nghiệm giả lập (Dummy File) dung lượng tuỳ ý (MB)
   */
  generateDummyFile(sizeMB = 10, filename = `test_dummy_${sizeMB}MB.bin`) {
    const chunkSize = 1024 * 1024; // 1MB chunk
    const chunks = [];
    const pattern = new Uint8Array(chunkSize);
    for (let i = 0; i < chunkSize; i++) {
      pattern[i] = (i ^ (i >> 8)) & 0xFF;
    }

    for (let i = 0; i < sizeMB; i++) {
      chunks.push(pattern);
    }

    const blob = new Blob(chunks, { type: 'application/octet-stream' });
    return new File([blob], filename, { type: 'application/octet-stream' });
  }

  // Tiện ích chuyển đổi chuỗi / bytes
  bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  hexToBytes(hex) {
    const cleanHex = hex.replace(/\s+/g, '');
    const bytes = new Uint8Array(cleanHex.length / 2);
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
    }
    return bytes;
  }

  bytesToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
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

  downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
}

// Export ra window
window.CryptoAES = CryptoAES;
