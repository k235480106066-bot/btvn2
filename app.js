/**
 * App Controller & Event Handlers
 * Điều phối toàn bộ giao diện người dùng và liên kết các module mật mã.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Khởi tạo các instance
  const aes = new window.CryptoAES();
  const rsa = new window.CryptoRSA();
  const benchmark = new window.RSABenchmark(rsa);
  const signature = new window.CryptoSignature(rsa);

  // Lưu trữ trạng thái file tạm thời
  let currentOriginalFile = null;
  let currentEncryptedBlob = null;
  let currentDecryptedBlob = null;
  let currentRSAOriginalBytes = null;
  let currentRSACiphertextBase64 = null;

  // Cấu hình ban đầu
  let aesSelectedBit = 256;
  let rsaSelectedBit = 2048;
  let bmIterations = 20;

  /* ============================================================
     1. TOAST NOTIFICATIONS & TIỆN ÍCH
  ============================================================ */
  function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = type === 'success' ? '✅' : (type === 'error' ? '❌' : 'ℹ️');
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  // Sao chép vào clipboard
  document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const targetEl = document.getElementById(targetId);
      if (targetEl) {
        const text = targetEl.innerText.trim();
        if (text && !text.startsWith('Chưa')) {
          navigator.clipboard.writeText(text);
          showToast('Đã sao chép vào bộ nhớ tạm (Clipboard)!');
        } else {
          showToast('Không có dữ liệu để sao chép.', 'error');
        }
      }
    });
  });

  /* ============================================================
     2. ĐIỀU HƯỚNG TABS
  ============================================================ */
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-tab');
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const activePane = document.getElementById(targetId);
      if (activePane) activePane.classList.add('active');
    });
  });

  /* ============================================================
     3. BÀI TẬP 1: MÃ HÓA ĐỐI XỨNG AES
  ============================================================ */
  // Lựa chọn độ dài khóa AES
  const aesBitBtns = {
    128: document.getElementById('btn-aes-128'),
    192: document.getElementById('btn-aes-192'),
    256: document.getElementById('btn-aes-256')
  };

  [128, 192, 256].forEach(bits => {
    aesBitBtns[bits].addEventListener('click', () => {
      Object.values(aesBitBtns).forEach(b => b.classList.remove('active'));
      aesBitBtns[bits].classList.add('active');
      aesSelectedBit = bits;
      document.getElementById('aes-key-badge').innerText = `${bits}-bit ${document.getElementById('aes-mode-select').value.replace('AES-', '')}`;
    });
  });

  document.getElementById('aes-mode-select').addEventListener('change', (e) => {
    document.getElementById('aes-key-badge').innerText = `${aesSelectedBit}-bit ${e.target.value.replace('AES-', '')}`;
  });

  // Sinh khóa AES mới
  async function doGenerateAESKey() {
    try {
      const mode = document.getElementById('aes-mode-select').value;
      const res = await aes.generateKey(aesSelectedBit, mode);
      document.getElementById('aes-key-base64').innerText = res.base64;
      document.getElementById('aes-key-hex').innerText = res.hex;
      showToast(`Đã sinh thành công khóa AES ${res.bitLength}-bit (${mode})!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
  document.getElementById('btn-gen-aes').addEventListener('click', doGenerateAESKey);

  // Lưu khóa ra file .key
  document.getElementById('btn-save-aes-file').addEventListener('click', () => {
    try {
      const filename = `aes_${aesSelectedBit}bit_${document.getElementById('aes-mode-select').value.toLowerCase()}.key`;
      aes.exportKeyFile('base64', filename);
      showToast(`Đã xuất khóa ra file ${filename}!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Import khóa từ file
  document.getElementById('aes-key-file-input').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const text = reader.result.trim();
        const mode = document.getElementById('aes-mode-select').value;
        const res = await aes.importKey(text, mode);
        document.getElementById('aes-key-base64').innerText = res.base64;
        document.getElementById('aes-key-hex').innerText = res.hex;
        aesSelectedBit = res.bitLength;
        Object.values(aesBitBtns).forEach(b => b.classList.remove('active'));
        if (aesBitBtns[res.bitLength]) aesBitBtns[res.bitLength].classList.add('active');
        document.getElementById('aes-key-badge').innerText = `${res.bitLength}-bit ${mode.replace('AES-', '')}`;
        showToast(`Đã nạp thành công khóa AES ${res.bitLength}-bit từ file!`);
      } catch (err) {
        showToast(err.message, 'error');
      }
    };
    reader.readAsText(file);
  });

  // Mã hóa văn bản AES
  document.getElementById('btn-aes-encrypt-text').addEventListener('click', async () => {
    try {
      if (!aes.currentKey) await doGenerateAESKey();
      const plainText = document.getElementById('aes-plain-text').value;
      if (!plainText) throw new Error('Vui lòng nhập văn bản cần mã hóa.');

      const res = await aes.encryptText(plainText);
      document.getElementById('aes-iv-output').innerText = res.ivHex;
      document.getElementById('aes-cipher-output').innerText = res.combinedBase64;
      document.getElementById('aes-text-time').innerText = `${res.durationMs} ms`;
      showToast(`Mã hóa văn bản thành công (${res.durationMs} ms)!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Giải mã văn bản AES
  document.getElementById('btn-aes-decrypt-text').addEventListener('click', async () => {
    try {
      const cipherText = document.getElementById('aes-cipher-output').innerText.trim();
      if (!cipherText || cipherText.startsWith('Chưa')) {
        throw new Error('Chưa có dữ liệu Ciphertext để giải mã.');
      }

      const res = await aes.decryptText(cipherText);
      document.getElementById('aes-decrypted-text').innerText = res.plainText;
      document.getElementById('aes-text-time').innerText = `${res.durationMs} ms`;
      showToast(`Giải mã văn bản thành công (${res.durationMs} ms)!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Chọn File nguồn
  document.getElementById('aes-source-file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      currentOriginalFile = file;
      document.getElementById('aes-file-info').innerText = `File: ${file.name} | Dung lượng: ${(file.size / (1024 * 1024)).toFixed(2)} MB (${file.size.toLocaleString()} bytes)`;
      document.getElementById('aes-file-status').innerText = 'Đã chọn file nguồn sẵn sàng mã hóa.';
    }
  });

  // Tạo Dummy Files (1MB, 10MB, 50MB, 100MB, 500MB)
  const dummyMap = {
    'btn-dummy-1mb': 1,
    'btn-dummy-10mb': 10,
    'btn-dummy-50mb': 50,
    'btn-dummy-100mb': 100,
    'btn-dummy-500mb': 500
  };

  Object.entries(dummyMap).forEach(([btnId, sizeMB]) => {
    document.getElementById(btnId).addEventListener('click', () => {
      showToast(`Đang sinh nhanh file mẫu dung lượng ${sizeMB} MB...`, 'info');
      setTimeout(() => {
        currentOriginalFile = aes.generateDummyFile(sizeMB, `sample_test_${sizeMB}MB.bin`);
        document.getElementById('aes-file-info').innerText = `File mẫu: ${currentOriginalFile.name} | Dung lượng: ${sizeMB} MB (${currentOriginalFile.size.toLocaleString()} bytes)`;
        document.getElementById('aes-file-status').innerText = `Đã tạo sẵn file mẫu ${sizeMB} MB. Sẵn sàng mã hóa!`;
        showToast(`Đã tạo xong file thử nghiệm ${sizeMB} MB!`);
      }, 50);
    });
  });

  // Mã hóa File lớn AES
  document.getElementById('btn-aes-encrypt-file').addEventListener('click', async () => {
    try {
      if (!currentOriginalFile) throw new Error('Vui lòng chọn hoặc tạo file thử nghiệm trước.');
      if (!aes.currentKey) await doGenerateAESKey();

      const progressBar = document.getElementById('aes-file-progress');
      const statusLabel = document.getElementById('aes-file-status');

      statusLabel.innerText = 'Bắt đầu quá trình mã hóa file...';
      progressBar.style.width = '10%';

      const res = await aes.encryptFile(currentOriginalFile, (pct, msg) => {
        progressBar.style.width = `${pct}%`;
        statusLabel.innerText = msg;
      });

      currentEncryptedBlob = res.blob;
      document.getElementById('aes-enc-time').innerText = `${res.durationSeconds} s`;
      document.getElementById('aes-enc-speed').innerText = `${res.speedMBs} MB/s`;

      document.getElementById('btn-aes-decrypt-file').disabled = false;
      showToast(`Mã hóa file hoàn tất trong ${res.durationSeconds}s (Tốc độ: ${res.speedMBs} MB/s)!`);

      // Tự động tải file mã hóa về máy
      aes.downloadBlob(res.blob, res.filename);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Giải mã File lớn AES
  document.getElementById('btn-aes-decrypt-file').addEventListener('click', async () => {
    try {
      if (!currentEncryptedBlob) throw new Error('Chưa có file mã hóa để giải mã.');

      const fileToDecrypt = new File([currentEncryptedBlob], `${currentOriginalFile.name}.enc`);
      const progressBar = document.getElementById('aes-file-progress');
      const statusLabel = document.getElementById('aes-file-status');

      statusLabel.innerText = 'Bắt đầu quá trình giải mã file...';
      progressBar.style.width = '10%';

      const res = await aes.decryptFile(fileToDecrypt, (pct, msg) => {
        progressBar.style.width = `${pct}%`;
        statusLabel.innerText = msg;
      });

      currentDecryptedBlob = res.blob;
      document.getElementById('aes-dec-time').innerText = `${res.durationSeconds} s`;
      document.getElementById('aes-dec-speed').innerText = `${res.speedMBs} MB/s`;

      document.getElementById('btn-aes-compare-bytes').disabled = false;
      showToast(`Giải mã file hoàn tất trong ${res.durationSeconds}s (Tốc độ: ${res.speedMBs} MB/s)!`);

      // Tự động tải file giải mã phục hồi
      aes.downloadBlob(res.blob, res.filename);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Đối chiếu Byte-by-byte (Compare)
  document.getElementById('btn-aes-compare-bytes').addEventListener('click', async () => {
    try {
      if (!currentOriginalFile || !currentDecryptedBlob) {
        throw new Error('Cần có cả file nguồn và file giải mã để thực hiện so sánh.');
      }

      const progressBar = document.getElementById('aes-file-progress');
      const statusLabel = document.getElementById('aes-file-status');

      const cmpRes = await aes.compareFiles(currentOriginalFile, currentDecryptedBlob, (pct, msg) => {
        progressBar.style.width = `${pct}%`;
        statusLabel.innerText = msg;
      });

      const resBox = document.getElementById('aes-compare-result-box');
      resBox.style.display = 'block';

      document.getElementById('cmp-orig-size').innerText = `${cmpRes.originalSize.toLocaleString()} bytes`;
      document.getElementById('cmp-dec-size').innerText = `${cmpRes.decryptedSize.toLocaleString()} bytes`;
      document.getElementById('cmp-orig-hash').innerText = cmpRes.originalHash;
      document.getElementById('cmp-dec-hash').innerText = cmpRes.decryptedHash;
      document.getElementById('cmp-diff-count').innerText = `${cmpRes.diffCount} bytes sai lệch`;
      document.getElementById('cmp-conclusion-text').innerText = cmpRes.conclusion;

      showToast('Đã đối chiếu byte-by-byte thành công!');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  /* ============================================================
     4. BÀI TẬP 2: MÃ HÓA BẤT ĐỐI XỨNG RSA & ASN.1 PEM
  ============================================================ */
  const rsaBitBtns = {
    1024: document.getElementById('btn-rsa-1024'),
    2048: document.getElementById('btn-rsa-2048'),
    4096: document.getElementById('btn-rsa-4096')
  };

  [1024, 2048, 4096].forEach(bits => {
    rsaBitBtns[bits].addEventListener('click', () => {
      Object.values(rsaBitBtns).forEach(b => b.classList.remove('active'));
      rsaBitBtns[bits].classList.add('active');
      rsaSelectedBit = bits;
      document.getElementById('rsa-key-badge').innerText = `${bits}-bit`;
    });
  });

  // Sinh cặp khóa RSA
  async function doGenerateRSAKeyPair() {
    try {
      showToast(`Đang sinh cặp khóa RSA ${rsaSelectedBit}-bit...`, 'info');
      const res = await rsa.generateKeyPair(rsaSelectedBit);
      document.getElementById('rsa-pub-pem-text').innerText = res.publicKeyPem;
      document.getElementById('rsa-priv-pem-text').innerText = res.privateKeyPem;

      renderRSAParameters(res.privateParsed || res.publicParsed);
      renderASN1Table(res.privateParsed || res.publicParsed);

      showToast(`Đã sinh xong cặp khóa RSA ${rsaSelectedBit}-bit!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  }
  document.getElementById('btn-gen-rsa').addEventListener('click', doGenerateRSAKeyPair);

  // Xuất file PEM
  document.getElementById('btn-save-pub-pem').addEventListener('click', () => {
    if (!rsa.publicKeyPem) return showToast('Chưa có Public Key.', 'error');
    rsa.exportPemFile(rsa.publicKeyPem, 'rsa_public_key.pem');
  });

  document.getElementById('btn-save-priv-pem').addEventListener('click', () => {
    if (!rsa.privateKeyPem) return showToast('Chưa có Private Key.', 'error');
    rsa.exportPemFile(rsa.privateKeyPem, 'rsa_private_key.pem');
  });

  // Hiển thị tham số n, e, d
  function renderRSAParameters(parsed) {
    if (!parsed || !parsed.fields) return;

    if (parsed.fields.n) {
      const n = parsed.fields.n;
      document.getElementById('rsa-modulus-hex').innerText = `${n.bitLength}-bit (0x${n.hex.substring(0, 48)}...)`;
    }
    if (parsed.fields.e) {
      const e = parsed.fields.e;
      document.getElementById('rsa-exponent-hex').innerText = `Decimal: ${e.decimal} | Hex: 0x${e.hex}`;
    }

    const dGroup = document.getElementById('rsa-private-d-group');
    if (parsed.fields.d) {
      dGroup.style.display = 'block';
      const d = parsed.fields.d;
      document.getElementById('rsa-private-d-hex').innerText = `${d.bitLength}-bit (0x${d.hex.substring(0, 48)}...)`;
    } else {
      dGroup.style.display = 'none';
    }
  }

  // Bảng phân tích chi tiết ASN.1 DER breakdown
  function renderASN1Table(parsed) {
    const tbody = document.getElementById('asn1-table-body');
    tbody.innerHTML = '';

    if (!parsed || !parsed.parsedFields || parsed.parsedFields.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">Không có dữ liệu ASN.1.</td></tr>`;
      return;
    }

    parsed.parsedFields.forEach(field => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td class="mono">0x${(field.startOffset || 0).toString(16).padStart(4, '0')}</td>
        <td><span class="badge badge-primary">0x02 INTEGER</span></td>
        <td>${field.length || field.rawBytes?.length || '-'} bytes</td>
        <td class="asn1-field-name">${field.label || field.key}</td>
        <td>${field.desc || '-'}</td>
        <td class="mono" style="word-break: break-all; font-size: 0.775rem; color: #38bdf8;">
          ${field.hex ? (field.hex.length > 32 ? field.hex.substring(0, 32) + '...' : field.hex) : '-'}
        </td>
      `;
      tbody.appendChild(tr);
    });
  }

  // Xem Public Key hiện tại
  document.getElementById('btn-view-current-pub').addEventListener('click', () => {
    if (rsa.publicParsed) {
      renderRSAParameters(rsa.publicParsed);
      renderASN1Table(rsa.publicParsed);
      showToast('Đang hiển thị cấu trúc ASN.1 của Public Key.');
    } else {
      showToast('Chưa có Public Key. Hãy sinh khóa trước.', 'error');
    }
  });

  // Xem Private Key hiện tại
  document.getElementById('btn-view-current-priv').addEventListener('click', () => {
    if (rsa.privateParsed) {
      renderRSAParameters(rsa.privateParsed);
      renderASN1Table(rsa.privateParsed);
      showToast('Đang hiển thị cấu trúc ASN.1 của Private Key.');
    } else {
      showToast('Chưa có Private Key. Hãy sinh khóa trước.', 'error');
    }
  });

  // Nhập file PEM từ máy tính
  document.getElementById('rsa-pem-file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const pemStr = reader.result.trim();
        let parsed;
        if (pemStr.includes('PUBLIC KEY')) {
          parsed = await rsa.importPublicKeyFromPem(pemStr);
          document.getElementById('rsa-pub-pem-text').innerText = pemStr;
          showToast('Đã nạp thành công Public Key PEM!');
        } else if (pemStr.includes('PRIVATE KEY')) {
          parsed = await rsa.importPrivateKeyFromPem(pemStr);
          document.getElementById('rsa-priv-pem-text').innerText = pemStr;
          showToast('Đã nạp thành công Private Key PEM!');
        } else {
          throw new Error('File không đúng định dạng PEM chứa PUBLIC KEY hoặc PRIVATE KEY.');
        }

        renderRSAParameters(parsed);
        renderASN1Table(parsed);
      } catch (err) {
        showToast(err.message, 'error');
      }
    };
    reader.readAsText(file);
  });

  // Nạp khóa AES từ Bài 1 sang RSA
  document.getElementById('btn-use-aes-key').addEventListener('click', async () => {
    if (!aes.currentRawKey) {
      await doGenerateAESKey();
    }
    const hex = aes.bytesToHex(aes.currentRawKey);
    document.getElementById('rsa-plain-input').value = hex;
    updateRSAPlainLength();
    showToast('Đã nạp khóa AES 256-bit (32 bytes) vào ô mã hóa RSA!');
  });

  document.getElementById('btn-sample-rsa-text').addEventListener('click', () => {
    document.getElementById('rsa-plain-input').value = 'Mật mã RSA Hybrid: Khóa đối xứng AES-256 bí mật được bọc an toàn.';
    updateRSAPlainLength();
  });

  function updateRSAPlainLength() {
    const text = document.getElementById('rsa-plain-input').value;
    const len = new TextEncoder().encode(text).length;
    const maxLen = 190;
    const info = document.getElementById('rsa-input-len');
    if (len > maxLen) {
      info.innerHTML = `<span style="color: var(--danger); font-weight: 700;">Độ dài: ${len} bytes (VƯỢT QUÁ GIỚI HẠN ${maxLen} BYTES CỦA RSA-2048 OAEP)!</span>`;
    } else {
      info.innerHTML = `Độ dài: ${len} bytes (&le; ${maxLen} bytes hợp lệ)`;
    }
  }
  document.getElementById('rsa-plain-input').addEventListener('input', updateRSAPlainLength);

  // Mã hóa RSA
  document.getElementById('btn-rsa-encrypt').addEventListener('click', async () => {
    try {
      if (!rsa.importedPublicKey) await doGenerateRSAKeyPair();

      const text = document.getElementById('rsa-plain-input').value;
      if (!text) throw new Error('Vui lòng nhập dữ liệu cần mã hóa.');

      const res = await rsa.encryptData(text);
      currentRSAOriginalBytes = res.rawPlainBytes;
      currentRSACiphertextBase64 = res.ciphertextBase64;

      document.getElementById('rsa-cipher-output').innerText = res.ciphertextBase64;
      showToast(`Mã hóa RSA thành công (${res.cipherSize} bytes ciphertext, ${res.durationMs} ms)!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Lưu file mã hóa RSA
  document.getElementById('btn-save-rsa-cipher').addEventListener('click', () => {
    if (!currentRSACiphertextBase64) return showToast('Chưa có dữ liệu mã hóa để lưu.', 'error');
    const blob = new Blob([currentRSACiphertextBase64], { type: 'text/plain;charset=utf-8' });
    aes.downloadBlob(blob, 'rsa_encrypted_data.base64');
  });

  // Giải mã RSA
  document.getElementById('btn-rsa-decrypt').addEventListener('click', async () => {
    try {
      if (!rsa.importedPrivateKey) await doGenerateRSAKeyPair();

      const cipherBase64 = document.getElementById('rsa-cipher-output').innerText.trim();
      if (!cipherBase64 || cipherBase64.startsWith('Chưa')) {
        throw new Error('Chưa có dữ liệu Ciphertext để giải mã.');
      }

      const res = await rsa.decryptData(cipherBase64);
      document.getElementById('rsa-decrypted-output').innerText = res.textPreview;

      // So sánh dữ liệu gốc
      if (currentRSAOriginalBytes) {
        const cmp = rsa.compareData(currentRSAOriginalBytes, res.plainBytes);
        const cmpBox = document.getElementById('rsa-compare-box');
        cmpBox.style.display = 'block';
        document.getElementById('rsa-compare-text').innerText = cmp.msg;
      }

      showToast(`Giải mã RSA thành công (${res.durationMs} ms)!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Nạp file mã hóa RSA
  document.getElementById('rsa-cipher-file-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      document.getElementById('rsa-cipher-output').innerText = reader.result.trim();
      showToast('Đã nạp file dữ liệu mã hóa!');
    };
    reader.readAsText(file);
  });

  /* ============================================================
     5. BENCHMARK: PUBLIC KEY vs PRIVATE KEY
  ============================================================ */
  const bmIterBtns = {
    20: document.getElementById('btn-iter-20'),
    50: document.getElementById('btn-iter-50'),
    100: document.getElementById('btn-iter-100')
  };

  [20, 50, 100].forEach(n => {
    bmIterBtns[n].addEventListener('click', () => {
      Object.values(bmIterBtns).forEach(b => b.classList.remove('active'));
      bmIterBtns[n].classList.add('active');
      bmIterations = n;
    });
  });

  document.getElementById('btn-run-benchmark').addEventListener('click', async () => {
    try {
      const progressBar = document.getElementById('benchmark-progress');
      const statusLabel = document.getElementById('benchmark-status');

      statusLabel.innerText = 'Đang bắt đầu bài đo lường hiệu năng...';
      progressBar.style.width = '5%';

      const res = await benchmark.runBenchmark(bmIterations, (pct, msg) => {
        progressBar.style.width = `${pct}%`;
        statusLabel.innerText = msg;
      });

      progressBar.style.width = '100%';
      statusLabel.innerText = 'Đo lường hoàn tất!';

      document.getElementById('bm-enc-time').innerText = `${res.avgEncTimeMs} ms`;
      document.getElementById('bm-enc-ops').innerText = `${res.encOpsPerSec} ops/s`;
      document.getElementById('bm-dec-time').innerText = `${res.avgDecTimeMs} ms`;
      document.getElementById('bm-dec-ops').innerText = `${res.decOpsPerSec} ops/s`;
      document.getElementById('bm-ratio').innerText = `${res.speedupRatio} x`;

      showToast(`Benchmark hoàn tất: Public Key nhanh hơn ${res.speedupRatio} lần!`);
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  /* ============================================================
     6. BÀI TẬP 2.8: SHA-256 & HIỆU ỨNG THÁC LŨ
  ============================================================ */
  const shaInputA = document.getElementById('sha-input-a');
  const shaInputB = document.getElementById('sha-input-b');

  async function updateAvalanche() {
    const valA = shaInputA.value;
    const valB = shaInputB.value;

    const res = await window.CryptoSHA.compareAvalanche(valA, valB);

    document.getElementById('sha-hash-a-hex').innerText = res.hashA.hex;
    document.getElementById('sha-hash-b-hex').innerText = res.hashB.hex;

    document.getElementById('sha-input-diff').innerText = `${res.inputBitDiff} bit`;
    document.getElementById('sha-diff-count').innerText = `${res.diffBitsCount} / 256 bits`;
    document.getElementById('sha-diff-pct').innerText = `${res.diffPercent} %`;
    document.getElementById('sha-rating').innerText = res.evaluation.rating;

    // Vẽ ma trận 256 ô bit
    const matrix = document.getElementById('bit-matrix-container');
    matrix.innerHTML = '';
    res.bitComparison.forEach(bit => {
      const cell = document.createElement('div');
      cell.className = `bit-cell ${bit.isDiff ? 'diff' : 'match'}`;
      cell.title = `Bit #${bit.index}: A=${bit.bitA}, B=${bit.bitB} ${bit.isDiff ? '(Đổi)' : '(Khớp)'}`;
      cell.innerText = bit.bitB;
      matrix.appendChild(cell);
    });
  }

  shaInputA.addEventListener('input', updateAvalanche);
  shaInputB.addEventListener('input', updateAvalanche);

  document.getElementById('btn-flip-bit').addEventListener('click', () => {
    shaInputB.value = window.CryptoSHA.flipOneBit(shaInputA.value);
    updateAvalanche();
    showToast('Đã đảo đúng 1 bit ở ký tự cuối của Input A sang Input B!');
  });

  // Chạy lần đầu cho SHA
  updateAvalanche();

  /* ============================================================
     7. BÀI TẬP 2.9: CHỮ KÝ SỐ & ĐỀ XUẤT CHỮ KÝ KHÁC NHAU
  ============================================================ */
  function renderSignatureHistory() {
    const tbody = document.getElementById('sig-history-body');
    tbody.innerHTML = '';

    if (signature.signatureHistory.length === 0) {
      tbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: var(--text-muted); padding: 1rem;">Chưa có chữ ký nào.</td></tr>`;
      return;
    }

    signature.signatureHistory.forEach(record => {
      const tr = document.createElement('tr');
      const isPSS = record.scheme.includes('PSS');
      tr.innerHTML = `
        <td class="mono">${record.time}</td>
        <td><span class="badge ${isPSS ? 'badge-primary' : 'badge-secondary'}">${record.scheme}</span></td>
        <td class="mono" style="color: #38bdf8; word-break: break-all; font-size: 0.775rem;">
          ${record.signatureBase64.substring(0, 36)}...
        </td>
        <td>${isPSS ? '🎲 <b>Khác nhau mỗi lần bấm</b>' : '🔒 <b>Cố định giống hệt</b>'}</td>
        <td>
          <button class="btn btn-secondary btn-sm btn-select-sig" data-sig="${record.signatureBase64}" data-scheme="${isPSS ? 'RSA-PSS' : 'RSASSA-PKCS1-v1_5'}">
            Chọn để xác minh
          </button>
        </td>
      `;
      tbody.appendChild(tr);
    });

    document.querySelectorAll('.btn-select-sig').forEach(b => {
      b.addEventListener('click', () => {
        document.getElementById('verify-sig-input').value = b.getAttribute('data-sig');
        document.getElementById('verify-scheme-select').value = b.getAttribute('data-scheme');
        showToast('Đã nạp chữ ký vào ô xác minh.');
      });
    });
  }

  // Ký PKCS#1 v1.5 (Deterministic)
  document.getElementById('btn-sign-pkcs1').addEventListener('click', async () => {
    try {
      const msg = document.getElementById('sig-message-input').value;
      if (!msg) throw new Error('Vui lòng nhập nội dung cần ký.');

      const rec = await signature.signWithPKCS1(msg);
      renderSignatureHistory();
      showToast('Đã ký bằng PKCS#1 v1.5 (Chữ ký cố định giống nhau)!');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Ký RSA-PSS (Probabilistic với Salt ngẫu nhiên)
  document.getElementById('btn-sign-pss').addEventListener('click', async () => {
    try {
      const msg = document.getElementById('sig-message-input').value;
      if (!msg) throw new Error('Vui lòng nhập nội dung cần ký.');

      const rec = await signature.signWithPSS(msg);
      renderSignatureHistory();
      showToast('Đã ký bằng RSA-PSS (Chữ ký hoàn toàn mới với Salt ngẫu nhiên)!');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Ký Nonce & Timestamp
  document.getElementById('btn-sign-nonce').addEventListener('click', async () => {
    try {
      const msg = document.getElementById('sig-message-input').value;
      if (!msg) throw new Error('Vui lòng nhập nội dung cần ký.');

      const rec = await signature.signWithTimestampNonce(msg);
      renderSignatureHistory();
      showToast('Đã ký kèm Nonce & Timestamp chống tấn công Replay!');
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Xác minh chữ ký
  document.getElementById('btn-verify-sig').addEventListener('click', async () => {
    try {
      const msg = document.getElementById('sig-message-input').value;
      const sigBase64 = document.getElementById('verify-sig-input').value.trim();
      const scheme = document.getElementById('verify-scheme-select').value;

      if (!sigBase64) throw new Error('Vui lòng nhập hoặc chọn chữ ký Base64 cần xác minh.');

      const res = await signature.verifySignature(msg, sigBase64, scheme);
      const resBox = document.getElementById('verify-result-box');
      resBox.style.display = 'block';

      if (res.isValid) {
        resBox.className = 'success-callout';
        document.getElementById('verify-result-title').innerText = '✅ XÁC MINH THÀNH CÔNG (HỢP LỆ VÀ NGUYÊN VẸN)';
        document.getElementById('verify-result-msg').innerText = `${res.message} (Thời gian xác thực: ${res.durationMs} ms).`;
        showToast('Chữ ký số hoàn toàn HỢP LỆ!');
      } else {
        resBox.className = 'info-callout';
        document.getElementById('verify-result-title').innerText = '❌ XÁC MINH THẤT BẠI';
        document.getElementById('verify-result-msg').innerText = res.message;
        showToast('Chữ ký KHÔNG HỢP LỆ!', 'error');
      }
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Tự động khởi tạo khóa mặc định ban đầu
  setTimeout(() => {
    doGenerateAESKey();
    doGenerateRSAKeyPair();
  }, 300);
});
