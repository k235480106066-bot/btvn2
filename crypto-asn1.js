/**
 * ASN.1 DER Parser & RSA PEM Inspector
 * Phân tích cú pháp ASN.1 DER cho khóa RSA (PKCS#1, PKCS#8, SPKI)
 * Giải mã chi tiết từng byte, nhãn Tag, độ dài Length, giá trị Value và ý nghĩa các trường.
 */

class ASN1Parser {
  static TAGS = {
    0x02: { name: 'INTEGER', desc: 'Số nguyên lớn (Modulus, Exponents, Primes)' },
    0x03: { name: 'BIT STRING', desc: 'Chuỗi bit nhị phân (Chứa khóa công khai)' },
    0x04: { name: 'OCTET STRING', desc: 'Chuỗi byte nhị phân (Chứa PKCS#1 trong PKCS#8)' },
    0x05: { name: 'NULL', desc: 'Giá trị rỗng (Tham số thuật toán)' },
    0x06: { name: 'OBJECT IDENTIFIER', desc: 'Định danh đối tượng OID (Thuật toán rsaEncryption)' },
    0x30: { name: 'SEQUENCE', desc: 'Khối tuần tự (Danh sách các phần tử ASN.1)' }
  };

  static KNOWN_OIDS = {
    '1.2.840.113549.1.1.1': 'rsaEncryption (PKCS #1 v1.5 / RSA)',
    '1.2.840.113549.1.1.7': 'rsaOAEP',
    '1.2.840.113549.1.1.10': 'rsaPSS',
    '2.16.840.1.101.3.4.2.1': 'sha256'
  };

  /**
   * Chuyển Base64 PEM thành Uint8Array DER
   */
  static pemToDer(pemString) {
    const cleanPem = pemString
      .replace(/-----BEGIN [^-]+-----/g, '')
      .replace(/-----END [^-]+-----/g, '')
      .replace(/\s+/g, '');
    const binary = atob(cleanPem);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Chuyển Uint8Array DER thành PEM
   */
  static derToPem(derBytes, header = 'PUBLIC KEY') {
    let binary = '';
    for (let i = 0; i < derBytes.length; i++) {
      binary += String.fromCharCode(derBytes[i]);
    }
    const base64 = btoa(binary);
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN ${header}-----\n${lines.join('\n')}\n-----END ${header}-----`;
  }

  /**
   * Đọc TLV (Tag, Length, Value) tại vị trí offset
   */
  static decodeTLV(bytes, offset = 0) {
    if (offset >= bytes.length) return null;

    const startOffset = offset;
    const tag = bytes[offset++];
    let length = 0;
    let lengthBytesCount = 1;

    const firstLenByte = bytes[offset++];
    if (firstLenByte < 0x80) {
      length = firstLenByte;
    } else {
      const numBytes = firstLenByte & 0x7F;
      lengthBytesCount = 1 + numBytes;
      for (let i = 0; i < numBytes; i++) {
        length = (length << 8) | bytes[offset++];
      }
    }

    const valueOffset = offset;
    const endOffset = valueOffset + length;
    const value = bytes.subarray(valueOffset, Math.min(endOffset, bytes.length));

    return {
      tag,
      tagName: this.TAGS[tag] ? this.TAGS[tag].name : `TAG_0x${tag.toString(16).toUpperCase()}`,
      tagDesc: this.TAGS[tag] ? this.TAGS[tag].desc : 'Unknown ASN.1 Tag',
      length,
      startOffset,
      valueOffset,
      endOffset,
      headerLen: valueOffset - startOffset,
      totalLen: (valueOffset - startOffset) + length,
      value
    };
  }

  /**
   * Giải mã OID từ chuỗi byte
   */
  static decodeOID(bytes) {
    if (bytes.length === 0) return '';
    const first = bytes[0];
    const s1 = Math.floor(first / 40);
    const s2 = first % 40;
    const parts = [s1, s2];

    let val = 0;
    for (let i = 1; i < bytes.length; i++) {
      val = (val << 7) | (bytes[i] & 0x7F);
      if ((bytes[i] & 0x80) === 0) {
        parts.push(val);
        val = 0;
      }
    }
    return parts.join('.');
  }

  /**
   * Chuyển bytes thành chuỗi Hex
   */
  static bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Chuyển số nguyên lớn ASN.1 INTEGER (dạng bytes) thành BigInt
   */
  static bytesToBigInt(bytes) {
    let hex = this.bytesToHex(bytes);
    if (!hex) return 0n;
    return BigInt('0x' + hex);
  }

  /**
   * Phân tích đệ quy cấu trúc cây ASN.1
   */
  static parseTree(bytes, offset = 0, maxLen = bytes.length) {
    const nodes = [];
    let cur = offset;
    const end = offset + maxLen;

    while (cur < end && cur < bytes.length) {
      const node = this.decodeTLV(bytes, cur);
      if (!node) break;

      // Nếu là SEQUENCE, duyệt sâu vào các phần tử con
      if (node.tag === 0x30) {
        node.children = this.parseTree(bytes, node.valueOffset, node.length);
      }
      // Nếu là BIT STRING
      else if (node.tag === 0x03) {
        // Byte đầu tiên của BIT STRING là số bit unused (thường = 0)
        const unusedBits = node.value[0];
        const content = node.value.subarray(1);
        // Kiểm tra xem bên trong có phải SEQUENCE lồng (như trong SPKI) không
        if (content.length > 2 && content[0] === 0x30) {
          node.isEncapsulated = true;
          node.children = this.parseTree(content, 0, content.length);
        }
      }
      // Nếu là OCTET STRING (trong PKCS#8 chứa PKCS#1)
      else if (node.tag === 0x04) {
        if (node.value.length > 2 && node.value[0] === 0x30) {
          node.isEncapsulated = true;
          node.children = this.parseTree(node.value, 0, node.value.length);
        }
      }
      // Nếu là OBJECT IDENTIFIER
      else if (node.tag === 0x06) {
        node.oid = this.decodeOID(node.value);
        node.oidName = this.KNOWN_OIDS[node.oid] || 'Unknown OID';
      }

      nodes.push(node);
      cur += node.totalLen;
    }

    return nodes;
  }

  /**
   * Trích xuất thông tin khóa RSA chi tiết từ DER
   * Hỗ trợ PKCS#1 Private Key, PKCS#8 Private Key, SPKI Public Key, PKCS#1 Public Key
   */
  static inspectRSA(bytes) {
    const root = this.decodeTLV(bytes, 0);
    if (!root || root.tag !== 0x30) {
      throw new Error('Định dạng ASN.1 DER không hợp lệ (Không bắt đầu bằng SEQUENCE 0x30).');
    }

    // Đọc tất cả các trường INTEGER cấp đầu nếu là PKCS#1
    const children = this.parseTree(bytes, root.valueOffset, root.length);

    // Kiểm tra loại khóa
    // 1. PKCS#1 RSA Private Key: SEQUENCE chứa >= 9 số nguyên INTEGER
    // (version, n, e, d, p, q, dp, dq, qinv)
    const isPKCS1Private = children.length >= 9 && children.every(c => c.tag === 0x02);
    if (isPKCS1Private) {
      return this._extractPKCS1Private(children, bytes);
    }

    // 2. PKCS#8 RSA Private Key: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING }
    const octetChild = children.find(c => c.tag === 0x04);
    if (octetChild && octetChild.children && octetChild.children.length === 1 && octetChild.children[0].tag === 0x30) {
      const innerSeq = octetChild.children[0];
      const innerChildren = innerSeq.children || this.parseTree(innerSeq.value, 0, innerSeq.length);
      if (innerChildren.length >= 9 && innerChildren.every(c => c.tag === 0x02)) {
        const res = this._extractPKCS1Private(innerChildren, bytes);
        res.format = 'PKCS#8 Private Key';
        return res;
      }
    }

    // 3. SPKI RSA Public Key: SEQUENCE { AlgorithmIdentifier, BIT STRING { SEQUENCE { n, e } } }
    const bitStringChild = children.find(c => c.tag === 0x03);
    if (bitStringChild && bitStringChild.children && bitStringChild.children.length > 0) {
      const innerSeq = bitStringChild.children[0];
      if (innerSeq.children && innerSeq.children.length >= 2) {
        return this._extractRSAPublic(innerSeq.children, bytes, 'SPKI (SubjectPublicKeyInfo) Public Key');
      }
    }

    // 4. PKCS#1 RSA Public Key: SEQUENCE { INTEGER n, INTEGER e }
    if (children.length === 2 && children[0].tag === 0x02 && children[1].tag === 0x02) {
      return this._extractRSAPublic(children, bytes, 'PKCS#1 Public Key');
    }

    return {
      type: 'UNKNOWN',
      format: 'Unknown ASN.1 Structure',
      tree: children
    };
  }

  static _cleanIntBytes(bytes) {
    // Nếu có byte 0x00 đệm đầu (do số dương trong ASN.1), bỏ đi khi tính độ dài bit/hex
    if (bytes.length > 1 && bytes[0] === 0x00) {
      return bytes.subarray(1);
    }
    return bytes;
  }

  static _extractPKCS1Private(items, originalBytes) {
    const fieldNames = [
      { key: 'version', label: 'Version', desc: 'Phiên bản định dạng (0 = hai số nguyên tố tiêu chuẩn)' },
      { key: 'n', label: 'Modulus (n)', desc: 'Mô-đun công khai n = p * q (kích thước thường là 1024, 2048, 4096 bit)' },
      { key: 'e', label: 'Public Exponent (e)', desc: 'Số mũ công khai e (thường là 65537 / 0x010001, dùng để mã hóa & xác minh)' },
      { key: 'd', label: 'Private Exponent (d)', desc: 'Số mũ bí mật d = e^(-1) mod phi(n) (dùng để giải mã & ký số)' },
      { key: 'p', label: 'Prime 1 (p)', desc: 'Thừa số nguyên tố bí mật thứ nhất' },
      { key: 'q', label: 'Prime 2 (q)', desc: 'Thừa số nguyên tố bí mật thứ hai' },
      { key: 'dp', label: 'Exponent 1 (dp)', desc: 'Số mũ CRT 1: dp = d mod (p - 1) để tăng tốc giải mã' },
      { key: 'dq', label: 'Exponent 2 (dq)', desc: 'Số mũ CRT 2: dq = d mod (q - 1) để tăng tốc giải mã' },
      { key: 'qinv', label: 'Coefficient (qinv)', desc: 'Hệ số CRT: qinv = q^(-1) mod p dùng trong định lý số dư Trung Hoa' }
    ];

    const fields = {};
    const parsedFields = [];

    items.forEach((item, idx) => {
      if (idx < fieldNames.length) {
        const meta = fieldNames[idx];
        const rawBytes = item.value;
        const cleanBytes = this._cleanIntBytes(rawBytes);
        const hex = this.bytesToHex(cleanBytes);
        const bigIntVal = this.bytesToBigInt(cleanBytes);
        const bitLength = cleanBytes.length * 8;

        const info = {
          ...meta,
          startOffset: item.startOffset,
          endOffset: item.endOffset,
          length: item.length,
          hex,
          bigInt: bigIntVal,
          decimal: bigIntVal.toString(),
          bitLength,
          rawBytes
        };

        fields[meta.key] = info;
        parsedFields.push(info);
      }
    });

    return {
      type: 'PRIVATE_KEY',
      format: 'PKCS#1 RSA Private Key',
      fields,
      parsedFields,
      bitSize: fields.n ? fields.n.bitLength : 2048,
      rawBytes: originalBytes
    };
  }

  static _extractRSAPublic(items, originalBytes, format) {
    const nItem = items[0];
    const eItem = items[1];

    const cleanN = this._cleanIntBytes(nItem.value);
    const cleanE = this._cleanIntBytes(eItem.value);

    const nHex = this.bytesToHex(cleanN);
    const eHex = this.bytesToHex(cleanE);

    const nBigInt = this.bytesToBigInt(cleanN);
    const eBigInt = this.bytesToBigInt(cleanE);

    const nInfo = {
      key: 'n',
      label: 'Modulus (n)',
      desc: 'Mô-đun công khai n = p * q',
      hex: nHex,
      decimal: nBigInt.toString(),
      bitLength: cleanN.length * 8,
      startOffset: nItem.startOffset,
      endOffset: nItem.endOffset
    };

    const eInfo = {
      key: 'e',
      label: 'Public Exponent (e)',
      desc: 'Số mũ công khai (thường là 65537)',
      hex: eHex,
      decimal: eBigInt.toString(),
      bitLength: cleanE.length * 8,
      startOffset: eItem.startOffset,
      endOffset: eItem.endOffset
    };

    return {
      type: 'PUBLIC_KEY',
      format,
      fields: { n: nInfo, e: eInfo },
      parsedFields: [nInfo, eInfo],
      bitSize: nInfo.bitLength,
      rawBytes: originalBytes
    };
  }
}

// Export ra window cho trình duyệt
window.ASN1Parser = ASN1Parser;
