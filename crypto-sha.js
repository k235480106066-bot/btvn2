/**
 * Module Băm SHA-256 và Trực Quan Hoá Hiệu Ứng Thác Lũ (Avalanche Effect)
 * Phân tích sự thay đổi cấp độ bit giữa 2 chuỗi đầu vào gần giống nhau.
 */

class CryptoSHA {
  /**
   * Tính băm SHA-256 cho chuỗi văn bản UTF-8
   */
  static async hashString(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const bytes = new Uint8Array(hashBuffer);

    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const binary = Array.from(bytes).map(b => b.toString(2).padStart(8, '0')).join('');

    return {
      bytes,
      hex,
      binary,
      bitLength: 256,
      inputLength: data.length
    };
  }

  /**
   * Phân tích so sánh hiệu ứng thác lũ giữa 2 đầu vào
   */
  static async compareAvalanche(inputA, inputB) {
    const hashA = await this.hashString(inputA);
    const hashB = await this.hashString(inputB);

    let diffBitsCount = 0;
    const bitComparison = [];

    for (let i = 0; i < 256; i++) {
      const bitA = hashA.binary[i];
      const bitB = hashB.binary[i];
      const isDiff = bitA !== bitB;
      if (isDiff) diffBitsCount++;

      bitComparison.push({
        index: i,
        byteIndex: Math.floor(i / 8),
        bitInByte: i % 8,
        bitA,
        bitB,
        isDiff
      });
    }

    const diffPercent = ((diffBitsCount / 256) * 100).toFixed(2);

    // Tính độ khác nhau của đầu vào (Input Hamming distance)
    const encA = new TextEncoder().encode(inputA);
    const encB = new TextEncoder().encode(inputB);
    let inputBitDiff = 0;
    const maxLen = Math.max(encA.length, encB.length);
    for (let i = 0; i < maxLen; i++) {
      const bA = encA[i] || 0;
      const bB = encB[i] || 0;
      let xor = bA ^ bB;
      while (xor > 0) {
        if (xor & 1) inputBitDiff++;
        xor >>= 1;
      }
    }

    return {
      inputA,
      inputB,
      inputBitDiff,
      hashA,
      hashB,
      diffBitsCount,
      diffPercent,
      bitComparison,
      evaluation: this.evaluateAvalanche(diffBitsCount, diffPercent)
    };
  }

  static evaluateAvalanche(diffCount, diffPercent) {
    let rating = 'Lý tưởng (Strict Avalanche Criterion - SAC)';
    let badgeColor = 'success';

    if (diffPercent >= 45 && diffPercent <= 55) {
      rating = 'Hoàn hảo (~50% bit thay đổi theo lý thuyết)';
    } else if (diffPercent >= 40 && diffPercent <= 60) {
      rating = 'Rất tốt (Hiệu ứng thác lũ mạnh mẽ)';
    } else {
      rating = 'Chấp nhận được';
    }

    return {
      rating,
      badgeColor,
      summary: `Khi đầu vào chỉ thay đổi rất ít (thậm chí chỉ 1 bit), có ${diffCount} / 256 bit của mã băm SHA-256 bị đảo ngược (${diffPercent}%).`,
      scientificTheory: `Hiệu ứng thác lũ (Avalanche Effect): Trong hàm băm mật mã học lý tưởng, nếu một bit đầu vào bị thay đổi, mỗi bit đầu ra phải thay đổi với xác suất 50% (Strict Avalanche Criterion - SAC). Thuật toán SHA-256 đạt được điều này nhờ 64 vòng lặp nén phi tuyến tính với các phép toán XOR, AND, OR, phép quay vòng bit (ROTR) và cộng modulo 2^32. Do đó, kẻ tấn công hoàn toàn KHÔNG THỂ dựa vào sự tương đồng của chuỗi băm để suy đoán dữ liệu gốc!`
    };
  }

  /**
   * Tạo chuỗi B bằng cách đảo đúng 1 bit ở ký tự cuối của chuỗi A
   */
  static flipOneBit(input) {
    if (!input || input.length === 0) return 'A';
    const codes = Array.from(input).map(c => c.charCodeAt(0));
    // Đảo bit thấp nhất (bit 0) của ký tự cuối
    codes[codes.length - 1] ^= 1;
    return String.fromCharCode(...codes);
  }
}

window.CryptoSHA = CryptoSHA;
