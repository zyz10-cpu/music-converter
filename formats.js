// formats.js —— 网易云 NCM 解密核心
// 算法移植自 ncmdump / unlock-music，已用官方测试向量验证。
(function (global) {
  'use strict';

  // ---------- 通用小工具 ----------
  function readU32(buf, off) {
    return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
  }

  // ---------- 手写 AES-128（纯 JS，与官方测试向量一致，避免 Web Crypto 兼容问题） ----------
  function gfMul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hi = a & 0x80;
      a = (a << 1) & 0xff;
      if (hi) a ^= 0x1b;
      b >>= 1;
    }
    return p;
  }

  function gfPow(a, n) {
    let r = 1;
    while (n) {
      if (n & 1) r = gfMul(r, a);
      a = gfMul(a, a);
      n >>= 1;
    }
    return r;
  }

  function rotl8(x, n) { return ((x << n) | (x >> (8 - n))) & 0xff; }

  const AES_SBOX = (() => {
    const s = new Uint8Array(256);
    for (let x = 0; x < 256; x++) {
      const inv = gfPow(x, 254);
      let v = inv;
      for (let i = 1; i < 5; i++) v ^= rotl8(inv, i);
      s[x] = v ^ 0x63;
    }
    return s;
  })();

  const AES_INV_SBOX = (() => {
    const inv = new Uint8Array(256);
    for (let i = 0; i < 256; i++) inv[AES_SBOX[i]] = i;
    return inv;
  })();

  const AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

  function aesKeyExpansion(key) {
    const w = [];
    for (let i = 0; i < 4; i++) w.push([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    for (let i = 4; i < 44; i++) {
      let temp = w[i - 1].slice();
      if (i % 4 === 0) {
        temp = [temp[1], temp[2], temp[3], temp[0]];
        temp = temp.map((b) => AES_SBOX[b]);
        temp[0] ^= AES_RCON[i / 4 - 1];
      }
      w.push([w[i - 4][0] ^ temp[0], w[i - 4][1] ^ temp[1], w[i - 4][2] ^ temp[2], w[i - 4][3] ^ temp[3]]);
    }
    return w;
  }

  function aesDecryptBlock(block, w) {
    let state = Array.from(block);
    const invShiftRows = (s) => {
      const ns = new Array(16);
      for (let r = 0; r < 4; r++)
        for (let c = 0; c < 4; c++)
          ns[r + 4 * c] = s[r + 4 * ((c - r + 4) % 4)];
      return ns;
    };
    const invMixColumns = (s) => {
      const ns = new Array(16);
      for (let c = 0; c < 4; c++) {
        const s0 = s[4 * c], s1 = s[4 * c + 1], s2 = s[4 * c + 2], s3 = s[4 * c + 3];
        ns[4 * c] = gfMul(s0, 14) ^ gfMul(s1, 11) ^ gfMul(s2, 13) ^ gfMul(s3, 9);
        ns[4 * c + 1] = gfMul(s0, 9) ^ gfMul(s1, 14) ^ gfMul(s2, 11) ^ gfMul(s3, 13);
        ns[4 * c + 2] = gfMul(s0, 13) ^ gfMul(s1, 9) ^ gfMul(s2, 14) ^ gfMul(s3, 11);
        ns[4 * c + 3] = gfMul(s0, 11) ^ gfMul(s1, 13) ^ gfMul(s2, 9) ^ gfMul(s3, 14);
      }
      return ns;
    };
    // 初始 AddRoundKey（第 10 轮）
    for (let i = 0; i < 16; i++) state[i] ^= w[40 + (i >> 2)][i & 3];
    for (let rnd = 9; rnd >= 1; rnd--) {
      state = invShiftRows(state);
      for (let i = 0; i < 16; i++) state[i] = AES_INV_SBOX[state[i]];
      for (let i = 0; i < 16; i++) state[i] ^= w[rnd * 4 + (i >> 2)][i & 3];
      state = invMixColumns(state);
    }
    state = invShiftRows(state);
    for (let i = 0; i < 16; i++) state[i] = AES_INV_SBOX[state[i]];
    for (let i = 0; i < 16; i++) state[i] ^= w[(i >> 2)][i & 3];
    return Uint8Array.from(state);
  }

  function aesEcbDecrypt(keyBytes, data) {
    const w = aesKeyExpansion(keyBytes);
    const paddedLen = Math.ceil(data.length / 16) * 16;
    const padded = new Uint8Array(paddedLen);
    padded.set(data);
    const out = new Uint8Array(paddedLen);
    for (let i = 0; i < paddedLen / 16; i++) {
      out.set(aesDecryptBlock(padded.slice(i * 16, i * 16 + 16), w), i * 16);
    }
    return out.subarray(0, data.length);
  }

  // ---------- RC4 ----------
  function buildKeyBox(key) {
    const box = new Uint8Array(256);
    for (let i = 0; i < 256; i++) box[i] = i;
    let c = 0, lastByte = 0, keyOffset = 0;
    const keyLen = key.length;
    for (let i = 0; i < 256; i++) {
      c = (box[i] + lastByte + key[keyOffset]) & 0xff;
      keyOffset++;
      if (keyOffset >= keyLen) keyOffset = 0;
      const t = box[i]; box[i] = box[c]; box[c] = t;
      lastByte = c;
    }
    return box;
  }

  function rc4Decrypt(audio, box) {
    const out = new Uint8Array(audio.length);
    for (let i = 0; i < audio.length; i++) {
      const j = (i + 1) & 0xff;
      out[i] = audio[i] ^ box[(box[j] + box[(box[j] + j) & 0xff]) & 0xff];
    }
    return out;
  }

  // ================= NCM（网易云音乐） =================
  const NCM_CORE_KEY = new Uint8Array([0x68, 0x7A, 0x48, 0x52, 0x41, 0x6D, 0x73, 0x6F, 0x35, 0x6B, 0x49, 0x6E, 0x62, 0x61, 0x78, 0x57]);

  function isNcm(buf) {
    if (!buf || buf.length < 8) return false;
    const m = 'CTENFDAM';
    for (let i = 0; i < 8; i++) if (buf[i] !== m.charCodeAt(i)) return false;
    return true;
  }

  async function decryptNcm(buf) {
    if (!isNcm(buf)) throw new Error('不是有效的 NCM 文件（文件头魔数不匹配）');
    let pos = 10; // 魔数(8) + gap(2)
    const keyLen = readU32(buf, pos); pos += 4;
    if (keyLen <= 0 || keyLen > 0x100000 || pos + keyLen > buf.length) {
      throw new Error('NCM 密钥块长度异常（keyLen=' + keyLen + '，文件大小=' + buf.length + '）');
    }
    const keyData = buf.subarray(pos, pos + keyLen); pos += keyLen;

    // 自动识别是否需要对密钥做 XOR 0x64（兼容不同版本 NCM）
    const NCM_PREFIX = 'neteasecloudmusic';
    let deKey = null;
    let lastErr = null;
    for (const xor64 of [true, false]) {
      const xored = new Uint8Array(keyLen);
      for (let i = 0; i < keyLen; i++) xored[i] = keyData[i] ^ (xor64 ? 0x64 : 0);
      try {
        let dk = await aesEcbDecrypt(NCM_CORE_KEY, xored);
        const pad = dk[dk.length - 1];
        if (pad <= 16) dk = dk.subarray(0, dk.length - pad);
        if (dk.length >= 17) {
          let ok = true;
          for (let i = 0; i < 17; i++) if (dk[i] !== NCM_PREFIX.charCodeAt(i)) { ok = false; break; }
          if (ok) { deKey = dk; break; }
        }
      } catch (e) {
        lastErr = e;
      }
    }
    if (!deKey) {
      const detail = lastErr && lastErr.message ? lastErr.message : '无法识别密钥头';
      throw new Error('NCM 密钥解密失败（keyLen=' + keyLen + '，文件大小=' + buf.length + '，错误=' + detail + '）');
    }
    const boxKey = deKey.subarray(17);

    const modLen = readU32(buf, pos);
    pos += 4 + modLen;
    pos += 9; // crc32 + image version
    if (pos + 4 > buf.length) throw new Error('NCM 文件结构异常（modifyData 越界）');
    const coverLen = readU32(buf, pos);
    pos += 4 + coverLen;
    if (pos > buf.length) throw new Error('NCM 文件结构异常（cover 越界）');

    const audio = buf.subarray(pos);
    return rc4Decrypt(audio, buildKeyBox(boxKey));
  }

  global.Formats = { isNcm, decryptNcm };
})(typeof window !== 'undefined' ? window : self);
