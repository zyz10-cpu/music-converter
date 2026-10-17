// formats.js —— 网易云 NCM 解密核心
// 算法移植自 ncmdump / unlock-music，已用官方测试向量验证。
(function (global) {
  'use strict';

  // ---------- 通用小工具 ----------
  function readU32(buf, off) {
    return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
  }

  // ---------- AES-128-ECB（用 Web Crypto 的 CBC 模拟 ECB：每块 IV=0 独立解密） ----------
  async function aesEcbDecrypt(keyBytes, data) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('当前环境不支持 Web Crypto。解密 .ncm 需要 HTTPS（如 GitHub Pages 链接）或 localhost');
    }
    const paddedLen = Math.ceil(data.length / 16) * 16;
    const padded = new Uint8Array(paddedLen);
    padded.set(data);
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
    const iv = new Uint8Array(16);
    const out = new Uint8Array(paddedLen);
    for (let i = 0; i < paddedLen / 16; i++) {
      const dec = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-CBC', iv }, key, padded.subarray(i * 16, i * 16 + 16)));
      out.set(dec, i * 16);
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
    for (const xor64 of [true, false]) {
      const xored = new Uint8Array(keyLen);
      for (let i = 0; i < keyLen; i++) xored[i] = keyData[i] ^ (xor64 ? 0x64 : 0);
      let dk = await aesEcbDecrypt(NCM_CORE_KEY, xored);
      const pad = dk[dk.length - 1];
      if (pad <= 16) dk = dk.subarray(0, dk.length - pad);
      if (dk.length >= 17) {
        let ok = true;
        for (let i = 0; i < 17; i++) if (dk[i] !== NCM_PREFIX.charCodeAt(i)) { ok = false; break; }
        if (ok) { deKey = dk; break; }
      }
    }
    if (!deKey) throw new Error('NCM 密钥解密失败：无法识别密钥头（文件可能损坏或为新版格式）');
    const boxKey = deKey.subarray(17);

    const modLen = readU32(buf, pos); pos += 4 + modLen;
    pos += 9; // crc32 + image version
    const coverLen = readU32(buf, pos); pos += 4 + coverLen;

    const audio = buf.subarray(pos);
    return rc4Decrypt(audio, buildKeyBox(boxKey));
  }

  global.Formats = { isNcm, decryptNcm };
})(typeof window !== 'undefined' ? window : self);
