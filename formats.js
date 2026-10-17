// formats.js —— 多格式解密核心（NCM / KWM / XM / QMC）
// 算法均来自权威开源实现（unlock-music / MusicDecrypto / ncmdump），已用官方测试向量验证。
(function (global) {
  'use strict';

  // ---------- 通用小工具 ----------
  function readU32(buf, off) {
    return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
  }
  function readU32BE(buf, off) {
    return ((buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]) >>> 0;
  }
  function writeU32BE(buf, off, v) {
    buf[off] = (v >>> 24) & 0xff;
    buf[off + 1] = (v >>> 16) & 0xff;
    buf[off + 2] = (v >>> 8) & 0xff;
    buf[off + 3] = v & 0xff;
  }
  function asciiStr(buf) {
    let s = '';
    for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
    return s;
  }
  function base64ToBytes(b64) {
    const bin = atob(b64.replace(/\0+$/, ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---------- AES-128-ECB（用 Web Crypto 的 CBC 模拟 ECB：每个块 IV=0 独立解密） ----------
  async function aesEcbDecrypt(keyBytes, data) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('当前环境不支持 Web Crypto。解密 .ncm 需要 HTTPS（如 GitHub Pages 链接）或 localhost，直接用 file:// 双击打开会失败');
    }
    // 补齐到 16 字节的倍数（正常文件本就是 16 的倍数，这里仅作防御）
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

  // ---------- RC4（NCM 用） ----------
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

    const xored = new Uint8Array(keyLen);
    for (let i = 0; i < keyLen; i++) xored[i] = keyData[i] ^ 0x64;

    let deKey = await aesEcbDecrypt(NCM_CORE_KEY, xored);
    const pad = deKey[deKey.length - 1];
    if (pad <= 16) deKey = deKey.subarray(0, deKey.length - pad);
    const boxKey = deKey.subarray(17);

    const modLen = readU32(buf, pos); pos += 4 + modLen;
    pos += 9; // crc32 + image version
    const coverLen = readU32(buf, pos); pos += 4 + coverLen;

    const audio = buf.subarray(pos);
    return rc4Decrypt(audio, buildKeyBox(boxKey));
  }

  // ================= KWM（酷我音乐） =================
  function isKwm(buf) {
    if (!buf || buf.length < 0x400) return false;
    const m = 'yeelion-kuwo';
    for (let i = 0; i < m.length; i++) if (buf[i] !== m.charCodeAt(i)) return false;
    return true;
  }

  function decryptKwm(buf) {
    const seed = String(readU32(buf, 24));
    const root = 'MoOtOiTvINGwd2E6n0E1i7L5t2IoOoNk';
    const mask = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      mask[i] = seed.charCodeAt(i % seed.length) ^ root.charCodeAt(i);
    }
    const audio = buf.subarray(0x400);
    const out = new Uint8Array(audio.length);
    for (let i = 0; i < audio.length; i++) out[i] = audio[i] ^ mask[i % 32];
    return out;
  }

  // ================= XM（虾米音乐） =================
  function isXm(buf) {
    if (!buf || buf.length < 16) return false;
    const m = 'ifmt';
    for (let i = 0; i < 4; i++) if (buf[i] !== m.charCodeAt(i)) return false;
    return true;
  }

  function decryptXm(buf) {
    const key = buf[15];
    const audio = buf.subarray(0x10);
    const out = new Uint8Array(audio.length);
    for (let i = 0; i < audio.length; i++) out[i] = (~(audio[i] - key)) & 0xff;
    return out;
  }

  // ================= QMC（QQ 音乐：qmc0/qmc3/qmcflac/qmcogg/mflac/mgg 等） =================
  const QMC_STATIC_BOX = new Uint8Array([
    0x77, 0x48, 0x32, 0x73, 0xde, 0xf2, 0xc0, 0xc8,
    0x95, 0xec, 0x30, 0xb2, 0x51, 0xc3, 0xe1, 0xa0,
    0x9e, 0xe6, 0x9d, 0xcf, 0xfa, 0x7f, 0x14, 0xd1,
    0xce, 0xb8, 0xdc, 0xc3, 0x4a, 0x67, 0x93, 0xd6,
    0x28, 0xc2, 0x91, 0x70, 0xca, 0x8d, 0xa2, 0xa4,
    0xf0, 0x08, 0x61, 0x90, 0x7e, 0x6f, 0xa2, 0xe0,
    0xeb, 0xae, 0x3e, 0xb6, 0x67, 0xc7, 0x92, 0xf4,
    0x91, 0xb5, 0xf6, 0x6c, 0x5e, 0x84, 0x40, 0xf7,
    0xf3, 0x1b, 0x02, 0x7f, 0xd5, 0xab, 0x41, 0x89,
    0x28, 0xf4, 0x25, 0xcc, 0x52, 0x11, 0xad, 0x43,
    0x68, 0xa6, 0x41, 0x8b, 0x84, 0xb5, 0xff, 0x2c,
    0x92, 0x4a, 0x26, 0xd8, 0x47, 0x6a, 0x7c, 0x95,
    0x61, 0xcc, 0xe6, 0xcb, 0xbb, 0x3f, 0x47, 0x58,
    0x89, 0x75, 0xc3, 0x75, 0xa1, 0xd9, 0xaf, 0xcc,
    0x08, 0x73, 0x17, 0xdc, 0xaa, 0x9a, 0xa2, 0x16,
    0x41, 0xd8, 0xa2, 0x06, 0xc6, 0x8b, 0xfc, 0x66,
    0x34, 0x9f, 0xcf, 0x18, 0x23, 0xa0, 0x0a, 0x74,
    0xe7, 0x2b, 0x27, 0x70, 0x92, 0xe9, 0xaf, 0x37,
    0xe6, 0x8c, 0xa7, 0xbc, 0x62, 0x65, 0x9c, 0xc2,
    0x08, 0xc9, 0x88, 0xb3, 0xf3, 0x43, 0xac, 0x74,
    0x2c, 0x0f, 0xd4, 0xaf, 0xa1, 0xc3, 0x01, 0x64,
    0x95, 0x4e, 0x48, 0x9f, 0xf4, 0x35, 0x78, 0x95,
    0x7a, 0x39, 0xd6, 0x6a, 0xa0, 0x6d, 0x40, 0xe8,
    0x4f, 0xa8, 0xef, 0x11, 0x1d, 0xf3, 0x1b, 0x3f,
    0x3f, 0x07, 0xdd, 0x6f, 0x5b, 0x19, 0x30, 0x19,
    0xfb, 0xef, 0x0e, 0x37, 0xf0, 0x0e, 0xcd, 0x16,
    0x49, 0xfe, 0x53, 0x47, 0x13, 0x1a, 0xbd, 0xa4,
    0xf1, 0x40, 0x19, 0x60, 0x0e, 0xed, 0x68, 0x09,
    0x06, 0x5f, 0x4d, 0xcf, 0x3d, 0x1a, 0xfe, 0x20,
    0x77, 0xe4, 0xd9, 0xda, 0xf9, 0xa4, 0x2b, 0x76,
    0x1c, 0x71, 0xdb, 0x00, 0xbc, 0xfd, 0x0c, 0x6c,
    0xa5, 0x47, 0xf7, 0xf6, 0x00, 0x79, 0x4a, 0x11,
  ]);
  const QMC_V2_MAGIC = 'QQMusic EncV2,Key:';
  const QMC_V2_TEA_KEY1 = '386ZJY!@#*$%^&)(';
  const QMC_V2_TEA_KEY2 = '**#!(#$%&^a1cZ,T';

  function teaDecryptBlock(buf, off, k) {
    const delta = 0x9e3779b9;
    let vl = readU32BE(buf, off);
    let vh = readU32BE(buf, off + 4);
    let sum = (delta * 16) >>> 0;
    for (let i = 0; i < 16; i++) {
      vh = (vh - ((((((vl << 4) >>> 0) + k[2]) ^ ((vl + sum) >>> 0) ^ (((vl >>> 5) + k[3]) >>> 0)) >>> 0))) >>> 0;
      vl = (vl - ((((((vh << 4) >>> 0) + k[0]) ^ ((vh + sum) >>> 0) ^ (((vh >>> 5) + k[1]) >>> 0)) >>> 0))) >>> 0;
      sum = (sum - delta) >>> 0;
    }
    writeU32BE(buf, off, vl);
    writeU32BE(buf, off + 4, vh);
  }

  function teaCbcDecrypt(teaKeyBytes, buf) {
    const k = [readU32BE(teaKeyBytes, 0), readU32BE(teaKeyBytes, 4), readU32BE(teaKeyBytes, 8), readU32BE(teaKeyBytes, 12)];
    const length = buf.length;
    const res = new Uint8Array(buf);
    const raw = new Uint8Array(buf);

    teaDecryptBlock(res, 0, k);
    const padLength = res[0] & 0x07;

    for (let i = 8; i < length; i += 8) {
      for (let j = 0; j < 8; j++) res[i + j] ^= res[i - 8 + j];
      teaDecryptBlock(res, i, k);
    }
    for (let i = 8; i < length; i++) res[i] ^= raw[i - 8];

    const start = 1 + padLength + 2;
    const end = length - 7;
    return [res.slice(start, end), end - start];
  }

  function decryptQmcKey(value) {
    let key = base64ToBytes(value);
    let length = key.length;

    if (length >= 18 && asciiStr(key.subarray(0, 18)) === QMC_V2_MAGIC) {
      key = key.subarray(18);
      let r = teaCbcDecrypt(new TextEncoder().encode(QMC_V2_TEA_KEY1), key);
      key = r[0]; length = r[1];
      r = teaCbcDecrypt(new TextEncoder().encode(QMC_V2_TEA_KEY2), key.subarray(0, length));
      key = r[0]; length = r[1];
      key = base64ToBytes(asciiStr(key.subarray(0, length)));
      length = key.length;
    }

    const teaKey = new Uint8Array(16);
    for (let i = 0; i < 8; i++) {
      teaKey[2 * i] = Math.floor(Math.abs(Math.tan(106 + i * 0.1)) * 100) & 0xff;
      teaKey[2 * i + 1] = key[i];
    }
    const r2 = teaCbcDecrypt(teaKey, key.subarray(8));
    return key.slice(0, r2[1] + 8);
  }

  function staticCipherDecrypt(audio) {
    const out = new Uint8Array(audio.length);
    for (let i = 0; i < audio.length; i++) {
      let index = i;
      if (index > 0x7fff) index %= 0x7fff;
      out[i] = audio[i] ^ QMC_STATIC_BOX[(index * index + 0x1b) & 0xff];
    }
    return out;
  }

  function mapCipherDecrypt(audio, key) {
    const boxSize = key.length;
    const out = new Uint8Array(audio.length);
    for (let i = 0; i < audio.length; i++) {
      let index = i;
      if (index > 0x7fff) index %= 0x7fff;
      const i_b = (index * index + 71214) % boxSize;
      const rotate = ((i_b & 0x07) + 4) % 8;
      out[i] = audio[i] ^ (((key[i_b] << rotate) | (key[i_b] >>> rotate)) & 0xff);
    }
    return out;
  }

  function rc4CipherDecrypt(data, key) {
    const size = key.length;
    const headerSize = 128;
    const blockSize = 5120;

    const box = new Uint8Array(size);
    for (let i = 0; i < size; i++) box[i] = i;
    let j = 0;
    for (let i = 0; i < size; i++) {
      j = (j + box[i] + key[i]) % size;
      const t = box[i]; box[i] = box[j]; box[j] = t;
    }

    let hash = 1;
    for (let i = 0; j < size && i < size; i++) {
      if (key[i] === 0) continue;
      const next = (hash * key[i]) >>> 0;
      if (next === 0 || next <= hash) break;
      hash = next;
    }

    const offsetCache = new Int32Array(blockSize);
    const getOffset = (index) => {
      const sum = Math.floor(hash / ((index + 1) * key[index % size]) * 100);
      return sum % size;
    };
    for (let i = 0; i < blockSize; i++) offsetCache[i] = getOffset(i);
    const getCachedOffset = (index) => (index < blockSize ? offsetCache[index] : getOffset(index));

    const out = new Uint8Array(data.length);
    const decryptBlock = (pos, offset, len) => {
      let jj = 0, kk = 0;
      const localBox = new Uint8Array(box);
      const skipLength = (offset % blockSize) + getCachedOffset(Math.floor(offset / blockSize));
      for (let i = -skipLength; i < len; i++) {
        jj = (jj + 1) % size;
        kk = (localBox[jj] + kk) % size;
        const t = localBox[jj]; localBox[jj] = localBox[kk]; localBox[kk] = t;
        if (i >= 0) out[pos + i] = data[pos + i] ^ localBox[(localBox[jj] + localBox[kk]) % size];
      }
    };

    let pos = 0, offset = 0;
    if (data.length > 0) {
      const sz = Math.min(headerSize, data.length);
      for (let i = 0; i < sz; i++) out[i] = data[i] ^ key[getCachedOffset(i)];
      pos = sz; offset = sz;
    }
    if (pos < data.length && offset % blockSize !== 0) {
      const sz = Math.min(blockSize - (offset % blockSize), data.length - pos);
      decryptBlock(pos, offset, sz);
      pos += sz; offset += sz;
    }
    while (data.length - pos >= blockSize) {
      decryptBlock(pos, offset, blockSize);
      pos += blockSize; offset += blockSize;
    }
    if (pos < data.length) {
      decryptBlock(pos, offset, data.length - pos);
    }
    return out;
  }

  function isQmc(ext) {
    const e = (ext || '').toLowerCase();
    const exts = ['.qmc0', '.qmc2', '.qmc3', '.qmc4', '.qmc6', '.qmc8', '.qmcflac', '.qmcogg', '.tkm',
      '.mflac', '.mflac0', '.mgg', '.mgg1', '.mggl', '.mmp4',
      '.bkcmp3', '.bkcflac', '.bkcogg', '.bkcwav', '.bkcape', '.bkcm4a', '.bkcwma'];
    return exts.includes(e);
  }

  function decryptQmc(buf) {
    if (buf.length < 8) throw new Error('文件太小');
    const indicator = readU32(buf, buf.length - 4);
    let key = null;
    let length = buf.length;

    if (indicator === 0x67615451) { // "QTag"
      const chunkLength = readU32BE(buf, buf.length - 8);
      length = buf.length - 8 - chunkLength;
      const metaStr = asciiStr(buf.subarray(length, length + chunkLength));
      key = decryptQmcKey(metaStr.split(',')[0]);
    } else if (indicator > 0 && indicator < 0x400) {
      length = buf.length - 4 - indicator;
      key = decryptQmcKey(asciiStr(buf.subarray(length, length + indicator)));
    } else {
      length = buf.length - 4;
      key = null;
    }

    const audio = buf.subarray(0, length);
    if (key === null) return staticCipherDecrypt(audio);
    else if (key.length > 300) return rc4CipherDecrypt(audio, key);
    else return mapCipherDecrypt(audio, key);
  }

  global.Formats = {
    isNcm, decryptNcm,
    isKwm, decryptKwm,
    isXm, decryptXm,
    isQmc, decryptQmc,
  };
})(typeof window !== 'undefined' ? window : self);
