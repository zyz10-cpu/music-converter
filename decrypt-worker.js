// decrypt-worker.js —— 解密专用后台线程
// 把 NCM（RC4）和 KGM/KGMA（XOR 掩码）的逐字节大循环放到 Worker 里跑，
// 主线程只负责刷新进度，界面不再假死。
/* global importScripts, decrypt, Formats */
importScripts('./kgm.js', './formats.js');

let cachedKeyTable = null; // 酷狗 73MB 密钥表，只需从主线程收一次

self.onmessage = async (e) => {
  const d = e.data;
  const report = (p) => self.postMessage({ id: d.id, progress: p });
  try {
    if (d.type === 'kgm') {
      if (d.keyTable) cachedKeyTable = new Uint8Array(d.keyTable);
      if (!cachedKeyTable) throw new Error('密钥表未就绪');
      const out = await decrypt(new Uint8Array(d.buf), cachedKeyTable, report);
      self.postMessage({ id: d.id, result: out.buffer }, [out.buffer]);
      return;
    }
    if (d.type === 'ncm') {
      const out = await Formats.decryptNcm(new Uint8Array(d.buf), report);
      self.postMessage({ id: d.id, result: out.buffer }, [out.buffer]);
      return;
    }
    throw new Error('未知任务类型：' + d.type);
  } catch (err) {
    self.postMessage({ id: d.id, error: String(err && err.message ? err.message : err) });
  }
};
