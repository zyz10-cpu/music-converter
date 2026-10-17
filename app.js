// 主逻辑：UI 交互 + 解密编排（Web Worker）+ 转码编排
// 解密函数 isKgm/decrypt/sniffFormat 来自 kgm.js，Formats.decryptNcm 来自 formats.js
// 重活在 decrypt-worker.js（后台线程）里跑，主线程只刷进度，界面不卡死。

const KEY_URL = './kugou_key.gz';

// ffmpeg 转码引擎的 CDN 候选源，按顺序自动探测（jsdelivr 在国内经常被墙，必须有备用）
const CDN_BASES = [
  'https://fastly.jsdelivr.net/npm',
  'https://gcore.jsdelivr.net/npm',
  'https://cdn.jsdelivr.net/npm',
  'https://unpkg.com',
];
const FFMPEG_VER = '@ffmpeg/ffmpeg@0.12.10';
const FFMPEG_UTIL_VER = '@ffmpeg/util@0.12.1';
const FFMPEG_CORE_VER = '@ffmpeg/core@0.12.6';

const MIME = { mp3: 'audio/mpeg', flac: 'audio/flac', ogg: 'audio/ogg', wav: 'audio/wav', aac: 'audio/aac', m4a: 'audio/mp4' };

const statusEl = document.getElementById('status');
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const pickBtn = document.getElementById('pickBtn');
const formatSel = document.getElementById('format');
const bitrateSel = document.getElementById('bitrate');
const bitrateField = document.getElementById('bitrateField');
const fileList = document.getElementById('fileList');

let keyTable = null;
let ffmpeg = null;
let ffmpegLoading = null;
let cdnBasePromise = null;

function setStatus(msg) { statusEl.textContent = msg; }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function withTimeout(promise, ms, label) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label + '超时（' + Math.round(ms / 1000) + ' 秒）')), ms)),
  ]);
}

async function loadKeyTable() {
  setStatus('正在加载解密密钥表（12MB，首次较慢，之后走缓存）…');
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('当前浏览器不支持 DecompressionStream，请升级到较新版本浏览器');
  }
  let gzBytes;
  if (typeof window.__KGM_KEY_B64__ === 'string' && window.__KGM_KEY_B64__.length > 0) {
    // 单文件版：使用内嵌的 base64 密钥表（gzip）
    const bin = atob(window.__KGM_KEY_B64__);
    gzBytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) gzBytes[i] = bin.charCodeAt(i);
  } else {
    const res = await withTimeout(fetch(KEY_URL), 60000, '密钥表下载');
    if (!res.ok) {
      throw new Error('密钥表加载失败（HTTP ' + res.status + '）。请通过 HTTP 方式访问，或使用单文件版。');
    }
    gzBytes = new Uint8Array(await res.arrayBuffer());
  }
  const stream = new Blob([gzBytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  const buf = await new Response(stream).arrayBuffer();
  keyTable = new Uint8Array(buf);
  if (keyTable.length !== 73155904) {
    throw new Error('密钥表大小异常（' + keyTable.length + '），文件可能损坏');
  }
  setStatus('✅ 密钥表已就绪，可以拖入文件开始转换。');
  return keyTable;
}

let keyTablePromise = null;
async function getKeyTable() {
  if (keyTable) return keyTable;
  if (!keyTablePromise) {
    keyTablePromise = loadKeyTable().then(() => keyTable).catch((e) => { keyTablePromise = null; throw e; });
  }
  return keyTablePromise;
}

// ---------- 解密 Worker ----------
let decryptWorker = null;
let workerTaskId = 0;
let workerHasKey = false;

function getDecryptWorker() {
  if (decryptWorker === null) {
    try {
      decryptWorker = new Worker('./decrypt-worker.js');
    } catch (e) {
      decryptWorker = false; // file:// 或单文件版等场景禁用 Worker，回退主线程
    }
  }
  return decryptWorker || null;
}

function runWorkerTask(worker, msg, transfers, onProgress) {
  return new Promise((resolve, reject) => {
    const id = ++workerTaskId;
    const handler = (e) => {
      const d = e.data;
      if (!d || d.id !== id) return;
      if (typeof d.progress === 'number') {
        if (onProgress) onProgress(d.progress);
        return;
      }
      worker.removeEventListener('message', handler);
      if (d.error) reject(new Error(d.error));
      else resolve(d);
    };
    worker.addEventListener('message', handler);
    worker.postMessage(Object.assign({ id }, msg), transfers);
  });
}

async function decryptByFormat(buf, ext, onProgress) {
  const kgmByMagic = isKgm(buf);
  const kgmLike = ext === '.kgm' || ext === '.kgma' || kgmByMagic;
  const ncmLike = !kgmLike && (ext === '.ncm' || Formats.isNcm(buf));
  if (!kgmLike && !ncmLike) throw new Error('无法识别的加密格式（支持 kgm/kgma/ncm）');
  if (kgmLike && !kgmByMagic) throw new Error('不是有效的 KGM/KGMA 文件（文件头不匹配）');

  const worker = getDecryptWorker();
  if (worker) {
    if (kgmLike) {
      const kt = await getKeyTable();
      const msg = { type: 'kgm', buf: buf.buffer };
      const transfers = [buf.buffer];
      if (!workerHasKey) {
        msg.keyTable = kt.buffer.slice(0); // 复制一份转移给 Worker 缓存，主线程保留原件
        transfers.push(msg.keyTable);
        workerHasKey = true;
      }
      const r = await runWorkerTask(worker, msg, transfers, onProgress);
      return new Uint8Array(r.result);
    }
    const r = await runWorkerTask(worker, { type: 'ncm', buf: buf.buffer }, [buf.buffer], onProgress);
    return new Uint8Array(r.result);
  }
  // 回退：主线程解密（循环里已分批让出事件循环，界面不会死，只是略慢）
  if (kgmLike) return decrypt(buf, await getKeyTable(), onProgress);
  return Formats.decryptNcm(buf, onProgress);
}

// ---------- ffmpeg 转码引擎（按需加载，多 CDN 自动切换） ----------
async function pickCDN() {
  if (!cdnBasePromise) {
    cdnBasePromise = (async () => {
      for (const base of CDN_BASES) {
        try {
          const res = await withTimeout(
            fetch(base + '/' + FFMPEG_CORE_VER + '/package.json', { method: 'HEAD' }),
            8000,
            'CDN 探测'
          );
          if (res.ok) return base;
        } catch (e) {
          // 当前源不可达，试下一个
        }
      }
      throw new Error('所有 CDN 均无法访问，请检查网络');
    })();
    cdnBasePromise.catch(() => { cdnBasePromise = null; });
  }
  return cdnBasePromise;
}

async function getFFmpeg() {
  if (ffmpeg) return ffmpeg;
  if (ffmpegLoading) return ffmpegLoading;
  ffmpegLoading = (async () => {
    setStatus('正在选择可用的转码引擎源…');
    const base = await pickCDN();
    setStatus('正在加载 ffmpeg 转码引擎（约 25MB，仅转码时需要，源：' + base + '）…');
    const [{ FFmpeg }, { toBlobURL }] = await withTimeout(
      Promise.all([
        import(base + '/' + FFMPEG_VER + '/dist/esm/index.js'),
        import(base + '/' + FFMPEG_UTIL_VER + '/dist/esm/index.js'),
      ]),
      60000,
      'ffmpeg 模块加载'
    );
    const instance = new FFmpeg();
    const coreBase = base + '/' + FFMPEG_CORE_VER + '/dist/umd';
    await withTimeout(
      instance.load({
        coreURL: await toBlobURL(coreBase + '/ffmpeg-core.js', 'text/javascript'),
        wasmURL: await toBlobURL(coreBase + '/ffmpeg-core.wasm', 'application/wasm'),
        classWorkerURL: await toBlobURL(base + '/' + FFMPEG_VER + '/dist/esm/worker.js', 'text/javascript'),
      }),
      120000,
      'ffmpeg 内核加载'
    );
    ffmpeg = instance;
    setStatus('✅ 转码引擎已就绪。');
    return instance;
  })();
  try {
    return await ffmpegLoading;
  } catch (e) {
    ffmpegLoading = null;
    throw new Error(
      'ffmpeg 引擎加载失败：' + (e && e.message ? e.message : e) +
      '。可直接选「原始格式」输出（只解密不转码，秒出，不受网络影响）。'
    );
  }
}

function makeDownloadUrl(data, ext) {
  const blob = new Blob([data], { type: MIME[ext] || 'application/octet-stream' });
  return URL.createObjectURL(blob);
}

function triggerDownload(url, filename) {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function ensureFormat(target, srcExt, audio) {
  // 「原始格式」或与源格式相同时，直接输出解密结果，不需要 ffmpeg
  if (target === 'original' || target === srcExt) return { ext: srcExt, data: audio, transcoded: false };
  const inst = await getFFmpeg();
  const inName = 'in.' + srcExt;
  const outName = 'out.' + target;
  await inst.writeFile(inName, audio);
  const args = ['-i', inName, '-vn', '-y'];
  if (target === 'mp3') args.push('-c:a', 'libmp3lame', '-b:a', bitrateSel.value + 'k');
  else if (target === 'flac') args.push('-c:a', 'flac');
  else if (target === 'wav') args.push('-c:a', 'pcm_s16le');
  else if (target === 'aac') args.push('-c:a', 'aac', '-b:a', bitrateSel.value + 'k');
  args.push(outName);
  await inst.exec(args);
  const data = await inst.readFile(outName);
  await inst.deleteFile(inName).catch(() => {});
  await inst.deleteFile(outName).catch(() => {});
  return { ext: target, data: new Uint8Array(data), transcoded: true };
}

// ---------- 单文件处理 ----------
async function processFile(file) {
  const li = document.createElement('li');
  li.className = 'file-item';
  li.innerHTML =
    '<div class="file-name">' + escapeHtml(file.name) + '</div>' +
    '<div class="file-status">处理中…</div>' +
    '<div class="file-meta"></div>' +
    '<div class="dl-links"></div>';
  fileList.prepend(li);

  const statusNode = li.querySelector('.file-status');
  const metaNode = li.querySelector('.file-meta');
  const linksNode = li.querySelector('.dl-links');

  try {
    const buf = new Uint8Array(await file.arrayBuffer());
    const ext = file.name.slice(file.name.lastIndexOf('.')).toLowerCase();

    statusNode.textContent = '正在解密… 0%';
    const audio = await decryptByFormat(buf, ext, (p) => {
      statusNode.textContent = '正在解密… ' + Math.round(p * 100) + '%';
    });
    const srcExt = sniffFormat(audio);
    const baseName = file.name.replace(/\.[^.]+$/, '');

    const fmt = formatSel.value;
    const needTranscode = fmt !== 'original' && fmt !== srcExt;
    if (needTranscode) {
      statusNode.textContent = '正在转码（首次需联网加载 ffmpeg 引擎，约 25MB）…';
    }
    const output = await ensureFormat(fmt, srcExt, audio);

    metaNode.textContent =
      '已转换 → ' + baseName + '.' + output.ext +
      '（源格式：' + srcExt.toUpperCase() + (output.transcoded ? '，已转码' : '，仅解密') + '）';

    const url = makeDownloadUrl(output.data, output.ext);
    const a = document.createElement('a');
    a.href = url;
    a.download = baseName + '.' + output.ext;
    a.className = 'dl-link';
    a.textContent = '下载 ' + output.ext.toUpperCase();
    linksNode.appendChild(a);

    triggerDownload(url, a.download);
    setTimeout(() => URL.revokeObjectURL(url), 60000); // 60 秒后释放内存

    statusNode.textContent = '完成 ✅';
    statusNode.classList.add('ok');
  } catch (e) {
    statusNode.textContent = '失败：' + (e && e.message ? e.message : e);
    statusNode.classList.add('err');
  }
}

async function handleFiles(files) {
  const arr = Array.from(files);
  if (arr.length === 0) return;
  for (const file of arr) {
    await processFile(file);
  }
  setStatus('处理完成。');
}

// ---------- 事件绑定 ----------
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag'));
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag');
  handleFiles(e.dataTransfer.files);
});
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    fileInput.click();
  }
});
pickBtn.addEventListener('click', (e) => {
  e.stopPropagation();
  fileInput.click();
});
fileInput.addEventListener('change', () => {
  handleFiles(fileInput.files);
  fileInput.value = '';
});

function syncBitrateVisibility() {
  bitrateField.style.display = formatSel.value === 'mp3' || formatSel.value === 'aac' ? '' : 'none';
}
formatSel.addEventListener('change', syncBitrateVisibility);
syncBitrateVisibility();

// ---------- 启动 ----------
setStatus('就绪。拖入 .kgm/.kgma/.ncm 文件开始转换。');
// 后台预加载酷狗密钥表（同源 12MB，很快）；ffmpeg 引擎改为转码时按需加载
getKeyTable().catch(() => {});
