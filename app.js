// 主逻辑：UI 交互 + 解密编排（Web Worker）+ 转码编排（直连 ffmpeg Worker）
// 解密函数 isKgm/decrypt/sniffFormat 来自 kgm.js，Formats.decryptNcm 来自 formats.js
// 转码不走 ffmpeg 官方封装层（classes.js 那套模块链太脆），
// 而是自己实现精简客户端，直接与 ffmpeg-worker-bundle.js 通信。

const KEY_URL = './kugou_key.gz';

// ffmpeg 核心库的 CDN 候选源（仅内置引擎缺失时兜底；经典 Worker 的 importScripts 不受跨域限制）
const CDN_CANDIDATES = [
  {
    name: 'npmmirror 国内镜像',
    file: (pkg, ver, p) => 'https://registry.npmmirror.com/' + pkg + '/' + ver + '/files/' + p,
  },
  {
    name: 'fastly.jsdelivr',
    file: (pkg, ver, p) => 'https://fastly.jsdelivr.net/npm/' + pkg + '@' + ver + '/' + p,
  },
  {
    name: 'gcore.jsdelivr',
    file: (pkg, ver, p) => 'https://gcore.jsdelivr.net/npm/' + pkg + '@' + ver + '/' + p,
  },
  {
    name: 'unpkg',
    file: (pkg, ver, p) => 'https://unpkg.com/' + pkg + '@' + ver + '/' + p,
  },
];
const PKG_CORE = ['@ffmpeg/core', '0.12.6'];

const MIME = { mp3: 'audio/mpeg', flac: 'audio/flac', ogg: 'audio/ogg', wav: 'audio/wav', aac: 'audio/aac', m4a: 'audio/mp4' };

// 无加密普通音频格式：直接读取，跳过解密，进入转码/直通流程
const PLAIN_EXTS = { '.flac': 'flac', '.mp3': 'mp3', '.wav': 'wav', '.aac': 'aac', '.m4a': 'm4a', '.ogg': 'ogg' };

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

// 站点部署在子路径（/music-converter/）下，一律用页面地址合成绝对 URL，杜绝路径拼接错误。
function pageURL(p) { return new URL(p, document.baseURI).href; }

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
  if (!kgmLike && !ncmLike) throw new Error('无法识别的加密格式（加密支持 kgm/kgma/ncm；普通音频 FLAC/MP3/WAV/AAC/M4A/OGG 可直接拖入互转）');
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

// ---------- ffmpeg 转码引擎（精简客户端，直连 Worker，无官方封装层） ----------
async function gunzipToBlobURL(url, type, onProgress) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(url + ' 加载失败（HTTP ' + res.status + '）');
  const total = parseInt(res.headers.get('content-length') || '0', 10);
  const reader = res.body.getReader();
  const chunks = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    if (onProgress && total > 0) onProgress(received / total);
  }
  const stream = new Blob(chunks).stream().pipeThrough(new DecompressionStream('gzip'));
  const buf = await new Response(stream).arrayBuffer();
  return URL.createObjectURL(new Blob([buf], { type }));
}

// 精简 ffmpeg 客户端：与 ffmpeg-worker-bundle.js 直接约定 {id, type, data} 协议。
// 经典 Worker 的 importScripts 可以加载 UMD 版核心库并挂全局变量（模块 Worker 做不到），
// 且 importScripts 跨域不需要 CORS —— CDN 兜底因此也可靠。
function createCoreClient() {
  const worker = new Worker(pageURL('ffmpeg-worker-bundle.js'));
  const client = {
    worker,
    seq: 0,
    pending: new Map(),
    onProgress: null,
    logs: [],
    call(type, data) {
      return new Promise((resolve, reject) => {
        const id = ++client.seq;
        client.pending.set(id, { resolve, reject });
        worker.postMessage({ id, type, data });
      });
    },
  };
  worker.onmessage = (e) => {
    const { id, type, data } = e.data || {};
    if (type === 'LOG') {
      const msg = typeof data === 'string' ? data : data && data.message ? data.message : JSON.stringify(data);
      client.logs.push(msg);
      if (client.logs.length > 200) client.logs.splice(0, client.logs.length - 200);
      return;
    }
    if (type === 'PROGRESS') {
      const p = data && typeof data.progress === 'number' ? data.progress
        : data && typeof data.ratio === 'number' ? data.ratio : null;
      if (p !== null && client.onProgress) client.onProgress(Math.min(Math.max(p, 0), 1));
      return;
    }
    const pending = client.pending.get(id);
    if (!pending) return;
    client.pending.delete(id);
    if (type === 'ERROR') pending.reject(new Error(String(data)));
    else pending.resolve(data);
  };
  worker.onerror = (e) => {
    const err = new Error('ffmpeg Worker 异常：' + (e.message || '未知错误'));
    for (const p of client.pending.values()) p.reject(err);
    client.pending.clear();
  };
  return client;
}

async function getFFmpeg() {
  if (ffmpeg) return ffmpeg;
  if (ffmpegLoading) return ffmpegLoading;
  ffmpegLoading = (async () => {
    const errors = [];
    // 方案一：内置引擎（核心库 114KB + wasm 10MB 全部从本站同源加载）
    try {
      const client = createCoreClient();
      const wasmURL = await gunzipToBlobURL(
        pageURL('vendor/core/ffmpeg-core.wasm.gz'),
        'application/wasm',
        (p) => setStatus('正在加载内置转码引擎（从本站下载）… ' + Math.round(p * 100) + '%')
      );
      await withTimeout(
        client.call('LOAD', { coreURL: pageURL('vendor/core/ffmpeg-core.js'), wasmURL }),
        60000,
        '内置引擎初始化'
      );
      ffmpeg = client;
      setStatus('✅ 转码引擎已就绪（内置）。');
      return client;
    } catch (e) {
      errors.push('内置引擎：' + (e && e.message ? e.message : e));
    }
    // 方案二：CDN（importScripts 跨域直取核心库；wasm 地址按核心库路径推导，由引擎内部下载）
    for (const cdn of CDN_CANDIDATES) {
      try {
        setStatus('内置引擎不可用，改从 ' + cdn.name + ' 加载 ffmpeg（约 25MB）…');
        const coreJs = cdn.file(PKG_CORE[0], PKG_CORE[1], 'dist/umd/ffmpeg-core.js');
        const client = createCoreClient();
        await withTimeout(client.call('LOAD', { coreURL: coreJs }), 60000, cdn.name + ' 引擎加载');
        ffmpeg = client;
        setStatus('✅ 转码引擎已就绪（' + cdn.name + '）。');
        return client;
      } catch (e) {
        errors.push(cdn.name + '：' + (e && e.message ? e.message : e));
      }
    }
    throw new Error('所有源均加载失败（' + errors.join('；') + '）');
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

// 检测网易云「菁彩声」（Audio Vivid / AV3A）沉浸声编码：
// 编码标记 av3a 位于 moov/stsd 盒内（通常在前 1MB），ffmpeg 无法解码，不能转码。
// 只有无损及以下音质（标准 FLAC/AAC/MP3）的 NCM 才可转码。
function isAudioVivid(buf) {
  const limit = Math.min(buf.length, 1048576);
  for (let i = 0; i + 4 <= limit; i++) {
    if (buf[i] === 0x61 && buf[i + 1] === 0x76 && buf[i + 2] === 0x33 && buf[i + 3] === 0x61) return true;
  }
  return false;
}

function triggerDownload(url, filename) {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

async function ensureFormat(target, srcExt, audio, onProgress) {
  // 「原始格式」或与源格式相同时，直接输出解密结果，不需要 ffmpeg
  if (target === 'original' || target === srcExt) return { ext: srcExt, data: audio, transcoded: false };
  const inst = await getFFmpeg();
  inst.onProgress = onProgress || null;
  const inName = 'in.' + srcExt;
  const outName = 'out.' + target;
  await inst.call('WRITE_FILE', { path: inName, data: audio });
  const args = ['-i', inName, '-vn', '-y'];
  if (target === 'mp3') args.push('-c:a', 'libmp3lame', '-b:a', bitrateSel.value + 'k');
  else if (target === 'flac') args.push('-c:a', 'flac');
  else if (target === 'wav') args.push('-c:a', 'pcm_s16le');
  else if (target === 'aac') args.push('-c:a', 'aac', '-b:a', bitrateSel.value + 'k');
  args.push(outName);
  const ret = await inst.call('EXEC', { args, timeout: -1 });
  if (ret !== 0) {
    const logText = (inst.logs || []).join('\n');
    if (logText.includes('av3a') || logText.includes('unknown codec')) {
      throw new Error(
        '这首歌是网易云「菁彩声」（Audio Vivid / AV3A）沉浸声格式，不是普通 AAC——' +
        'ffmpeg 全系列（含桌面版 7.1 以下）都无法解码它，任何转换工具都转不了。' +
        '解密出的 M4A 文件本身是完整无损的，请改用「原始格式」输出后在网易云客户端播放。'
      );
    }
    const tailLines = (inst.logs || []).slice(-3).join(' | ');
    throw new Error('ffmpeg 转码失败（返回码 ' + ret + '）' + (tailLines ? '：' + tailLines : ''));
  }
  const data = await inst.call('READ_FILE', { path: outName, encoding: 'binary' });
  await inst.call('DELETE_FILE', { path: inName }).catch(() => {});
  await inst.call('DELETE_FILE', { path: outName }).catch(() => {});
  if (onProgress) onProgress(1);
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

    let audio;
    let srcExt;
    let wasEncrypted;
    const plainExt = PLAIN_EXTS[ext];
    if (plainExt) {
      // 普通音频：不解密，直接进转码/直通
      statusNode.textContent = '正在读取…';
      audio = buf;
      srcExt = plainExt;
      wasEncrypted = false;
    } else {
      statusNode.textContent = '正在解密… 0%';
      audio = await decryptByFormat(buf, ext, (p) => {
        statusNode.textContent = '正在解密… ' + Math.round(p * 100) + '%';
      });
      srcExt = sniffFormat(audio);
      wasEncrypted = true;
    }
    const baseName = file.name.replace(/\.[^.]+$/, '');

    const fmt = formatSel.value;
    const needTranscode = fmt !== 'original' && fmt !== srcExt;

    // 菁彩声（高于无损的音质档位）提前拦截：不白加载转码引擎，直接给出指引
    const audioVivid = srcExt === 'm4a' && isAudioVivid(audio);
    if (audioVivid && needTranscode) {
      throw new Error(
        '这首歌是网易云「菁彩声」（沉浸声）音质，高于无损档位——只有无损及以下音质的 NCM 才能转码。' +
        '解决办法：① 网易云客户端 → 设置 → 下载音质 → 改选「无损音质」后重新下载这首歌；' +
        '或 ② 改用「原始格式」仅解密输出（M4A 完整无损，可在网易云客户端播放）。'
      );
    }
    if (needTranscode) {
      statusNode.textContent = '正在准备转码引擎…';
    }
    const output = await ensureFormat(fmt, srcExt, audio, (p) => {
      statusNode.textContent = '正在转码… ' + Math.round(p * 100) + '%';
    });

    const action = output.transcoded ? '已转码' : wasEncrypted ? '仅解密' : '格式相同，直接输出';
    metaNode.textContent =
      '已转换 → ' + baseName + '.' + output.ext +
      '（源格式：' + srcExt.toUpperCase() + '，' + action + '）' +
      (audioVivid ? ' ⚠️ 菁彩声格式，仅网易云客户端可播放' : '');

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
// 选了需要转码的格式后立刻后台预载 ffmpeg 引擎，拖文件时引擎已就绪，感知零等待
formatSel.addEventListener('change', () => {
  if (formatSel.value !== 'original') getFFmpeg().catch(() => {});
});
syncBitrateVisibility();

// ---------- 启动 ----------
setStatus('就绪。拖入 .kgm/.kgma/.ncm 加密文件或 FLAC/MP3/WAV 等普通音频开始转换。');
// 后台预加载酷狗密钥表（同源 12MB，很快）；ffmpeg 引擎改为转码时按需加载
getKeyTable().catch(() => {});
