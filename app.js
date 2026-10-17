// 主逻辑：UI 交互 + 解密 + 转码编排
// 解密函数 isKgm/decrypt/sniffFormat 来自 kgm.js（通过 <script> 先加载，全局共享）

const KEY_URL = './kugou_key.gz';
const FFMPEG_FFMPEG_URL = 'https://cdn.jsdelivr.net/npm/@ffmpeg/ffmpeg@0.12.10/dist/esm/index.js';
const FFMPEG_UTIL_URL = 'https://cdn.jsdelivr.net/npm/@ffmpeg/util@0.12.1/dist/esm/index.js';
const FFMPEG_CORE_BASE = 'https://cdn.jsdelivr.net/npm/@ffmpeg/core@0.12.6/dist/umd';

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

function setStatus(msg) { statusEl.textContent = msg; }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
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
    const res = await fetch(KEY_URL);
    if (!res.ok) {
      throw new Error('密钥表加载失败（HTTP ' + res.status + '）。请通过 HTTP 方式访问，或使用单文件版。');
    }
    gzBytes = new Uint8Array(await res.arrayBuffer());
  }
  const stream = new Blob([gzBytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  const buf = await new Response(stream).arrayBuffer();
  keyTable = new Uint8Array(buf);
  setStatus('✅ 密钥表已就绪，可以拖入文件开始转换。');
  return keyTable;
}

let keyTablePromise = null;
async function getKeyTable() {
  if (keyTable) return keyTable;
  if (!keyTablePromise) keyTablePromise = loadKeyTable().then(() => keyTable);
  return keyTablePromise;
}

async function decryptByFormat(buf, ext) {
  if (ext === '.kgm' || ext === '.kgma' || ext === '.vpr') {
    const kt = await getKeyTable();
    if (!isKgm(buf)) throw new Error('不是有效的 KGM/KGMA 文件（文件头不匹配）');
    return decrypt(buf, kt);
  }
  if (ext === '.ncm') return await Formats.decryptNcm(buf);
  // 兜底：按魔数识别
  if (isKgm(buf)) return decrypt(buf, await getKeyTable());
  if (Formats.isNcm(buf)) return await Formats.decryptNcm(buf);
  throw new Error('无法识别的加密格式（支持 kgm/kgma/ncm）');
}

async function getFFmpeg() {
  if (ffmpeg) return ffmpeg;
  if (ffmpegLoading) return ffmpegLoading;
  ffmpegLoading = (async () => {
    setStatus('正在加载 ffmpeg 转码引擎（约 25MB，来自 CDN，仅首次需要）…');
    const [{ FFmpeg }, { toBlobURL }] = await Promise.all([
      import(FFMPEG_FFMPEG_URL),
      import(FFMPEG_UTIL_URL),
    ]);
    const instance = new FFmpeg();
    await instance.load({
      coreURL: await toBlobURL(`${FFMPEG_CORE_BASE}/ffmpeg-core.js`, 'text/javascript'),
      wasmURL: await toBlobURL(`${FFMPEG_CORE_BASE}/ffmpeg-core.wasm`, 'application/wasm'),
    });
    ffmpeg = instance;
    return instance;
  })();
  try {
    return await ffmpegLoading;
  } catch (e) {
    ffmpegLoading = null;
    throw new Error('ffmpeg 引擎加载失败（' + (e && e.message ? e.message : e) + '）。转码需要网络访问 CDN，解密还原原始格式则不受影响。');
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
  if (target === srcExt) return { ext: target, data: audio, transcoded: false };
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
    const isKgmFmt = ext === '.kgm' || ext === '.kgma' || ext === '.vpr';

    statusNode.textContent = isKgmFmt ? '正在加载解密密钥表（12MB，首次较慢，之后走缓存）…' : '正在解密…';
    await new Promise((r) => setTimeout(r, 0)); // 让状态文字有机会渲染
    const audio = await decryptByFormat(buf, ext);
    const srcExt = sniffFormat(audio);
    const baseName = file.name.replace(/\.[^.]+$/, '');

    const fmt = formatSel.value;
    const outputs = [];

    if (fmt === 'auto') {
      outputs.push({ ext: srcExt, data: audio });
    } else {
      outputs.push(await ensureFormat(fmt, srcExt, audio));
    }

    metaNode.textContent = '原始格式：' + srcExt.toUpperCase() + ' · ' + (file.size / 1024 / 1024).toFixed(1) + ' MB';

    // 生成下载链接并自动触发下载（浏览器若拦截，仍可手动点击）
    for (let i = 0; i < outputs.length; i++) {
      const o = outputs[i];
      const url = makeDownloadUrl(o.data, o.ext);
      const a = document.createElement('a');
      a.href = url;
      a.download = baseName + '.' + o.ext;
      a.className = 'dl-link';
      a.textContent = '下载 ' + o.ext.toUpperCase();
      linksNode.appendChild(a);

      triggerDownload(url, a.download);
      if (outputs.length > 1 && i < outputs.length - 1) {
        await new Promise((r) => setTimeout(r, 400));
      }
    }

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
// 后台预加载酷狗解密密钥表，加速后续酷狗文件转换
getKeyTable().catch(() => {});
