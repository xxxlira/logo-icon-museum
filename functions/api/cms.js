/* ============================================================================
 * APP LOGO 图标收藏馆 · 在线 CMS 后端（Cloudflare Pages Functions）
 * 路由：/api/cms
 *
 * 让纯静态站点拥有「登录后在线编辑并保存」的能力，不额外购买数据库：
 *   - 管理员登录 → HttpOnly 签名 Cookie（HMAC-SHA256，密钥由 ADMIN_PASSWORD 派生）
 *   - 保存     → 把整份馆藏拆成 manifest.json / index.html 内嵌快照 / 图标文件
 *               → 用 GitHub Git Data API 一次原子提交到 main
 *               → 纯文字改动在提交信息加 [CI Skip] 跳过 Pages 构建；
 *                 含新图片时才触发一次构建，把文件铺到 CDN（1-2 分钟）
 *   - 暂存发布 → 前端后台改动只写本机草稿，点「发布到线上」才调用一次保存，
 *               避免每改一处就消耗一次构建额度
 *   - 即时生效 → 前端改从 /api/cms?action=manifest 读 GitHub 上的最新清单，
 *               边缘缓存 15 秒且保存时主动清除，访客刷新即可看到，无需等重建
 *
 * ---- Cloudflare 控制台需要做的两件事（Settings → Environment variables）----
 *   ADMIN_PASSWORD   管理员密码，至少 8 位；不要在前端代码或仓库里出现
 *   GITHUB_TOKEN     Fine-grained PAT，只授权 xxxlira/logo-icon-museum 一个仓库，
 *                   权限 Contents: Read & Write；不要用 classic PAT
 * 两个变量都设置后才会启用在线 CMS；没设置时 /api/cms 返回 cms:false，
 * 前端完全回退到原来的只读静态行为，站点不会受任何影响。
 *
 * ---- 安全边界 ----
 *   - 密码、令牌只在服务端环境变量里，永远不会下发到浏览器
 *   - 写接口校验 Cookie 签名 + 同源 Origin/Referer，Cookie 为 HttpOnly/Secure/SameSite=Strict
 *   - 请求体上限 20 MB；文件名严格白名单 [a-z0-9-] + .webp/.png/.jpg，防路径穿越
 *   - 只写 manifest.json / index.html / icons/* / thumbs/*，不碰仓库其他文件
 *   - 私有字段 activity / suggestions / security / subscribers 一律不写入公开清单
 *   - 不做自动删除旧图片（避免误删）；跑本地 update_site.sh 批量重建时会清理
 *   - 建议另外在 Cloudflare Access 里给 /api/* 加一层访问策略，防密码爆破
 *
 * 任何异常都返回 JSON 而不是抛出，保证即使未配置也不会让站点报错。
 * ========================================================================== */

const REPO = 'xxxlira/logo-icon-museum';
const BRANCH = 'main';
const COOKIE = 'im_cms';
const MAX_BODY = 20 * 1024 * 1024;
const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const GH = 'https://api.github.com/repos/' + REPO;
const SNAP_RE = /(<script id="site-db"[^>]*>)[\s\S]*?(<\/script>)/;
const SAFE_NAME = /^[a-z0-9][a-z0-9-]{0,80}\.(webp|png|jpg|jpeg)$/i;

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extra,
    },
  });
}

function configured(env) {
  return typeof env.ADMIN_PASSWORD === 'string' && env.ADMIN_PASSWORD.length >= 8
      && typeof env.GITHUB_TOKEN === 'string' && env.GITHUB_TOKEN.length > 10;
}

/* ---------------------------------------------------------------- 编码工具 */

function utf8ToB64(s) {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  }
  return btoa(bin);
}

function b64ToUtf8(b64) {
  const bin = atob(String(b64).replace(/\s/g, ''));
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(u);
}

function b64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function mac(payload, env) {
  const k = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode('im-cms|' + env.ADMIN_PASSWORD),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(payload));
  return b64url(new Uint8Array(sig));
}

/* ---------------------------------------------------------------- 会话 */

async function issueCookie(env) {
  const exp = Date.now() + SESSION_MS;
  const body = b64url(new TextEncoder().encode(JSON.stringify({ exp })));
  return COOKIE + '=' + body + '.' + (await mac(body, env))
    + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + Math.round(SESSION_MS / 1000);
}

async function authed(request, env) {
  const raw = (request.headers.get('Cookie') || '');
  const hit = raw.split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  if (!hit) return false;
  const token = hit.slice(COOKIE.length + 1);
  const dot = token.lastIndexOf('.');
  if (dot < 1) return false;
  const body = token.slice(0, dot), sig = token.slice(dot + 1);
  let expected;
  try { expected = await mac(body, env); } catch (e) { return false; }
  // 长度固定，逐字符比较，避免短路带来的时序差
  if (sig.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig.charCodeAt(i) ^ expected.charCodeAt(i);
  if (diff) return false;
  try {
    const p = JSON.parse(b64ToUtf8(body.replace(/-/g, '+').replace(/_/g, '/')));
    return !!(p && typeof p.exp === 'number' && p.exp > Date.now());
  } catch (e) { return false; }
}

function sameOrigin(request, url) {
  const o = request.headers.get('Origin') || request.headers.get('Referer') || '';
  if (!o) return false;                       // 同源 fetch 一定会带 Origin/Referer
  try { return new URL(o).host === url.host; } catch (e) { return false; }
}

function logout() {
  return json({ ok: true }, 200, {
    'Set-Cookie': COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0',
  });
}

/* ---------------------------------------------------------------- GitHub */

async function gh(path, env, opt = {}) {
  const headers = {
    'Authorization': 'Bearer ' + env.GITHUB_TOKEN,
    'Accept': 'application/vnd.github+json',
    'User-Agent': 'icon-museum-cms',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (opt.body) headers['Content-Type'] = 'application/json';
  const r = await fetch('https://api.github.com' + path, {
    method: opt.method || 'GET', headers, body: opt.body || undefined,
  });
  if (!r.ok) {
    const t = (await r.text()).slice(0, 300);
    throw new Error('GitHub ' + r.status + '：' + t);
  }
  return r.json();
}

async function readRepoFile(path, env) {
  const d = await gh('/repos/' + REPO + '/contents/' + path + '?ref=' + BRANCH, env);
  if (!d || !d.content) throw new Error('读取 ' + path + ' 失败');
  return b64ToUtf8(d.content);
}

/* 边缘缓存：让公开读取不把 GitHub API 额度耗尽；保存时会主动清除 */
function cacheObj() {
  try { return (typeof caches !== 'undefined' && caches.default) ? caches.default : null; }
  catch (e) { return null; }
}
function cacheKey(url) {
  return new Request(new URL('/__cms_manifest__', url.origin).toString());
}
async function cachedManifest(env, url) {
  const c = cacheObj(), k = cacheKey(url);
  if (c) {
    try {
      const hit = await c.match(k);
      if (hit) return { manifest: await hit.json(), cached: true };
    } catch (e) { /* 缓存不可用则直接读源 */ }
  }
  const text = await readRepoFile('manifest.json', env);
  const manifest = JSON.parse(text);
  if (c) {
    try {
      await c.put(k, new Response(JSON.stringify(manifest), {
        headers: { 'Cache-Control': 'public, max-age=15' },
      }));
    } catch (e) { /* 缓存写入失败不影响主流程 */ }
  }
  return { manifest, cached: false };
}

/* ---------------------------------------------------------------- 保存 */

function parseDataURL(v) {
  const m = /^data:([^;,]+)?;base64,([A-Za-z0-9+/=\s]+)$/.exec(String(v));
  if (!m) return null;
  const mime = (m[1] || 'image/webp').toLowerCase();
  const ext = mime.includes('png') ? 'png'
            : (mime.includes('jpeg') || mime.includes('jpg')) ? 'jpg' : 'webp';
  return { ext, b64: m[2].replace(/\s/g, '') };
}

function publicPayload(db) {
  const p = Object.assign({}, db, {
    version: 5, generatedAt: new Date().toISOString(),
  });
  ['activity', 'suggestions', 'security', 'subscribers', 'colors'].forEach(k => delete p[k]);
  if (!Array.isArray(p.apps)) throw new Error('数据格式不正确：缺少 apps');
  if (!Array.isArray(p.designers)) p.designers = [];
  if (!Array.isArray(p.categories)) p.categories = [];
  if (!Array.isArray(p.types)) p.types = [];
  return p;
}

/* 把 DB 里的 dataURL 图片拆成独立文件，并把字段改成站内相对路径 */
function extractImages(p) {
  const files = [], seen = new Set();
  for (const a of p.apps) {
    const slug = a && a.app && a.app.slug;
    if (!slug || !/^[a-z0-9][a-z0-9-]{0,80}$/.test(slug)) {
      throw new Error('应用 slug 不合法：' + String(slug).slice(0, 60));
    }
    for (const ic of (a.icons || [])) {
      for (const field of ['url', 'hdUrl']) {
        const v = ic[field];
        if (typeof v !== 'string' || !v.startsWith('data:')) continue;
        const d = parseDataURL(v);
        if (!d) continue;                       // 非图片 dataURL（如内联 SVG）保留原样
        const suffix = ic.type === 'variant' ? '-' + String(ic.id || '').replace(/[^a-z0-9-]/gi, '').slice(-24) : '';
        const dir = field === 'hdUrl' ? 'icons' : 'thumbs';
        const name = slug + suffix + '.' + d.ext;
        if (!SAFE_NAME.test(name)) throw new Error('图片文件名不合法：' + name);
        const path = dir + '/' + name;
        if (!seen.has(path)) { files.push({ path, base64: d.b64 }); seen.add(path); }
        ic[field] = path;
      }
    }
    /* 详情页「相关图片」：同样拆成独立文件，避免 dataURL 撑爆 manifest.json */
    const rels = a.app && Array.isArray(a.app.relatedImages) ? a.app.relatedImages : [];
    for (const ri of rels) {
      const v = ri && ri.url;
      if (typeof v !== 'string' || !v.startsWith('data:')) continue;
      const d = parseDataURL(v);
      if (!d) continue;
      const rid = String(ri.id || '').replace(/[^a-z0-9-]/gi, '').slice(-24) || 'img';
      const name = slug + '-' + rid + '.' + d.ext;
      if (!SAFE_NAME.test(name)) throw new Error('相关图片文件名不合法：' + name);
      const path = 'related/' + name;
      if (!seen.has(path)) { files.push({ path, base64: d.b64 }); seen.add(path); }
      ri.url = path;
    }
  }
  return files;
}

function buildManifest(p) {
  const m = {
    generatedAt: p.generatedAt,
    apps: p.apps,
    designers: p.designers,
    categories: p.categories,
  };
  if (p.styles) m.styles = p.styles;
  if (p.types) m.types = p.types;
  if (p.about) m.about = p.about;
  if (p.settings) m.settings = p.settings;
  return m;
}

async function buildIndexHTML(p, env) {
  const html = await readRepoFile('index.html', env);
  if (!SNAP_RE.test(html)) throw new Error('index.html 里找不到 #site-db 快照节点');
  const snapshot = JSON.stringify({
    generatedAt: p.generatedAt, apps: p.apps, designers: p.designers,
    categories: p.categories, styles: p.styles, types: p.types, about: p.about,
    settings: p.settings, version: 5,
  }).replace(/</g, '\\u003c');
  return html.replace(SNAP_RE, (all, open, close) => open + snapshot + close);
}

/* 清单里仍被引用到的站内图片路径（icons / thumbs / related） */
function referencedImagePaths(m) {
  const set = new Set();
  const SITE_IMG = /^(\.\/)?(icons|thumbs|related)\//;
  for (const a of (m && Array.isArray(m.apps) ? m.apps : [])) {
    for (const ic of (a.icons || [])) {
      for (const f of ['url', 'hdUrl']) {
        const v = ic[f];
        if (typeof v === 'string' && SITE_IMG.test(v)) set.add(v.replace(/^\.\//, ''));
      }
    }
    for (const ri of ((a.app && a.app.relatedImages) || [])) {
      const v = ri && ri.url;
      if (typeof v === 'string' && SITE_IMG.test(v)) set.add(v.replace(/^\.\//, ''));
    }
  }
  return set;
}

/* 批量删除应用后，找出新清单已不再引用、但仓库里还存在的图片文件。
   只做「旧引用 - 新引用」差集，因此不会误删仍被其它应用共用的图片。 */
async function orphanedImagePaths(p, env) {
  let old;
  try { old = JSON.parse(await readRepoFile('manifest.json', env)); }
  catch (e) { return []; }   /* 首次发布 / 旧清单读不到时不做猜测 */
  const before = referencedImagePaths(old), after = referencedImagePaths(p);
  return [...before].filter(x => !after.has(x)).slice(0, 500);
}

/* 用 Git Data API 一次性提交多个文件，避免产生多次无谓的 Pages 构建 */
async function atomicCommit(items, env, message) {
  const ref = await gh('/repos/' + REPO + '/git/ref/heads/' + BRANCH, env);
  const baseSha = ref.object.sha;
  const baseCommit = await gh('/repos/' + REPO + '/git/commits/' + baseSha, env);
  const entries = [];
  // 串行创建 blob，避免并发触发 GitHub 的二级限流
  for (const it of items) {
    /* sha:null 是 GitHub Git Trees API 的删除语义，用于回收已删应用的孤儿图片 */
    if (it.remove) { entries.push({ path: it.path, mode: '100644', type: 'blob', sha: null }); continue; }
    const blob = await gh('/repos/' + REPO + '/git/blobs', env, {
      method: 'POST',
      body: JSON.stringify({ content: it.base64, encoding: 'base64' }),
    });
    entries.push({ path: it.path, mode: '100644', type: 'blob', sha: blob.sha });
  }
  const tree = await gh('/repos/' + REPO + '/git/trees', env, {
    method: 'POST',
    body: JSON.stringify({ base_tree: baseCommit.tree.sha, tree: entries }),
  });
  const commit = await gh('/repos/' + REPO + '/git/commits', env, {
    method: 'POST',
    body: JSON.stringify({ message, tree: tree.sha, parents: [baseSha] }),
  });
  await gh('/repos/' + REPO + '/git/refs/heads/' + BRANCH, env, {
    method: 'PATCH', body: JSON.stringify({ sha: commit.sha }),
  });
  return commit.sha;
}

/* ---------------------------------------------------------------- 路由 */

async function handleGet(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url);
  const action = url.searchParams.get('action') || 'session';

  if (!configured(env)) return json({ cms: false, reason: '未配置 ADMIN_PASSWORD / GITHUB_TOKEN' });

  if (action === 'session') {
    return json({ cms: true, configured: true, authed: await authed(request, env) });
  }
  if (action === 'manifest') {
    const { manifest, cached } = await cachedManifest(env, url);
    return json(manifest, 200, { 'X-CMS-Cache': cached ? 'hit' : 'miss' });
  }
  return json({ error: '未知操作' }, 400);
}

async function handlePost(ctx) {
  const { request, env } = ctx;
  const url = new URL(request.url);
  if (!configured(env)) return json({ error: '在线 CMS 尚未配置' }, 503);
  if (!sameOrigin(request, url)) return json({ error: '请求来源不合法' }, 403);

  const len = Number(request.headers.get('Content-Length') || 0);
  if (len > MAX_BODY) return json({ error: '请求体过大' }, 413);
  const text = await request.text();
  if (text.length > MAX_BODY) return json({ error: '请求体过大' }, 413);
  let body;
  try { body = JSON.parse(text); } catch (e) { return json({ error: 'JSON 解析失败' }, 400); }

  if (body.action === 'login') {
    const pass = String(body.password || '');
    // 固定小延迟，降低在线爆破速度
    await new Promise(r => setTimeout(r, 350));
    if (pass !== env.ADMIN_PASSWORD) return json({ error: '密码不正确' }, 401);
    return json({ ok: true, authed: true }, 200, { 'Set-Cookie': await issueCookie(env) });
  }
  if (body.action === 'logout') return logout();

  if (!await authed(request, env)) return json({ error: '登录已失效，请重新登录' }, 401);

  if (body.action === 'save') {
    const p = publicPayload(body.db || {});
    /* 防止另一台设备 / 过期草稿把整馆数据整包覆盖：
       一次发布若把应用数砍掉一半以上且减少 >= 20 个，直接拒绝。
       正常的分批删除不受影响；确需整批清理可分批进行。 */
    let oldCount = 0;
    try {
      const oldM = JSON.parse(await readRepoFile('manifest.json', env));
      oldCount = Array.isArray(oldM.apps) ? oldM.apps.length : 0;
    } catch (e) { /* 读不到旧清单时不做猜测，放行 */ }
    const newCount = Array.isArray(p.apps) ? p.apps.length : 0;
    if (oldCount >= 20 && newCount < oldCount * 0.5 && oldCount - newCount >= 20) {
      return json({
        error: '已拦截一次疑似旧草稿覆盖：线上现有 ' + oldCount + ' 个应用，'
             + '本次发布只剩 ' + newCount + ' 个。请先退出登录再重新登录'
             + '（或点「放弃更改」）同步云端最新馆藏，确认后再发布；'
             + '确实要删除请分批操作。'
      }, 409);
    }
    const images = extractImages(p);
    const orphans = await orphanedImagePaths(p, env);
    const removals = orphans.map(path => ({ path, remove: true }));
    const items = images.concat(removals).concat([
      { path: 'manifest.json', base64: utf8ToB64(JSON.stringify(buildManifest(p))) },
      { path: 'index.html', base64: utf8ToB64(await buildIndexHTML(p, env)) },
    ]);
    /* 纯文字改动不需要重建静态资源：用 Cloudflare 官方的 [CI Skip] 提交信息前缀
       跳过 Pages 构建；内容本身通过 /api/cms?action=manifest 即时生效。
       含新图片或删了应用（要回收 CDN 上的旧图）时才正常构建。 */
    const skippedBuild = images.length === 0 && removals.length === 0;
    const message = (skippedBuild ? '[CI Skip] ' : '')
      + '站内编辑：' + p.apps.length + ' 个应用 · ' + new Date().toISOString();
    const sha = await atomicCommit(items, env, message);
    const c = cacheObj();
    if (c) { try { await c.delete(cacheKey(url)); } catch (e) { /* ignore */ } }
    return json({ ok: true, sha, files: items.length, generatedAt: p.generatedAt, skippedBuild });
  }
  return json({ error: '未知操作' }, 400);
}

export async function onRequest(ctx) {
  try {
    const m = ctx.request.method;
    if (m === 'GET') return await handleGet(ctx);
    if (m === 'POST') return await handlePost(ctx);
    if (m === 'DELETE') return logout();
    return json({ error: '不支持的请求方法' }, 405);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}
