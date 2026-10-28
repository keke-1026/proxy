'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const { CookieJar } = require('tough-cookie');
const http = require('http');
const https = require('https');
const net = require('net');
const zlib = require('zlib');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');
const { pipeline } = require('stream');
const { rewriteHtml, rewriteCss, proxify, isDirect } = require('./rewrite');
const { encodeOrigin, decodeOrigin, toProxyPath, decodeBase64Text } = require('./urlcodec');
const { isBlockedIp, safeLookup, ALLOW_PRIVATE } = require('./ssrf');

const gzip = promisify(zlib.gzip);

// ==========================================
// 設定（環境変数）
// ==========================================
const VERSION = 'v3.1.0';
const PORT = process.env.PORT || 3000;

// ログインパスワード。未設定なら起動ごとにランダム生成してログに出す（オープンプロキシ防止）
const PASSWORD_GENERATED = !process.env.PROXY_PASSWORD;
const PASSWORD = process.env.PROXY_PASSWORD || crypto.randomBytes(9).toString('base64url');

// 'browser' を指定するとブラウザ本来のUser-Agentをそのまま使う
const DESKTOP_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36';
const FORCE_UA = process.env.USER_AGENT === 'browser' ? null : process.env.USER_AGENT || DESKTOP_UA;

// 外部ドメインの画像・JS・CSS の扱い
//   auto   : ブラウザが直接取りに行き、失敗したらプロキシ経由で取り直す（既定。速く、サーバー負荷も小さい）
//   direct : ブラウザが直接取りに行くだけ（旧v2.1.0と同じ）
//   proxy  : すべてサーバー経由（ブラウザが外部へ一切つながらない。遅くなり、CDNにサーバーIPを弾かれると表示できない）
const ASSETS = ['auto', 'direct', 'proxy'].includes(process.env.EXTERNAL_ASSETS) ? process.env.EXTERNAL_ASSETS : 'auto';

// DEBUG_LOG=1: 上流がエラー(4xx/5xx・接続失敗)を返したURLと、ページ内のJSエラーをログに出す。
// 「動かないサイトの原因」を調べるためのもの。訪問先のURLがログに残るので、普段は無効のままにする。
const DEBUG = process.env.DEBUG_LOG === '1';

const MAX_REWRITE_BYTES = Number(process.env.MAX_REWRITE_BYTES) || 15 * 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS) || 30000;
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_SESSIONS = Number(process.env.MAX_SESSIONS) || 200;
const INSECURE_TLS = process.env.INSECURE_TLS === '1'; // 自己署名証明書などを許可

const agents = {
  'http:': new http.Agent({ keepAlive: true, maxSockets: 128 }),
  'https:': new https.Agent({ keepAlive: true, maxSockets: 128, rejectUnauthorized: !INSECURE_TLS }),
};

// ==========================================
// セッション（ログイン状態 + 上流サイトごとのCookie）
// ==========================================
const sessions = new Map();

function readCookie(header, name) {
  if (!header) return null;
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i) === name) return decodeURIComponent(part.slice(i + 1));
  }
  return null;
}

function createSession() {
  if (sessions.size >= MAX_SESSIONS) {
    let oldestId = null;
    let oldest = Infinity;
    for (const [id, s] of sessions) {
      if (s.last < oldest) {
        oldest = s.last;
        oldestId = id;
      }
    }
    if (oldestId) sessions.delete(oldestId);
  }
  const id = crypto.randomBytes(24).toString('base64url');
  const sess = { jar: new CookieJar(), last: Date.now() };
  sessions.set(id, sess);
  return { id, sess };
}

function getSession(req) {
  const id = readCookie(req.headers.cookie, '__psid');
  if (!id) return null;
  const s = sessions.get(id);
  if (!s) return null;
  s.last = Date.now();
  return s;
}

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) if (now - s.last > SESSION_TTL_MS) sessions.delete(id);
}, 10 * 60 * 1000).unref();

function checkPassword(input) {
  const a = crypto.createHash('sha256').update(String(input)).digest();
  const b = crypto.createHash('sha256').update(PASSWORD).digest();
  return crypto.timingSafeEqual(a, b);
}

// ==========================================
// 画面（ホーム / ログイン / エラー）
// ==========================================
const escapeHtml = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function sendPage(res, status, title, body) {
  res
    .status(status)
    .set({
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
    })
    .type('html')
    .send(`<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; max-width: 30rem; margin: 12vh auto; padding: 0 1rem; line-height: 1.6; }
  h1 { font-size: 1.3rem; }
  input[type=text], input[type=password] { width: 100%; box-sizing: border-box; padding: .6rem; font-size: 1rem; }
  button { margin-top: .6rem; padding: .6rem 1.2rem; font-size: 1rem; cursor: pointer; }
  small, footer { opacity: .7; }
  .err { color: #c0392b; }
</style>
</head>
<body>
${body}
</body>
</html>`);
}

function sendError(res, status, message) {
  if (res.headersSent) {
    res.destroy();
    return;
  }
  sendPage(res, status, 'エラー', `<h1>エラー</h1><p class="err">${escapeHtml(message)}</p><p><a href="/">ホームへ戻る</a></p>`);
}

function describeError(err) {
  const code = err && err.code;
  if (code === 'EBLOCKED') return [403, 'このアドレスには接続できません。'];
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return [502, 'ホストが見つかりませんでした。'];
  if (code === 'ETIMEDOUT') return [504, '接続がタイムアウトしました。'];
  if (code === 'ECONNREFUSED') return [502, '接続を拒否されました。'];
  if (code === 'ETOOBIG') return [502, 'ページが大きすぎるため変換できませんでした。'];
  if (code && /CERT|TLS|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(code)) return [502, 'SSL証明書の検証に失敗しました。'];
  return [502, `接続エラー (${code || (err && err.message) || 'unknown'})`];
}

// ==========================================
// アプリ本体
// ==========================================
const app = express();
app.disable('x-powered-by');
if (process.env.TRUST_PROXY) {
  const n = Number(process.env.TRUST_PROXY);
  app.set('trust proxy', Number.isNaN(n) ? process.env.TRUST_PROXY === 'true' || process.env.TRUST_PROXY : n);
}

const SHIM = fs.readFileSync(path.join(__dirname, 'shim.js'));

app.get('/healthz', (req, res) => res.type('text').send('ok'));

// ---- ログイン ----
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  // 失敗(パスワード違い)だけを数える。リダイレクトは常に 3xx なのでステータスでは判定できない
  skipSuccessfulRequests: true,
  requestWasSuccessful: (req, res) => res.locals.loginOk === true,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: (req, res) => sendError(res, 429, '試行回数が多すぎます。しばらくしてからやり直してください。'),
});

const safeNext = (n) => (typeof n === 'string' && /^\/(?![\\/])/.test(n) ? n : '/');

app.get('/login', (req, res) => {
  if (getSession(req)) return res.redirect(safeNext(req.query.next));
  sendPage(
    res,
    200,
    'ログイン',
    `<h1>keke pro-xyz</h1>
<form method="POST" action="/login">
  <input type="hidden" name="next" value="${escapeHtml(safeNext(req.query.next))}">
  <input type="password" name="password" placeholder="パスワード" autofocus required>
  <button type="submit">ログイン</button>
  ${req.query.e ? '<p class="err">パスワードが違います。</p>' : ''}
</form>`
  );
});

app.post('/login', loginLimiter, express.urlencoded({ extended: false, limit: '4kb' }), (req, res) => {
  const next = safeNext(req.body && req.body.next);
  if (!req.body || !checkPassword(req.body.password || '')) {
    return res.redirect('/login?e=1&next=' + encodeURIComponent(next));
  }
  res.locals.loginOk = true;
  const { id } = createSession();
  res.cookie('__psid', id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: req.secure,
    maxAge: SESSION_TTL_MS,
    path: '/',
  });
  res.redirect(next);
});

// ---- 認証ゲート（以降はログイン必須） ----
app.use((req, res, next) => {
  const s = getSession(req);
  if (s) {
    req.sess = s;
    return next();
  }
  if (req.method === 'GET' && (req.headers.accept || '').includes('text/html')) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  res.status(401).type('text').send('Unauthorized');
});

app.get('/logout', (req, res) => {
  const id = readCookie(req.headers.cookie, '__psid');
  if (id) sessions.delete(id);
  res.clearCookie('__psid', { path: '/' });
  res.redirect('/login');
});

app.get('/__home', (req, res) => res.redirect('/'));

app.get('/', (req, res) => {
  sendPage(
    res,
    200,
    'keke pro-xyz',
    `<h1>keke pro-xyz ${escapeHtml(VERSION)}</h1>
<form id="f" action="/go" method="GET">
  <input type="text" name="url" placeholder="example.com または検索ワード" autofocus required>
  <button type="submit">アクセス</button>
  ${req.query.e ? '<p class="err">URLを解釈できませんでした。</p>' : ''}
</form>
<footer><p><a href="/logout">ログアウト</a><br>&copy; 2026 keke</p></footer>
<script src="/__home.js"></script>`
  );
});

// ホーム画面のフォーム: 入力されたURLをブラウザ側でbase64にして /go?u=... へ送る。
// 平文のURLが、履歴やサーバーへのリクエストに残らない。(JSが無効なら /go?url=... にフォールバック)
const HOME_JS = String.raw`(function () {
  var f = document.getElementById('f');
  if (!f) return;
  function normalize(v) {
    v = v.trim();
    if (!v) return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
      if (/\s/.test(v) || !/[.:]/.test(v)) v = 'https://html.duckduckgo.com/html/?q=' + encodeURIComponent(v);
      else v = 'https://' + v;
    }
    return v;
  }
  f.addEventListener('submit', function (e) {
    try {
      var v = normalize(f.elements.url.value);
      if (!v) return;
      var u = new URL(v);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return;
      e.preventDefault();
      location.href = '/go?u=' + btoa(u.href).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    } catch (err) { /* 失敗したら通常の送信 */ }
  });
})();
`;

app.get('/__home.js', (req, res) => {
  res.set({ 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'private, max-age=300' }).send(HOME_JS);
});

// URL入力 → /p/<base64(オリジン)>/... へ。
//   /go?u=<URLをbase64(またはbase64url)にしたもの>   例: /go?u=aHR0cHM6Ly9leGFtcGxlLmNvbS9hP3g9MQ
//   /go?url=<平文のURL・ドメイン・検索ワード>
// スキームなしなら https:// を補い、URLらしくなければ検索する
app.get('/go', (req, res) => {
  let u;
  if (req.query.u) {
    u = decodeBase64Text(req.query.u);
    if (!u) return res.redirect('/?e=1');
  } else {
    u = String(req.query.url || '');
  }
  u = u.trim();
  if (!u) return res.redirect('/');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) {
    if (/\s/.test(u) || !/[.:]/.test(u)) {
      u = 'https://html.duckduckgo.com/html/?q=' + encodeURIComponent(u);
    } else {
      u = 'https://' + u;
    }
  }
  try {
    const t = new URL(u);
    if (t.protocol !== 'http:' && t.protocol !== 'https:') throw new Error('scheme');
    res.redirect(toProxyPath(t));
  } catch {
    res.redirect('/?e=1');
  }
});

// ページ内のJSエラーを受け取ってログに出す（DEBUG_LOG=1 のときだけ。shim.js が送る）
app.post('/__log', express.json({ limit: '4kb' }), (req, res) => {
  if (DEBUG) console.log('[client]', JSON.stringify(req.body || {}).slice(0, 700));
  res.sendStatus(204);
});

app.get('/__shim.js', (req, res) => {
  res.set({ 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'private, max-age=300' }).send(SHIM);
});

// ページ内JSが document.cookie に書いた内容を、サーバー側のCookieジャーへ同期
app.post('/__cookie', express.json({ limit: '8kb' }), (req, res) => {
  try {
    const { url, cookie } = req.body || {};
    const u = new URL(url);
    if ((u.protocol !== 'http:' && u.protocol !== 'https:') || typeof cookie !== 'string' || cookie.length > 4096) {
      return res.sendStatus(400);
    }
    if (!/;\s*httponly/i.test(cookie)) req.sess.jar.setCookieSync(cookie, u.href, { ignoreError: true });
    res.sendStatus(204);
  } catch {
    res.sendStatus(400);
  }
});

// ==========================================
// プロキシ本体:  /p/<base64url(オリジン)>/<path>?<query>   (旧形式 /p/<scheme>/<host>/<path> も受け付ける)
// ==========================================
const HOP = [
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'proxy-connection',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
];
const DROP_REQ = new Set([
  ...HOP, 'host', 'cookie', 'origin', 'referer', 'accept-encoding', 'expect',
  'forwarded', 'via', 'x-real-ip', 'x-keke-hop',
]);
const DROP_RES = new Set([
  ...HOP, 'set-cookie', 'content-security-policy', 'content-security-policy-report-only',
  'x-frame-options', 'strict-transport-security', 'public-key-pins', 'public-key-pins-report-only',
  'report-to', 'nel', 'cross-origin-opener-policy', 'cross-origin-embedder-policy',
  'cross-origin-resource-policy', 'link', 'alt-svc', 'clear-site-data',
]);

const LEGACY_PATH = /^\/p\/(https?)\/([^/?#]+)([^?#]*)(\?[^#]*)?/; // 旧形式 /p/<scheme>/<host>/<path>
const ENCODED_PATH = /^\/p\/([A-Za-z0-9_-]+)([^?#]*)(\?[^#]*)?/;    // /p/<base64url(オリジン)>/<path>
const HOST_OK = /^(?:[a-z0-9_.-]+|\[[0-9a-f:.]+\])(?::\d{1,5})?$/i;

// 戻り値: { target: URL(上流の完全なURL), needsSlash: パスが無いか, prefix: /p/... のオリジン部分 }
function parseProxyUrl(url) {
  let originUrl;
  let prefix;
  let p;
  let q;

  const lm = LEGACY_PATH.exec(url);
  if (lm) {
    const [, scheme, hostSeg] = lm;
    if (!HOST_OK.test(hostSeg)) return null;
    try {
      originUrl = new URL(`${scheme.toLowerCase()}://${hostSeg}`);
    } catch {
      return null;
    }
    prefix = `/p/${scheme}/${hostSeg}`;
    p = lm[3];
    q = lm[4];
  } else {
    const em = ENCODED_PATH.exec(url);
    if (!em) return null;
    originUrl = decodeOrigin(em[1]);
    if (!originUrl || !HOST_OK.test(originUrl.host)) return null;
    prefix = `/p/${em[1]}`;
    p = em[2];
    q = em[3];
  }

  let target;
  try {
    target = new URL(`${originUrl.origin}${p || '/'}${q || ''}`);
  } catch {
    return null;
  }
  if (target.username || target.password) return null;
  return { target, needsSlash: !p, prefix, query: q || '' };
}

// Referer が「プロキシ内のページ」なら、そのページの上流URLを返す
function upstreamFromReferer(req) {
  const ref = req.headers.referer;
  if (!ref) return null;
  let r;
  try {
    r = new URL(ref);
  } catch {
    return null;
  }
  if (r.host !== req.headers.host) return null;
  const p = parseProxyUrl(r.pathname + r.search);
  return p ? p.target : null;
}

function buildRequestHeaders(req, target, sess) {
  const h = {};
  for (const [k, v] of Object.entries(req.headers)) {
    if (DROP_REQ.has(k) || k.startsWith('x-forwarded-') || k.startsWith('cf-')) continue;
    if (FORCE_UA && k.startsWith('sec-ch-ua')) continue;
    h[k] = v;
  }
  h.host = target.host;
  h['accept-encoding'] = 'gzip, deflate, br';
  h['x-keke-hop'] = '1';
  if (FORCE_UA) h['user-agent'] = FORCE_UA;
  const cookie = sess.jar.getCookieStringSync(target.href);
  if (cookie) h.cookie = cookie;
  const page = upstreamFromReferer(req);
  h.referer = page ? page.href : target.origin + '/';
  if (req.headers.origin) h.origin = page ? page.origin : target.origin;
  return h;
}

function decodeText(buf, contentType, kind) {
  let label = (/charset\s*=\s*["']?([\w.:-]+)/i.exec(contentType || '') || [])[1];
  if (buf[0] === 0xef && buf[1] === 0xbb && buf[2] === 0xbf) label = 'utf-8';
  if (!label && kind === 'html') {
    const head = buf.subarray(0, 2048).toString('latin1');
    const m = /<meta[^>]+charset\s*=\s*["']?\s*([\w.:-]+)/i.exec(head);
    if (m) label = m[1];
  }
  if (!label && kind === 'css') {
    const m = /^@charset\s+"([^"]+)"/.exec(buf.subarray(0, 100).toString('latin1'));
    if (m) label = m[1];
  }
  try {
    return new TextDecoder(label || 'utf-8').decode(buf);
  } catch {
    return new TextDecoder('utf-8').decode(buf);
  }
}

async function readAll(stream, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) {
      stream.destroy();
      const e = new Error('too large');
      e.code = 'ETOOBIG';
      throw e;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function cookieSnapshot(sess, url) {
  return sess.jar
    .getCookiesSync(url.href)
    .filter((c) => !c.httpOnly)
    .map((c) => `${c.key}=${c.value}`)
    .join('; ');
}

async function sendRewritten({ req, res, upRes, out, kind, target, sess }) {
  const enc = String(upRes.headers['content-encoding'] || '').toLowerCase().trim();
  let stream = upRes;
  if (enc && enc !== 'identity') {
    const dec =
      enc === 'gzip' || enc === 'x-gzip' ? zlib.createGunzip()
      : enc === 'deflate' ? zlib.createInflate()
      : enc === 'br' ? zlib.createBrotliDecompress()
      : null;
    if (!dec) {
      // 未知のエンコーディングは変換せずそのまま流す
      res.writeHead(upRes.statusCode, out);
      upRes.pipe(res);
      return;
    }
    stream = pipeline(upRes, dec, () => {});
  }

  const buf = await readAll(stream, MAX_REWRITE_BYTES);
  const text = decodeText(buf, upRes.headers['content-type'], kind);
  const body = kind === 'html'
    ? rewriteHtml(text, target.href, { cookieString: cookieSnapshot(sess, target), assets: ASSETS, debug: DEBUG })
    : rewriteCss(text, target.href, { direct: isDirect(ASSETS), baseHost: target.host });
  let bodyBuf = Buffer.from(body, 'utf8');

  out['content-type'] = (kind === 'html' ? 'text/html' : 'text/css') + '; charset=utf-8';
  delete out['content-encoding'];
  delete out['content-length'];
  delete out['accept-ranges'];
  if (kind === 'html') {
    // Cookie 状態を埋め込んでいるのでキャッシュさせない
    delete out.etag;
    delete out['last-modified'];
    delete out.expires;
    out['cache-control'] = 'private, no-cache';
  }
  if (bodyBuf.length > 1024 && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
    bodyBuf = await gzip(bodyBuf);
    out['content-encoding'] = 'gzip';
    out.vary = out.vary ? out.vary + ', accept-encoding' : 'accept-encoding';
  }
  out['content-length'] = bodyBuf.length;
  res.writeHead(upRes.statusCode, out);
  res.end(bodyBuf);
}

function onUpstreamResponse(req, res, upRes, target, sess) {
  const status = upRes.statusCode;
  if (DEBUG && status >= 400) console.log('[up]', status, req.method, target.href);

  const setCookies = upRes.headers['set-cookie'];
  if (setCookies) {
    for (const c of setCookies) {
      try {
        sess.jar.setCookieSync(c, target.href, { ignoreError: true });
      } catch { /* ignore */ }
    }
  }

  const out = {};
  for (const [k, v] of Object.entries(upRes.headers)) {
    if (!DROP_RES.has(k)) out[k] = v;
  }
  if (out.location) out.location = proxify(out.location, target.href);
  if (out.refresh) {
    out.refresh = String(out.refresh).replace(/(url\s*=\s*)(['"]?)([^'"]+)\2/i, (m, a, q, u) => `${a}${q}${proxify(u, target.href)}${q}`);
  }
  out['referrer-policy'] = 'same-origin';

  const ct = String(upRes.headers['content-type'] || '').toLowerCase();
  const kind = /^(text\/html|application\/xhtml\+xml)/.test(ct) ? 'html' : /^text\/css/.test(ct) ? 'css' : null;
  const rewritable = kind && req.method !== 'HEAD' && status !== 204 && status !== 304 && status !== 206;

  if (rewritable) {
    // 最後に開いたページの上流サイトを覚える。JS が作ったルート直下のURL(/api/x や /favicon.ico)で
    // Referer が付かなかったときの振り分け先に使う。
    const dest = req.headers['sec-fetch-dest'];
    if (kind === 'html' && (!dest || dest === 'document')) {
      sess.lastUpstream = { origin: target.origin };
    }
    sendRewritten({ req, res, upRes, out, kind, target, sess }).catch((err) => {
      const [code, msg] = describeError(err);
      sendError(res, code, msg);
    });
    return;
  }

  // 画像・動画・JS・ダウンロードなどは変換せずストリームのまま中継（Range も素通し）
  res.writeHead(status, out);
  upRes.pipe(res);
}

// proxyUrl は /p/<scheme>/<host>/<path>?<query> 形式の文字列
function proxyRequest(req, res, proxyUrl) {
  if (req.headers['x-keke-hop']) return sendError(res, 508, 'プロキシのループを検出しました。');

  const parsed = parseProxyUrl(proxyUrl);
  if (!parsed) return sendError(res, 400, 'URLが不正です。');
  const { target, needsSlash, prefix, query } = parsed;

  if (needsSlash) {
    return res.redirect(req.method === 'GET' ? 302 : 307, `${prefix}/${query}`);
  }
  if (target.host.toLowerCase() === String(req.headers.host || '').toLowerCase()) {
    return sendError(res, 403, 'このプロキシ自身には接続できません。');
  }
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(hostname) && isBlockedIp(hostname)) {
    return sendError(res, 403, 'このアドレスには接続できません。');
  }

  const isHttps = target.protocol === 'https:';
  const upReq = (isHttps ? https : http).request({
    protocol: target.protocol,
    hostname,
    port: target.port || (isHttps ? 443 : 80),
    method: req.method,
    path: target.pathname + target.search,
    headers: buildRequestHeaders(req, target, req.sess),
    agent: agents[target.protocol],
    lookup: safeLookup,
  });

  upReq.setTimeout(UPSTREAM_TIMEOUT_MS, () => {
    upReq.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));
  });
  upReq.on('error', (err) => {
    if (DEBUG) console.log('[up] error', (err && (err.code || err.message)) || 'unknown', req.method, target.href);
    const [code, msg] = describeError(err);
    sendError(res, code, msg);
  });
  upReq.on('response', (upRes) => {
    upReq.setTimeout(0); // ヘッダ受信後は長時間のストリーミングを許可
    onUpstreamResponse(req, res, upRes, target, req.sess);
  });
  res.on('close', () => {
    if (!res.writableFinished) upReq.destroy();
  });

  req.pipe(upReq);
}

app.use('/p', (req, res) => proxyRequest(req, res, req.originalUrl));

// ==========================================
// フォールバック
// ==========================================
// JS などが組み立てた「/api/xxx」のようなルート直下のURLを、元サイトのURLとして扱う。
// 元サイトは Referer から、無ければ「最後に開いたページ」から推定する。
const isNavigation = (req) => {
  const dest = req.headers['sec-fetch-dest'];
  return req.headers['sec-fetch-mode'] === 'navigate' || dest === 'document' || dest === 'iframe' || dest === 'frame';
};

app.use((req, res) => {
  const page = upstreamFromReferer(req);
  const up = page ? { origin: page.origin } : req.sess && req.sess.lastUpstream;
  if (!up) return sendError(res, 404, 'ページが見つかりません。');

  const proxyUrl = `/p/${encodeOrigin(up.origin)}${req.originalUrl}`;
  // ページ遷移はアドレスバーと相対URLの基準を正しくするためリダイレクト。
  // 画像やAPIなどの部品は、往復を増やさないようその場で中継する。
  if (isNavigation(req)) return res.redirect(307, proxyUrl);
  proxyRequest(req, res, proxyUrl);
});

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error(err);
  sendError(res, 500, 'サーバー内部エラーが発生しました。');
});

const server = app.listen(PORT, () => {
  console.log(`keke pro-xyz ${VERSION} => http://localhost:${PORT}`);
  if (PASSWORD_GENERATED) {
    console.log(`[!] PROXY_PASSWORD が未設定のため一時パスワードを生成しました: ${PASSWORD}`);
    console.log('    (再起動すると変わります。固定する場合は環境変数 PROXY_PASSWORD を設定してください)');
  }
  console.log(`外部ドメインの部品(画像/JS/CSS): ${ASSETS}`);
  if (ALLOW_PRIVATE) console.log('[!] ALLOW_PRIVATE=1: プライベートIPへの接続が許可されています。公開環境では無効にしてください。');
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
