'use strict';
// プロキシURLの形式:  /p/<base64url(オリジン)>/<パス>?<クエリ>
//   例) https://example.com/a/b?x=1  →  /p/aHR0cHM6Ly9leGFtcGxlLmNvbQ/a/b?x=1
//
// 全体ではなく「オリジン(https://ホスト)」だけを符号化するのは、ページ内の相対URL(img/a.png など)が
// ブラウザの標準の解決だけで正しく動くようにするため。パス以降は元のまま残る。
// 旧形式 /p/<scheme>/<host>/<path> も、受け取るだけはできる（server.js 側）。

const cache = new Map();
const CACHE_MAX = 500;

function encodeOrigin(origin) {
  let v = cache.get(origin);
  if (v === undefined) {
    v = Buffer.from(origin, 'utf8').toString('base64url');
    if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value);
    cache.set(origin, v);
  }
  return v;
}

/**
 * base64url の1区間を、オリジンのURLオブジェクトに戻す。不正なら null。
 * 「ちょうどオリジン」の形(パス・認証情報・既定ポート付きなどは不可)で、再符号化して同じになるものだけ通す。
 */
function decodeOrigin(seg) {
  if (!/^[A-Za-z0-9_-]{6,512}$/.test(seg)) return null;
  let s;
  try {
    s = Buffer.from(seg, 'base64url').toString('utf8');
  } catch {
    return null;
  }
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  if (u.origin !== s) return null;
  if (Buffer.from(s, 'utf8').toString('base64url') !== seg) return null;
  return u;
}

/** URLオブジェクト(http/https)をプロキシ経由のパスにする */
function toProxyPath(u) {
  return `/p/${encodeOrigin(u.origin)}${u.pathname}${u.search}${u.hash}`;
}

/** 任意の文字列(base64 / base64url どちらでも可)を UTF-8 文字列に戻す。失敗したら null */
function decodeBase64Text(s) {
  try {
    const t = Buffer.from(String(s).replace(/ /g, '+'), 'base64').toString('utf8');
    return t && !t.includes('\uFFFD') ? t : null;
  } catch {
    return null;
  }
}

module.exports = { encodeOrigin, decodeOrigin, toProxyPath, decodeBase64Text };
