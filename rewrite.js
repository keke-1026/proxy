'use strict';
// HTML / CSS の URL 書き換え。
// 上流URL(https://example.com/a/b) を  /p/https/example.com/a/b  に変換する。
//
// 外部ドメインの画像・JS・CSS などの扱い（EXTERNAL_ASSETS）:
//   proxy  : すべてプロキシ経由（サーバーの負荷は増えるが、ブラウザが外部へ直接つながらない）
//   auto   : 外部の部品はブラウザが直接取りに行く。失敗したらプロキシ経由で取り直す（shim.js）
//   direct : 外部の部品はブラウザが直接取りに行く（失敗しても取り直さない。旧v2.1.0と同じ挙動）
// ページ遷移(<a href> / <form action>)は、どのモードでも必ずプロキシ経由。

const cheerio = require('cheerio');

const SKIP = /^(#|data:|blob:|javascript:|mailto:|tel:|sms:|about:)/i;

// フォントは CORS が必要で、直接取ると失敗しやすい（読み込み元のサイトしか許可しないCDNが多い）ので常にプロキシ経由
const FONT_EXT = /\.(?:woff2?|ttf|otf|eot)$/i;

const ASSET_ATTRS = ['src', 'poster', 'background', 'data-src', 'data-original', 'data-lazy-src'];
const NAV_ATTRS = ['action', 'formaction', 'data-href'];
const SRCSET_ATTRS = ['srcset', 'data-srcset'];
// href が「ページ遷移」ではなく「部品の読み込み」になる要素
const HREF_ASSET_TAGS = new Set(['link', 'image', 'use', 'script', 'feimage']);
const CROSSORIGIN_TAGS = new Set(['img', 'script', 'link', 'video', 'audio', 'source', 'input']);

/** 外部の部品を直接取りに行くモードか */
const isDirect = (mode) => mode === 'auto' || mode === 'direct';

/**
 * base を基準に raw を解決して、プロキシ経由のパスに変換する。
 * @param {*} raw
 * @param {string} base
 * @param {{direct?: boolean, baseHost?: string}} [ctx] direct=true なら、asset=true かつ別ホストのURLは絶対URLのまま返す
 * @param {boolean} [asset] 画像・JS・CSS などの「部品」か（ページ遷移ではない）
 */
function proxify(raw, base, ctx, asset) {
  if (raw === undefined || raw === null) return raw;
  const s = String(raw).trim();
  if (!s || SKIP.test(s)) return raw;
  let u;
  try {
    u = new URL(s, base);
  } catch {
    return raw;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return raw;
  if (asset && ctx && ctx.direct && u.host !== ctx.baseHost && !FONT_EXT.test(u.pathname)) return u.href;
  return `/p/${u.protocol.slice(0, -1)}/${u.host}${u.pathname}${u.search}${u.hash}`;
}

/** CSS 内の url(...) と @import を書き換える */
function rewriteCss(css, base, ctx) {
  return css
    .replace(/@charset\s+["'][^"']*["']\s*;?/gi, '')
    .replace(/@import\s+(["'])(.+?)\1/gi, (m, q, u) => `@import ${q}${proxify(u, base, ctx, true)}${q}`)
    .replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (m, q, u) => `url(${q}${proxify(u, base, ctx, true)}${q})`);
}

/** srcset 属性（HTML仕様どおりにパース: URL中のカンマを壊さない） */
function rewriteSrcset(value, base, ctx) {
  const out = [];
  const n = value.length;
  let i = 0;
  while (i < n) {
    while (i < n && /[\s,]/.test(value[i])) i++;
    if (i >= n) break;
    let start = i;
    while (i < n && !/\s/.test(value[i])) i++;
    let url = value.slice(start, i);
    let desc = '';
    if (url.endsWith(',')) {
      url = url.replace(/,+$/, '');
    } else {
      start = i;
      while (i < n && value[i] !== ',') i++;
      desc = value.slice(start, i).trim();
    }
    const p = proxify(url, base, ctx, true);
    out.push(desc ? `${p} ${desc}` : p);
  }
  return out.join(', ');
}

function jsonForScript(s) {
  return JSON.stringify(s)
    .replace(/</g, '\\u003c')
    .replace(/[\u2028]/g, '\\u2028')
    .replace(/[\u2029]/g, '\\u2029');
}

/**
 * HTML を書き換える。
 * @param {string} html
 * @param {string} docUrl 上流ドキュメントの絶対URL
 * @param {{cookieString?: string, assets?: 'proxy'|'auto'|'direct'}} opts
 *   cookieString: JS から見える (HttpOnlyでない) Cookie
 *   assets: 外部の部品の扱い（既定 proxy）
 */
function rewriteHtml(html, docUrl, opts = {}) {
  const mode = opts.assets || 'proxy';
  const $ = cheerio.load(html);

  // <base href> は解決してから取り除く（以降の相対URLは base で解決済みになる）
  let base = docUrl;
  const baseEl = $('base[href]').first();
  if (baseEl.length) {
    try {
      base = new URL(baseEl.attr('href'), docUrl).href;
    } catch { /* ignore */ }
  }
  $('base').remove();

  const ctx = { direct: isDirect(mode), baseHost: new URL(base).host };

  // CSP / charset / refresh / referrer の meta
  $('meta').each((_, el) => {
    const name = ($(el).attr('name') || '').toLowerCase();
    if (name === 'referrer') {
      // ページ側が no-referrer などを指定すると、JS が作った /api/x のようなURLの救済(Refererで元サイトを判定)が効かなくなる
      $(el).remove();
      return;
    }
    const he = ($(el).attr('http-equiv') || '').toLowerCase();
    if (he === 'content-security-policy' || he === 'content-security-policy-report-only' || he === 'content-type') {
      $(el).remove();
    } else if (he === 'refresh') {
      const c = $(el).attr('content') || '';
      $(el).attr(
        'content',
        c.replace(/^(\s*[\d.]+\s*[;,]\s*(?:url\s*=\s*)?)(['"]?)(.*?)\2\s*$/i, (m, pre, q, u) => `${pre}${q}${proxify(u, base)}${q}`)
      );
    }
  });
  $('meta[charset]').remove();

  $('*').each((_, el) => {
    const a = el.attribs;
    if (!a) return;

    if (a.href !== undefined) a.href = proxify(a.href, base, ctx, HREF_ASSET_TAGS.has(el.name));
    for (const name of ASSET_ATTRS) {
      if (a[name] !== undefined) a[name] = proxify(a[name], base, ctx, true);
    }
    for (const name of NAV_ATTRS) {
      if (a[name] !== undefined) a[name] = proxify(a[name], base);
    }
    if (el.name === 'object' && a.data !== undefined) a.data = proxify(a.data, base, ctx, true);
    for (const name of SRCSET_ATTRS) {
      if (a[name] !== undefined) a[name] = rewriteSrcset(a[name], base, ctx);
    }
    if (a.style !== undefined) a.style = rewriteCss(a.style, base, ctx);

    // 内容を書き換えるので SRI は必ず失敗する
    if (a.integrity !== undefined) delete a.integrity;

    // 外部の部品を直接取りに行く場合、crossorigin が付いていると相手のCORS設定次第で失敗するので外す
    if (a.crossorigin !== undefined && ctx.direct && CROSSORIGIN_TAGS.has(el.name)) {
      const v = el.name === 'link' ? a.href : a.src;
      if (v && /^https?:\/\//i.test(v)) delete a.crossorigin;
    }

    // Referer を送らせない指定は、救済処理（Refererで元サイトを判定）を壊すので外す
    if (a.referrerpolicy !== undefined) delete a.referrerpolicy;
    if (a.rel !== undefined && /\bnoreferrer\b/i.test(a.rel)) {
      const rel = a.rel.replace(/\bnoreferrer\b/gi, '').replace(/\s+/g, ' ').trim();
      if (rel) a.rel = rel;
      else delete a.rel;
    }
  });

  $('style').each((_, el) => {
    for (const c of el.children || []) {
      if (c.type === 'text' && typeof c.data === 'string') c.data = rewriteCss(c.data, base, ctx);
    }
  });

  const inject =
    '<meta charset="utf-8">' +
    '<meta name="referrer" content="same-origin">' +
    `<script>window.__PX_COOKIES=${jsonForScript(opts.cookieString || '')};window.__PX_ASSETS=${jsonForScript(mode)};</script>` +
    '<script src="/__shim.js"></script>';
  $('head').prepend(inject);

  return $.html();
}

module.exports = { proxify, rewriteCss, rewriteHtml, isDirect };
