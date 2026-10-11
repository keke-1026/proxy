'use strict';
// HTML / CSS の URL 書き換え。
// 上流URL(https://example.com/a/b) を  /p/https/example.com/a/b  に変換する。

const cheerio = require('cheerio');

const SKIP = /^(#|data:|blob:|javascript:|mailto:|tel:|sms:|about:)/i;

const URL_ATTRS = [
  'href', 'src', 'action', 'poster', 'formaction', 'background',
  'data-src', 'data-original', 'data-lazy-src', 'data-href',
];
const SRCSET_ATTRS = ['srcset', 'data-srcset'];

/** base を基準に raw を解決して、プロキシ経由のパスに変換する */
function proxify(raw, base) {
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
  return `/p/${u.protocol.slice(0, -1)}/${u.host}${u.pathname}${u.search}${u.hash}`;
}

/** CSS 内の url(...) と @import を書き換える */
function rewriteCss(css, base) {
  return css
    .replace(/@charset\s+["'][^"']*["']\s*;?/gi, '')
    .replace(/@import\s+(["'])(.+?)\1/gi, (m, q, u) => `@import ${q}${proxify(u, base)}${q}`)
    .replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (m, q, u) => `url(${q}${proxify(u, base)}${q})`);
}

/** srcset 属性（HTML仕様どおりにパース: URL中のカンマを壊さない） */
function rewriteSrcset(value, base) {
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
    const p = proxify(url, base);
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
 * @param {{cookieString?: string}} opts JS から見える (HttpOnlyでない) Cookie
 */
function rewriteHtml(html, docUrl, opts = {}) {
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

  // CSP / charset / refresh の meta
  $('meta[http-equiv]').each((_, el) => {
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
    for (const name of URL_ATTRS) {
      if (a[name] !== undefined) a[name] = proxify(a[name], base);
    }
    if (el.name === 'object' && a.data !== undefined) a.data = proxify(a.data, base);
    for (const name of SRCSET_ATTRS) {
      if (a[name] !== undefined) a[name] = rewriteSrcset(a[name], base);
    }
    if (a.style !== undefined) a.style = rewriteCss(a.style, base);
    // 内容を書き換えるので SRI は必ず失敗する
    if (a.integrity !== undefined) delete a.integrity;
  });

  $('style').each((_, el) => {
    for (const c of el.children || []) {
      if (c.type === 'text' && typeof c.data === 'string') c.data = rewriteCss(c.data, base);
    }
  });

  const inject =
    '<meta charset="utf-8">' +
    '<meta name="referrer" content="same-origin">' +
    `<script>window.__PX_COOKIES=${jsonForScript(opts.cookieString || '')};</script>` +
    '<script src="/__shim.js"></script>';
  $('head').prepend(inject);

  return $.html();
}

module.exports = { proxify, rewriteCss, rewriteHtml };
