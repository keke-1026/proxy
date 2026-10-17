'use strict';
// SSRF 対策: プライベート / ループバック / リンクローカル等のアドレスへの接続を禁止する。
//
// 注意: net.BlockList は IPv4 アドレスを「IPv4射影IPv6 (::ffff:0:0/96)」のルールとも照合するため、
// そのルールを入れると *すべての* IPv4 が一致してしまう。そこでIPv4用とIPv6用でリストを分け、
// IPv4射影・NAT64・6to4 に埋め込まれたIPv4は自前で取り出して IPv4 ルールで判定する。

const dns = require('dns');
const net = require('net');

// ローカル開発/テスト専用。公開環境では絶対に有効にしない
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';

const v4Rules = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([a, p]) => v4Rules.addSubnet(a, p, 'ipv4'));

const v6Rules = new net.BlockList();
[
  ['::', 96], // ::, ::1, IPv4互換アドレス
  ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
].forEach(([a, p]) => v6Rules.addSubnet(a, p, 'ipv6'));

/** IPv6 文字列を 16bit x 8 の配列にする。不正なら null */
function parseIPv6(ip) {
  ip = String(ip).split('%')[0];
  const dotted = /(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  if (dotted) {
    const o = dotted[1].split('.').map(Number);
    if (o.some((n) => n > 255)) return null;
    ip = ip.slice(0, -dotted[1].length) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let parts;
  if (halves.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    parts = [...head, ...Array(fill).fill('0'), ...rest];
  } else {
    parts = head;
  }
  if (parts.length !== 8) return null;
  const nums = parts.map((p) => (/^[0-9a-f]{1,4}$/i.test(p) ? parseInt(p, 16) : NaN));
  return nums.some(Number.isNaN) ? null : nums;
}

const v4From = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

function isBlockedIp(ip) {
  if (ALLOW_PRIVATE) return false;
  const fam = net.isIP(ip);
  if (fam === 4) return v4Rules.check(ip, 'ipv4');
  if (fam !== 6) return true;

  const h = parseIPv6(ip);
  if (!h) return true;
  // IPv4射影 ::ffff:a.b.c.d
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) return v4Rules.check(v4From(h[6], h[7]), 'ipv4');
  // NAT64 64:ff9b::a.b.c.d （IPv6オンリー環境のDNS64で公開サイトもここに来る）
  if (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0)) return v4Rules.check(v4From(h[6], h[7]), 'ipv4');
  // 6to4 2002:AABB:CCDD::
  if (h[0] === 0x2002) return v4Rules.check(v4From(h[1], h[2]), 'ipv4');
  return v6Rules.check(ip, 'ipv6');
}

// 検証済みのDNS結果を短時間だけ覚える（新規接続のたびに getaddrinfo を呼ぶのを避ける）。
// 覚えるのは「検証を通ったIP」だけで、接続もそのIPに対して行うので、DNS rebinding 対策は崩れない。
const DNS_TTL_MS = 30 * 1000;
const DNS_CACHE_MAX = 500;
const dnsCache = new Map();

function cacheGet(key) {
  const hit = dnsCache.get(key);
  if (!hit) return null;
  if (hit.exp < Date.now()) {
    dnsCache.delete(key);
    return null;
  }
  return hit.addrs;
}

function cacheSet(key, addrs) {
  if (dnsCache.size >= DNS_CACHE_MAX) dnsCache.delete(dnsCache.keys().next().value);
  dnsCache.set(key, { addrs, exp: Date.now() + DNS_TTL_MS });
}

// 接続時にDNSの結果を検証する（DNS rebinding対策: 検証したIPにそのまま接続する）
function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  const reply = (ok) => {
    if (options.all) return callback(null, ok);
    callback(null, ok[0].address, ok[0].family);
  };
  const key = `${hostname}|${options.family || 0}`;
  const cached = cacheGet(key);
  if (cached) return reply(cached);

  dns.lookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return callback(err);
    const ok = addrs.filter((a) => !isBlockedIp(a.address));
    if (!ok.length) {
      console.warn(`[ssrf] blocked ${hostname} -> ${addrs.map((a) => a.address).join(', ')}`);
      const e = new Error('blocked address');
      e.code = 'EBLOCKED';
      return callback(e);
    }
    cacheSet(key, ok);
    reply(ok);
  });
}

module.exports = { isBlockedIp, safeLookup, parseIPv6, ALLOW_PRIVATE };
