// プロキシ経由で表示されたページの中で動くクライアント側スクリプト。
// JS が実行時に組み立てるURL（fetch / XHR / 動的な src など）をプロキシ経由に直す。
(function () {
  'use strict';

  var PROXIED = /^\/p\/(?:https?\/[^/]+|[A-Za-z0-9_-]{6,})(?:[/?#]|$)/;
  var SKIP = /^(#|data:|blob:|javascript:|mailto:|tel:|sms:|about:)/i;
  var FONT_EXT = /\.(?:woff2?|ttf|otf|eot)$/i;
  var rawFetch = window.fetch ? window.fetch.bind(window) : null;
  var rawSetAttr = Element.prototype.setAttribute;

  // 外部ドメインの部品(画像/JS/CSS)の扱い: proxy=全部プロキシ経由 / auto=直接取得して失敗したらプロキシ経由 / direct=直接取得のみ
  var MODE = window.__PX_ASSETS || 'proxy';
  var DIRECT = MODE === 'auto' || MODE === 'direct';
  var FALLBACK = MODE === 'auto';

  // プロキシURLは /p/<base64url(オリジン)>/<パス>。オリジンだけを符号化するので、相対URLはブラウザの標準の解決で動く。
  function b64e(s) { return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function b64d(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return atob(s);
  }
  function proxyPath(u) { return '/p/' + b64e(u.origin) + u.pathname + u.search + u.hash; }

  // /p/... を { origin, scheme, host, rest } に分解（旧形式 /p/<scheme>/<host>/... も読める）
  function parseProxyPath(pathname) {
    var m = /^\/p\/(https?)\/([^/]+)(\/.*)?$/.exec(pathname);
    if (m) return { origin: m[1] + '://' + m[2], scheme: m[1], host: m[2], rest: m[3] || '/' };
    m = /^\/p\/([A-Za-z0-9_-]{6,})(\/.*)?$/.exec(pathname);
    if (!m) return null;
    try {
      var o = new URL(b64d(m[1]));
      if (o.protocol !== 'http:' && o.protocol !== 'https:') return null;
      return { origin: o.origin, scheme: o.protocol.slice(0, -1), host: o.host, rest: m[2] || '/' };
    } catch (e) {
      return null;
    }
  }

  function upstream() {
    return parseProxyPath(location.pathname);
  }

  function upstreamHref() {
    var p = parseProxyPath(location.pathname);
    return p ? p.origin + p.rest + location.search : null;
  }

  // 入力URLをプロキシ経由のURLにする。変換不要ならそのまま返す。
  // asset=true: 画像/JS/CSS などの「部品」。直接取得モードなら、別ホストのURLは絶対URLのまま返す。
  function toProxy(input, asset) {
    try {
      var s = String(input).trim();
      if (!s || SKIP.test(s)) return input;
      var up = upstream();
      if (!up) return input;
      if (s.slice(0, 2) === '//') s = up.scheme + ':' + s;
      var u = new URL(s, location.href);
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return input;
      if (u.origin === location.origin) {
        // すでに /p/... なら（相対URLの解決結果も含めて）そのまま
        if (PROXIED.test(u.pathname)) return input;
        // /api/x のような絶対パス → 現在の上流サイトのパスとして扱う
        return '/p/' + b64e(up.origin) + u.pathname + u.search + u.hash;
      }
      if (asset && DIRECT && u.host !== up.host && !FONT_EXT.test(u.pathname)) return u.href;
      return proxyPath(u);
    } catch (e) {
      return input;
    }
  }

  // 直接取得に失敗した外部URLを、プロキシ経由のURLにする（外部URLでなければ null）
  function viaProxy(raw) {
    try {
      var up = upstream();
      if (!up || !raw) return null;
      var u = new URL(String(raw), location.href);
      if ((u.protocol !== 'http:' && u.protocol !== 'https:') || u.origin === location.origin) return null;
      return proxyPath(u);
    } catch (e) {
      return null;
    }
  }

  function guard(fn) {
    try { fn(); } catch (e) { /* 一部ブラウザで定義できないものは諦める */ }
  }

  // fetch
  if (rawFetch) {
    guard(function () {
      window.fetch = function (input, init) {
        if (typeof Request !== 'undefined' && input instanceof Request) {
          var nu = toProxy(input.url);
          if (nu !== input.url) input = new Request(nu, input);
          return rawFetch(input, init);
        }
        return rawFetch(toProxy(input), init);
      };
    });
  }

  // XMLHttpRequest
  guard(function () {
    var open = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      var args = Array.prototype.slice.call(arguments);
      args[1] = toProxy(url);
      return open.apply(this, args);
    };
  });

  // window.open / sendBeacon / EventSource
  guard(function () {
    var wo = window.open;
    window.open = function (url) {
      var args = Array.prototype.slice.call(arguments);
      if (url) args[0] = toProxy(url);
      return wo.apply(this, args);
    };
  });
  guard(function () {
    var sb = navigator.sendBeacon;
    if (sb) navigator.sendBeacon = function (url, data) { return sb.call(navigator, toProxy(url), data); };
  });
  guard(function () {
    var ES = window.EventSource;
    if (!ES) return;
    window.EventSource = function (url, cfg) { return new ES(toProxy(url), cfg); };
    window.EventSource.prototype = ES.prototype;
    ['CONNECTING', 'OPEN', 'CLOSED'].forEach(function (k) { window.EventSource[k] = ES[k]; });
  });

  // history.pushState / replaceState（SPA のルーティング）
  ['pushState', 'replaceState'].forEach(function (name) {
    guard(function () {
      var orig = history[name];
      history[name] = function (state, title, url) {
        return orig.call(this, state, title, url == null ? url : toProxy(url));
      };
    });
  });

  // setAttribute('src' / 'href' ...)
  guard(function () {
    // 値は「部品の読み込み」(true) か「ページ遷移・送信先」(false)
    var ATTRS = { src: true, poster: true, data: true, action: false, formaction: false };
    var HREF_ASSET = { link: true, image: true, use: true, script: true };
    Element.prototype.setAttribute = function (name, value) {
      if (typeof name === 'string') {
        var n = name.toLowerCase();
        if (n === 'href') {
          value = toProxy(value, !!HREF_ASSET[this.localName]);
        } else if (Object.prototype.hasOwnProperty.call(ATTRS, n) && (n !== 'data' || this.tagName === 'OBJECT')) {
          value = toProxy(value, ATTRS[n]);
        }
      }
      return rawSetAttr.call(this, name, value);
    };
  });

  // el.src = ... / a.href = ... / form.action = ...
  function patchProp(ctor, prop, asset) {
    guard(function () {
      if (typeof window[ctor] === 'undefined') return;
      var proto = window[ctor].prototype;
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: d.enumerable,
        get: d.get,
        set: function (v) { d.set.call(this, toProxy(v, asset)); },
      });
    });
  }
  [
    ['HTMLAnchorElement', 'href', false], ['HTMLAreaElement', 'href', false], ['HTMLLinkElement', 'href', true],
    ['HTMLImageElement', 'src', true], ['HTMLScriptElement', 'src', true], ['HTMLIFrameElement', 'src', true],
    ['HTMLSourceElement', 'src', true], ['HTMLMediaElement', 'src', true], ['HTMLEmbedElement', 'src', true],
    ['HTMLTrackElement', 'src', true], ['HTMLInputElement', 'src', true], ['HTMLFormElement', 'action', false],
  ].forEach(function (p) { patchProp(p[0], p[1], p[2]); });

  // 直接取得した外部の部品が読み込みに失敗したら（IPブロック・混在コンテンツ・接続不可など）、プロキシ経由で取り直す。
  // 失敗イベントはバブリングしないので、キャプチャ段階で拾う。
  if (FALLBACK) {
    guard(function () {
      document.addEventListener('error', function (e) {
        var el = e.target;
        if (!el || el.__pxRetry || !el.localName || el === window) return;
        var tag = el.localName;
        var parent = el.parentNode;
        var fixed = null;
        if (tag === 'img') fixed = viaProxy(el.currentSrc || el.getAttribute('src'));
        else if (tag === 'link' && /stylesheet/i.test(el.getAttribute('rel') || '')) fixed = viaProxy(el.getAttribute('href'));
        else if (tag === 'script' || tag === 'video' || tag === 'audio') fixed = viaProxy(el.getAttribute('src'));
        else if (tag === 'source' && parent && /^(video|audio)$/.test(parent.localName)) fixed = viaProxy(el.getAttribute('src'));
        if (!fixed) return;
        el.__pxRetry = true;

        if (tag === 'img') {
          el.removeAttribute('srcset');
          if (parent && parent.localName === 'picture') {
            Array.prototype.slice.call(parent.querySelectorAll('source')).forEach(function (s) { parent.removeChild(s); });
          }
          rawSetAttr.call(el, 'src', fixed);
        } else if (tag === 'link') {
          rawSetAttr.call(el, 'href', fixed);
        } else if (tag === 'script') {
          // script は src を変えても再実行されないので、複製して差し替える
          var n = document.createElement('script');
          for (var i = 0; i < el.attributes.length; i++) {
            var at = el.attributes[i];
            if (at.name !== 'src') rawSetAttr.call(n, at.name, at.value);
          }
          n.async = el.hasAttribute('async');
          n.__pxRetry = true;
          rawSetAttr.call(n, 'src', fixed);
          if (parent) parent.insertBefore(n, el.nextSibling);
        } else if (tag === 'source') {
          rawSetAttr.call(el, 'src', fixed);
          if (parent.load) parent.load();
        } else {
          rawSetAttr.call(el, 'src', fixed);
          if (el.load) el.load();
        }
      }, true);
    });
  }

  // Service Worker
  // 上流サイトが登録した Service Worker は、プロキシ全体(同じオリジン)の通信を横取りして壊してしまうので、
  // 登録を拒否し、残っている登録も解除する。
  guard(function () {
    var sw = navigator.serviceWorker;
    if (!sw) return;
    sw.register = function () {
      return Promise.reject(new DOMException('Service Worker is disabled by the proxy', 'SecurityError'));
    };
    if (sw.getRegistrations) {
      sw.getRegistrations().then(function (rs) {
        rs.forEach(function (r) { r.unregister(); });
      }).catch(function () {});
    }
  });

  // 診断(DEBUG_LOG=1 のとき): ページ内のJSエラー・読み込み失敗・未処理のPromise拒否を、サーバーのログへ送る
  if (window.__PX_DEBUG && rawFetch) {
    guard(function () {
      var sent = 0;
      var report = function (kind, msg) {
        if (sent++ >= 60) return;
        rawFetch('/__log', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ kind: kind, msg: String(msg).slice(0, 400), page: upstreamHref() }),
          keepalive: true,
          credentials: 'same-origin',
        }).catch(function () {});
      };
      window.addEventListener('error', function (e) {
        var t = e.target;
        if (t && t !== window && t.localName) report('resource', t.localName + ' ' + (t.currentSrc || t.src || t.href || ''));
        else report('js', (e.message || '') + ' @' + (e.filename || '') + ':' + (e.lineno || '') + ':' + (e.colno || ''));
      }, true);
      window.addEventListener('unhandledrejection', function (e) {
        var r = e.reason;
        report('promise', r && (r.stack || r.message) || r);
      });
    });
  }

  // document.cookie
  // 上流サイトのCookieはサーバー側のジャーに保存されているので、JS が読み書きする分だけ同期する。
  guard(function () {
    var cookies = Object.create(null);
    String(window.__PX_COOKIES || '').split(/;\s*/).forEach(function (p) {
      var i = p.indexOf('=');
      if (i > 0) cookies[p.slice(0, i)] = p.slice(i + 1);
    });
    var d = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (!d) return;
    Object.defineProperty(Document.prototype, 'cookie', {
      configurable: true,
      enumerable: d.enumerable,
      get: function () {
        return Object.keys(cookies).map(function (k) { return k + '=' + cookies[k]; }).join('; ');
      },
      set: function (str) {
        str = String(str);
        var parts = str.split(';');
        var kv = parts[0];
        var i = kv.indexOf('=');
        var name = (i < 0 ? '' : kv.slice(0, i)).trim();
        var value = (i < 0 ? kv : kv.slice(i + 1)).trim();
        var expired = false;
        parts.slice(1).forEach(function (a) {
          var j = a.indexOf('=');
          var k = (j < 0 ? a : a.slice(0, j)).trim().toLowerCase();
          var v = j < 0 ? '' : a.slice(j + 1).trim();
          if (k === 'max-age' && Number(v) <= 0) expired = true;
          if (k === 'expires') {
            var t = Date.parse(v);
            if (!isNaN(t) && t <= Date.now()) expired = true;
          }
        });
        if (name) {
          if (expired) delete cookies[name];
          else cookies[name] = value;
        }
        var href = upstreamHref();
        if (href && rawFetch) {
          rawFetch('/__cookie', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ url: href, cookie: str }),
            keepalive: true,
            credentials: 'same-origin',
          }).catch(function () {});
        }
      },
    });
  });
})();
