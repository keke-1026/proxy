// プロキシ経由で表示されたページの中で動くクライアント側スクリプト。
// JS が実行時に組み立てるURL（fetch / XHR / 動的な src など）をプロキシ経由に直す。
(function () {
  'use strict';

  var PROXIED = /^\/p\/https?\/[^/]+(?:[/?#]|$)/;
  var SKIP = /^(#|data:|blob:|javascript:|mailto:|tel:|sms:|about:)/i;
  var rawFetch = window.fetch ? window.fetch.bind(window) : null;

  function upstream() {
    var m = /^\/p\/(https?)\/([^/]+)/.exec(location.pathname);
    return m ? { scheme: m[1], host: m[2] } : null;
  }

  function upstreamHref() {
    var m = /^\/p\/(https?)\/([^/]+)(\/[^?#]*)?/.exec(location.pathname);
    return m ? m[1] + '://' + m[2] + (m[3] || '/') + location.search : null;
  }

  // 入力URLをプロキシ経由のURLにする。変換不要ならそのまま返す。
  function toProxy(input) {
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
        return '/p/' + up.scheme + '/' + up.host + u.pathname + u.search + u.hash;
      }
      return '/p/' + u.protocol.slice(0, -1) + '/' + u.host + u.pathname + u.search + u.hash;
    } catch (e) {
      return input;
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
    var ATTRS = { src: 1, href: 1, action: 1, poster: 1, formaction: 1, data: 1 };
    var setAttr = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      if (typeof name === 'string') {
        var n = name.toLowerCase();
        if (ATTRS[n] && (n !== 'data' || this.tagName === 'OBJECT')) value = toProxy(value);
      }
      return setAttr.call(this, name, value);
    };
  });

  // el.src = ... / a.href = ... / form.action = ...
  function patchProp(ctor, prop) {
    guard(function () {
      if (typeof window[ctor] === 'undefined') return;
      var proto = window[ctor].prototype;
      var d = Object.getOwnPropertyDescriptor(proto, prop);
      if (!d || !d.set) return;
      Object.defineProperty(proto, prop, {
        configurable: true,
        enumerable: d.enumerable,
        get: d.get,
        set: function (v) { d.set.call(this, toProxy(v)); },
      });
    });
  }
  [
    ['HTMLAnchorElement', 'href'], ['HTMLAreaElement', 'href'], ['HTMLLinkElement', 'href'],
    ['HTMLImageElement', 'src'], ['HTMLScriptElement', 'src'], ['HTMLIFrameElement', 'src'],
    ['HTMLSourceElement', 'src'], ['HTMLMediaElement', 'src'], ['HTMLEmbedElement', 'src'],
    ['HTMLTrackElement', 'src'], ['HTMLInputElement', 'src'], ['HTMLFormElement', 'action'],
  ].forEach(function (p) { patchProp(p[0], p[1]); });

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
