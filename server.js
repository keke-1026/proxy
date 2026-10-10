const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = 'v1.4.0';

// CookieからURLを取り出す
const getTargetFromCookie = (req) => {
    if (req.headers.cookie) {
        const match = req.headers.cookie.match(/(?:^|; )proxy_url=([^;]*)/);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
};

// 事前チェック: URLの補完とループ防止
app.use((req, res, next) => {
    if (req.query.url) {
        let u = req.query.url;
        if (u === 'home') return next();

        // https:// が無ければ付ける
        if (!/^https?:\/\//i.test(u)) {
            u = 'https://' + u;
            req.query.url = u;
        }

        // 自分のRenderドメインが入り込んでループするのを防ぐ
        if (req.headers.host && u.includes(req.headers.host)) {
            return res.redirect('/?url=home');
        }

        // 存在しない変なURLが打ち込まれたらHomeに戻す
        try {
            new URL(u);
        } catch(e) {
            return res.redirect('/?url=home');
        }
    }
    next();
});

// Home画面
app.get('/', (req, res, next) => {
    if (!req.query.url || req.query.url === 'home') {
        
        if (req.query.url === 'home') {
            res.clearCookie('proxy_url');
        } else if (getTargetFromCookie(req)) {
            return next(); // Cookieがあるならプロキシへ
        }

        // CSS完全排除・左寄せの超シンプルHTML
        return res.send(`
            <!DOCTYPE html>
            <html lang="ja">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>keke pro-xyz</title>
            </head>
            <body>
                keke pro-xyz ${VERSION}<br><br>
                <form action="/" method="GET">
                    <input type="text" name="url" placeholder="example.com" required size="30">
                    <button type="submit">アクセス</button>
                </form>
                <br>
                &copy; 2026 keke
            </body>
            </html>
        `);
    }
    next();
});

// Cookieに保存
app.use((req, res, next) => {
    if (req.query.url && req.query.url !== 'home') {
        res.cookie('proxy_url', req.query.url, { path: '/' });
    }
    next();
});

// プロキシ本体
app.use('/', createProxyMiddleware({
    target: 'http://127.0.0.1', // ダミー
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    cookieDomainRewrite: '*', // ログイン情報保持
    cookiePathRewrite: '/',

    router: (req) => {
        const targetUrlStr = req.query.url || getTargetFromCookie(req);
        if (targetUrlStr && targetUrlStr !== 'home') {
            try { return new URL(targetUrlStr).origin; } catch (e) {}
        }
    },
    
    pathRewrite: (path, req) => {
        if (req.query.url && req.query.url !== 'home') {
            try {
                const targetUrl = new URL(req.query.url);
                return targetUrl.pathname + targetUrl.search;
            } catch(e) {}
        }
        return path;
    },

    onProxyReq: (proxyReq, req, res) => {
        proxyReq.removeHeader('accept-encoding');
        
        // 【ログイン対策】対象サイトに合わせてOriginとRefererを偽装
        const targetUrlStr = req.query.url || getTargetFromCookie(req);
        if (targetUrlStr && targetUrlStr !== 'home') {
            try {
                const targetObj = new URL(targetUrlStr);
                proxyReq.setHeader('Origin', targetObj.origin);
                proxyReq.setHeader('Referer', targetObj.origin + '/');
            } catch (e) {}
        }
    },

    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        const currentUrlStr = req.query.url || getTargetFromCookie(req);
        if (!currentUrlStr || currentUrlStr === 'home') return responseBuffer;

        // リダイレクトの書き換え
        if (proxyRes.headers['location']) {
            try {
                const absoluteLocation = new URL(proxyRes.headers['location'], currentUrlStr).href;
                if (req.headers.host && !absoluteLocation.includes(req.headers.host)) {
                    res.setHeader('location', '/?url=' + encodeURIComponent(absoluteLocation));
                }
            } catch (e) {}
        }

        const contentType = proxyRes.headers['content-type'];
        
        if (contentType && contentType.includes('text/html')) {
            try {
                let html = responseBuffer.toString('utf8');
                
                // ★修正: 「絶対URL（http〜）」のみ書き換えるように戻しました。
                // これによりサイト内の相対パス（/style.css）が壊れず、デザインが正しく表示されます。
                html = html.replace(/(src|href|action)=["'](https?:\/\/[^"']+)["']/gi, (match, attr, url) => {
                    if (req.headers.host && url.includes(req.headers.host)) return match;
                    return `${attr}="/?url=${encodeURIComponent(url)}"`;
                });

                // リンククリック横取りJS
                const injectedScript = `
                <script>
                    document.addEventListener('click', function(e) {
                        const a = e.target.closest('a');
                        if (a && a.href && a.href.startsWith('http') && !a.href.includes('/?url=') && !a.href.includes(location.host)) {
                            e.preventDefault();
                            window.location.href = '/?url=' + encodeURIComponent(a.href);
                        }
                    });
                </script>
                `;
                
                if (html.includes('</body>')) {
                    html = html.replace('</body>', injectedScript + '</body>');
                } else {
                    html += injectedScript;
                }
                
                return html;
            } catch (e) {
                return responseBuffer;
            }
        }
        
        return responseBuffer;
    }),
    
    onError: (err, req, res) => {
        // エラー（真っ白）になったら強制的にHomeへ戻す
        res.redirect('/?url=home');
    }
}));

app.listen(PORT, () => {
    console.log('Proxy Server Start! => http://localhost:' + PORT);
});
