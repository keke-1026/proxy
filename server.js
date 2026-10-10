const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = 'v1.0.0'; // ここでバージョンを管理

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

// ホーム画面 ＆ リセット処理
app.get('/', (req, res, next) => {
    // ?url=home で来た場合、またはURL指定もCookieもない場合
    if (!req.query.url || req.query.url === 'home') {
        
        // homeの時はCookieを削除してリセットする
        if (req.query.url === 'home') {
            res.clearCookie('proxy_url');
        } else if (getTargetFromCookie(req)) {
            // URL指定はないがCookieが残っている場合は、プロキシ処理へ進む
            return next();
        }
        
        const sampleUrl = 'https://example.com';
        
        // ホーム画面のHTML
        return res.send(`
            <!DOCTYPE html>
            <html lang="ja">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Proxy</title>
                <style>
                    body { font-family: sans-serif; text-align: center; padding: 50px 20px; background: #121212; color: #fff; }
                    .container { background: #1e1e1e; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); max-width: 500px; margin: 0 auto; }
                    h1 { margin-top: 0; color: #4dabf7; }
                    span.ver { font-size: 0.5em; color: #888; vertical-align: middle; margin-left: 10px; }
                    input { padding: 12px; width: calc(100% - 24px); margin-bottom: 15px; border: 1px solid #333; border-radius: 6px; background: #2a2a2a; color: #fff; }
                    button { padding: 12px 24px; background: #4dabf7; color: #121212; font-weight: bold; border: none; border-radius: 6px; cursor: pointer; width: 100%; transition: 0.2s; }
                    button:hover { background: #3bc9db; }
                    a { color: #4dabf7; text-decoration: none; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Keke Proxy<span class="ver">${VERSION}</span></h1>
                    <form action="/" method="GET">
                        <input type="text" name="url" placeholder="https://..." required>
                        <button type="submit">アクセス</button>
                    </form>
                    <p style="margin-top:20px; font-size:14px;"><a href="/?url=${encodeURIComponent(sampleUrl)}">テストアクセス (example.com)</a></p>
                </div>
            </body>
            </html>
        `);
    }
    next();
});

// URL指定がある場合はCookieに記憶させる
app.use((req, res, next) => {
    if (req.query.url && req.query.url !== 'home') {
        res.cookie('proxy_url', req.query.url, { path: '/' });
    }
    next();
});

// プロキシ本体
app.use('/', createProxyMiddleware({
    target: 'http://localhost',
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    
    router: (req) => {
        let targetUrlStr = req.query.url || getTargetFromCookie(req);
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
        proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
    },

    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        // リダイレクトの書き換え
        if (proxyRes.headers['location']) {
            let currentUrlStr = req.query.url || getTargetFromCookie(req);
            if (currentUrlStr && currentUrlStr !== 'home') {
                try {
                    const absoluteLocation = new URL(proxyRes.headers['location'], currentUrlStr).href;
                    res.setHeader('location', '/?url=' + encodeURIComponent(absoluteLocation));
                } catch (e) {}
            }
        }

        const contentType = proxyRes.headers['content-type'];
        
        // HTMLの書き換え処理
        if (contentType && contentType.includes('text/html')) {
            try {
                let html = responseBuffer.toString('utf8');
                
                // ★追加: HTML内の絶対URL（画像・CSS・リンク）もすべてプロキシサーバーを通すように書き換える
                html = html.replace(/(src|href)=["'](https?:\/\/[^"']+)["']/gi, (match, attr, url) => {
                    return `${attr}="/?url=${encodeURIComponent(url)}"`;
                });

                // Homeに戻るための右下フローティングボタン
                const injectUI = `
                <div style="position:fixed; bottom:20px; right:20px; z-index:999999; background:rgba(0,0,0,0.8); padding:10px 15px; border-radius:50px; box-shadow:0 2px 10px rgba(0,0,0,0.5);">
                    <a href="/?url=home" style="color:white; text-decoration:none; font-family:sans-serif; font-size:14px; font-weight:bold;">🏠 Home</a>
                </div>
                `;

                // クリック横取りJS（念のため残す）
                const injectedScript = `
                <script>
                    document.addEventListener('click', function(e) {
                        const a = e.target.closest('a');
                        if (a && a.href && a.href.startsWith('http') && !a.href.includes('/?url=')) {
                            e.preventDefault();
                            window.location.href = '/?url=' + encodeURIComponent(a.href);
                        }
                    });
                </script>
                `;
                
                if (html.includes('</body>')) {
                    html = html.replace('</body>', injectUI + injectedScript + '</body>');
                } else {
                    html += injectUI + injectedScript;
                }
                
                return html;
            } catch (e) {
                return responseBuffer;
            }
        }
        
        return responseBuffer;
    }),
    
    onError: (err, req, res) => {
        console.error('[通信エラー]', err.message);
        res.status(500).send('Proxy Error');
    }
}));

app.listen(PORT, () => {
    console.log('Proxy Server Start! => http://localhost:' + PORT);
});
