const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = 'v1.3.0';

// Cookieから記憶しているURLを取り出す
const getTargetFromCookie = (req) => {
    if (req.headers.cookie) {
        const match = req.headers.cookie.match(/(?:^|; )proxy_url=([^;]*)/);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
};

// 1. URLの自動補完 ＆ ループ防止
app.use((req, res, next) => {
    let inputUrl = req.query.url;

    if (inputUrl && inputUrl !== 'home') {
        // http(s):// が無ければ https:// を自動で付ける
        if (!/^https?:\/\//i.test(inputUrl)) {
            inputUrl = 'https://' + inputUrl;
            req.query.url = inputUrl;
        }
        
        // 自分のRenderドメインがURLに入り込んでループするのを防ぐ
        if (inputUrl.includes(req.headers.host)) {
            return res.redirect('/?url=home');
        }
    }

    // アクセス先が不明でHomeでもない場合はHomeに強制送還
    const target = req.query.url || getTargetFromCookie(req);
    if (!target && req.path !== '/') {
        return res.redirect('/?url=home');
    }

    next();
});

// 2. ホーム画面（?url=home または 指定なし時）
app.get('/', (req, res, next) => {
    if (!req.query.url || req.query.url === 'home') {
        
        // homeの時はCookieを削除してリセット
        if (req.query.url === 'home') {
            res.clearCookie('proxy_url');
        } else if (getTargetFromCookie(req)) {
            // Cookieが残っている場合はプロキシ処理へ進む
            return next();
        }

        return res.send(`
            <!DOCTYPE html>
            <html lang="ja">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>keke pro-xyz</title>
                <!-- 細いGoogle Fontを読み込み -->
                <link rel="preconnect" href="https://fonts.googleapis.com">
                <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
                <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+JP:wght@300&display=swap" rel="stylesheet">
                <style>
                    /* 全て同じサイズ、左寄せで統一 */
                    body {
                        font-family: 'Noto Sans JP', sans-serif;
                        font-weight: 300;
                        background-color: #ffffff;
                        color: #111111;
                        margin: 0;
                        padding: 40px 20px;
                        font-size: 18px;
                        text-align: left;
                    }
                    h1 {
                        font-size: 18px;
                        font-weight: 300;
                        margin: 0 0 20px 0;
                    }
                    form {
                        margin-bottom: 20px;
                    }
                    input, button {
                        font-family: 'Noto Sans JP', sans-serif;
                        font-weight: 300;
                        font-size: 18px;
                        padding: 8px 12px;
                        margin: 0 10px 10px 0;
                        border: 1px solid #cccccc;
                        border-radius: 4px;
                        background: #ffffff;
                        color: #111111;
                    }
                    input {
                        width: 300px;
                        max-width: 100%;
                    }
                    button {
                        cursor: pointer;
                    }
                    button:hover {
                        background: #f0f0f0;
                    }
                    .copy {
                        font-size: 18px;
                    }
                </style>
            </head>
            <body>
                <h1>keke pro-xyz <span>${VERSION}</span></h1>
                <form action="/" method="GET">
                    <input type="text" name="url" placeholder="example.com" required>
                    <button type="submit">アクセス</button>
                </form>
                <div class="copy">&copy; 2026 keke</div>
            </body>
            </html>
        `);
    }
    next();
});

// 3. アクセス時にCookieにURLを記憶させる
app.use((req, res, next) => {
    if (req.query.url && req.query.url !== 'home') {
        res.cookie('proxy_url', req.query.url, { path: '/' });
    }
    next();
});

// 4. プロキシ本体処理
app.use('/', createProxyMiddleware({
    target: 'http://localhost', // ダミー
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    cookieDomainRewrite: '*', // Cookieのドメインを書き換え
    cookiePathRewrite: '/',   // Cookieのパスも一律ルートに書き換え（ログイン維持率アップ）

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
        
        // ★ ログイン突破用: どこからアクセスしたか（Referer / Origin）を対象サイトに合わせて偽装する
        let targetUrlStr = req.query.url || getTargetFromCookie(req);
        if (targetUrlStr && targetUrlStr !== 'home') {
            try {
                const targetObj = new URL(targetUrlStr);
                proxyReq.setHeader('Origin', targetObj.origin);
                proxyReq.setHeader('Referer', targetObj.origin + '/');
            } catch (e) {}
        }
    },

    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        let currentUrlStr = req.query.url || getTargetFromCookie(req);
        if (!currentUrlStr || currentUrlStr === 'home') return responseBuffer;

        // リダイレクトの書き換え（ループ防止判定付き）
        if (proxyRes.headers['location']) {
            try {
                const absoluteLocation = new URL(proxyRes.headers['location'], currentUrlStr).href;
                if (!absoluteLocation.includes(req.headers.host)) {
                    res.setHeader('location', '/?url=' + encodeURIComponent(absoluteLocation));
                }
            } catch (e) {}
        }

        const contentType = proxyRes.headers['content-type'];
        
        // HTMLの書き換え処理
        if (contentType && contentType.includes('text/html')) {
            try {
                let html = responseBuffer.toString('utf8');
                const host = req.headers.host;
                
                // ★ 改良: 絶対パスも相対パス（/img.pngや/favicon.ico）もすべて正しいプロキシURLに一括変換
                html = html.replace(/(src|href|action)=["']([^"']+)["']/gi, (match, attr, url) => {
                    // data: や javascript: やページ内リンク(#) は無視
                    if (url.startsWith('javascript:') || url.startsWith('data:') || url.startsWith('#')) {
                        return match;
                    }
                    try {
                        const absoluteUrl = new URL(url, currentUrlStr).href;
                        // すでにプロキシのURLになっているものは二重に変換しない
                        if (absoluteUrl.includes(host)) return match;
                        
                        return `${attr}="/?url=${encodeURIComponent(absoluteUrl)}"`;
                    } catch (e) {
                        return match;
                    }
                });

                // クリック横取りJS
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
        console.error('[通信エラー]', err.message);
        res.status(500).send('Proxy Error');
    }
}));

app.listen(PORT, () => {
    console.log('Proxy Server Start! => http://localhost:' + PORT);
});
