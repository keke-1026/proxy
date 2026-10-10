const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = 'v2.1.0'; 

// Cookie読み取り
const getTargetFromCookie = (req) => {
    if (req.headers.cookie) {
        const match = req.headers.cookie.match(/(?:^|; )__proxy_target=([^;]*)/);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
};

// ==========================================
// 1. ホーム画面 ( /__home )
// ==========================================
app.get('/__home', (req, res) => {
    res.clearCookie('__proxy_target', { path: '/' });
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
            <!-- フォームは万能トンネル(/__p)へ送信 -->
            <form action="/__p" method="GET">
                <input type="text" name="url" placeholder="example.com" required size="30">
                <button type="submit">アクセス</button>
            </form>
            <br>
            &copy; 2026 keke
        </body>
        </html>
    `);
});

// ==========================================
// 2. 万能トンネル ＆ 別ドメインへの遷移用 ( /__p )
// ==========================================
// POSTデータ（ログイン情報など）を壊さずに中継するための仕組み
app.use('/__p', (req, res, next) => {
    let u = req.query.url;
    if (!u) return res.redirect('/__home');
    
    if (!/^https?:\/\//i.test(u)) {
        u = 'https://' + u;
    }
    
    try {
        const targetObj = new URL(u);
        // 新しいドメインをCookieに記憶
        res.cookie('__proxy_target', targetObj.origin, { path: '/' });
        
        // プロキシに対して「このドメインに中継してね」と指示を出す
        req.customTarget = targetObj.origin;
        
        // アクセス先のパスを書き換える（例: /login?id=1）
        req.url = targetObj.pathname + targetObj.search;
        
        next();
    } catch(e) {
        res.redirect('/__home');
    }
});

// ==========================================
// 3. ルートチェック
// ==========================================
app.use((req, res, next) => {
    if (req.path !== '/__home' && !req.customTarget) {
        if (!getTargetFromCookie(req)) {
            return res.redirect('/__home');
        }
    }
    next();
});

// ==========================================
// 4. プロキシ本体
// ==========================================
app.use('/', createProxyMiddleware({
    target: 'http://127.0.0.1', 
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    cookieDomainRewrite: '*',
    cookiePathRewrite: '/',

    // 万能トンネルの指示か、Cookieの記憶から中継先を決定
    router: (req) => {
        return req.customTarget || getTargetFromCookie(req);
    },

    onProxyReq: (proxyReq, req, res) => {
        proxyReq.removeHeader('accept-encoding');
        
        // ★PC表示にするための偽装
        proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
        
        const targetOrigin = req.customTarget || getTargetFromCookie(req);
        if (targetOrigin) {
            proxyReq.setHeader('Origin', targetOrigin);
            // ★画像出ない問題の対策: サイト内の正しいURLからアクセスしているように偽装
            proxyReq.setHeader('Referer', targetOrigin + req.url);
        }
    },

    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        const targetOrigin = req.customTarget || getTargetFromCookie(req);
        if (!targetOrigin) return responseBuffer;

        // リダイレクトの処理
        if (proxyRes.headers['location']) {
            const loc = proxyRes.headers['location'];
            if (loc.startsWith(targetOrigin)) {
                let rel = loc.replace(targetOrigin, '');
                if (rel === '') rel = '/';
                res.setHeader('location', rel);
            } else if (loc.startsWith('http')) {
                // 別ドメインへのリダイレクトも万能トンネルを通す
                res.setHeader('location', '/__p?url=' + encodeURIComponent(loc));
            }
        }

        const contentType = proxyRes.headers['content-type'];
        
        // HTMLの中身の書き換え
        if (contentType && contentType.includes('text/html')) {
            try {
                let html = responseBuffer.toString('utf8');
                
                html = html.replace(/(src|href|action)=["'](https?:\/\/[^"']+)["']/gi, (match, attr, url) => {
                    // 同じドメインなら相対パスに変換
                    if (url.startsWith(targetOrigin)) {
                        let relativePath = url.replace(targetOrigin, '');
                        if (relativePath === '') relativePath = '/';
                        return `${attr}="${relativePath}"`;
                    }
                    
                    const attrLower = attr.toLowerCase();
                    // ★ログイン問題の対策: リンク(href)やフォーム送信(action)が別ドメインなら万能トンネルを通す
                    if (attrLower === 'href' || attrLower === 'action') {
                        return `${attr}="/__p?url=${encodeURIComponent(url)}"`;
                    }
                    
                    return match;
                });
                
                return html;
            } catch (e) {
                return responseBuffer;
            }
        }
        
        return responseBuffer;
    }),
    
    onError: (err, req, res) => {
        res.redirect('/__home');
    }
}));

app.listen(PORT, () => {
    console.log('Proxy Server Start! => http://localhost:' + PORT);
});
