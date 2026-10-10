const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = 'v1.2.0';

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

// Cookieから履歴（配列）を取り出す
const getHistory = (req) => {
    if (req.headers.cookie) {
        const match = req.headers.cookie.match(/(?:^|; )proxy_history=([^;]*)/);
        if (match) {
            try { return JSON.parse(decodeURIComponent(match[1])); } catch(e) {}
        }
    }
    return [];
};

// 履歴を更新してCookieに保存する
const updateHistory = (res, historyList, newUrl) => {
    // すでに同じURLがあれば消して、一番前に追加する
    let list = historyList.filter(url => url !== newUrl);
    list.unshift(newUrl);
    if (list.length > 5) list = list.slice(0, 5); // 最大5件まで
    res.cookie('proxy_history', encodeURIComponent(JSON.stringify(list)), { path: '/' });
};

// ホーム画面 ＆ リセット処理
app.get('/', (req, res, next) => {
    let inputUrl = req.query.url;

    // URLが入力されていて、かつ「home」ではない場合
    if (inputUrl && inputUrl !== 'home') {
        // http(s):// が無ければ https:// を自動で付ける
        if (!/^https?:\/\//i.test(inputUrl)) {
            inputUrl = 'https://' + inputUrl;
            req.query.url = inputUrl; // リクエスト自体を上書き
        }
    }

    // ?url=home で来た場合、またはURL指定もCookieもない場合
    if (!req.query.url || req.query.url === 'home') {
        
        // homeの時は現在のURLのCookieだけ削除してリセット（履歴は残す）
        if (req.query.url === 'home') {
            res.clearCookie('proxy_url');
        } else if (getTargetFromCookie(req)) {
            // URL指定はないがCookieが残っている場合は、プロキシ処理へ進む
            return next();
        }
        
        const history = getHistory(req);
        let historyHtml = '';
        if (history.length > 0) {
            historyHtml = '<h3>最近アクセスしたサイト:</h3><ul>';
            history.forEach(url => {
                historyHtml += `<li><a href="/?url=${encodeURIComponent(url)}">${url}</a></li>`;
            });
            historyHtml += '</ul>';
        }

        // 超シンプルなホーム画面
        return res.send(`
            <!DOCTYPE html>
            <html lang="ja">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>proxy</title>
            </head>
            <body>
                <h1>Keke Proxy <span style="font-size:0.5em; color:gray;">${VERSION}</span></h1>
                <form action="/" method="GET">
                    <input type="text" name="url" placeholder="example.com" required size="40">
                    <button type="submit">アクセス</button>
                </form>
                ${historyHtml}
            </body>
            </html>
        `);
    }
    next();
});

// URL指定がある場合はCookieに記憶し、履歴も更新する
app.use((req, res, next) => {
    if (req.query.url && req.query.url !== 'home') {
        res.cookie('proxy_url', req.query.url, { path: '/' });
        const history = getHistory(req);
        updateHistory(res, history, req.query.url);
    }
    next();
});

// プロキシ本体
app.use('/', createProxyMiddleware({
    target: 'http://localhost',
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    
    // ★追加: ログイン用Cookieなどをプロキシドメインでも使えるように書き換える
    cookieDomainRewrite: '*',

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
        // User-Agentの強制書き換えを削除（PC/スマホの判定を正常化）
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
        
        if (contentType && contentType.includes('text/html')) {
            try {
                let html = responseBuffer.toString('utf8');
                
                // ★追加: href, src に加えて action (フォーム送信先) も書き換え対象に追加
                html = html.replace(/(src|href|action)=["'](https?:\/\/[^"']+)["']/gi, (match, attr, url) => {
                    return `${attr}="/?url=${encodeURIComponent(url)}"`;
                });

                // 右下のボタンは削除。クリック横取りJSのみ残す
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
