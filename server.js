const express = require('express');
const { createProxyMiddleware, responseInterceptor } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const VERSION = 'v2.0.0'; // Cookieルーティング採用のメジャーアップデート

// POSTで送られたフォームデータを読み取るための設定
app.use(express.urlencoded({ extended: true }));

// Cookieから記憶している「ターゲットドメイン」を取り出す
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
// 1. ホーム画面 ( /__home ) - CSS完全なし
// ==========================================
app.get('/__home', (req, res) => {
    // Homeに来たらCookieを消去
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
            <form action="/__set" method="POST">
                <input type="text" name="url" placeholder="example.com" required size="30">
                <button type="submit">アクセス</button>
            </form>
            <br>
            &copy; 2026 keke
            このサイトはCookieを使用します｡プライベートブラウザではうまく動作しません｡
            Cookieを使用するのは､ドメインの記録のみです｡
            ここに戻るにはurlをドメインまで消して「 /__home 」で帰ってきてね
        </body>
        </html>
    `);
});

// ==========================================
// 2. アクセス先設定用エンドポイント ( /__set )
// ==========================================
// フォーム送信や外部リンククリック時にここを通り、Cookieを更新する
app.all('/__set', (req, res) => {
    let u = req.body.url || req.query.url;
    if (!u) return res.redirect('/__home');

    // https:// が無ければ付ける
    if (!/^https?:\/\//i.test(u)) {
        u = 'https://' + u;
    }

    try {
        const targetObj = new URL(u);
        // ドメイン（オリジン）だけをCookieに保存
        res.cookie('__proxy_target', targetObj.origin, { path: '/' });
        
        // ターゲットの「パス＋クエリ（/about?id=1など）」へリダイレクト
        let redirectPath = targetObj.pathname + targetObj.search;
        if (!redirectPath || redirectPath === '') redirectPath = '/';
        
        res.redirect(redirectPath);
    } catch (e) {
        res.redirect('/__home');
    }
});

// ==========================================
// 3. ルートチェック
// ==========================================
// Cookieが設定されていないのにアクセスしてきたらHomeへ飛ばす
app.use((req, res, next) => {
    // /__home と /__set 以外のアクセスでチェック
    if (req.path !== '/__home' && req.path !== '/__set') {
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
    target: 'http://127.0.0.1', // ダミー（routerで上書きされる）
    changeOrigin: true,
    secure: false,
    selfHandleResponse: true,
    cookieDomainRewrite: '*', // ログインCookieを維持
    cookiePathRewrite: '/',

    // Cookieに保存されているドメインを接続先に設定
    router: (req) => {
        return getTargetFromCookie(req);
    },

    onProxyReq: (proxyReq, req, res) => {
        proxyReq.removeHeader('accept-encoding');
        
        const targetOrigin = getTargetFromCookie(req);
        if (targetOrigin) {
            // Cloudflare以外の一般的なBot対策やログインチェックをすり抜けるための偽装
            proxyReq.setHeader('Origin', targetOrigin);
            proxyReq.setHeader('Referer', targetOrigin + '/');
        }
    },

    onProxyRes: responseInterceptor(async (responseBuffer, proxyRes, req, res) => {
        const targetOrigin = getTargetFromCookie(req);
        if (!targetOrigin) return responseBuffer;

        // リダイレクト処理（Locationヘッダーの書き換え）
        if (proxyRes.headers['location']) {
            const loc = proxyRes.headers['location'];
            // 絶対URLでリダイレクトされた場合、同じドメインなら相対パスに変換
            if (loc.startsWith(targetOrigin)) {
                let rel = loc.replace(targetOrigin, '');
                if (rel === '') rel = '/';
                res.setHeader('location', rel);
            } else if (loc.startsWith('http')) {
                // 別のドメインにリダイレクトされたら /__set を経由させてCookieを切り替える
                res.setHeader('location', '/__set?url=' + encodeURIComponent(loc));
            }
        }

        const contentType = proxyRes.headers['content-type'];
        
        // HTMLの中身を賢く書き換え
        if (contentType && contentType.includes('text/html')) {
            try {
                let html = responseBuffer.toString('utf8');
                
                // href(リンク), src(画像など), action(フォーム送信先) をチェック
                html = html.replace(/(src|href|action)=["'](https?:\/\/[^"']+)["']/gi, (match, attr, url) => {
                    // もし「現在のターゲットと同じドメイン」の絶対URLなら、相対パスに短縮する（これが一番バグが起きない）
                    if (url.startsWith(targetOrigin)) {
                        let relativePath = url.replace(targetOrigin, '');
                        if (relativePath === '') relativePath = '/';
                        return `${attr}="${relativePath}"`;
                    }
                    
                    // 「別のドメイン」へのリンク(href)だった場合のみ、/__set を経由させる
                    if (attr.toLowerCase() === 'href') {
                        return `${attr}="/__set?url=${encodeURIComponent(url)}"`;
                    }
                    
                    // 別ドメインの画像(src)などはそのままブラウザに読み込ませる
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
        // 接続エラーが起きたらHomeへ戻す
        res.redirect('/__home');
    }
}));

app.listen(PORT, () => {
    console.log('Proxy Server Start! => http://localhost:' + PORT);
});
