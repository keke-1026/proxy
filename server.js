const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;

const getTargetFromCookie = (req) => {
    if (req.headers.cookie) {
        const match = req.headers.cookie.match(/(?:^|; )proxy_url=([^;]*)/);
        if (match) {
            return decodeURIComponent(match[1]);
        }
    }
    return null;
};

app.get('/', (req, res, next) => {
    if (!req.query.url && !getTargetFromCookie(req)) {
        const sampleUrl = 'https://example.com';
        return res.send(`
            <h1>Proxy Server</h1>
            <p>使い方: <code>http://localhost:${PORT}/?url=アクセスしたい絶対URL</code></p>
            <p><a href="/?url=${sampleUrl}">テスト (example.com にアクセス)</a></p>
        `);
    }
    next();
});

app.use((req, res, next) => {
    if (req.query.url) {
        res.cookie('proxy_url', req.query.url, { path: '/' });
    }
    next();
});

app.use('/', createProxyMiddleware({
    target: 'http://localhost',
    changeOrigin: true,
    secure: false,
    
    router: (req) => {
        let targetUrlStr = req.query.url || getTargetFromCookie(req);
        if (targetUrlStr) {
            try {
                return new URL(targetUrlStr).origin;
            } catch (e) {}
        }
    },
    
    pathRewrite: (path, req) => {
        if (req.query.url) {
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

    onProxyRes: (proxyRes, req, res) => {
        if (proxyRes.headers['location']) {
            let currentUrlStr = req.query.url || getTargetFromCookie(req);
            if (currentUrlStr) {
                try {
                    const absoluteLocation = new URL(proxyRes.headers['location'], currentUrlStr).href;
                    proxyRes.headers['location'] = '/?url=' + encodeURIComponent(absoluteLocation);
                } catch (e) {}
            }
        }
    },
    
    onError: (err, req, res) => {
        console.error('[通信エラー]', err.message);
        res.status(500).send('Proxy Error');
    }
}));

app.listen(PORT, () => {
    console.log('Proxy Server Start! => http://localhost:' + PORT);
});
