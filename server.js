'use strict';

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const { collect } = require('./lib/analytics');
const { Images, Visits, ensure } = require('./lib/store');

const PORT = process.env.PORT || 3000;
// ホスト（管理者）用トークン。未設定ならランダム生成して起動時に表示。
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || crypto.randomBytes(9).toString('hex');
// 匿名IDのハッシュ用ソルト。
const SALT = process.env.ANON_SALT || crypto.randomBytes(16).toString('hex');

ensure();
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use('/static', express.static(path.join(__dirname, 'public')));

// 対応ブラウザに対して、接続方法のクライアントヒント送出を要求する。
// （送るかどうかはブラウザ側の判断。取れない場合は「不明」として扱う。）
app.use((req, res, next) => {
  res.setHeader('Accept-CH', 'ECT, Downlink, RTT');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ---- 画像アップロード（ホスト限定） ----
const ALLOWED = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif']);
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const id = crypto.randomBytes(8).toString('hex');
    const ext = (path.extname(file.originalname) || '').toLowerCase().slice(0, 8);
    cb(null, id + ext);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024, files: 20 },
  fileFilter: (req, file, cb) => cb(null, ALLOWED.has(file.mimetype)),
});

// ---- 認可ミドルウェア（ホスト） ----
function requireHost(req, res, next) {
  const token = req.query.token || req.body.token || req.headers['x-admin-token'];
  if (token && crypto.timingSafeEqual(Buffer.from(String(token)), Buffer.from(ADMIN_TOKEN))) {
    return next();
  }
  if (req.method === 'GET') return res.status(401).render('login', { error: null });
  return res.status(401).send('認証が必要です。');
}
// タイミング安全比較は長さが違うと例外になるため吸収するラッパ。
function safeHost(req, res, next) {
  try {
    return requireHost(req, res, next);
  } catch {
    if (req.method === 'GET') return res.status(401).render('login', { error: '認証に失敗しました。' });
    return res.status(401).send('認証に失敗しました。');
  }
}

// ===== 公開ページ：ギャラリー（匿名の閲覧者向け） =====
app.get('/', (req, res) => {
  // 閲覧者アクセスを匿名化して記録（プライバシー通知はページ上で明示）。
  try {
    Visits.add(collect(req, SALT));
  } catch { /* ログ失敗は無視 */ }
  res.render('gallery', { images: Images.all() });
});

// 画像本体の配信（閲覧のみ）。
app.get('/img/:file', (req, res, next) => {
  const file = path.basename(req.params.file); // パストラバーサル防止
  const full = path.join(UPLOAD_DIR, file);
  if (!full.startsWith(UPLOAD_DIR) || !fs.existsSync(full)) return next();
  res.sendFile(full);
});

// ===== ホスト用：ログイン・管理・アップロード・解析 =====
app.get('/host', safeHost, (req, res) => {
  res.render('host', {
    token: req.query.token,
    images: Images.all(),
    adminTokenHint: process.env.ADMIN_TOKEN ? null : ADMIN_TOKEN,
  });
});

app.post('/host/upload', safeHost, upload.array('images', 20), (req, res) => {
  const caption = (req.body.caption || '').toString().slice(0, 200);
  for (const f of req.files || []) {
    Images.add({
      id: crypto.randomBytes(8).toString('hex'),
      file: f.filename,
      caption,
      size: f.size,
      mime: f.mimetype,
      uploadedAt: new Date().toISOString(),
    });
  }
  res.redirect('/host?token=' + encodeURIComponent(req.body.token || ''));
});

app.post('/host/delete', safeHost, (req, res) => {
  const img = Images.get(req.body.id);
  if (img) {
    const full = path.join(UPLOAD_DIR, path.basename(img.file));
    if (full.startsWith(UPLOAD_DIR)) fs.rm(full, { force: true }, () => {});
    Images.remove(img.id);
  }
  res.redirect('/host?token=' + encodeURIComponent(req.body.token || ''));
});

// 接続者（閲覧者）の解析ダッシュボード。
app.get('/host/analytics', safeHost, (req, res) => {
  const visits = Visits.all();
  const tally = (key, pick) => {
    const m = {};
    for (const v of visits) {
      const k = pick(v) || '不明';
      m[k] = (m[k] || 0) + 1;
    }
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  };
  res.render('analytics', {
    token: req.query.token,
    total: visits.length,
    uniqueVisitors: new Set(visits.map((v) => v.visitorId)).size,
    byRegion: tally('region', (v) => v.region),
    byDevice: tally('device', (v) => v.deviceType),
    byOs: tally('os', (v) => v.os),
    byBrowser: tally('browser', (v) => v.browser),
    byNetwork: tally('network', (v) => v.connection && v.connection.network),
    recent: visits.slice(-100).reverse(),
  });
});

// 起動
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`\n匿名画像共有ツールを起動しました: http://localhost:${PORT}`);
    console.log(`ホスト管理画面:            http://localhost:${PORT}/host?token=${ADMIN_TOKEN}`);
    if (!process.env.ADMIN_TOKEN) {
      console.log(`（ADMIN_TOKEN 未設定のため今回のトークンを自動生成しました: ${ADMIN_TOKEN}）`);
    }
    console.log('');
  });
}

module.exports = { app, ADMIN_TOKEN };
