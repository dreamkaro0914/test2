'use strict';
// 依存の少ない自己完結スモークテスト。node test/smoke.test.js で実行。
const assert = require('assert');
const http = require('http');
const { parseUserAgent, parseConnection, parseRegion, anonId } = require('../lib/analytics');

let failures = 0;
function ok(name, fn) {
  try { fn(); console.log('  ✓ ' + name); }
  catch (e) { failures++; console.error('  ✗ ' + name + ' -> ' + e.message); }
}

console.log('analytics ユニット:');
ok('モバイル判定', () => {
  const r = parseUserAgent('Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605 Safari/604');
  assert.strictEqual(r.deviceType, 'モバイル');
  assert.strictEqual(r.os, 'iOS');
  assert.strictEqual(r.browser, 'Safari');
});
ok('デスクトップChrome判定', () => {
  const r = parseUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537 Chrome/120 Safari/537');
  assert.strictEqual(r.deviceType, 'デスクトップ');
  assert.strictEqual(r.os, 'Windows');
  assert.strictEqual(r.browser, 'Chrome');
});
ok('接続ヒント解釈', () => {
  const r = parseConnection({ headers: { ect: '4g', downlink: '10', 'x-forwarded-proto': 'https' }, protocol: 'http' });
  assert.strictEqual(r.network, '4G/高速相当');
  assert.strictEqual(r.scheme, 'HTTPS（暗号化）');
  assert.strictEqual(r.downlinkMbps, 10);
});
ok('地域はCFヘッダ優先', () => {
  const r = parseRegion({ headers: { 'cf-ipcountry': 'JP', 'accept-language': 'en-US' } });
  assert.strictEqual(r.country, 'JP');
});
ok('匿名IDは逆引き不可・安定', () => {
  const a = anonId('1.2.3.4', 's'); const b = anonId('1.2.3.4', 's');
  assert.strictEqual(a, b);
  assert.notStrictEqual(a, '1.2.3.4');
  assert.strictEqual(a.length, 12);
});

console.log('HTTP エンドポイント:');
process.env.ADMIN_TOKEN = 'testtoken123';
const { app } = require('../server');
const server = app.listen(0, () => {
  const port = server.address().port;
  const get = (p, cb) => http.get({ port, path: p }, (res) => {
    let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => cb(res, d));
  });
  get('/', (res, body) => {
    ok('公開ページ 200', () => assert.strictEqual(res.statusCode, 200));
    ok('プライバシー通知を含む', () => assert.ok(body.includes('プライバシー')));
    get('/host', (res2) => {
      ok('/host はトークン無しで401', () => assert.strictEqual(res2.statusCode, 401));
      get('/host/analytics?token=testtoken123', (res3, b3) => {
        ok('/host/analytics 正しいトークンで200', () => assert.strictEqual(res3.statusCode, 200));
        ok('解析ページに見出し', () => assert.ok(b3.includes('接続者の解析')));
        server.close();
        console.log(failures ? `\n${failures} 件失敗` : '\n全テスト成功');
        process.exit(failures ? 1 : 0);
      });
    });
  });
});
