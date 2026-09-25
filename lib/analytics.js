'use strict';

// 接続者の「おおよその情報」を、リクエストヘッダから推定する。
// - IPアドレスそのものは保存せず、地域推定のみに使い、保存時はハッシュ化した短い識別子だけを残す。
// - すべて閲覧者に見える形（プライバシー通知）で運用する前提。

const crypto = require('crypto');

function clientIp(req) {
  // プロキシ経由を考慮しつつ、最初のホップだけを見る。
  const xff = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  const ip = xff || req.socket.remoteAddress || '';
  // IPv6のIPv4射影表記を素の形へ。
  return ip.replace(/^::ffff:/, '');
}

// IPを保存用の短い匿名IDへ（同一訪問者の概算カウント用。逆引き不可）。
function anonId(ip, salt) {
  return crypto
    .createHmac('sha256', salt || 'anon-image-share')
    .update(ip || 'unknown')
    .digest('hex')
    .slice(0, 12);
}

// User-Agent から機種・OS・ブラウザをざっくり判定（外部依存なし）。
function parseUserAgent(ua) {
  ua = ua || '';
  let deviceType = 'デスクトップ';
  if (/iPad|Tablet|PlayBook|Silk/i.test(ua)) deviceType = 'タブレット';
  else if (/Mobi|Android.+Mobile|iPhone|iPod|Windows Phone/i.test(ua)) deviceType = 'モバイル';

  let os = '不明';
  if (/Windows NT/i.test(ua)) os = 'Windows';
  else if (/iPhone|iPad|iPod/i.test(ua)) os = 'iOS';
  else if (/Mac OS X/i.test(ua)) os = 'macOS';
  else if (/Android/i.test(ua)) os = 'Android';
  else if (/Linux/i.test(ua)) os = 'Linux';

  let browser = '不明';
  if (/Edg\//i.test(ua)) browser = 'Edge';
  else if (/OPR\/|Opera/i.test(ua)) browser = 'Opera';
  else if (/Chrome\//i.test(ua) && !/Chromium/i.test(ua)) browser = 'Chrome';
  else if (/Firefox\//i.test(ua)) browser = 'Firefox';
  else if (/Safari\//i.test(ua) && !/Chrome/i.test(ua)) browser = 'Safari';

  return { deviceType, os, browser };
}

// 「通信方法」の推定。ブラウザからは正確なキャリア種別は取れないため、
// クライアントヒント（対応ブラウザのみ）と接続プロトコルから分かる範囲を返す。
function parseConnection(req) {
  // Network Information API のクライアントヒント（Chromium系のみ送出、任意）。
  const effType = req.headers['ect'];            // "4g" / "3g" など
  const downlink = req.headers['downlink'];      // Mbps
  const rtt = req.headers['rtt'];                // ms
  const proto =
    (req.headers['x-forwarded-proto'] || req.protocol || '').toLowerCase();

  let network = '不明';
  if (effType) {
    const map = { 'slow-2g': '低速回線', '2g': '2G相当', '3g': '3G相当', '4g': '4G/高速相当' };
    network = map[effType] || effType;
  }

  return {
    scheme: proto === 'https' ? 'HTTPS（暗号化）' : (proto ? proto.toUpperCase() : '不明'),
    network,
    downlinkMbps: downlink ? Number(downlink) : null,
    rttMs: rtt ? Number(rtt) : null,
  };
}

// おおよその地域推定。外部ジオIPは使わず、Accept-Language / CF等の
// プロキシが付けた地域ヘッダがあれば利用する（無ければ「不明」）。
// 一部CDN（Cloudflare等）は country ヘッダを付与するため、それを尊重する。
function parseRegion(req) {
  const cf = req.headers['cf-ipcountry'];                 // Cloudflare
  const fly = req.headers['fly-region'];                  // Fly.io
  const vercel = req.headers['x-vercel-ip-country'];      // Vercel
  const country = (cf || vercel || '').toUpperCase();

  const lang = (req.headers['accept-language'] || '').split(',')[0].trim();

  let region = '不明';
  if (country && country !== 'XX') region = country;
  else if (lang) region = `言語設定: ${lang}`;

  return { country: country && country !== 'XX' ? country : null, region, acceptLanguage: lang || null };
}

function collect(req, salt) {
  const ip = clientIp(req);
  const ua = req.headers['user-agent'] || '';
  return {
    ts: new Date().toISOString(),
    visitorId: anonId(ip, salt),
    ...parseRegion(req),
    ...parseUserAgent(ua),
    connection: parseConnection(req),
    referer: req.headers['referer'] || null,
    path: req.originalUrl || req.url || null,
  };
}

module.exports = { collect, clientIp, anonId, parseUserAgent, parseConnection, parseRegion };
