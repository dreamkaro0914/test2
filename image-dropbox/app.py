import io
import ipaddress
import logging
import os
import re
import threading
import time
import uuid
from collections import defaultdict, deque

from flask import Flask, request, render_template
from PIL import Image, UnidentifiedImageError
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.environ.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 1リクエスト最大16MB

# 信頼するリバースプロキシの段数（Nginx 1段なら 1）。
# 0 のときは X-Forwarded-For を一切信用せず、直接の接続元IPのみを使う。
TRUSTED_PROXIES = int(os.environ.get('TRUSTED_PROXIES', '0'))
if TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES, x_proto=TRUSTED_PROXIES)

# GeoIP はローカルDB（MaxMind GeoLite2-City.mmdb）で引く。外部APIへIPを送信しない。
GEOIP_DB = os.environ.get('GEOIP_DB', os.path.join(BASE_DIR, 'GeoLite2-City.mmdb'))

# 簡易レート制限（同一IPから WINDOW 秒あたり LIMIT 件まで）
RATE_LIMIT = int(os.environ.get('RATE_LIMIT', '10'))
RATE_WINDOW = int(os.environ.get('RATE_WINDOW', '600'))

# 中身の実フォーマット → 保存時の拡張子
ALLOWED_FORMATS = {'PNG': '.png', 'JPEG': '.jpg', 'GIF': '.gif', 'WEBP': '.webp'}
ALLOWED_EFFECTIVE_TYPES = {'slow-2g', '2g', '3g', '4g'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# ログ設定（ホストが確認するための記録）
upload_logger = logging.getLogger('upload_history')
upload_logger.setLevel(logging.INFO)
_handler = logging.FileHandler(
    os.environ.get('UPLOAD_LOG', os.path.join(BASE_DIR, 'upload_history.log')), encoding='utf-8'
)
_handler.setFormatter(logging.Formatter('%(asctime)s | %(message)s'))
upload_logger.addHandler(_handler)

_geoip_reader = None
_geoip_lock = threading.Lock()


def get_region_from_ip(ip_address):
    """ローカルの GeoLite2 DB から地域情報を取得する（DB未配置なら「未設定」）"""
    global _geoip_reader
    try:
        if ipaddress.ip_address(ip_address).is_private:
            return 'プライベートIP'
    except ValueError:
        return '不正なIP'
    try:
        with _geoip_lock:
            if _geoip_reader is None:
                if not os.path.exists(GEOIP_DB):
                    return 'GeoIP未設定'
                import geoip2.database
                _geoip_reader = geoip2.database.Reader(GEOIP_DB)
        r = _geoip_reader.city(ip_address)
        return ' '.join(filter(None, [
            r.country.names.get('ja') or r.country.name,
            r.subdivisions.most_specific.names.get('ja') or r.subdivisions.most_specific.name,
            r.city.names.get('ja') or r.city.name,
        ])) or '不明'
    except Exception as e:
        upload_logger.warning('GeoIP lookup failed: %s', sanitize(repr(e)))
        return '取得失敗'


_CTRL_CHARS = re.compile(r'[\x00-\x1f\x7f]')


def sanitize(value, max_len=300):
    """ログ偽造を防ぐため制御文字（改行等）と区切り文字を除去し、長さを制限する"""
    return _CTRL_CHARS.sub(' ', str(value)).replace('|', '/')[:max_len]


def parse_network_info(form):
    """クライアントから送られた回線情報を検証する（改ざん可能な参考値）"""
    effective_type = form.get('net_type', '')
    downlink = form.get('net_downlink', '')
    if effective_type not in ALLOWED_EFFECTIVE_TYPES:
        return 'Unknown'
    try:
        downlink_value = float(downlink)
        if not 0 <= downlink_value <= 10000:
            raise ValueError
    except ValueError:
        return f'Type: {effective_type}'
    return f'Type: {effective_type}, Downlink: {downlink_value:g}Mbps'


_rate_hits = defaultdict(deque)
_rate_lock = threading.Lock()


def is_rate_limited(ip_addr):
    """プロセス内メモリで判定する簡易版。複数ワーカー運用時は Flask-Limiter + Redis 等に置き換えること"""
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits[ip_addr]
        while hits and now - hits[0] > RATE_WINDOW:
            hits.popleft()
        if len(hits) >= RATE_LIMIT:
            return True
        hits.append(now)
        return False


def detect_image_format(data):
    """中身を解析して許可された画像形式なら拡張子を返す。画像でなければ None"""
    try:
        with Image.open(io.BytesIO(data)) as img:
            img.verify()
            return ALLOWED_FORMATS.get(img.format)
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, SyntaxError, ValueError):
        return None


@app.errorhandler(413)
def too_large(_e):
    return 'ファイルサイズは16MBまでです。', 413


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'GET':
        return render_template('index.html')

    # 接続元IP（TRUSTED_PROXIES 設定時のみ ProxyFix が X-Forwarded-For を反映済み）
    ip_addr = request.remote_addr or 'Unknown'

    if is_rate_limited(ip_addr):
        return '送信回数が多すぎます。しばらくしてから再度お試しください。', 429

    file = request.files.get('file')
    if file is None or file.filename == '':
        return 'ファイルが選択されていません。', 400

    data = file.read()
    ext = detect_image_format(data)
    if ext is None:
        return '画像ファイル（PNG / JPEG / GIF / WebP）のみアップロード可能です。', 400

    # 保存名はサーバー側で生成（元のファイル名は使わない＝パストラバーサル対策）
    safe_filename = f"{time.strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
    with open(filepath, 'xb') as f:
        f.write(data)

    log_data = ' | '.join([
        f'File: {safe_filename}',
        f'Original: {sanitize(file.filename, 100)}',
        f'IP: {sanitize(ip_addr, 64)}',
        f'Region: {get_region_from_ip(ip_addr)}',
        f"Device(UA): {sanitize(request.headers.get('User-Agent', 'Unknown'))}",
        f'Network: {parse_network_info(request.form)}',
    ])
    upload_logger.info(log_data)
    print(f'[NEW UPLOAD] {log_data}')  # コンソールにも出力

    return '送信が完了しました。ご協力ありがとうございます。'


if __name__ == '__main__':
    # 本番環境では Gunicorn 等 + Nginx(HTTPS) で公開し、TRUSTED_PROXIES=1 を設定すること
    app.run(host='0.0.0.0', port=5000, debug=False)
