import functools
import hmac
import io
import ipaddress
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import timedelta
from hashlib import sha256

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_from_directory, session, url_for)
from PIL import Image, UnidentifiedImageError
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_env_file(path):
    """KEY=VALUE 形式の .env を読み込む（$ などを展開しない。既存の環境変数を優先）"""
    if not os.path.exists(path):
        return
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or '=' not in line:
                continue
            key, value = line.split('=', 1)
            os.environ.setdefault(key.strip(), value.strip().strip('\'"'))


load_env_file(os.path.join(BASE_DIR, '.env'))

# 必須の秘密情報。未設定なら起動しない（既定値で動かすと第三者にログイン・復元される）
REQUIRED_ENV = ('FLASK_SECRET_KEY', 'ADMIN_PASS_HASH', 'IP_HASH_KEY')
_missing = [k for k in REQUIRED_ENV if not os.environ.get(k)]
if _missing:
    sys.exit(f"必須の環境変数が未設定です: {', '.join(_missing)}（python gen_env.py で .env を作成してください）")

app = Flask(__name__)
app.secret_key = os.environ['FLASK_SECRET_KEY']
app.config.update(
    UPLOAD_FOLDER=os.environ.get('UPLOAD_FOLDER', os.path.join(BASE_DIR, 'uploads')),
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 1リクエスト最大16MB
    SESSION_COOKIE_HTTPONLY=True,
    # HTTPS 前提。ローカルの HTTP で試すときだけ COOKIE_SECURE=0 を設定する
    SESSION_COOKIE_SECURE=os.environ.get('COOKIE_SECURE', '1') != '0',
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

ADMIN_USERNAME = os.environ.get('ADMIN_USER', 'admin')
ADMIN_PASSWORD_HASH = os.environ['ADMIN_PASS_HASH']
IP_HASH_KEY = os.environ['IP_HASH_KEY'].encode()
DB_PATH = os.environ.get('DB_PATH', os.path.join(BASE_DIR, 'metadata.db'))

# 信頼するリバースプロキシの段数（Nginx 1段なら 1）。
# 0 のときは X-Forwarded-For を一切信用せず、直接の接続元IPのみを使う。
TRUSTED_PROXIES = int(os.environ.get('TRUSTED_PROXIES', '0'))
if TRUSTED_PROXIES > 0:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUSTED_PROXIES, x_proto=TRUSTED_PROXIES)

# GeoIP はローカルDB（MaxMind GeoLite2-City.mmdb）で引く。外部APIへIPを送信しない。
GEOIP_DB = os.environ.get('GEOIP_DB', os.path.join(BASE_DIR, 'GeoLite2-City.mmdb'))

# 簡易レート制限（同一IPから window 秒あたり limit 件まで）
UPLOAD_LIMIT = (int(os.environ.get('RATE_LIMIT', '10')), int(os.environ.get('RATE_WINDOW', '600')))
LOGIN_LIMIT = (5, 900)

# 中身の実フォーマット → 保存時の拡張子
ALLOWED_FORMATS = {'PNG': '.png', 'JPEG': '.jpg', 'GIF': '.gif', 'WEBP': '.webp'}
ALLOWED_EFFECTIVE_TYPES = {'slow-2g', '2g', '3g', '4g'}
STORED_NAME_RE = re.compile(r'^(guest|host)_\d{14}_[0-9a-f]{32}\.(png|jpg|gif|webp)$')
PAGE_SIZE = 100
SHARE_DAYS = (1, 7, 30)  # 共有リンクの有効期限の選択肢（日）

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# --- データベース ---

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT DEFAULT (datetime('now', 'localtime')),
                is_host INTEGER NOT NULL,
                ip_hash TEXT,
                region TEXT,
                ua TEXT,
                network TEXT,
                original_name TEXT,
                filename TEXT NOT NULL
            )
        ''')


        conn.execute('''
            CREATE TABLE IF NOT EXISTS shares (
                token TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now')),
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            )
        ''')


init_db()


def record_upload(**fields):
    with db() as conn:
        conn.execute(
            'INSERT INTO uploads (is_host, ip_hash, region, ua, network, original_name, filename) '
            'VALUES (:is_host, :ip_hash, :region, :ua, :network, :original_name, :filename)',
            fields,
        )


# --- ヘルパー ---

def hash_ip(ip_address):
    """IPを鍵付きハッシュ（HMAC）で仮名化する。鍵を知らなければ総当たりで元のIPに戻せない"""
    return hmac.new(IP_HASH_KEY, ip_address.encode(), sha256).hexdigest()[:16]


_geoip_reader = None
_geoip_lock = threading.Lock()


def get_region_from_ip(ip_address):
    """ローカルの GeoLite2 DB から地域情報を取得する（DB未配置なら「GeoIP未設定」）"""
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
        app.logger.warning('GeoIP lookup failed: %r', e)
        return '取得失敗'


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


def is_rate_limited(bucket, limit, window):
    """プロセス内メモリで判定する簡易版。複数ワーカー運用時は Flask-Limiter + Redis 等に置き換えること"""
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits[bucket]
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= limit:
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


def save_image(file, prefix):
    """検証済みの画像をサーバー生成の名前で保存する。(保存名, エラーメッセージ) を返す"""
    if file is None or file.filename == '':
        return None, 'ファイルが選択されていません。'
    data = file.read()
    ext = detect_image_format(data)
    if ext is None:
        return None, '画像ファイル（PNG / JPEG / GIF / WebP）のみアップロード可能です。'
    # 元のファイル名は使わない（パストラバーサル対策）
    stored_name = f"{prefix}_{time.strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex}{ext}"
    with open(os.path.join(app.config['UPLOAD_FOLDER'], stored_name), 'xb') as f:
        f.write(data)
    return stored_name, None


def client_ip():
    # TRUSTED_PROXIES 設定時のみ ProxyFix が X-Forwarded-For を反映済み
    return request.remote_addr or 'unknown'


# --- CSRF 対策（管理画面のフォーム） ---

def csrf_token():
    if '_csrf' not in session:
        session['_csrf'] = secrets.token_urlsafe(32)
    return session['_csrf']


app.jinja_env.globals['csrf_token'] = csrf_token


def check_csrf():
    token = session.get('_csrf')
    if not token or not hmac.compare_digest(token, request.form.get('csrf_token', '')):
        abort(400, 'CSRFトークンが不正です。ページを再読み込みしてやり直してください。')


def admin_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        if request.method == 'POST':
            check_csrf()
        return f(*args, **kwargs)
    return decorated_function


# --- セキュリティヘッダー ---

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    # インラインスクリプトは禁止（JS は static/ から読み込む）
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"
    )
    if request.path.startswith(('/admin', '/s/')):
        response.headers['Cache-Control'] = 'no-store'
    if request.path.startswith('/s/'):
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    return response


@app.errorhandler(413)
def too_large(_e):
    return 'ファイルサイズは16MBまでです。', 413


# ==============================
# ゲスト用ルート（送信のみ）
# ==============================

@app.route('/', methods=['GET', 'POST'])
def guest_upload():
    if request.method == 'GET':
        return render_template('index.html')

    ip_addr = client_ip()
    if is_rate_limited(('upload', ip_addr), *UPLOAD_LIMIT):
        return '送信回数が多すぎます。しばらくしてから再度お試しください。', 429

    file = request.files.get('file')
    stored_name, error = save_image(file, 'guest')
    if error:
        return error, 400

    record_upload(
        is_host=0,
        ip_hash=hash_ip(ip_addr),
        region=get_region_from_ip(ip_addr),
        ua=request.headers.get('User-Agent', 'Unknown')[:300],
        network=parse_network_info(request.form),
        original_name=file.filename[:100],
        filename=stored_name,
    )
    return '送信が完了しました。ご協力ありがとうございます。'


# ==============================
# ホスト用ルート（認証・管理・送信）
# ==============================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        check_csrf()
        if is_rate_limited(('login', client_ip()), *LOGIN_LIMIT):
            flash('ログイン試行回数が多すぎます。15分後に再度お試しください。')
            return render_template('login.html'), 429
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user_ok = hmac.compare_digest(username.encode(), ADMIN_USERNAME.encode())
        if check_password_hash(ADMIN_PASSWORD_HASH, password) and user_ok:
            session.clear()  # ログイン前のセッションを引き継がない
            session.permanent = True
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        flash('認証に失敗しました。')
    return render_template('login.html')


@app.route('/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    page = max(request.args.get('page', 1, type=int), 1)
    with db() as conn:
        total = conn.execute('SELECT COUNT(*) FROM uploads').fetchone()[0]
        rows = conn.execute(
            'SELECT timestamp, is_host, ip_hash, region, ua, network, original_name, filename '
            'FROM uploads ORDER BY id DESC LIMIT ? OFFSET ?',
            (PAGE_SIZE, (page - 1) * PAGE_SIZE),
        ).fetchall()
        shares = conn.execute(
            "SELECT s.token, s.filename, u.original_name, datetime(s.expires_at, 'localtime') AS expires_local "
            'FROM shares s LEFT JOIN uploads u ON u.filename = s.filename '
            "WHERE s.revoked = 0 AND s.expires_at > datetime('now') ORDER BY s.created_at DESC"
        ).fetchall()
    last_page = max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1)
    return render_template('dashboard.html', rows=rows, page=page, last_page=last_page, total=total,
                           shares=shares, share_days=SHARE_DAYS, new_token=request.args.get('shared'))


@app.route('/admin/upload', methods=['GET', 'POST'])
@admin_required
def admin_upload():
    if request.method == 'POST':
        file = request.files.get('file')
        stored_name, error = save_image(file, 'host')
        if error:
            return error, 400
        record_upload(
            is_host=1, ip_hash=None, region='Local',
            ua=request.headers.get('User-Agent', 'Unknown')[:300],
            network='Host Direct', original_name=file.filename[:100], filename=stored_name,
        )
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_upload.html')


@app.route('/admin/files/<filename>')
@admin_required
def download_file(filename):
    if not STORED_NAME_RE.match(filename):
        abort(404)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# ==============================
# 共有リンク（ホストが選んだ画像を、リンクを知る人だけが閲覧できる）
# ==============================

@app.route('/admin/share', methods=['POST'])
@admin_required
def create_share():
    filename = request.form.get('filename', '')
    days = request.form.get('days', type=int)
    if not STORED_NAME_RE.match(filename) or days not in SHARE_DAYS:
        abort(400)
    if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        abort(404)
    token = secrets.token_urlsafe(16)  # 128bit。推測できない
    with db() as conn:
        conn.execute(
            "INSERT INTO shares (token, filename, expires_at) VALUES (?, ?, datetime('now', ?))",
            (token, filename, f'+{days} days'),
        )
    return redirect(url_for('admin_dashboard', shared=token) + '#shares')


@app.route('/admin/share/<token>/revoke', methods=['POST'])
@admin_required
def revoke_share(token):
    with db() as conn:
        conn.execute('UPDATE shares SET revoked = 1 WHERE token = ?', (token,))
    return redirect(url_for('admin_dashboard') + '#shares')


def active_share(token):
    """有効な（取り消されておらず期限内の）共有を返す。なければ 404"""
    with db() as conn:
        share = conn.execute(
            "SELECT filename, datetime(expires_at, 'localtime') AS expires_local FROM shares "
            "WHERE token = ? AND revoked = 0 AND expires_at > datetime('now')",
            (token,),
        ).fetchone()
    if share is None or not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], share['filename'])):
        abort(404)
    return share


@app.route('/s/<token>')
def view_share(token):
    share = active_share(token)
    return render_template('share.html', token=token, expires=share['expires_local'])


@app.route('/s/<token>/image')
def share_image(token):
    share = active_share(token)
    download = request.args.get('dl') == '1'
    return send_from_directory(app.config['UPLOAD_FOLDER'], share['filename'], as_attachment=download)


@app.errorhandler(404)
def not_found(_e):
    return 'ページが見つからないか、共有リンクの有効期限が切れています。', 404


if __name__ == '__main__':
    # 本番環境では Gunicorn 等 + Nginx(HTTPS) で公開し、TRUSTED_PROXIES=1 を設定すること
    app.run(host='0.0.0.0', port=5000, debug=False)
