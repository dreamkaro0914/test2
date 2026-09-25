"""初回だけ実行して .env（秘密情報）を作成する。

- 秘密鍵・IPハッシュ鍵は一度だけ生成して固定する（再起動のたびに変えると
  ログインが切れ、同じ送信者のハッシュが一致しなくなるため）
- パスワードは画面に表示せず入力させ、ハッシュ値だけを保存する
"""
import getpass
import os
import secrets
import sys

from werkzeug.security import generate_password_hash

ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')

if os.path.exists(ENV_PATH):
    sys.exit(f'{ENV_PATH} は既に存在します。作り直す場合は削除してから実行してください。')

user = input('管理者ユーザー名 [admin]: ').strip() or 'admin'
password = getpass.getpass('管理者パスワード（12文字以上）: ')
if len(password) < 12:
    sys.exit('パスワードは12文字以上にしてください。')
if password != getpass.getpass('確認のためもう一度: '):
    sys.exit('パスワードが一致しません。')

lines = [
    f'ADMIN_USER={user}',
    f'ADMIN_PASS_HASH={generate_password_hash(password)}',
    f'FLASK_SECRET_KEY={secrets.token_hex(32)}',
    f'IP_HASH_KEY={secrets.token_hex(32)}',
]
fd = os.open(ENV_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w', encoding='utf-8') as f:
    f.write('\n'.join(lines) + '\n')
print(f'{ENV_PATH} を作成しました（権限 600）。このファイルは共有・コミットしないでください。')
