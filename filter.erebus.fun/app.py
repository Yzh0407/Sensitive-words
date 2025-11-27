from flask import Flask, request, render_template, jsonify, redirect, url_for, session, Response, has_request_context
from datetime import timedelta
import requests
import openpyxl
from io import BytesIO
import pymysql
import hashlib
import json
import gzip

import logging
import os
from logging.handlers import RotatingFileHandler
try:
    from systemd.journal import JournalHandler
    JOURNAL_AVAILABLE = True
except ImportError:
    JournalHandler = None
    JOURNAL_AVAILABLE = False

app = Flask(__name__)
app.secret_key = '8f2d9a1c5b3e4f7a9d2c6b1e3f4a7c8d'
app.permanent_session_lifetime = timedelta(days=7)

# 配置区
APP_ID = "cli_a8496e3b08ab900d"  
APP_SECRET = "kMkJpJx0BG1LrQSvOjGpueUG1O84gnRZ"  
BASE_TOKEN = "KQtFbPBcBahDg8sPE2UcX4d4nKe"
TABLE_ID = "tblwJKXZIZTGmB9C"
MYSQL_HOST = '43.153.149.113'
MYSQL_USER = 'appuser'
MYSQL_PASSWORD = 'appuser@123456'
MYSQL_DB = 'UserDB'

# ---------------- 日志配置 ----------------
log_file = '/var/www/filter.erebus.fun/log/erebus_filter.log'
try:
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
except OSError:
    fallback_dir = os.path.join(os.getcwd(), 'logs')
    os.makedirs(fallback_dir, exist_ok=True)
    log_file = os.path.join(fallback_dir, 'erebus_filter.log')

app.logger.handlers.clear()

# 日志 Filter：自动加用户名
class UserFilter(logging.Filter):
    def filter(self, record):
        if has_request_context():
            record.username = session.get("username", "anonymous")
        else:
            record.username = "system"
        return True

log_format = logging.Formatter('%(asctime)s [%(levelname)s] [%(username)s] %(message)s')

# 1️⃣ 文件日志（带轮转）
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5, encoding='utf-8')
file_handler.setFormatter(log_format)
file_handler.setLevel(logging.INFO)
file_handler.addFilter(UserFilter())

# 2️⃣ systemd journal 日志
if JOURNAL_AVAILABLE:
    extra_handler = JournalHandler()
else:
    extra_handler = logging.StreamHandler()
extra_handler.setFormatter(log_format)
extra_handler.setLevel(logging.INFO)
extra_handler.addFilter(UserFilter())

# 3️⃣ 添加到 app.logger
app.logger.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.addHandler(extra_handler)

# ---------------- 业务逻辑 ----------------
def get_tenant_access_token():
    url = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
    headers = {"Content-Type": "application/json"}
    payload = {"app_id": APP_ID, "app_secret": APP_SECRET}
    try:
        resp = requests.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        if data.get("code") != 0:
            app.logger.warning(f"❌ 获取 token 失败: {data}")
            raise Exception(f"❌ 获取 token 失败: {data}")
        app.logger.info("✅ 成功获取 tenant_access_token")
        return data["tenant_access_token"]
    except requests.RequestException as e:
        app.logger.error(f"❌ 获取 token 异常: {e}")
        raise

# （其他函数不用改，日志会自动带上 [username]）



def get_sensitive_words():
    token = get_tenant_access_token()
    headers = {"Authorization": f"Bearer {token}"}
    url = f"https://open.feishu.cn/open-apis/bitable/v1/apps/{BASE_TOKEN}/tables/{TABLE_ID}/records"
    sensitive_words = []
    colors = ["#FF0000", "#00FF00", "#0000FF"]
    field_names = ["禁止使用的词", "本行业容易引起审核的词", "可以用尽量少用"]

    page_token = None
    while True:
        params = {"page_size": 500}
        if page_token:
            params["page_token"] = page_token
        try:
            resp = requests.get(url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            if data.get("code", -1) != 0:
                app.logger.error(f"❌ 读取数据失败: {data}")
                return sensitive_words

            items = data.get("data", {}).get("items", [])
            if not items and not page_token and not sensitive_words:
                app.logger.warning("⚠️ Base 表格为空")
                return sensitive_words

            for record in items:
                fields = record.get('fields', {})
                for field_name, color in zip(field_names, colors):
                    if field_name in fields and fields[field_name]:
                        word = fields[field_name]
                        if isinstance(word, list) and word and isinstance(word[0], dict) and 'text' in word[0]:
                            word = word[0]['text']
                        elif isinstance(word, dict) and 'text' in word:
                            word = word['text']
                        else:
                            word = str(word).strip()
                        if word:
                            sensitive_words.append({"word": word, "color": color})

            has_more = data.get("data", {}).get("has_more", False)
            page_token = data.get("data", {}).get("page_token")
            if not has_more:
                break
        except requests.RequestException as e:
            app.logger.error(f"❌ 读取数据异常: {e}")
            app.logger.error(f"Response: {resp.text if 'resp' in locals() else '无响应'}")
            return sensitive_words

    app.logger.info(f"✅ 共加载敏感词 {len(sensitive_words)} 条")
    return sensitive_words


def check_user(username, password):
    try:
        conn = pymysql.connect(
            host=MYSQL_HOST, user=MYSQL_USER, password=MYSQL_PASSWORD,
            db=MYSQL_DB, charset='utf8mb4'
        )
        cursor = conn.cursor(pymysql.cursors.DictCursor)
        cursor.execute("SELECT * FROM Login WHERE UserName=%s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            hashed_input = hashlib.sha256(password.encode('utf-8')).hexdigest()
            return hashed_input == user['PassWord']
        return False
    except Exception as e:
        app.logger.error(f"数据库连接或查询失败: {e}")
        return False



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember_me = request.form.get('remember_me') == 'on'
        if check_user(username, password):
            session['logged_in'] = True
            session['username'] = username   # ✅ 把用户名写进 session
            session.permanent = remember_me
            app.logger.info(f"✅ 用户 {username} 登录成功，Session: {session}")
            return redirect(url_for('index'))
        else:
            app.logger.warning(f"❌ 用户 {username} 登录失败")
            return render_template('login.html', error='用户名或密码错误或登录服务暂不可用', remember_me=remember_me)
    return render_template('login.html', remember_me=False)


@app.route('/')
def index():
    if not session.get('logged_in'):
        app.logger.warning("⚠️ 未登录，拒绝访问首页")
        return redirect(url_for('login'))
    return render_template('index.html')


def index_post():
    if not session.get('logged_in'):
        app.logger.warning("⚠️ 未登录，拒绝访问 / POST")
        return jsonify({"error": "未登录"}), 401
    content_file = request.files.get('contentFile')
    if not content_file:
        app.logger.warning("⚠️ 未上传内容文件")
        return jsonify({"error": "未上传内容文件"}), 400

    wb = openpyxl.load_workbook(BytesIO(content_file.read()))
    ws = wb.active
    content_lines = [cell.value for cell in ws['A'][1:] if cell.value]

    sensitive_words = get_sensitive_words()
    results = []
    for idx, line in enumerate(content_lines, start=2):
        audited_text = line
        for w in sensitive_words:
            audited_text = audited_text.replace(w['word'], f"<span style='color:{w['color']}'>{w['word']}</span>")
        results.append({"row": idx, "original": line, "audited": audited_text})

    return jsonify({"results": results, "sensitive_count": len(sensitive_words)})


@app.route('/api/sensitive', methods=['GET'])
def get_sensitive():
    if not session.get('logged_in'):
        app.logger.warning(f"⚠️ 未登录，拒绝访问 /api/sensitive, Session: {session}")
        return jsonify({"error": "未登录"}), 401
    try:
        sensitive_words = get_sensitive_words()
        response_data = jsonify({"sensitive_words": sensitive_words}).get_data()
        if request.headers.get('Accept-Encoding', '').find('gzip') >= 0:
            out = BytesIO()
            with gzip.GzipFile(fileobj=out, mode='wb') as gz:
                gz.write(response_data)
            response_data = out.getvalue()
            app.logger.info(f"✅ 返回敏感词 {len(sensitive_words)} 条（GZIP 压缩）")
            return Response(response_data, headers={
                'Content-Encoding': 'gzip',
                'Content-Length': len(response_data),
                'Content-Type': 'application/json'
            })
        app.logger.info(f"✅ 返回敏感词 {len(sensitive_words)} 条")
        return jsonify({"sensitive_words": sensitive_words})
    except Exception as e:
        app.logger.error(f"❌ 处理 /api/sensitive 失败: {e}")
        return jsonify({"error": str(e)}), 500



@app.route('/logout')
def logout():
    username = session.get('username', 'anonymous')
    session.clear()
    app.logger.info(f"✅ 用户 {username} 登出")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
