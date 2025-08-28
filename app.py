from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, bcrypt, os, re
from functools import wraps
from datetime import timedelta
import random

app = Flask(__name__)
app.secret_key = 'thisIsTmfd'
DB_NAME = 'users.db'

# ---------------- DB ----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT,
            phone TEXT,
            password_hash BLOB,
            mileage INTEGER DEFAULT 2500
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            title TEXT,
            points INTEGER,
            visited_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# --------------- Utils ---------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def get_db():
    return sqlite3.connect(DB_NAME)

def is_valid_email(email: str) -> bool:
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) is not None

def is_valid_phone(phone: str) -> bool:
    digits = re.sub(r'\D', '', phone)
    return len(digits) in (10, 11)

# --------------- Routes ---------------
# 루트: 로그인 안했으면 login, 했으면 index
@app.route('/')
def root():
    if 'user' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

# 메인 대시보드
@app.route('/index')
@login_required
def index():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mileage FROM users WHERE email = ?", (session['email'],))
    row = c.fetchone()
    mileage = row[0] if row else 0

    c.execute("""
        SELECT title, points, visited_at
        FROM activities
        WHERE email = ?
        ORDER BY visited_at DESC
        LIMIT 5
    """, (session['email'],))
    activities = c.fetchall()
    conn.close()

    return render_template(
        'index.html',
        username=session.get('user'),
        mileage=mileage,
        activities=activities
    )

# ---------------- 어바웃 ----------------
@app.route('/about')
@app.route('/about.html')
@login_required
def about_page():
    return render_template('about.html')

# ---------------- 학습자료실 ----------------
@app.route('/study')
@app.route('/study.html')
@login_required
def study_page():
    return render_template('study.html')

# 파일명 접근 호환
@app.route('/index.html')
def index_html():
    return redirect(url_for('index'))

@app.route('/main.html')
def main_html():
    return redirect(url_for('index'))

# ---------------- 기타 페이지 ----------------
@app.route('/assessment')
@app.route('/assessment.html')
@login_required
def assessment_page():
    return render_template('assessment.html')

@app.route('/TimeAndFood')
@app.route('/TimeAndFood.html')
@login_required
def time_and_food_page():
    return render_template('TimeAndFood.html')

@app.route('/reservation')
@app.route('/reservation.html')
@login_required
def reservation():
    return render_template('reservation.html')

# ---------------- 인증 ----------------
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')

        if not name:
            return render_template('signup.html', error="이름을 입력하세요.")
        if not email or not is_valid_email(email):
            return render_template('signup.html', error="올바른 이메일을 입력하세요.")
        if not phone or not is_valid_phone(phone):
            return render_template('signup.html', error="올바른 휴대폰 번호를 입력하세요.")
        if not password or len(password) < 6:
            return render_template('signup.html', error="비밀번호는 최소 6자 이상이어야 합니다.")

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return render_template('signup.html', error="이미 등록된 이메일입니다.")

        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        c.execute("""
            INSERT INTO users (email, name, phone, password_hash, mileage)
            VALUES (?, ?, ?, ?, ?)
        """, (email, name, phone, pw_hash, 2500))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember')

        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT email, name, phone, password_hash FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if not user:
            return render_template('login.html', error="존재하지 않는 이메일입니다.")
        if not user[3]:
            return render_template('login.html', error="비밀번호 데이터가 손상되었습니다. 다시 회원가입을 진행해 주세요.")

        if bcrypt.checkpw(password.encode('utf-8'), user[3]):
            session['user'] = user[1]
            session['email'] = user[0]
            if remember == "on":
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=7)

            if user[0] == "admin@admin.com":
                return redirect(url_for('admin'))
            return redirect(url_for('index'))
        return render_template('login.html', error="이메일 또는 비밀번호가 올바르지 않습니다.")
    return render_template('login.html')

# 로그아웃
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

# 비밀번호 찾기(2단계)
@app.route('/find_password', methods=['GET', 'POST'])
def find_password():
    if request.method == 'POST':
        step = int(request.form.get('step', 1))
        email = request.form.get('email', '').strip().lower()
        code = request.form.get('code', '').strip()
        new_pw = request.form.get('new_password', '')

        if step == 1:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT 1 FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            conn.close()
            if not user:
                return render_template('find_password.html', error="등록되지 않은 이메일입니다.", email=email, step=1)
            session['pwreset_email'] = email
            session['pwreset_code'] = str(random.randint(100000, 999999))  # 실제 서비스에서는 이메일 발송
            return render_template('find_password.html', step=2, email=email, code=session['pwreset_code'])

        if step == 2:
            if code != session.get('pwreset_code'):
                return render_template('find_password.html', step=2, email=email, error="인증번호가 다릅니다.", code=session.get('pwreset_code'))
            if not new_pw or len(new_pw) < 6:
                return render_template('find_password.html', step=2, email=email, error="새 비밀번호는 최소 6자 이상입니다.", code=session.get('pwreset_code'))

            pw_hash = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email))
            conn.commit()
            conn.close()
            session.pop('pwreset_email', None)
            session.pop('pwreset_code', None)
            return render_template('find_password.html', step=3, success="비밀번호 변경이 완료되었습니다.")
    return render_template('find_password.html', step=1)

# API 예시
@app.route('/api/user')
def api_user():
    if 'user' in session:
        return jsonify({'login': True, 'username': session['user']})
    return jsonify({'login': False})

# 관리자(샘플)
@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')

if __name__ == '__main__':
    # 프로덕션에서는 debug=False 권장
    app.run(host="0.0.0.0", port=5000, debug=True)
