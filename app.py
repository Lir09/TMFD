from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, bcrypt, os, re, calendar, random
from functools import wraps
from datetime import timedelta, date

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET', 'thisIsTmfd')
DB_NAME = 'users.db'

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def init_db():
    conn = get_db()
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
            visited_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            ymd TEXT NOT NULL,
            title TEXT NOT NULL,
            time TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(email) REFERENCES users(email) ON DELETE CASCADE
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def is_valid_email(email: str) -> bool:
    return re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email) is not None

def is_valid_phone(phone: str) -> bool:
    digits = re.sub(r'\D', '', phone)
    return len(digits) in (10, 11)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        authed = session.get('user') and session.get('email')
        if authed:
            return f(*args, **kwargs)
        if request.path.startswith('/api/'):
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
        return redirect(url_for('login'))
    return decorated

@app.context_processor
def inject_user():
    return {"current_user": session.get('user'), "current_email": session.get('email')}

@app.route('/')
def root():
    if session.get('user') and session.get('email'):
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    email = session.get('email')
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mileage FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    mileage = (row['mileage'] if row else 0)
    c.execute("""
        SELECT title, points, visited_at
        FROM activities
        WHERE email = ?
        ORDER BY visited_at DESC
        LIMIT 5
    """, (email,))
    activities = c.fetchall()
    conn.close()
    return render_template('index.html', username=session.get('user', ''), mileage=mileage, activities=activities)

@app.route('/index.html')
def index_html():
    return redirect(url_for('index'))

@app.route('/main.html')
def main_html():
    return redirect(url_for('index'))

@app.route('/personal')
@app.route('/personal.html')
@login_required
def personal():
    email = session.get('email')
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT mileage FROM users WHERE email = ?", (email,))
    row = c.fetchone()
    mileage = row['mileage'] if row else 0
    c.execute("""
        SELECT title, points, visited_at
        FROM activities
        WHERE email = ?
        ORDER BY visited_at DESC
        LIMIT 5
    """, (email,))
    activities = c.fetchall()
    conn.close()
    return render_template('personal.html', username=session.get('user', ''), mileage=mileage, activities=activities)

@app.route('/about')
@app.route('/about.html')
@login_required
def about_page():
    return render_template('about.html')

@app.route('/study')
@app.route('/study.html')
@login_required
def study_page():
    return render_template('study.html')

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
        if not user['password_hash']:
            return render_template('login.html', error="비밀번호 데이터가 손상되었습니다. 다시 회원가입을 진행해 주세요.")
        if bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            session['user'] = user['name']
            session['email'] = user['email']
            if remember == "on":
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=7)
            if user['email'] == "admin@admin.com":
                return redirect(url_for('admin'))
            return redirect(url_for('index'))
        return render_template('login.html', error="이메일 또는 비밀번호가 올바르지 않습니다.")
    if session.get('user') and session.get('email'):
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

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
            session['pwreset_code'] = str(random.randint(100000, 999999))
            return render_template('find_password.html', step=2, email=email, code=session['pwreset_code'])
        if step == 2:
            email_s = session.get('pwreset_email')
            if not email_s:
                return render_template('find_password.html', step=1, error="세션이 만료되었습니다. 다시 진행하세요.")
            if code != session.get('pwreset_code'):
                return render_template('find_password.html', step=2, email=email_s, error="인증번호가 다릅니다.", code=session.get('pwreset_code'))
            if not new_pw or len(new_pw) < 6:
                return render_template('find_password.html', step=2, email=email_s, error="새 비밀번호는 최소 6자 이상입니다.", code=session.get('pwreset_code'))
            pw_hash = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
            conn = get_db()
            c = conn.cursor()
            c.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email_s))
            conn.commit()
            conn.close()
            session.pop('pwreset_email', None)
            session.pop('pwreset_code', None)
            return render_template('find_password.html', step=3, success="비밀번호 변경이 완료되었습니다.")
    return render_template('find_password.html', step=1)

@app.route('/api/user')
def api_user():
    if session.get('user'):
        return jsonify({'login': True, 'username': session.get('user')})
    return jsonify({'login': False})

def month_range(ym):
    y, m = map(int, ym.split('-'))
    first = date(y, m, 1)
    last = date(y, m, calendar.monthrange(y, m)[1])
    return first.strftime('%Y-%m-%d'), last.strftime('%Y-%m-%d')

@app.route('/api/events', methods=['GET', 'POST'])
@login_required
def api_events():
    email = session['email']
    conn = get_db()
    c = conn.cursor()
    if request.method == 'GET':
        ym = request.args.get('month')
        start = request.args.get('start')
        end = request.args.get('end')
        if ym and not (start and end):
            start, end = month_range(ym)
        if not start or not end:
            today = date.today()
            start, end = month_range(today.strftime('%Y-%m'))
        c.execute("""
            SELECT id, ymd, title, time
            FROM events
            WHERE email = ? AND ymd BETWEEN ? AND ?
            ORDER BY ymd ASC, time ASC, id ASC
        """, (email, start, end))
        rows = [dict(id=r['id'], ymd=r['ymd'], title=r['title'], time=r['time']) for r in c.fetchall()]
        conn.close()
        return jsonify(rows)
    data = request.get_json(silent=True) or {}
    ymd = (data.get('ymd') or '').strip()
    title = (data.get('title') or '').strip()
    tm = (data.get('time') or '').strip()
    if not re.match(r'^\d{4}-\d{2}-\d{2}$', ymd):
        conn.close(); return jsonify({'ok': False, 'error': 'invalid ymd'}), 400
    if not title:
        conn.close(); return jsonify({'ok': False, 'error': 'title required'}), 400
    c.execute("INSERT INTO events(email, ymd, title, time) VALUES(?,?,?,?)", (email, ymd, title, tm or None))
    conn.commit()
    ev_id = c.lastrowid
    conn.close()
    return jsonify({'ok': True, 'id': ev_id, 'ymd': ymd, 'title': title, 'time': tm}), 201

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@login_required
def api_events_delete(event_id):
    email = session['email']
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM events WHERE id = ? AND email = ?", (event_id, email))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted:
        return jsonify({'ok': True})
    return jsonify({'ok': False, 'error': 'not found'}), 404

@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')

@app.route('/_debug_session')
def _debug_session():
    return {"user": session.get('user'), "email": session.get('email')}

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
