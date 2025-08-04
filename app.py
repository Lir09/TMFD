from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, bcrypt, os
from functools import wraps
import random
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'supersecret!'
DB_NAME = 'users.db'

def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                email TEXT PRIMARY KEY,
                name TEXT,
                phone TEXT,
                password_hash TEXT,
                mileage INTEGER DEFAULT 2500
            )
        ''')
        c.execute('''
            CREATE TABLE activities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                title TEXT,
                points INTEGER,
                visited_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    else:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
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

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT mileage FROM users WHERE email = ?", (session['email'],))
    row = c.fetchone()
    mileage = row[0] if row else 0

    c.execute("SELECT title, points, visited_at FROM activities WHERE email = ? ORDER BY visited_at DESC LIMIT 5", (session['email'],))
    activities = c.fetchall()
    conn.close()
    return render_template('index.html', username=session.get('user'), mileage=mileage, activities=activities)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        phone = request.form['phone']
        password = request.form['password']
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        if c.fetchone():
            conn.close()
            return render_template('signup.html', error="이미 등록된 이메일입니다.")
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        c.execute("INSERT INTO users (email, name, phone, password_hash, mileage) VALUES (?, ?, ?, ?, ?)",
                  (email, name, phone, pw_hash, 2500))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        remember = request.form.get('remember')
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()
        print("user:", user)
        if not user:
            return render_template('login.html', error="존재하지 않는 이메일입니다.")
        if not user[3]:
            return render_template('login.html', error="비밀번호 데이터가 손상되었습니다. 회원가입을 다시 해주세요.")
        if bcrypt.checkpw(password.encode('utf-8'), user[3]):
            session['user'] = user[1]
            session['email'] = user[0]
            if remember == "on":
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=7)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error="이메일 또는 비밀번호가 잘못되었습니다.")
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/find_password', methods=['GET', 'POST'])
def find_password():
    if request.method == 'POST':
        step = int(request.form.get('step', 1))
        email = request.form.get('email')
        code = request.form.get('code')
        new_pw = request.form.get('new_password')
        if step == 1:
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = c.fetchone()
            conn.close()
            if not user:
                return render_template('find_password.html', error="등록되지 않은 이메일입니다.", email=email, step=1)
            session['pwreset_email'] = email
            session['pwreset_code'] = str(random.randint(100000, 999999))
            return render_template('find_password.html', step=2, email=email, code=session['pwreset_code'])
        elif step == 2:
            if code != session.get('pwreset_code'):
                return render_template('find_password.html', step=2, email=email, error="인증번호가 다릅니다.", code=session.get('pwreset_code'))
            pw_hash = bcrypt.hashpw(new_pw.encode('utf-8'), bcrypt.gensalt())
            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email))
            conn.commit()
            conn.close()
            session.pop('pwreset_email', None)
            session.pop('pwreset_code', None)
            return render_template('find_password.html', step=3, success="비밀번호 변경 완료!")
    return render_template('find_password.html', step=1)

@app.route('/api/user')
def api_user():
    if 'user' in session:
        return jsonify({'login': True, 'username': session['user']})
    return jsonify({'login': False})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
