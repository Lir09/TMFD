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

# ====== 관리자 기능: 학급/반장 배치(최대 2명), 계정 삭제 ======

# --- DB 마이그레이션(컬럼/테이블 없으면 생성) ---
def column_exists(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(row[1] == col for row in cur.fetchall())

def ensure_admin_schema():
    conn = get_db()
    c = conn.cursor()
    # classes 테이블
    c.execute("""
        CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            grade TEXT
        )
    """)
    # users.role, users.class_id 없으면 추가
    if not column_exists(c, "users", "role"):
        c.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'student'")
    if not column_exists(c, "users", "class_id"):
        c.execute("ALTER TABLE users ADD COLUMN class_id INTEGER REFERENCES classes(id)")
    conn.commit()
    conn.close()

ensure_admin_schema()

# --- 관리자 권한 체크(세션의 이메일로 간단 구분) ---
def admin_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if 'email' not in session or session['email'] != "admin@admin.com":
            return jsonify({"error": "admin only"}), 403
        return f(*args, **kwargs)
    return _wrap

# --- 헬퍼 ---
def count_leaders_in_class(class_id: int) -> int:
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE role='leader' AND class_id=?", (class_id,))
    n = c.fetchone()[0] or 0
    conn.close()
    return n

def class_exists(class_id: int) -> bool:
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT 1 FROM classes WHERE id=?", (class_id,))
    ok = c.fetchone() is not None
    conn.close()
    return ok

# --- 통계 ---
@app.route('/admin/api/overview')
@login_required
@admin_required
def admin_overview():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users"); total_users = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM classes"); total_classes = c.fetchone()[0]
    c.execute("SELECT id FROM classes")
    assigned_two = 0
    for (cid,) in c.fetchall():
        if count_leaders_in_class(cid) == 2:
            assigned_two += 1
    conn.close()
    return jsonify({
        "users": total_users,
        "classes": total_classes,
        "classes_with_two_leaders": assigned_two
    })

# --- 학급 CRUD ---
@app.route('/admin/api/classes', methods=['GET'])
@login_required
@admin_required
def list_classes():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, name, grade FROM classes ORDER BY name")
    rows = [{"id": r[0], "name": r[1], "grade": r[2]} for r in c.fetchall()]
    conn.close()
    return jsonify(rows)

@app.route('/admin/api/classes', methods=['POST'])
@login_required
@admin_required
def create_class():
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    grade = (data.get("grade") or None)
    if not name:
        return jsonify({"error": "학급명은 필수"}), 400
    conn = get_db(); c = conn.cursor()
    try:
        c.execute("INSERT INTO classes(name, grade) VALUES (?,?)", (name, grade))
        conn.commit()
        cid = c.lastrowid
        return jsonify({"id": cid, "name": name, "grade": grade}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "중복 학급명"}), 409
    finally:
        conn.close()

@app.route('/admin/api/classes/<int:cid>', methods=['PATCH'])
@login_required
@admin_required
def rename_class(cid):
    data = request.get_json(force=True) or {}
    name = (data.get("name") or "").strip()
    grade = data.get("grade")
    if not class_exists(cid):
        return jsonify({"error": "존재하지 않는 학급"}), 404
    if not name:
        return jsonify({"error": "학급명은 필수"}), 400
    conn = get_db(); c = conn.cursor()
    # 이름 중복 체크
    c.execute("SELECT 1 FROM classes WHERE name=? AND id<>?", (name, cid))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "중복 학급명"}), 409
    c.execute("UPDATE classes SET name=?, grade=? WHERE id=?", (name, grade, cid))
    conn.commit(); conn.close()
    return jsonify({"id": cid, "name": name, "grade": grade})

@app.route('/admin/api/classes/<int:cid>', methods=['DELETE'])
@login_required
@admin_required
def delete_class(cid):
    if not class_exists(cid):
        return jsonify({"error": "존재하지 않는 학급"}), 404
    conn = get_db(); c = conn.cursor()
    # 해당 반 소속 사용자 class_id 해제
    c.execute("UPDATE users SET class_id=NULL WHERE class_id=?", (cid,))
    c.execute("DELETE FROM classes WHERE id=?", (cid,))
    conn.commit(); conn.close()
    return "", 204

# --- 사용자 조회(역할/배정 포함) ---
@app.route('/admin/api/users', methods=['GET'])
@login_required
@admin_required
def admin_users():
    conn = get_db(); c = conn.cursor()
    c.execute("""
      SELECT u.email, u.name, u.phone, u.role, u.class_id, c.name
      FROM users u
      LEFT JOIN classes c ON u.class_id = c.id
      ORDER BY u.name
    """)
    rows = [{
        "email": r[0], "name": r[1], "phone": r[2],
        "role": r[3] or "student",
        "class_id": r[4],
        "class_name": r[5]
    } for r in c.fetchall()]
    conn.close()
    return jsonify(rows)

# --- 계정 삭제 ---
@app.route('/admin/api/users/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user():
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "email 필수"}), 400
    if email == "admin@admin.com":
        return jsonify({"error": "관리자 계정은 삭제 불가"}), 400
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM activities WHERE email=?", (email,))
    c.execute("DELETE FROM users WHERE email=?", (email,))
    conn.commit(); conn.close()
    return "", 204

# --- 계정당 반 할당 + 역할 설정(반마다 반장 2명 강제) ---
@app.route('/admin/api/users/assign', methods=['POST'])
@login_required
@admin_required
def admin_assign_user():
    """
    body: {
      "email": "user@example.com",
      "class_id": 1 or null,
      "role": "leader" or "student"
    }
    규칙:
    - role='leader'로 지정 + class_id!=null 인 경우, 해당 반의 leader 수가 2명이면 409
    - class_id=None 이면 소속 해제
    """
    data = request.get_json(force=True) or {}
    email = (data.get("email") or "").strip().lower()
    role = (data.get("role") or "student").strip()
    class_id = data.get("class_id", None)

    conn = get_db(); c = conn.cursor()
    c.execute("SELECT email FROM users WHERE email=?", (email,))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "존재하지 않는 계정"}), 404

    if class_id is not None and not class_exists(int(class_id)):
        conn.close()
        return jsonify({"error": "존재하지 않는 학급"}), 404

    # 리더 2명 제한
    if role == "leader" and class_id is not None:
        n = count_leaders_in_class(int(class_id))
        # 이미 그 반에 배정된 본인이라면, 현재 수를 다시 계산해야 하지만
        # 간단히: 먼저 본인 정보를 읽어서 이전 class_id와 role을 확인
        c.execute("SELECT role, class_id FROM users WHERE email=?", (email,))
        prev_role, prev_cid = c.fetchone()
        if not (prev_role == "leader" and prev_cid == int(class_id)):
            if n >= 2:
                conn.close()
                return jsonify({"error": "해당 반에는 이미 반장이 2명입니다."}), 409

    # 업데이트
    c.execute("UPDATE users SET role=?, class_id=? WHERE email=?",
              (role, int(class_id) if class_id is not None else None, email))
    conn.commit()

    # 최종 보증: 해당 반 리더 수 초과 시 롤백(이론상 위에서 걸러짐)
    if class_id is not None and role == "leader":
        if count_leaders_in_class(int(class_id)) > 2:
            # 초과 시 원복
            c.execute("UPDATE users SET class_id=NULL WHERE email=?", (email,))
            conn.commit(); conn.close()
            return jsonify({"error": "반장 2인 제한 위반(롤백됨)"}), 409

    # 응답
    c.execute("""
      SELECT u.email, u.name, u.phone, u.role, u.class_id, c.name
      FROM users u LEFT JOIN classes c ON u.class_id=c.id WHERE u.email=?
    """, (email,))
    r = c.fetchone(); conn.close()
    return jsonify({
        "email": r[0], "name": r[1], "phone": r[2],
        "role": r[3], "class_id": r[4], "class_name": r[5]
    })

# --- 학급별 2명 일괄 배치(테이블 방식) ---
@app.route('/admin/api/classes/<int:cid>/assign', methods=['POST'])
@login_required
@admin_required
def admin_assign_two(cid):
    if not class_exists(cid):
        return jsonify({"error": "존재하지 않는 학급"}), 404
    data = request.get_json(force=True) or {}
    ids = data.get("emails") or []  # 이메일 0~2개
    ids = [str(x).strip().lower() for x in ids if x]
    if len(set(ids)) > 2:
        return jsonify({"error": "한 반에는 최대 2명만 지정"}), 400

    conn = get_db(); c = conn.cursor()
    # 존재 확인
    for em in ids:
        c.execute("SELECT 1 FROM users WHERE email=?", (em,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": f"존재하지 않는 계정: {em}"}), 400

    # 먼저 이 반의 기존 리더/학생 소속을 해제하지 않고, 리더 2명만 맞춥니다.
    # 1) 이 반의 기존 'leader' 들 모두 소속 해제
    c.execute("UPDATE users SET class_id=NULL WHERE role='leader' AND class_id=?", (cid,))
    # 2) 선택된 0~2명을 leader로 지정 + 이 반으로 이동
    for em in ids:
        c.execute("UPDATE users SET role='leader', class_id=? WHERE email=?", (cid, em))

    # 최종 2명 보증
    conn.commit()
    if count_leaders_in_class(cid) > 2:
        # 매우 이례적이지만 초과 시 모두 해제
        c.execute("UPDATE users SET class_id=NULL WHERE role='leader' AND class_id=?", (cid,))
        conn.commit(); conn.close()
        return jsonify({"error": "반장 2인 제한 위반(롤백됨)"}), 409

    # 응답
    c.execute("""
      SELECT u.email, u.name FROM users u WHERE u.role='leader' AND u.class_id=? ORDER BY u.name
    """, (cid,))
    leaders = [{"email": em, "name": nm} for (em, nm) in c.fetchall()]
    conn.close()
    return jsonify({"class_id": cid, "leaders": leaders})


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
