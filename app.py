import mimetypes, uuid, pathlib, requests, html
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3, bcrypt, os, re, calendar, random, json
from functools import wraps
from datetime import timedelta, date
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
import mimetypes, uuid, pathlib, time
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET', 'thisIsTmfd')
DB_NAME = 'users.db'


# ---- Upload config ----
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_ROOT, exist_ok=True)

ALLOWED_EXTS = {
    "png","jpg","jpeg","gif","webp","svg",
    "pdf","txt","md","csv","doc","docx","ppt","pptx","xls","xlsx",
    "mp4","webm","ogg","mp3","wav","m4a","mov",
    "py","js","ts","json","html","css"
}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024  # 20MB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ---------------------- DB 헬퍼 ----------------------
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

# ---------------------- 라우팅(일반) ----------------------
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

# ---------------------- 인증 ----------------------
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

# ---------------------- /api/user (확장) ----------------------
@app.route('/api/user')
def api_user():
    if session.get('user'):
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT role, class_id FROM users WHERE email=?", (session['email'],))
        row = c.fetchone(); conn.close()
        return jsonify({
            'login': True,
            'username': session.get('user'),
            'email': session.get('email'),
            'role': (row['role'] if row and row['role'] else 'student'),
            'class_id': (row['class_id'] if row else None)
        })
    return jsonify({'login': False})

# ---------------------- Events API ----------------------
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

# ---------------------- 관리자 페이지 ----------------------
@app.route('/admin')
@login_required
def admin():
    return render_template('admin.html')

@app.route('/_debug_session')
def _debug_session():
    return {"user": session.get('user'), "email": session.get('email')}

# ---------------------- 관리자 스키마/권한 ----------------------
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

def admin_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if 'email' not in session or session['email'] != "admin@admin.com":
            return jsonify({"error": "admin only"}), 403
        return f(*args, **kwargs)
    return _wrap

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

# ---------------------- 관리자 API ----------------------
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
    c.execute("UPDATE users SET class_id=NULL WHERE class_id=?", (cid,))
    c.execute("DELETE FROM classes WHERE id=?", (cid,))
    conn.commit(); conn.close()
    return "", 204

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
        c.execute("SELECT role, class_id FROM users WHERE email=?", (email,))
        prev_role, prev_cid = c.fetchone()
        if not (prev_role == "leader" and prev_cid == int(class_id)):
            if n >= 2:
                conn.close()
                return jsonify({"error": "해당 반에는 이미 반장이 2명입니다."}), 409

    c.execute("UPDATE users SET role=?, class_id=? WHERE email=?",
              (role, int(class_id) if class_id is not None else None, email))
    conn.commit()

    if class_id is not None and role == "leader":
        if count_leaders_in_class(int(class_id)) > 2:
            c.execute("UPDATE users SET class_id=NULL WHERE email=?", (email,))
            conn.commit(); conn.close()
            return jsonify({"error": "반장 2인 제한 위반(롤백됨)"}), 409

    c.execute("""
      SELECT u.email, u.name, u.phone, u.role, u.class_id, c.name
      FROM users u LEFT JOIN classes c ON u.class_id=c.id WHERE u.email=?
    """, (email,))
    r = c.fetchone(); conn.close()
    return jsonify({
        "email": r[0], "name": r[1], "phone": r[2],
        "role": r[3], "class_id": r[4], "class_name": r[5]
    })

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
    for em in ids:
        c.execute("SELECT 1 FROM users WHERE email=?", (em,))
        if not c.fetchone():
            conn.close()
            return jsonify({"error": f"존재하지 않는 계정: {em}"}), 400

    c.execute("UPDATE users SET class_id=NULL WHERE role='leader' AND class_id=?", (cid,))
    for em in ids:
        c.execute("UPDATE users SET role='leader', class_id=? WHERE email=?", (cid, em))

    conn.commit()
    if count_leaders_in_class(cid) > 2:
        c.execute("UPDATE users SET class_id=NULL WHERE role='leader' AND class_id=?", (cid,))
        conn.commit(); conn.close()
        return jsonify({"error": "반장 2인 제한 위반(롤백됨)"}), 409

    c.execute("""
      SELECT u.email, u.name FROM users u WHERE u.role='leader' AND u.class_id=? ORDER BY u.name
    """, (cid,))
    leaders = [{"email": em, "name": nm} for (em, nm) in c.fetchall()]
    conn.close()
    return jsonify({"class_id": cid, "leaders": leaders})

# ---------------------- 수행평가 스키마 ----------------------
def ensure_assessment_schema():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
            subject TEXT NOT NULL,
            title TEXT NOT NULL,
            type TEXT,
            due_at TEXT NOT NULL,          -- ISO string (YYYY-MM-DDTHH:MM)
            status TEXT DEFAULT '미제출',   -- 미제출/진행중/제출/채점중/완료
            progress INTEGER DEFAULT 0,     -- 0~100
            checklist TEXT                 -- JSON list[str]
        )
    """)
    conn.commit()
    conn.close()

# classes 테이블/role 추가한 뒤에 assessments 보장
ensure_assessment_schema()

# ---------------------- 권한 헬퍼 ----------------------
def get_me_role_class():
    email = session.get('email')
    if not email:
        return None, None
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT role, class_id FROM users WHERE email=?", (email,))
    row = c.fetchone()
    conn.close()
    role = (row['role'] if row and row['role'] else 'student')
    class_id = (row['class_id'] if row else None)
    return role, class_id

# ---------------------- Assessments API ----------------------
@app.route('/api/assessments', methods=['GET', 'POST'])
@login_required
def api_assessments():
    role, my_cid = get_me_role_class()
    me = session.get('email')

    conn = get_db(); c = conn.cursor()

    if request.method == 'GET':
        q_cid = request.args.get('class_id', type=int)
        if me == "admin@admin.com":
            cid = q_cid if q_cid else my_cid
        else:
            cid = my_cid
        if cid is None:
            conn.close()
            return jsonify([])

        c.execute("""
            SELECT id, class_id, subject, title, type, due_at, status, progress, checklist
            FROM assessments
            WHERE class_id=?
            ORDER BY due_at ASC, id ASC
        """, (cid,))
        rows = []
        for r in c.fetchall():
            rows.append({
                "id": r["id"],
                "class_id": r["class_id"],
                "subject": r["subject"],
                "title": r["title"],
                "type": r["type"],
                "due_at": r["due_at"],
                "status": r["status"],
                "progress": r["progress"],
                "checklist": json.loads(r["checklist"]) if r["checklist"] else []
            })
        conn.close()
        return jsonify(rows)

    # POST: 반장/관리자만
    if not (me == "admin@admin.com" or role == "leader"):
        conn.close()
        return jsonify({"error": "leader only"}), 403

    data = request.get_json(force=True) or {}
    subject = (data.get("subject") or "").strip()
    title   = (data.get("title") or "").strip()
    typ     = (data.get("type") or "").strip()
    due_at  = (data.get("due_at") or "").strip()      # "YYYY-MM-DDTHH:MM"
    status  = (data.get("status") or "미제출").strip()
    progress= int(data.get("progress") or 0)
    checklist = data.get("checklist") or []

    if not subject or not title or not due_at:
        conn.close()
        return jsonify({"error": "subject, title, due_at required"}), 400

    progress = max(0, min(100, progress))
    cid = my_cid if me != "admin@admin.com" else (data.get("class_id") or my_cid)
    if cid is None:
        conn.close()
        return jsonify({"error": "class not assigned"}), 400

    c.execute("""
      INSERT INTO assessments(class_id, subject, title, type, due_at, status, progress, checklist)
      VALUES (?,?,?,?,?,?,?,?)
    """, (int(cid), subject, title, typ, due_at, status, progress, json.dumps(checklist)))
    conn.commit()
    new_id = c.lastrowid
    conn.close()
    return jsonify({"ok": True, "id": new_id}), 201

@app.route('/api/assessments/<int:aid>', methods=['PATCH', 'DELETE'])
@login_required
def api_assessments_detail(aid):
    role, my_cid = get_me_role_class()
    me = session.get('email')

    conn = get_db(); c = conn.cursor()
    c.execute("SELECT class_id FROM assessments WHERE id=?", (aid,))
    row = c.fetchone()
    if not row:
        conn.close(); return jsonify({"error": "not found"}), 404

    target_cid = row["class_id"]
    if not (me == "admin@admin.com" or (role == "leader" and my_cid == target_cid)):
        conn.close(); return jsonify({"error": "forbidden"}), 403

    if request.method == 'DELETE':
        c.execute("DELETE FROM assessments WHERE id=?", (aid,))
        conn.commit(); conn.close()
        return "", 204

    data = request.get_json(force=True) or {}
    fields, params = [], []
    for k in ("subject","title","type","due_at","status","progress","checklist"):
        if k in data:
            if k == "progress":
                v = max(0, min(100, int(data["progress"])))
            elif k == "checklist":
                v = json.dumps(data["checklist"] or [])
            else:
                v = str(data[k]).strip()
            fields.append(f"{k}=?"); params.append(v)
    if fields:
        params.append(aid)
        c.execute(f"UPDATE assessments SET {', '.join(fields)} WHERE id=?", params)
        conn.commit()
    conn.close()
    return jsonify({"ok": True})

# ---------------------- 노트 스키마 ----------------------
def ensure_notes_schema():
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT DEFAULT '',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # 최신순 목록을 위해 인덱스
    c.execute("CREATE INDEX IF NOT EXISTS idx_notes_email_updated ON notes(email, updated_at DESC)")
    conn.commit()
    conn.close()

ensure_notes_schema()  # <- 추가

def ensure_files_schema():
    conn = get_db(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            orig_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            mime TEXT,
            size INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_email ON files(email)")
    conn.commit(); conn.close()

ensure_files_schema()  # <- 이 줄도 추가



# ---------------------- Notes API ----------------------
def note_row_to_dict(r):
    return {
        "id": r["id"],
        "title": r["title"],
        "content": r["content"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"]
    }

@app.route('/api/notes', methods=['GET', 'POST'])
@login_required
def api_notes():
    email = session['email']
    conn = get_db(); c = conn.cursor()

    if request.method == 'GET':
        q = (request.args.get('q') or '').strip()
        limit = min(int(request.args.get('limit', 50)), 100)
        offset = max(int(request.args.get('offset', 0)), 0)

        if q:
            # 간단 검색: 제목/내용 LIKE
            like = f"%{q}%"
            c.execute("""
                SELECT id, title, content, created_at, updated_at
                FROM notes
                WHERE email=? AND (title LIKE ? OR content LIKE ?)
                ORDER BY updated_at DESC, id DESC
                LIMIT ? OFFSET ?
            """, (email, like, like, limit, offset))
        else:
            c.execute("""
                SELECT id, title, content, created_at, updated_at
                FROM notes
                WHERE email=?
                ORDER BY updated_at DESC, id DESC
                LIMIT ? OFFSET ?
            """, (email, limit, offset))
        rows = [note_row_to_dict(r) for r in c.fetchall()]
        conn.close()
        return jsonify(rows)

    # POST: 새 노트 생성
    data = request.get_json(force=True) or {}
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "")

    if not title:
        conn.close()
        return jsonify({"error": "title required"}), 400

    c.execute("""
        INSERT INTO notes(email, title, content)
        VALUES (?,?,?)
    """, (email, title, content))
    conn.commit()
    nid = c.lastrowid

    c.execute("""
        SELECT id, title, content, created_at, updated_at
        FROM notes WHERE id=? AND email=?
    """, (nid, email))
    row = c.fetchone(); conn.close()
    return jsonify(note_row_to_dict(row)), 201


@app.route('/api/notes/<int:nid>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def api_notes_detail(nid):
    email = session['email']
    conn = get_db(); c = conn.cursor()

    # 소유권 체크 + 로드
    c.execute("""
        SELECT id, title, content, created_at, updated_at
        FROM notes WHERE id=? AND email=?
    """, (nid, email))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404

    if request.method == 'GET':
        data = note_row_to_dict(row)
        conn.close()
        return jsonify(data)

    if request.method == 'DELETE':
        c.execute("DELETE FROM notes WHERE id=? AND email=?", (nid, email))
        conn.commit(); conn.close()
        return "", 204

    # PATCH: 부분 수정
    data = request.get_json(force=True) or {}
    fields, params = [], []
    if "title" in data:
        title = (data.get("title") or "").strip()
        if not title:
            conn.close(); return jsonify({"error": "title required"}), 400
        fields.append("title=?"); params.append(title)
    if "content" in data:
        fields.append("content=?"); params.append(data.get("content") or "")

    if fields:
        fields.append("updated_at=CURRENT_TIMESTAMP")
        params.extend([nid, email])
        c.execute(f"UPDATE notes SET {', '.join(fields)} WHERE id=? AND email=?", params)
        conn.commit()

    c.execute("""
        SELECT id, title, content, created_at, updated_at
        FROM notes WHERE id=? AND email=?
    """, (nid, email))
    row = c.fetchone(); conn.close()
    return jsonify(note_row_to_dict(row))

def _user_upload_dir(email: str) -> str:
    safe = re.sub(r'[^a-zA-Z0-9._-]+','_', email)
    d = os.path.join(UPLOAD_ROOT, safe)
    os.makedirs(d, exist_ok=True)
    return d

def _is_allowed(filename: str) -> bool:
    ext = filename.rsplit('.',1)[-1].lower() if '.' in filename else ''
    return ext in ALLOWED_EXTS

@app.route('/api/files', methods=['POST'])
@login_required
def api_files_upload():
    if 'file' not in request.files:
        return jsonify({"error":"no file"}), 400
    f = request.files['file']
    if not f or not f.filename:
        return jsonify({"error":"empty file"}), 400
    if not _is_allowed(f.filename):
        return jsonify({"error":"not allowed"}), 400

    email = session['email']
    orig = secure_filename(f.filename)
    ext = (orig.rsplit('.',1)[-1].lower() if '.' in orig else '')
    token = uuid.uuid4().hex[:10]
    stored = f"{int(time.time())}_{token}.{ext}" if ext else f"{int(time.time())}_{token}"
    user_dir = _user_upload_dir(email)
    path = os.path.join(user_dir, stored)
    f.save(path)

    size = os.path.getsize(path)
    if size > MAX_CONTENT_LENGTH:
        os.remove(path)
        return jsonify({"error":"file too large"}), 413

    mime, _ = mimetypes.guess_type(path)
    conn = get_db(); c = conn.cursor()
    c.execute("""INSERT INTO files(email, orig_name, stored_name, mime, size)
                 VALUES(?,?,?,?,?)""", (email, orig, stored, mime or 'application/octet-stream', size))
    conn.commit()
    fid = c.lastrowid
    # URL
    safe_email = re.sub(r'[^a-zA-Z0-9._-]+','_', email)
    url = f"/uploads/{safe_email}/{stored}"
    c.execute("""SELECT created_at FROM files WHERE id=?""", (fid,))
    created_at = c.fetchone()[0]
    conn.close()

    return jsonify({"id":fid,"name":orig,"mime":mime,"size":size,"url":url,"created_at":created_at}), 201

@app.route('/uploads/<path:subpath>')
@login_required
def serve_upload(subpath):
    # 소유자만 읽기
    email = session['email']
    safe_email = re.sub(r'[^a-zA-Z0-9._-]+','_', email)
    # subpath는 "safe_email/filename"이어야 함
    parts = pathlib.PurePosixPath(subpath).parts
    if not parts or parts[0] != safe_email:
        return "forbidden", 403
    directory = os.path.join(UPLOAD_ROOT, safe_email)
    filename = os.path.join(*parts[1:]) if len(parts) > 1 else ''
    if not filename:
        return "not found", 404
    return flask.send_from_directory(directory, filename, as_attachment=False)

@app.route('/api/bookmark')
@login_required
def api_bookmark():
    url = request.args.get('url','').strip()
    if not url:
        return jsonify({"error":"url required"}), 400
    try:
        resp = requests.get(url, timeout=5, headers={"User-Agent":"Mozilla/5.0"})
        html_text = resp.text
    except Exception:
        return jsonify({"error":"fetch failed"}), 400

    def _meta(name):
        m = re.search(rf'<meta[^>]+property=["\']{re.escape(name)}["\'][^>]*content=["\'](.*?)["\']', html_text, re.I|re.S)
        if m: return html.unescape(m.group(1)).strip()
        m = re.search(rf'<meta[^>]+name=["\']{re.escape(name)}["\'][^>]*content=["\'](.*?)["\']', html_text, re.I|re.S)
        return html.unescape(m.group(1)).strip() if m else None

    title = _meta('og:title') or re.search(r'<title[^>]*>(.*?)</title>', html_text, re.I|re.S)
    title = (title.group(1).strip() if hasattr(title,'group') else title) or url
    desc  = _meta('og:description') or _meta('description')
    image = _meta('og:image')
    icon  = None
    m = re.search(r'<link[^>]+rel=["\'](?:icon|shortcut icon)["\'][^>]*href=["\'](.*?)["\']', html_text, re.I|re.S)
    if m: icon = m.group(1).strip()

    # 절대경로 보정
    def _abs(u):
        try:
            return requests.compat.urljoin(url, u) if u else None
        except: return None

    return jsonify({
        "url": url,
        "title": title,
        "description": desc,
        "image": _abs(image),
        "icon": _abs(icon)
    })



# ---------------------- 엔트리 포인트 ----------------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
