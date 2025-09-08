import os, re, json, time, uuid, pathlib, mimetypes, calendar, random, html, requests
from datetime import datetime, timedelta, date
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from werkzeug.utils import secure_filename
import psycopg2, psycopg2.extras, bcrypt
from dotenv import load_dotenv

# ---------------------- 초기 설정 ----------------------
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv('APP_SECRET', 'thisIsTmfd')

UPLOAD_ROOT = os.path.join("/tmp", "uploads")
os.makedirs(UPLOAD_ROOT, exist_ok=True)

ALLOWED_EXTS = {
    "png","jpg","jpeg","gif","webp","svg",
    "pdf","txt","md","csv","doc","docx","ppt","pptx","xls","xlsx",
    "mp4","webm","ogg","mp3","wav","m4a","mov",
    "py","js","ts","json","html","css"
}
MAX_CONTENT_LENGTH = 20 * 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# ---------------------- DB 헬퍼 ----------------------
def get_db():
    dsn = os.getenv("DATABASE_URL")
    if not dsn:
        raise RuntimeError("DATABASE_URL not set")
    # psycopg2는 postgresql:// 대신 postgres:// 를 기대할 수 있음
    if dsn.startswith("postgresql://"):
        dsn = dsn.replace("postgresql://", "postgres://", 1)
    conn = psycopg2.connect(dsn, cursor_factory=psycopg2.extras.DictCursor)
    return conn


def init_db():
    conn = get_db(); c = conn.cursor()

    # 1. 학급 테이블 (users에서 참조하므로 제일 먼저 생성)
    c.execute("""
        CREATE TABLE IF NOT EXISTS classes (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            grade TEXT
        )
    """)

    # 2. 사용자 테이블 (class_id → classes.id 외래키)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            name TEXT,
            phone TEXT,
            password_hash BYTEA,
            mileage INTEGER DEFAULT 2500,
            role TEXT DEFAULT 'student',
            class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL
        )
    """)

    # 3. 활동 테이블 (users.email 참조)
    c.execute("""
        CREATE TABLE IF NOT EXISTS activities (
            id SERIAL PRIMARY KEY,
            email TEXT REFERENCES users(email) ON DELETE CASCADE,
            title TEXT,
            points INTEGER,
            visited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 4. 일정 테이블 (users.email 참조)
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            ymd DATE NOT NULL,
            title TEXT NOT NULL,
            time TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit(); conn.close()


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

def admin_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if 'email' not in session or session['email'] != "admin@admin.com":
            return jsonify({"error": "admin only"}), 403
        return f(*args, **kwargs)
    return _wrap


@app.context_processor
def inject_user():
    return {"current_user": session.get('user'), "current_email": session.get('email')}

# ---------------------- 라우팅 ----------------------
@app.route('/')
def root():
    if session.get('user') and session.get('email'):
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route('/index')
@login_required
def index():
    email = session.get('email')
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT mileage FROM users WHERE email = %s", (email,))
    row = c.fetchone()
    mileage = (row['mileage'] if row else 0)
    c.execute("""
        SELECT title, points, visited_at
        FROM activities
        WHERE email = %s
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
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT mileage FROM users WHERE email = %s", (email,))
    row = c.fetchone()
    mileage = row['mileage'] if row else 0
    c.execute("""
        SELECT title, points, visited_at
        FROM activities
        WHERE email = %s
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

# ---------------------- 로그인 ----------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = request.form.get('remember')

        conn = get_db(); c = conn.cursor()
        c.execute("SELECT email, name, phone, password_hash FROM users WHERE email=%s", (email,))
        user = c.fetchone(); conn.close()

        if not user:
            return render_template('login.html', error="존재하지 않는 이메일입니다.")
        if not user['password_hash']:
            return render_template('login.html', error="비밀번호 데이터가 손상되었습니다. 다시 회원가입을 진행해 주세요.")

        # memoryview → bytes 변환 필수
        hashed_pw = bytes(user['password_hash'])

        if bcrypt.checkpw(password.encode("utf-8"), hashed_pw):
            # 로그인 성공
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


# ---------------------- 로그아웃 ----------------------
@app.route('/logout', methods=['GET','POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))


# ---------------------- 비밀번호 찾기 ----------------------
@app.route('/find_password', methods=['GET','POST'])
def find_password():
    if request.method == 'POST':
        step = int(request.form.get('step', 1))
        email = request.form.get('email', '').strip().lower()
        code = request.form.get('code', '').strip()
        new_pw = request.form.get('new_password', '')

        if step == 1:
            conn = get_db(); c = conn.cursor()
            c.execute("SELECT 1 FROM users WHERE email=%s", (email,))
            user = c.fetchone(); conn.close()
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
            conn = get_db(); c = conn.cursor()
            c.execute("UPDATE users SET password_hash=%s WHERE email=%s", (pw_hash, email_s))
            conn.commit(); conn.close()
            session.pop('pwreset_email', None)
            session.pop('pwreset_code', None)
            return render_template('find_password.html', step=3, success="비밀번호 변경이 완료되었습니다.")
    return render_template('find_password.html', step=1)

# ---------------------- Classes API ----------------------
@app.route('/admin/api/classes', methods=['GET'])
@login_required
@admin_required
def list_classes():
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT id, name, grade FROM classes ORDER BY name")
    rows = [{"id": r["id"], "name": r["name"], "grade": r["grade"]} for r in c.fetchall()]
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
        c.execute("INSERT INTO classes(name, grade) VALUES (%s,%s) RETURNING id", (name, grade))
        cid = c.fetchone()[0]; conn.commit()
        return jsonify({"id": cid, "name": name, "grade": grade}), 201
    except psycopg2.Error:
        conn.rollback(); return jsonify({"error": "중복 학급명"}), 409
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
    c.execute("SELECT 1 FROM classes WHERE name=%s AND id<>%s", (name, cid))
    if c.fetchone():
        conn.close(); return jsonify({"error": "중복 학급명"}), 409
    c.execute("UPDATE classes SET name=%s, grade=%s WHERE id=%s", (name, grade, cid))
    conn.commit(); conn.close()
    return jsonify({"id": cid, "name": name, "grade": grade})

@app.route('/admin/api/classes/<int:cid>', methods=['DELETE'])
@login_required
@admin_required
def delete_class(cid):
    if not class_exists(cid):
        return jsonify({"error": "존재하지 않는 학급"}), 404
    conn = get_db(); c = conn.cursor()
    c.execute("UPDATE users SET class_id=NULL WHERE class_id=%s", (cid,))
    c.execute("DELETE FROM classes WHERE id=%s", (cid,))
    conn.commit(); conn.close()
    return "", 204


# ---------------------- Users API ----------------------
@app.route('/admin/api/users', methods=['GET'])
@login_required
@admin_required
def admin_users():
    conn = get_db(); c = conn.cursor()
    c.execute("""
      SELECT u.email, u.name, u.phone, u.role, u.class_id, c.name AS class_name
      FROM users u
      LEFT JOIN classes c ON u.class_id = c.id
      ORDER BY u.name
    """)
    rows = [dict(r) for r in c.fetchall()]
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
    c.execute("DELETE FROM activities WHERE email=%s", (email,))
    c.execute("DELETE FROM users WHERE email=%s", (email,))
    conn.commit(); conn.close()
    return "", 204

def get_me_role_class():
    email = session.get('email')
    if not email:
        return None, None
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT role, class_id FROM users WHERE email=%s", (email,))
    row = c.fetchone(); conn.close()
    role = (row['role'] if row and row['role'] else 'student')
    class_id = (row['class_id'] if row else None)
    return role, class_id

@app.route('/api/assessments', methods=['GET','POST'])
@login_required
def api_assessments():
    role, my_cid = get_me_role_class()
    me = session.get('email')

    conn = get_db(); c = conn.cursor()
    if request.method == 'GET':
        q_cid = request.args.get('class_id', type=int)
        cid = q_cid if me == "admin@admin.com" else my_cid
        if cid is None:
            conn.close(); return jsonify([])

        c.execute("""
            SELECT id, class_id, subject, title, type, due_at, status, progress, checklist
            FROM assessments WHERE class_id=%s
            ORDER BY due_at ASC, id ASC
        """, (cid,))

        rows = []
        for r in c.fetchall():
            r = dict(r)  # DictRow를 일반 dict로 변환 (안전)
            checklist_raw = r.get("checklist")
            checklist = []
            if checklist_raw:
                try:
                    checklist = json.loads(checklist_raw)
                except Exception:
                    checklist = []
            rows.append({
                "id": r.get("id"),
                "class_id": r.get("class_id"),
                "subject": r.get("subject"),
                "title": r.get("title"),
                "type": r.get("type"),
                "due_at": r.get("due_at"),
                "status": r.get("status"),
                "progress": r.get("progress"),
                "checklist": checklist
            })

        conn.close()
        return jsonify(rows)

    # POST
    if not (me == "admin@admin.com" or role == "leader"):
        conn.close(); return jsonify({"error": "leader only"}), 403

    data = request.get_json(force=True) or {}
    subject = (data.get("subject") or "").strip()
    title   = (data.get("title") or "").strip()
    typ     = (data.get("type") or "").strip()
    due_at  = (data.get("due_at") or "").strip()
    status  = (data.get("status") or "미제출").strip()
    progress= int(data.get("progress") or 0)
    checklist = data.get("checklist") or []

    if not subject or not title or not due_at:
        conn.close(); return jsonify({"error": "subject, title, due_at required"}), 400

    progress = max(0, min(100, progress))
    cid = my_cid if me != "admin@admin.com" else (data.get("class_id") or my_cid)
    if cid is None:
        conn.close(); return jsonify({"error": "class not assigned"}), 400

    c.execute("""
      INSERT INTO assessments(class_id, subject, title, type, due_at, status, progress, checklist)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
    """, (int(cid), subject, title, typ, due_at, status, progress, json.dumps(checklist)))
    new_id = c.fetchone()[0]; conn.commit(); conn.close()
    return jsonify({"ok": True, "id": new_id}), 201

@app.route('/api/activities', methods=['POST'])
@login_required
def add_activity():
    email = session['email']
    data = request.get_json(force=True) or {}
    title = (data.get("title") or "").strip()
    points = int(data.get("points") or 0)
    if not title:
        return jsonify({"error": "title required"}), 400

    conn = get_db(); c = conn.cursor()
    c.execute("INSERT INTO activities(email, title, points) VALUES(%s,%s,%s) RETURNING id, visited_at",
              (email, title, points))
    row = c.fetchone(); conn.commit(); conn.close()
    return jsonify({"id": row["id"], "title": title, "points": points, "visited_at": row["visited_at"]}), 201


# ---------------------- 인증 ----------------------
@app.route('/signup', methods=['GET','POST'])
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

        conn = get_db(); c = conn.cursor()
        c.execute("SELECT 1 FROM users WHERE email=%s", (email,))
        if c.fetchone():
            conn.close()
            return render_template('signup.html', error="이미 등록된 이메일입니다.")

        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        c.execute("""
            INSERT INTO users (email, name, phone, password_hash, mileage)
            VALUES (%s, %s, %s, %s, %s)
        """, (email, name, phone, pw_hash, 2500))
        conn.commit(); conn.close()
        return redirect(url_for('login'))
    return render_template('signup.html')
# ---------------------- /api/user ----------------------
@app.route('/api/user')
def api_user():
    if session.get('user'):
        conn = get_db(); c = conn.cursor()
        c.execute("SELECT role, class_id FROM users WHERE email=%s", (session['email'],))
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
    conn = get_db(); c = conn.cursor()
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
            WHERE email=%s AND ymd BETWEEN %s AND %s
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

    c.execute("INSERT INTO events(email, ymd, title, time) VALUES(%s,%s,%s,%s) RETURNING id",
              (email, ymd, title, tm or None))
    ev_id = c.fetchone()[0]
    conn.commit(); conn.close()
    return jsonify({'ok': True, 'id': ev_id, 'ymd': ymd, 'title': title, 'time': tm}), 201

@app.route('/api/events/<int:event_id>', methods=['DELETE'])
@login_required
def api_events_delete(event_id):
    email = session['email']
    conn = get_db(); c = conn.cursor()
    c.execute("DELETE FROM events WHERE id=%s AND email=%s", (event_id, email))
    deleted = c.rowcount
    conn.commit(); conn.close()
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
def ensure_admin_schema():
    conn = get_db(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS classes (
            id SERIAL PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            grade TEXT
        )
    """)
    conn.commit(); conn.close()

ensure_admin_schema()

def count_leaders_in_class(class_id: int) -> int:
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM users WHERE role='leader' AND class_id=%s", (class_id,))
    n = c.fetchone()[0] or 0
    conn.close()
    return n

def class_exists(class_id: int) -> bool:
    conn = get_db(); c = conn.cursor()
    c.execute("SELECT 1 FROM classes WHERE id=%s", (class_id,))
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
# ---------------------- 수행평가 스키마 ----------------------
def ensure_assessment_schema():
    conn = get_db(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS assessments (
            id SERIAL PRIMARY KEY,
            class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
            subject TEXT NOT NULL,
            title TEXT NOT NULL,
            type TEXT,
            due_at TEXT NOT NULL,
            status TEXT DEFAULT '미제출',
            progress INTEGER DEFAULT 0,
            checklist TEXT
        )
    """)
    conn.commit(); conn.close()

ensure_assessment_schema()


# ---------------------- Notes 스키마 ----------------------
def ensure_notes_schema():
    conn = get_db(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            title TEXT NOT NULL,
            content TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_notes_email_updated ON notes(email, updated_at DESC)")
    conn.commit(); conn.close()

ensure_notes_schema()


# ---------------------- Files 스키마 ----------------------
def ensure_files_schema():
    conn = get_db(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            orig_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            mime TEXT,
            size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_files_email ON files(email)")
    conn.commit(); conn.close()

ensure_files_schema()


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
            like = f"%{q}%"
            c.execute("""
                SELECT id, title, content, created_at, updated_at
                FROM notes
                WHERE email=%s AND (title ILIKE %s OR content ILIKE %s)
                ORDER BY updated_at DESC, id DESC
                LIMIT %s OFFSET %s
            """, (email, like, like, limit, offset))
        else:
            c.execute("""
                SELECT id, title, content, created_at, updated_at
                FROM notes
                WHERE email=%s
                ORDER BY updated_at DESC, id DESC
                LIMIT %s OFFSET %s
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
        VALUES (%s, %s, %s)
        RETURNING id, title, content, created_at, updated_at
    """, (email, title, content))
    row = c.fetchone(); conn.commit(); conn.close()
    return jsonify(note_row_to_dict(row)), 201


@app.route('/api/notes/<int:nid>', methods=['GET', 'PATCH', 'DELETE'])
@login_required
def api_notes_detail(nid):
    email = session['email']
    conn = get_db(); c = conn.cursor()

    c.execute("""
        SELECT id, title, content, created_at, updated_at
        FROM notes WHERE id=%s AND email=%s
    """, (nid, email))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404

    if request.method == 'GET':
        conn.close(); return jsonify(note_row_to_dict(row))

    if request.method == 'DELETE':
        c.execute("DELETE FROM notes WHERE id=%s AND email=%s", (nid, email))
        conn.commit(); conn.close()
        return "", 204

    # PATCH
    data = request.get_json(force=True) or {}
    fields, params = [], []
    if "title" in data:
        title = (data.get("title") or "").strip()
        if not title:
            conn.close(); return jsonify({"error": "title required"}), 400
        fields.append("title=%s"); params.append(title)
    if "content" in data:
        fields.append("content=%s"); params.append(data.get("content") or "")

    if fields:
        fields.append("updated_at=CURRENT_TIMESTAMP")
        params.extend([nid, email])
        c.execute(f"UPDATE notes SET {', '.join(fields)} WHERE id=%s AND email=%s", params)
        conn.commit()

    c.execute("""
        SELECT id, title, content, created_at, updated_at
        FROM notes WHERE id=%s AND email=%s
    """, (nid, email))
    row = c.fetchone(); conn.close()
    return jsonify(note_row_to_dict(row))


# ---------------------- Files API ----------------------
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
    c.execute("""
        INSERT INTO files(email, orig_name, stored_name, mime, size)
        VALUES(%s,%s,%s,%s,%s) RETURNING id, created_at
    """, (email, orig, stored, mime or 'application/octet-stream', size))
    fid, created_at = c.fetchone()
    conn.commit(); conn.close()

    safe_email = re.sub(r'[^a-zA-Z0-9._-]+','_', email)
    url = f"/uploads/{safe_email}/{stored}"
    return jsonify({
        "id":fid,"name":orig,"mime":mime,"size":size,"url":url,"created_at":created_at
    }), 201

@app.route('/uploads/<path:subpath>')
@login_required
def serve_upload(subpath):
    email = session['email']
    safe_email = re.sub(r'[^a-zA-Z0-9._-]+','_', email)

    parts = pathlib.PurePosixPath(subpath).parts
    if not parts or parts[0] != safe_email:
        return "forbidden", 403

    directory = os.path.join(UPLOAD_ROOT, safe_email)
    filename = os.path.join(*parts[1:]) if len(parts) > 1 else ''
    if not filename:
        return "not found", 404

    return send_from_directory(directory, filename, as_attachment=False)
# ====================== Kakao Talk (OpenBuilder Skill) ======================
from datetime import datetime, timedelta
import re

# ---------- DB 스키마 ----------
def ensure_notify_schema():
    conn = get_db(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS notify_subscriptions (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
            id_type TEXT NOT NULL DEFAULT 'botUserKey',
            kakao_user_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(email, class_id)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_notify_class ON notify_subscriptions(class_id, enabled)")
    conn.commit(); conn.close()

def ensure_pair_schema():
    conn = get_db(); c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS pair_codes(
            code TEXT PRIMARY KEY,
            email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
            class_id INTEGER REFERENCES classes(id) ON DELETE SET NULL,
            expires_at TIMESTAMP NOT NULL
        )
    """)
    conn.commit(); conn.close()

ensure_notify_schema()
ensure_pair_schema()


# ---------- Kakao Skill 응답 헬퍼 ----------
def _kakao_simple_text(text: str):
    return {
        "version": "2.0",
        "template": {
            "outputs": [{"simpleText": {"text": text}}],
            "quickReplies": [
                {"action": "message", "label": "수행평가 보기", "messageText": "/수행평가"},
            ],
        },
    }

def _kakao_list_card(header_title: str, items: list, more_url: str = "/assessment.html"):
    return {
        "version":"2.0",
        "template":{
            "outputs":[
                {"listCard":{
                    "header":{"title": header_title},
                    "items":[
                        {
                            "title": it["title"],
                            "description": it["description"],
                            "link": {"web": it.get("linkUrl", more_url)}
                        } for it in items[:5]
                    ],
                    "buttons":[
                        {"label":"TMFD 열기","action":"webLink","webLinkUrl": more_url}
                    ]
                }}],
            "quickReplies":[
                {"action":"message","label":"새로고침","messageText":"/수행평가"}
            ]
        }
    }

def _parse_skill_user(req_json):
    u = (req_json or {}).get("userRequest", {}).get("user", {})
    return u.get("id"), (u.get("type") or "botUserKey")

def _fmt_ko(dt: datetime):
    return dt.strftime("%m/%d %H:%M")

def _human_remain(due: datetime):
    diff = due - datetime.now()
    h = int(diff.total_seconds() // 3600)
    if h < 0:
        return f"지각 {abs(h)}h"
    if h < 24:
        return f"{h}h 남음"
    return f"{h//24}일 남음"


# ---------- 1) TMFD → 6자리 코드 발급 ----------
@app.route('/api/kakao/pair/start', methods=['POST'])
@login_required
def pair_start():
    role, class_id = get_me_role_class()
    if not class_id:
        return jsonify({"error":"class not assigned"}), 400

    code = f"{random.randint(0, 999999):06d}"
    exp = (datetime.utcnow() + timedelta(minutes=10))

    conn = get_db(); c = conn.cursor()
    c.execute("""
        INSERT INTO pair_codes(code, email, class_id, expires_at)
        VALUES(%s,%s,%s,%s)
        ON CONFLICT (code) DO UPDATE
        SET email=EXCLUDED.email,
            class_id=EXCLUDED.class_id,
            expires_at=EXCLUDED.expires_at
    """, (code, session['email'], class_id, exp))
    conn.commit(); conn.close()

    return jsonify({"code": code, "expires_in": 600})


# ---------- 2) 카톡 → "/등록 123456" ----------
@app.route("/kakao/skill/register", methods=["POST"])
def kakao_skill_register():
    payload = request.get_json(force=True, silent=True) or {}
    bot_user_id, id_type = _parse_skill_user(payload)
    utter = (payload.get("userRequest", {}).get("utterance") or "").strip()

    m = re.search(r'(\d{6,8})', utter)
    if not m:
        return jsonify(_kakao_simple_text("등록코드가 필요해요. 예) /등록 123456"))

    code = m.group(1)

    conn = get_db(); c = conn.cursor()
    c.execute("SELECT email, class_id, expires_at FROM pair_codes WHERE code=%s", (code,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify(_kakao_simple_text("유효하지 않은 코드예요. TMFD에서 새 코드를 발급해 주세요."))

    if datetime.utcnow() > row["expires_at"]:
        conn.close()
        return jsonify(_kakao_simple_text("코드가 만료되었어요. TMFD에서 새 코드를 발급해 주세요."))

    email, class_id = row["email"], row["class_id"]

    c.execute("""
        INSERT INTO notify_subscriptions(email, class_id, id_type, kakao_user_id, enabled)
        VALUES(%s,%s,%s,%s,1)
        ON CONFLICT(email, class_id) DO UPDATE
        SET id_type=EXCLUDED.id_type,
            kakao_user_id=EXCLUDED.kakao_user_id,
            enabled=1
    """, (email, class_id, 'botUserKey', bot_user_id))
    c.execute("DELETE FROM pair_codes WHERE code=%s", (code,))
    conn.commit(); conn.close()

    return jsonify(_kakao_simple_text("연결 완료! 이제 '/수행평가'라고 보내면 목록을 보여줄게요."))


# ---------- 3) 카톡 → "/수행평가" ----------
@app.route("/kakao/skill/assessments", methods=["POST"])
def kakao_skill_assessments():
    payload = request.get_json(force=True, silent=True) or {}
    bot_user_id, id_type = _parse_skill_user(payload)

    conn = get_db(); c = conn.cursor()
    c.execute("""
        SELECT class_id FROM notify_subscriptions
        WHERE id_type=%s AND kakao_user_id=%s AND enabled=1
        LIMIT 1
    """, (id_type, bot_user_id or ""))
    r = c.fetchone()
    if not r:
        conn.close()
        return jsonify(_kakao_simple_text("아직 계정 연결이 필요합니다.\nTMFD에서 '카카오 연결'로 코드를 받고, /등록 6자리코드를 입력해 주세요."))

    class_id = int(r["class_id"])

    c.execute("""
        SELECT id, subject, title, type, due_at
        FROM assessments
        WHERE class_id=%s
        ORDER BY due_at ASC, id ASC
    """, (class_id,))
    rows = c.fetchall(); conn.close()

    if not rows:
        return jsonify(_kakao_simple_text("등록된 수행평가가 없어요. 🧹"))

    items=[]
    for x in rows:
        try:
            due = datetime.strptime(x["due_at"].replace(" ", "T"), "%Y-%m-%dT%H:%M")
        except Exception:
            continue
        items.append({
            "title": f"[{x['subject']}] {x['title']}",
            "description": f"마감 { _fmt_ko(due) } · { _human_remain(due) } · { x['type'] or '-' }",
            "linkUrl": "/assessment.html"
        })

    return jsonify(_kakao_list_card("수행평가 · 남은시간", items))


# ---------------------- 엔트리 포인트 ----------------------
if __name__ == '__main__':
    init_db()
    ensure_admin_schema()
    ensure_assessment_schema()
    ensure_notes_schema()
    ensure_files_schema()
    ensure_notify_schema()
    ensure_pair_schema()

    app.run(host="0.0.0.0", port=5000, debug=True)
