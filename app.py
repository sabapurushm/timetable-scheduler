from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, json, random, datetime
from werkzeug.security import check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "super-secret-key"  # change in real deployment

DATABASE = 'timetable.db'


# ---------- DB HELPER ----------

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# ---------- AUTH HELPERS ----------

def current_user():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()
        conn.close()
        return user
    return None


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user['role'] != 'ADMIN':
            flash("You do not have permission to access this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return wrapper


# ---------- SCHEDULING LOGIC ----------

def generate_timetable_options(input_data, num_options=3):
    """
    input_data: dict parsed from form
    returns: (options_list, suggestions_text)
    options_list is a list of timetables (each a dict)
    """

    num_days = input_data['num_days']
    slots_per_day = input_data['slots_per_day']
    max_classes_per_day = input_data['max_classes_per_day']

    rooms = input_data['rooms']
    batches = input_data['batches']
    subjects = input_data['subjects']
    special_slots = input_data.get('special_slots', [])

    batch_names = [b['name'] for b in batches]

    options = []
    overall_unscheduled = []

    for option_index in range(num_options):
        # timetable[batch][day][slot] = {subject_code, room, faculty}
        timetable = {}
        room_usage = set()      # (room_name, day, slot)
        faculty_usage = set()   # (faculty_name, day, slot)

        def ensure_cell(batch, day):
            if batch not in timetable:
                timetable[batch] = {}
            if day not in timetable[batch]:
                timetable[batch][day] = {}

        def batch_has_class(batch, day, slot):
            return (
                batch in timetable and
                day in timetable[batch] and
                slot in timetable[batch][day]
            )

        def classes_for_batch_day(batch, day):
            if batch not in timetable or day not in timetable[batch]:
                return 0
            return len(timetable[batch][day])

        # Pre-fill special slots
        for sp in special_slots:
            day = sp['day']
            slot = sp['slot']
            batch = sp['batch']
            room = sp['room']
            subj = sp['subject']
            faculty = sp.get('faculty', 'TBA')

            ensure_cell(batch, day)
            timetable[batch][day][slot] = {
                'subject': subj,
                'room': room,
                'faculty': faculty,
                'special': True
            }
            room_usage.add((room, day, slot))
            faculty_usage.add((faculty, day, slot))

        subjs = subjects[:]
        random.shuffle(subjs)

        unscheduled = []

        for subj in subjs:
            classes_needed = subj['classes_per_week']
            placed = 0

            day_slot_list = [(d, s) for d in range(num_days) for s in range(slots_per_day)]
            random.shuffle(day_slot_list)

            while placed < classes_needed and day_slot_list:
                day, slot = day_slot_list.pop()

                batch = subj['batch']
                faculty = subj['faculty']
                subj_code = subj['code']
                subj_name = subj['name']
                subj_type = subj['type']
                pref_rooms = subj.get('preferred_rooms', [])

                if batch_has_class(batch, day, slot):
                    continue

                if classes_for_batch_day(batch, day) >= max_classes_per_day:
                    continue

                possible_rooms = rooms[:]
                if pref_rooms:
                    possible_rooms = [r for r in rooms if r['name'] in pref_rooms] + \
                                     [r for r in rooms if r['name'] not in pref_rooms]

                chosen_room = None
                for r in possible_rooms:
                    if r['capacity'] < subj['batch_size']:
                        continue
                    if subj_type.lower() == 'lab' and r['type'].lower() != 'lab':
                        continue
                    if (r['name'], day, slot) in room_usage:
                        continue
                    chosen_room = r
                    break

                if not chosen_room:
                    continue

                if (faculty, day, slot) in faculty_usage:
                    continue

                ensure_cell(batch, day)
                timetable[batch][day][slot] = {
                    'subject': f"{subj_code} - {subj_name}",
                    'room': chosen_room['name'],
                    'faculty': faculty,
                    'special': False
                }
                room_usage.add((chosen_room['name'], day, slot))
                faculty_usage.add((faculty, day, slot))
                placed += 1

            if placed < classes_needed:
                unscheduled.append({
                    'subject': subj,
                    'placed': placed,
                    'needed': classes_needed
                })

        option = {
            'timetable': timetable,
            'num_days': num_days,
            'slots_per_day': slots_per_day,
            'batches': batch_names
        }
        options.append(option)
        overall_unscheduled.extend(unscheduled)

    if overall_unscheduled:
        lines = ["Some classes could not be scheduled due to constraints:"]
        for u in overall_unscheduled:
            s = u['subject']
            missing = u['needed'] - u['placed']
            lines.append(
                f"- {s['code']} ({s['name']}) for batch {s['batch']}: {missing} class(es) missing."
            )
        lines.append("")
        lines.append("Suggestions:")
        lines.append("- Increase the maximum number of classes per day for busy batches.")
        lines.append("- Add more rooms or labs with higher capacity.")
        lines.append("- Reduce weekly class count for some low-priority subjects.")
        lines.append("- Relax room type or faculty availability constraints.")
        suggestions_text = "\n".join(lines)
    else:
        suggestions_text = "All classes were scheduled successfully. No conflicts detected."

    return options, suggestions_text


# ---------- HELPER TO FIX JSON KEYS ----------

def normalize_timetable_keys(timetable):
    """
    JSON turns dict keys into strings; convert day/slot keys back to ints.
    timetable: dict[batch][day][slot] -> cell
    """
    new_tt = {}
    for batch, days in timetable.items():
        new_tt[batch] = {}
        for day_key, slots in days.items():
            day = int(day_key) if not isinstance(day_key, int) else day_key
            new_tt[batch][day] = {}
            for slot_key, cell in slots.items():
                slot = int(slot_key) if not isinstance(slot_key, int) else slot_key
                new_tt[batch][day][slot] = cell
    return new_tt


# ---------- ROUTES ----------

@app.route('/')
def index():
    if current_user():
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash("Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials.", "danger")

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    timetables = conn.execute(
        "SELECT * FROM timetables ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, timetables=timetables)


# ----- USER MANAGEMENT (ADMIN ONLY) -----

@app.route('/users')
@admin_required
def list_users():
    user = current_user()
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, role FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return render_template('users.html', user=user, users=users)


@app.route('/users/new', methods=['GET', 'POST'])
@admin_required
def create_user():
    user = current_user()

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role'].strip() or 'COORDINATOR'

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for('create_user'))

        from werkzeug.security import generate_password_hash
        password_hash = generate_password_hash(password)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (username, password_hash, role)
            )
            conn.commit()
            flash("User created successfully.", "success")
            return redirect(url_for('list_users'))
        except sqlite3.IntegrityError:
            flash("Username already exists.", "danger")
        finally:
            conn.close()

    return render_template('new_user.html', user=user)


# ----- TIMETABLE CREATION -----

@app.route('/timetable/new', methods=['GET', 'POST'])
@login_required
def create_timetable():
    user = current_user()

    if request.method == 'POST':
        name = request.form['name'].strip()
        department = request.form['department'].strip()
        shift = request.form['shift'].strip() or "Regular"

        num_days = int(request.form['num_days'])
        slots_per_day = int(request.form['slots_per_day'])
        max_classes_per_day = int(request.form['max_classes_per_day'])

        # Rooms: name,capacity,type
        rooms_raw = request.form['rooms'].strip().splitlines()
        rooms = []
        for line in rooms_raw:
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 3:
                continue
            rooms.append({
                'name': parts[0],
                'capacity': int(parts[1]),
                'type': parts[2]
            })

        # Batches: name,size
        batches_raw = request.form['batches'].strip().splitlines()
        batches = []
        for line in batches_raw:
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 2:
                continue
            batches.append({
                'name': parts[0],
                'size': int(parts[1])
            })

        # Subjects: code,name,batch,classes_per_week,type,faculty
        subs_raw = request.form['subjects'].strip().splitlines()
        subjects = []
        for line in subs_raw:
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 6:
                continue
            code, sname, batch, cpw, stype, faculty = parts[:6]
            bsize = next((b['size'] for b in batches if b['name'] == batch), 0)
            subjects.append({
                'code': code,
                'name': sname,
                'batch': batch,
                'batch_size': bsize,
                'classes_per_week': int(cpw),
                'type': stype,
                'faculty': faculty,
                'preferred_rooms': []
            })

        # Special slots: day,slot,batch,subject,room,faculty
        specials_raw = request.form['special_slots'].strip().splitlines()
        special_slots = []
        for line in specials_raw:
            if not line.strip():
                continue
            parts = [p.strip() for p in line.split(',')]
            if len(parts) < 5:
                continue
            day, slot, batch, subj, room = parts[:5]
            faculty = parts[5] if len(parts) > 5 else "TBA"
            special_slots.append({
                'day': int(day),
                'slot': int(slot),
                'batch': batch,
                'subject': subj,
                'room': room,
                'faculty': faculty
            })

        input_data = {
            'num_days': num_days,
            'slots_per_day': slots_per_day,
            'max_classes_per_day': max_classes_per_day,
            'rooms': rooms,
            'batches': batches,
            'subjects': subjects,
            'special_slots': special_slots
        }

        options, suggestions_text = generate_timetable_options(input_data, num_options=3)

        conn = get_db()
        conn.execute(
            """
            INSERT INTO timetables
            (name, department, shift, status, input_json, solution_json, suggestions, created_by, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                department,
                shift,
                'DRAFT',
                json.dumps(input_data),
                json.dumps(options),
                suggestions_text,
                user['id'],
                datetime.datetime.now().isoformat(timespec='seconds')
            )
        )
        conn.commit()
        conn.close()

        flash("Timetable generated (DRAFT).", "success")
        return redirect(url_for('dashboard'))

    return render_template('create_timetable.html', user=user)


# ----- TIMETABLE VIEW / STATUS / DELETE -----

@app.route('/timetable/<int:timetable_id>')
@login_required
def view_timetable(timetable_id):
    user = current_user()
    conn = get_db()
    t = conn.execute(
        "SELECT * FROM timetables WHERE id = ?",
        (timetable_id,)
    ).fetchone()
    conn.close()
    if not t:
        flash("Timetable not found.", "danger")
        return redirect(url_for('dashboard'))

    input_data = json.loads(t['input_json'])
    options = json.loads(t['solution_json']) if t['solution_json'] else []
    suggestions = t['suggestions']

    try:
        option_index = int(request.args.get('option', 0) or 0)
    except ValueError:
        option_index = 0

    current_option = None
    if options:
        option_index = max(0, min(option_index, len(options) - 1))
        current_option = options[option_index]

        # 🔥 normalize JSON-loaded timetable keys
        current_option['timetable'] = normalize_timetable_keys(current_option['timetable'])

    return render_template(
        'view_timetable.html',
        user=user,
        t=t,
        input_data=input_data,
        options=options,
        current_option=current_option,
        option_index=option_index,
        suggestions=suggestions
    )


@app.route('/timetable/<int:timetable_id>/status/<new_status>', methods=['POST'])
@login_required
def change_status(timetable_id, new_status):
    if new_status not in ['DRAFT', 'UNDER_REVIEW', 'APPROVED']:
        flash("Invalid status.", "danger")
        return redirect(url_for('dashboard'))

    conn = get_db()
    conn.execute(
        "UPDATE timetables SET status = ? WHERE id = ?",
        (new_status, timetable_id)
    )
    conn.commit()
    conn.close()

    flash(f"Timetable status changed to {new_status}.", "success")
    return redirect(url_for('view_timetable', timetable_id=timetable_id))


@app.route('/timetable/<int:timetable_id>/delete', methods=['POST'])
@login_required
def delete_timetable(timetable_id):
    conn = get_db()
    conn.execute("DELETE FROM timetables WHERE id = ?", (timetable_id,))
    conn.commit()
    conn.close()

    flash("Timetable deleted successfully.", "success")
    return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.run()

