
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
import os
import sqlite3
from datetime import datetime, date
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "roomconnect-development-key")

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "roomconnect.db")


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_columns(conn, table):
    return [
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    ]


def add_column_if_missing(conn, table, column, definition):
    if column not in get_columns(conn, table):
        conn.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


# ==========================================
# DATABASE INITIALIZATION
# ==========================================

def init_db():
    conn = get_db_connection()

    # USERS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # BLOCKS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_name TEXT UNIQUE NOT NULL,
            description TEXT,
            building_number TEXT
        )
    """)

    # ROOMS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_number TEXT NOT NULL,
            block_id INTEGER NOT NULL,
            capacity INTEGER NOT NULL DEFAULT 0,
            room_type TEXT DEFAULT 'Classroom',
            FOREIGN KEY (block_id) REFERENCES blocks(id),
            UNIQUE(room_number, block_id)
        )
    """)

    # BOOKING REQUESTS
    conn.execute("""
        CREATE TABLE IF NOT EXISTS booking_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            room_id INTEGER,
            purpose TEXT,
            booking_date TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (room_id) REFERENCES rooms(id)
        )
    """)

    # SAFE MIGRATIONS FOR EXISTING DATABASES

    add_column_if_missing(conn, "blocks", "building_number", "TEXT")
    add_column_if_missing(conn, "blocks", "description", "TEXT")

    add_column_if_missing(conn, "rooms", "capacity", "INTEGER DEFAULT 0")
    add_column_if_missing(conn, "rooms", "room_type", "TEXT DEFAULT 'Classroom'")
    add_column_if_missing(conn, "rooms", "block_id", "INTEGER")

    add_column_if_missing(conn, "users", "section", "TEXT")
    add_column_if_missing(conn, "users", "department", "TEXT")

    add_column_if_missing(conn, "booking_requests", "purpose", "TEXT")
    add_column_if_missing(conn, "booking_requests", "booking_date", "TEXT")
    add_column_if_missing(conn, "booking_requests", "start_time", "TEXT")
    add_column_if_missing(conn, "booking_requests", "end_time", "TEXT")
    add_column_if_missing(conn, "booking_requests", "status", "TEXT DEFAULT 'Pending'")
    add_column_if_missing(conn, "booking_requests", "created_at", "TEXT")

    # TIMETABLE / CLASS SCHEDULE
    conn.execute("""
        CREATE TABLE IF NOT EXISTS class_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            section TEXT NOT NULL,
            department TEXT,
            day TEXT NOT NULL,
            subject TEXT NOT NULL,
            faculty_id INTEGER,
            room_id INTEGER,
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            academic_session TEXT,
            FOREIGN KEY (faculty_id) REFERENCES users(id),
            FOREIGN KEY (room_id) REFERENCES rooms(id)
        )
    """)

    # DEMO USERS: created only if they do not already exist.
    demo_users = [
        ("Admin", "admin@roomconnect.com", "Admin123", "admin"),
        ("Faculty", "faculty@roomconnect.com", "Faculty123", "faculty"),
        ("Student", "student@roomconnect.com", "Student123", "student")
    ]

    for name, email, password, role in demo_users:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        if not existing:
            conn.execute("""
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                generate_password_hash(password),
                role
            ))

    conn.commit()
    conn.close()


# ==========================================
# AUTHENTICATION AND ACCESS CONTROL
# ==========================================

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def role_required(role):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))

            if session.get("role") != role:
                flash("You are not authorized to access that page.", "error")
                return redirect(url_for("dashboard"))

            return function(*args, **kwargs)
        return wrapper
    return decorator


admin_required = role_required("admin")
faculty_required = role_required("faculty")
student_required = role_required("student")


# ==========================================
# COMMON ROUTES
# ==========================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip().lower()

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE LOWER(email) = ?", (email,)
        ).fetchone()
        conn.close()

        valid = False
        if user and user["role"] == role:
            try:
                valid = check_password_hash(user["password"], password)
            except (ValueError, TypeError):
                valid = False

        if valid:
            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["email"] = user["email"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Invalid email, password or role.", "error")

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():

    role = session.get("role")

    if role == "admin":
        return redirect(url_for("admin_dashboard"))

    if role == "faculty":
        return redirect(url_for("faculty_dashboard"))

    if role == "student":
        return redirect(url_for("student_dashboard"))

    session.clear()
    return redirect(url_for("login"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==========================================
# ADMIN DASHBOARD
# ==========================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():

    conn = get_db_connection()

    total_blocks = conn.execute(
        "SELECT COUNT(*) FROM blocks"
    ).fetchone()[0]

    total_rooms = conn.execute(
        "SELECT COUNT(*) FROM rooms"
    ).fetchone()[0]

    total_users = conn.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    pending_bookings = conn.execute("""
        SELECT COUNT(*) FROM booking_requests
        WHERE status = 'Pending'
    """).fetchone()[0]

    conn.close()

    return render_template(
        "admin_dashboard.html",
        total_blocks=total_blocks,
        total_rooms=total_rooms,
        total_users=total_users,
        pending_bookings=pending_bookings
    )


# ==========================================
# ADMIN - MANAGE BLOCKS
# ==========================================

@app.route("/admin/blocks", methods=["GET", "POST"])
@admin_required
def manage_blocks():

    conn = get_db_connection()

    if request.method == "POST":
        building_number = request.form.get("building_number", "").strip()
        block_name = request.form.get("building_name", "").strip()
        description = request.form.get("description", "").strip()

        if not building_number or not block_name:
            flash("Building number and building name are required.", "error")
        else:
            try:
                conn.execute("""
                    INSERT INTO blocks (building_number, block_name, description)
                    VALUES (?, ?, ?)
                """, (building_number, block_name, description))
                conn.commit()
                flash("Academic block added successfully.", "success")
            except sqlite3.IntegrityError:
                flash("A building with this name already exists.", "error")

        conn.close()
        return redirect(url_for("manage_blocks"))

    blocks = conn.execute("""
        SELECT
            b.*,
            (SELECT COUNT(*) FROM rooms r WHERE r.block_id = b.id)
            AS room_count
        FROM blocks b
        ORDER BY b.id DESC
    """).fetchall()

    conn.close()

    return render_template("admin_blocks.html", blocks=blocks)


@app.route("/admin/blocks/delete/<int:block_id>", methods=["POST"])
@admin_required
def delete_block(block_id):

    conn = get_db_connection()

    room_count = conn.execute("""
        SELECT COUNT(*) FROM rooms WHERE block_id = ?
    """, (block_id,)).fetchone()[0]

    if room_count > 0:
        flash("Cannot delete a block that still contains rooms.", "error")
    else:
        conn.execute("DELETE FROM blocks WHERE id = ?", (block_id,))
        conn.commit()
        flash("Block deleted successfully.", "success")

    conn.close()
    return redirect(url_for("manage_blocks"))


# ==========================================
# ADMIN - MANAGE ROOMS
# ==========================================

@app.route("/admin/rooms", methods=["GET", "POST"])
@admin_required
def manage_rooms():

    conn = get_db_connection()

    if request.method == "POST":
        room_number = request.form.get("room_number", "").strip()
        capacity = request.form.get("capacity", "0").strip()
        room_type = request.form.get("room_type", "Classroom").strip()
        block_id = request.form.get("block_id", "").strip()

        try:
            capacity = int(capacity)
        except ValueError:
            capacity = -1

        block = conn.execute(
            "SELECT id FROM blocks WHERE id = ?", (block_id,)
        ).fetchone()

        if not room_number or not block:
            flash("Please enter room details and select a valid block.", "error")
        elif capacity < 1:
            flash("Please enter a valid room capacity.", "error")
        else:
            try:
                conn.execute("""
                    INSERT INTO rooms (room_number, capacity, room_type, block_id)
                    VALUES (?, ?, ?, ?)
                """, (room_number, capacity, room_type, block_id))
                conn.commit()
                flash("Room added successfully.", "success")
            except sqlite3.IntegrityError:
                flash("That room already exists in this block.", "error")

        conn.close()
        return redirect(url_for("manage_rooms"))

    rooms = conn.execute("""
        SELECT r.*, b.block_name AS block_name, b.building_number
        FROM rooms r
        LEFT JOIN blocks b ON r.block_id = b.id
        ORDER BY r.id DESC
    """).fetchall()

    blocks = conn.execute(
        "SELECT * FROM blocks ORDER BY building_number"
    ).fetchall()

    conn.close()

    return render_template("admin_rooms.html", rooms=rooms, blocks=blocks)


@app.route("/admin/rooms/delete/<int:room_id>", methods=["POST"])
@admin_required
def delete_room(room_id):

    conn = get_db_connection()

    booking_count = conn.execute("""
        SELECT COUNT(*) FROM booking_requests
        WHERE room_id = ?
    """, (room_id,)).fetchone()[0]

    schedule_count = conn.execute("""
        SELECT COUNT(*) FROM class_schedule
        WHERE room_id = ?
    """, (room_id,)).fetchone()[0]

    if booking_count or schedule_count:
        flash("This room is linked to bookings or timetable entries and cannot be deleted.", "error")
    else:
        conn.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
        conn.commit()
        flash("Room deleted successfully.", "success")

    conn.close()
    return redirect(url_for("manage_rooms"))


# ==========================================
# ADMIN - MANAGE USERS
# ==========================================

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def manage_users():

    conn = get_db_connection()

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "").strip().lower()
        section = request.form.get("section", "").strip()
        department = request.form.get("department", "").strip()

        if not name or not email or not password or role not in (
            "admin", "faculty", "student"
        ):
            flash("Please fill in all required user details.", "error")

        else:
            try:
                conn.execute("""
                    INSERT INTO users
                    (name, email, password, role, section, department)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    name,
                    email,
                    generate_password_hash(password),
                    role,
                    section,
                    department
                ))

                conn.commit()
                flash("User added successfully.", "success")

            except sqlite3.IntegrityError:
                flash("An account with this email already exists.", "error")

        conn.close()
        return redirect(url_for("manage_users"))

    users = conn.execute("""
        SELECT * FROM users ORDER BY id DESC
    """).fetchall()

    conn.close()

    return render_template("admin_users.html", users=users)


@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):

    if user_id == session.get("user_id"):
        flash("You cannot delete your own active account.", "error")
        return redirect(url_for("manage_users"))

    conn = get_db_connection()

    booking_count = conn.execute("""
        SELECT COUNT(*) FROM booking_requests WHERE user_id = ?
    """, (user_id,)).fetchone()[0]

    schedule_count = conn.execute("""
        SELECT COUNT(*) FROM class_schedule WHERE faculty_id = ?
    """, (user_id,)).fetchone()[0]

    if booking_count or schedule_count:
        flash("This user has linked bookings or timetable entries and cannot be deleted.", "error")
    else:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash("User deleted successfully.", "success")

    conn.close()
    return redirect(url_for("manage_users"))


# ==========================================
# BOOKING HELPERS
# ==========================================

def has_room_conflict(conn, room_id, booking_date, start_time, end_time,
                      exclude_booking_id=None):

    query = """
        SELECT id FROM booking_requests
        WHERE room_id = ?
        AND booking_date = ?
        AND status = 'Approved'
        AND start_time < ?
        AND end_time > ?
    """

    params = [room_id, booking_date, end_time, start_time]

    if exclude_booking_id is not None:
        query += " AND id != ?"
        params.append(exclude_booking_id)

    booking_conflict = conn.execute(query, params).fetchone()

    if booking_conflict:
        return True

    schedule_conflict = conn.execute("""
        SELECT id FROM class_schedule
        WHERE room_id = ?
        AND day = ?
        AND start_time < ?
        AND end_time > ?
    """, (
        room_id,
        datetime.strptime(booking_date, "%Y-%m-%d").strftime("%A"),
        end_time,
        start_time
    )).fetchone()

    return schedule_conflict is not None


def get_room_list(conn, building_id=None):
    query = """
        SELECT
            r.*,
            b.building_number,
            b.block_name AS block_name
        FROM rooms r
        LEFT JOIN blocks b ON r.block_id = b.id
    """

    params = []

    if building_id:
        query += " WHERE r.block_id = ?"
        params.append(building_id)

    query += " ORDER BY b.building_number, r.room_number"

    return conn.execute(query, params).fetchall()


def room_is_available(conn, room_id, booking_date, start_time, end_time):
    if not booking_date or not start_time or not end_time:
        return None

    try:
        selected_date = datetime.strptime(booking_date, "%Y-%m-%d").date()
        datetime.strptime(start_time, "%H:%M")
        datetime.strptime(end_time, "%H:%M")
    except ValueError:
        return None

    if start_time >= end_time:
        return None

    return not has_room_conflict(
        conn, room_id, booking_date, start_time, end_time
    )


# ==========================================
# FACULTY DASHBOARD
# ==========================================

@app.route("/faculty/dashboard")
@faculty_required
def faculty_dashboard():

    conn = get_db_connection()
    faculty_id = session["user_id"]

    total_bookings = conn.execute("""
        SELECT COUNT(*) FROM booking_requests WHERE user_id = ?
    """, (faculty_id,)).fetchone()[0]

    pending_bookings = conn.execute("""
        SELECT COUNT(*) FROM booking_requests
        WHERE user_id = ? AND status = 'Pending'
    """, (faculty_id,)).fetchone()[0]

    approved_bookings = conn.execute("""
        SELECT COUNT(*) FROM booking_requests
        WHERE user_id = ? AND status = 'Approved'
    """, (faculty_id,)).fetchone()[0]

    conn.close()

    return render_template(
        "faculty_dashboard.html",
        total_bookings=total_bookings,
        pending_bookings=pending_bookings,
        approved_bookings=approved_bookings
    )


# ==========================================
# FACULTY - BOOK A ROOM
# ==========================================

@app.route("/faculty/book-room", methods=["GET", "POST"])
@faculty_required
def faculty_book_room():

    conn = get_db_connection()

    if request.method == "POST":

        room_id = request.form.get("room_id", "").strip()
        purpose = request.form.get("purpose", "").strip()
        booking_date = request.form.get("booking_date", "").strip()
        start_time = request.form.get("start_time", "").strip()
        end_time = request.form.get("end_time", "").strip()
        description = request.form.get("description", "").strip()

        if description:
            purpose = f"{purpose} - {description}"

        room = conn.execute(
            "SELECT id FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()

        valid_date = valid_time = False
        try:
            selected_date = datetime.strptime(booking_date, "%Y-%m-%d").date()
            valid_date = selected_date >= date.today()
        except ValueError:
            pass

        try:
            datetime.strptime(start_time, "%H:%M")
            datetime.strptime(end_time, "%H:%M")
            valid_time = start_time < end_time
        except ValueError:
            pass

        if not room or not purpose or not booking_date:
            flash("Please complete all required booking details.", "error")

        elif not valid_date:
            flash("Please select a valid current or future date.", "error")

        elif not valid_time:
            flash("Enter valid times; end time must be later than start time.", "error")

        elif has_room_conflict(conn, room_id, booking_date, start_time, end_time):
            flash("This room is already occupied during that time.", "error")

        else:
            conn.execute("""
                INSERT INTO booking_requests
                (user_id, room_id, purpose, booking_date,
                 start_time, end_time, status)
                VALUES (?, ?, ?, ?, ?, ?, 'Pending')
            """, (session["user_id"], room_id, purpose,
                  booking_date, start_time, end_time))

            conn.commit()
            conn.close()
            flash("Your booking request has been submitted.", "success")
            return redirect(url_for("faculty_my_bookings"))

    blocks = conn.execute(
        "SELECT * FROM blocks ORDER BY building_number"
    ).fetchall()

    rooms = get_room_list(conn)

    conn.close()

    return render_template("faculty_book_room.html", blocks=blocks, rooms=rooms)


# ==========================================
# FACULTY - MY BOOKINGS
# ==========================================

@app.route("/faculty/my-bookings")
@faculty_required
def faculty_my_bookings():

    conn = get_db_connection()

    bookings = conn.execute("""
        SELECT
            br.*,
            r.room_number,
            b.building_number,
            b.block_name AS block_name
        FROM booking_requests br
        LEFT JOIN rooms r ON br.room_id = r.id
        LEFT JOIN blocks b ON r.block_id = b.id
        WHERE br.user_id = ?
        ORDER BY br.booking_date DESC, br.start_time DESC
    """, (session["user_id"],)).fetchall()

    conn.close()

    return render_template(
        "faculty_my_bookings.html",
        bookings=bookings
    )


# ==========================================
# FACULTY - MY TIMETABLE
# ==========================================

@app.route("/faculty/timetable")
@faculty_required
def faculty_timetable():

    conn = get_db_connection()

    timetable = conn.execute("""
        SELECT
            cs.*,
            r.room_number,
            b.building_number,
            b.block_name AS block_name
        FROM class_schedule cs
        LEFT JOIN rooms r ON cs.room_id = r.id
        LEFT JOIN blocks b ON r.block_id = b.id
        WHERE cs.faculty_id = ?
        ORDER BY
            CASE cs.day
                WHEN 'Monday' THEN 1
                WHEN 'Tuesday' THEN 2
                WHEN 'Wednesday' THEN 3
                WHEN 'Thursday' THEN 4
                WHEN 'Friday' THEN 5
                WHEN 'Saturday' THEN 6
                WHEN 'Sunday' THEN 7
                ELSE 8
            END,
            cs.start_time
    """, (session["user_id"],)).fetchall()

    conn.close()

    return render_template(
        "faculty_timetable.html",
        timetable=timetable
    )


# ==========================================
# FACULTY - ROOM AVAILABILITY
# ==========================================

@app.route("/faculty/room-availability")
@faculty_required
def faculty_room_availability():

    conn = get_db_connection()

    building_id = request.args.get("building_id", "").strip()
    booking_date = request.args.get("booking_date", "").strip()
    start_time = request.args.get("start_time", "").strip()
    end_time = request.args.get("end_time", "").strip()

    blocks = conn.execute("""
        SELECT * FROM blocks ORDER BY building_number
    """).fetchall()

    rooms = get_room_list(conn, building_id)

    filtered_rooms = []

    for room in rooms:
        room_data = dict(room)

        room_data["available"] = room_is_available(
            conn,
            room["id"],
            booking_date,
            start_time,
            end_time
        )

        filtered_rooms.append(room_data)

    conn.close()

    return render_template(
        "faculty_room_availability.html",
        blocks=blocks,
        rooms=filtered_rooms,
        selected_building=building_id,
        selected_date=booking_date,
        selected_start=start_time,
        selected_end=end_time
    )


# ==========================================
# ADMIN - BOOKING REQUESTS
# ==========================================

@app.route("/admin/booking-requests", methods=["GET", "POST"])
@admin_required
def booking_requests():

    conn = get_db_connection()

    if request.method == "POST":

        booking_id = request.form.get(
            "booking_id",
            request.form.get("id", "")
        )

        action = request.form.get(
            "status",
            request.form.get("action", "")
        ).strip().capitalize()

        if action not in ("Approved", "Rejected"):
            flash("Invalid booking action.", "error")

        else:
            booking = conn.execute("""
                SELECT * FROM booking_requests WHERE id = ?
            """, (booking_id,)).fetchone()

            if not booking:
                flash("Booking request not found.", "error")

            elif booking["status"] != "Pending":
                flash("This booking request has already been processed.", "error")

            elif action == "Approved" and has_room_conflict(
                conn,
                booking["room_id"],
                booking["booking_date"],
                booking["start_time"],
                booking["end_time"],
                exclude_booking_id=booking["id"]
            ):
                flash("Cannot approve: this room is already occupied.", "error")

            else:
                conn.execute("""
                    UPDATE booking_requests
                    SET status = ?
                    WHERE id = ?
                """, (action, booking_id))

                conn.commit()
                flash(f"Booking request {action.lower()} successfully.", "success")

        conn.close()
        return redirect(url_for("booking_requests"))

    bookings = conn.execute("""
        SELECT
            br.*,
            u.name AS faculty_name,
            u.email AS faculty_email,
            r.room_number,
            b.building_number,
            b.block_name AS block_name
        FROM booking_requests br
        LEFT JOIN users u ON br.user_id = u.id
        LEFT JOIN rooms r ON br.room_id = r.id
        LEFT JOIN blocks b ON r.block_id = b.id
        ORDER BY
            CASE br.status
                WHEN 'Pending' THEN 1
                WHEN 'Approved' THEN 2
                ELSE 3
            END,
            br.created_at DESC
    """).fetchall()

    conn.close()

    return render_template(
        "booking_requests.html",
        bookings=bookings
    )


# ==========================================
# STUDENT DASHBOARD
# ==========================================

@app.route("/student/dashboard")
@student_required
def student_dashboard():

    conn = get_db_connection()

    student = conn.execute("""
        SELECT section, department
        FROM users WHERE id = ?
    """, (session["user_id"],)).fetchone()

    section = student["section"] if student else None
    department = student["department"] if student else None

    conn.close()

    return render_template(
        "student_dashboard.html",
        section=section,
        department=department
    )


# ==========================================
# STUDENT - TIMETABLE
# ==========================================

@app.route("/student/timetable")
@student_required
def student_timetable():

    conn = get_db_connection()

    student = conn.execute("""
        SELECT section, department
        FROM users WHERE id = ?
    """, (session["user_id"],)).fetchone()

    section = student["section"] if student else None
    department = student["department"] if student else None

    timetable = []

    if section:
        timetable = conn.execute("""
            SELECT
                cs.*,
                u.name AS faculty_name,
                r.room_number,
                b.building_number,
                b.block_name AS block_name
            FROM class_schedule cs
            LEFT JOIN users u ON cs.faculty_id = u.id
            LEFT JOIN rooms r ON cs.room_id = r.id
            LEFT JOIN blocks b ON r.block_id = b.id
            WHERE cs.section = ?
            ORDER BY
                CASE cs.day
                    WHEN 'Monday' THEN 1
                    WHEN 'Tuesday' THEN 2
                    WHEN 'Wednesday' THEN 3
                    WHEN 'Thursday' THEN 4
                    WHEN 'Friday' THEN 5
                    WHEN 'Saturday' THEN 6
                    WHEN 'Sunday' THEN 7
                    ELSE 8
                END,
                cs.start_time
        """, (section,)).fetchall()

    conn.close()

    return render_template(
        "student_timetable.html",
        timetable=timetable,
        section=section,
        department=department,
        academic_session="Current Session"
    )


# ==========================================
# STUDENT - ROOM AVAILABILITY
# ==========================================

@app.route("/student/room-availability")
@student_required
def student_room_availability():

    conn = get_db_connection()

    building_id = request.args.get("building_id", "").strip()
    booking_date = request.args.get("booking_date", "").strip()
    start_time = request.args.get("start_time", "").strip()
    end_time = request.args.get("end_time", "").strip()

    blocks = conn.execute("""
        SELECT * FROM blocks ORDER BY building_number
    """).fetchall()

    rooms = get_room_list(conn, building_id)

    filtered_rooms = []

    for room in rooms:
        room_data = dict(room)

        room_data["available"] = room_is_available(
            conn,
            room["id"],
            booking_date,
            start_time,
            end_time
        )

        filtered_rooms.append(room_data)

    conn.close()

    return render_template(
        "student_room_availability.html",
        blocks=blocks,
        rooms=filtered_rooms,
        selected_building=building_id,
        selected_date=booking_date,
        selected_start=start_time,
        selected_end=end_time
    )


# ==========================================
# ADMIN - MANAGE TIMETABLE
# ==========================================

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday",
        "Friday", "Saturday", "Sunday"]


@app.route("/admin/schedule", methods=["GET", "POST"])
@admin_required
def manage_schedule():

    conn = get_db_connection()

    if request.method == "POST":
        section = request.form.get("section", "").strip()
        department = request.form.get("department", "").strip()
        day = request.form.get("day", "").strip()
        subject = request.form.get("subject", "").strip()
        faculty_id = request.form.get("faculty_id", "").strip()
        room_id = request.form.get("room_id", "").strip()
        start_time = request.form.get("start_time", "").strip()
        end_time = request.form.get("end_time", "").strip()

        room = conn.execute("SELECT id FROM rooms WHERE id = ?", (room_id,)).fetchone()
        faculty = conn.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'faculty'", (faculty_id,)
        ).fetchone()

        times_ok = False
        try:
            datetime.strptime(start_time, "%H:%M")
            datetime.strptime(end_time, "%H:%M")
            times_ok = start_time < end_time
        except ValueError:
            pass

        if not section or not subject or day not in DAYS or not room or not faculty:
            flash("Please fill in all timetable details correctly.", "error")
        elif not times_ok:
            flash("End time must be later than start time.", "error")
        else:
            clash = conn.execute("""
                SELECT id FROM class_schedule
                WHERE room_id = ? AND day = ?
                AND start_time < ? AND end_time > ?
            """, (room_id, day, end_time, start_time)).fetchone()

            if clash:
                flash("That room already has a class at this time.", "error")
            else:
                conn.execute("""
                    INSERT INTO class_schedule
                    (section, department, day, subject, faculty_id, room_id,
                     start_time, end_time, academic_session)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Current Session')
                """, (section, department, day, subject, faculty_id,
                      room_id, start_time, end_time))
                conn.commit()
                flash("Timetable entry added.", "success")

        conn.close()
        return redirect(url_for("manage_schedule"))

    entries = conn.execute("""
        SELECT cs.*, u.name AS faculty_name, r.room_number,
               b.building_number
        FROM class_schedule cs
        LEFT JOIN users u ON cs.faculty_id = u.id
        LEFT JOIN rooms r ON cs.room_id = r.id
        LEFT JOIN blocks b ON r.block_id = b.id
        ORDER BY cs.section, cs.start_time
    """).fetchall()

    faculty = conn.execute(
        "SELECT id, name FROM users WHERE role = 'faculty' ORDER BY name"
    ).fetchall()
    rooms = get_room_list(conn)

    conn.close()

    return render_template("admin_schedule.html", entries=entries,
                           faculty=faculty, rooms=rooms, days=DAYS)


@app.route("/admin/schedule/delete/<int:entry_id>", methods=["POST"])
@admin_required
def delete_schedule(entry_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM class_schedule WHERE id = ?", (entry_id,))
    conn.commit()
    conn.close()
    flash("Timetable entry deleted.", "success")
    return redirect(url_for("manage_schedule"))


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def page_not_found(error):
    return "Page not found.", 404


# ==========================================
# START APPLICATION
# ==========================================

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
