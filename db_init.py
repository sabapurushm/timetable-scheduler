import sqlite3
from werkzeug.security import generate_password_hash

# Run this once to create DB and admin user
def init_db():
    conn = sqlite3.connect('timetable.db')
    with open('schema.sql', 'r') as f:
        conn.executescript(f.read())

    # Create default admin user
    username = 'admin'
    password = 'admin123'
    role = 'ADMIN'
    password_hash = generate_password_hash(password)

    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        (username, password_hash, role)
    )
    conn.commit()
    conn.close()
    print("Database initialized. Admin login: admin / admin123")

if __name__ == "__main__":
    init_db()
