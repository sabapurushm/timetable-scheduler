DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS timetables;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL
);

-- All input parameters + solutions stored as JSON text
CREATE TABLE timetables (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    department TEXT,
    shift TEXT,
    status TEXT NOT NULL,         -- DRAFT / UNDER_REVIEW / APPROVED
    input_json TEXT NOT NULL,     -- stores rooms, batches, subjects, etc.
    solution_json TEXT,           -- stores multiple timetable options
    suggestions TEXT,             -- text explaining problems/suggestions
    created_by INTEGER,
    created_at TEXT,
    FOREIGN KEY (created_by) REFERENCES users(id)
);
