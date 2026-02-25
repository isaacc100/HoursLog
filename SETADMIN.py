import sqlite3

with sqlite3.connect('hourslog.db') as conn:
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET is_admin = 1 WHERE username = 'artificial_001';")
    conn.commit()