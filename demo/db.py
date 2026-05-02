"""Mirrors classic SQL injection CVE patterns (e.g. CVE-2019-15224 family).

Weakness description: "Improper neutralization of special elements in SQL"
Vulnerable: user input is interpolated directly into the query string.
"""
import sqlite3

_conn = sqlite3.connect("demo.db", check_same_thread=False)


# VULNERABLE: f-string interpolates raw `user_id` into SQL
def get_user_by_id(user_id):
    cur = _conn.cursor()
    cur.execute(f"SELECT id, name, email FROM users WHERE id = {user_id}")
    row = cur.fetchone()
    return dict(zip(["id", "name", "email"], row)) if row else None


# VULNERABLE: string concatenation lets attacker inject SQL clauses
def search_users(name):
    cur = _conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE name LIKE '%" + name + "%'")
    return [{"id": r[0], "name": r[1]} for r in cur.fetchall()]


# SAFE reference (after fix):
# def get_user_by_id_safe(user_id):
#     cur = _conn.cursor()
#     cur.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
#     ...
