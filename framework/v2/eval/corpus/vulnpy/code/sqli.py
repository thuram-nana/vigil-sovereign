from flask import request
import sqlite3
def search(cur: sqlite3.Cursor):
    term = request.args.get("q")
    cur.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'")
    return cur.fetchall()
