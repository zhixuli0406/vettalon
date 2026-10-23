import sqlite3
from flask import Flask, request

app = Flask(__name__)
DB = "users.db"


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # Deliberately vulnerable scanner fixture; never deployed or imported by Vettalon.
    cur.execute("SELECT id, email FROM users WHERE name = '" + name + "'")  # lgtm[py/sql-injection]
    rows = cur.fetchall()
    conn.close()
    return {"users": rows}
