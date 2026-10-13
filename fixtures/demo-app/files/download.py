import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/uploads"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    path = os.path.join(BASE, filename)
    return send_file(path)
