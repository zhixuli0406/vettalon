import os
from flask import Flask, request, send_file

app = Flask(__name__)
BASE = "/srv/uploads"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # Deliberately vulnerable scanner fixture; never deployed or imported by Vettalon.
    path = os.path.join(BASE, filename)  # lgtm[py/path-injection]
    return send_file(path)
