import os

from flask import request, send_file
from werkzeug.utils import secure_filename


def bad():
    name = request.args.get("file")
    # ruleid: shipguard.python.path-traversal
    open(os.path.join("/srv/data", name))
    # ruleid: shipguard.python.path-traversal
    return send_file(request.args["path"])


def good():
    name = secure_filename(request.args.get("file"))
    # ok: shipguard.python.path-traversal
    open(os.path.join("/srv/data", name))
    # ok: shipguard.python.path-traversal
    open("/etc/hostname")
