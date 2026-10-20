import requests
from flask import request


def bad():
    target = request.args.get("url")
    # ruleid: shipguard.python.ssrf
    requests.get(target)
    # ruleid: shipguard.python.ssrf
    requests.post(request.form["callback"], data={})


def good():
    # ok: shipguard.python.ssrf
    requests.get("https://api.example.com/health")
