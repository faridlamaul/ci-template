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


def good_body():
    # ok: shipguard.python.ssrf
    requests.get("https://api.example.com/search", params={"q": request.args.get("q")})
    # ok: shipguard.python.ssrf
    requests.post("https://api.example.com/x", json={"x": request.form["x"]})
