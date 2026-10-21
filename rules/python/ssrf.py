import httpx
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


def bad_generic_request():
    target = request.args.get("url")
    # ruleid: shipguard.python.ssrf
    requests.request("GET", target)
    # ruleid: shipguard.python.ssrf
    requests.request(method="GET", url=target)
    # ruleid: shipguard.python.ssrf
    requests.request("POST", url=request.form["callback"], data={})
    # ruleid: shipguard.python.ssrf
    httpx.request("GET", request.GET.get("next"))
    # ruleid: shipguard.python.ssrf
    httpx.request(method="GET", url=target)
    # ruleid: shipguard.python.ssrf
    requests.get(url=target)


def good_generic_request():
    method = request.args.get("method")
    # ok: shipguard.python.ssrf
    requests.request(method, "https://api.example.com/items")
    # ok: shipguard.python.ssrf
    requests.request(method=method, url="https://api.example.com/items")
    # ok: shipguard.python.ssrf
    httpx.request("GET", "https://api.example.com/search", params={"q": request.args.get("q")})
    # ok: shipguard.python.ssrf
    requests.request("GET", url="https://api.example.com/x", json={"x": request.form["x"]})
