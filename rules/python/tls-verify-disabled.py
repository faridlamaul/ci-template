import ssl

import requests


def bad(url):
    # ruleid: shipguard.python.tls-verify-disabled
    requests.get(url, verify=False)
    # ruleid: shipguard.python.tls-verify-disabled
    ssl._create_unverified_context()


def good(url):
    # ok: shipguard.python.tls-verify-disabled
    requests.get(url, verify=True)
    # ok: shipguard.python.tls-verify-disabled
    requests.get(url, timeout=5)
