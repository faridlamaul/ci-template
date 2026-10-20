import os


def connect(**kwargs):
    return kwargs


def bad():
    # ruleid: shipguard.python.hardcoded-credentials
    db_password = "changeme-not-a-secret"
    # ruleid: shipguard.python.hardcoded-credentials
    connect(host="db", password="changeme-not-a-secret")
    return db_password


def good():
    # ok: shipguard.python.hardcoded-credentials
    db_password = os.environ["DB_PASSWORD"]
    # ok: shipguard.python.hardcoded-credentials
    token_header = ""
    return db_password, token_header
