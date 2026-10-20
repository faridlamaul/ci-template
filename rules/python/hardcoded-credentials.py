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
    # ok: shipguard.python.hardcoded-credentials
    token_url = "https://auth.example.com/token"
    # ok: shipguard.python.hardcoded-credentials
    password_prompt = "Enter your password now"
    # ok: shipguard.python.hardcoded-credentials
    secret_name = "db-credentials"
    return db_password, token_header, token_url, password_prompt, secret_name
