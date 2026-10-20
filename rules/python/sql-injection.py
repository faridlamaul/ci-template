import sqlite3


def bad(cur, name):
    # ruleid: shipguard.python.sql-injection
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    # ruleid: shipguard.python.sql-injection
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: shipguard.python.sql-injection
    cur.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: shipguard.python.sql-injection
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")


def good(cur, name):
    # ok: shipguard.python.sql-injection
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    # ok: shipguard.python.sql-injection
    cur.execute("SELECT * FROM users WHERE name = %s", [name])
