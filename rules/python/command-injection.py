import os
import subprocess


def bad(user, path):
    # ruleid: shipguard.python.command-injection
    subprocess.run("ls " + user, shell=True)
    # ruleid: shipguard.python.command-injection
    subprocess.Popen(f"cat {path}", shell=True)
    # ruleid: shipguard.python.command-injection
    os.system("rm -rf %s" % path)


def good(path):
    # ok: shipguard.python.command-injection
    subprocess.run(["ls", path])
    # ok: shipguard.python.command-injection
    subprocess.run("ls -l", shell=True)
    # ok: shipguard.python.command-injection
    os.system("clear")
