"""Intentionally insecure shipguard test fixture."""
import subprocess


def list_dir(user):
    subprocess.run("ls " + user, shell=True)
