import hashlib

from Crypto.Cipher import DES


def bad(data, key):
    # ruleid: shipguard.python.weak-crypto
    hashlib.md5(data).hexdigest()
    # ruleid: shipguard.python.weak-crypto
    hashlib.sha1(data)
    # ruleid: shipguard.python.weak-crypto
    DES.new(key, DES.MODE_ECB)


def good(data):
    # ok: shipguard.python.weak-crypto
    hashlib.sha256(data).hexdigest()
    # ok: shipguard.python.weak-crypto
    hashlib.md5(data, usedforsecurity=False)
