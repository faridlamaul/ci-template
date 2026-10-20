import pickle

import yaml


def bad(blob, text):
    # ruleid: shipguard.python.unsafe-deserialization
    pickle.loads(blob)
    # ruleid: shipguard.python.unsafe-deserialization
    yaml.load(text)
    # ruleid: shipguard.python.unsafe-deserialization
    yaml.load(text, Loader=yaml.Loader)


def good(text):
    # ok: shipguard.python.unsafe-deserialization
    yaml.safe_load(text)
    # ok: shipguard.python.unsafe-deserialization
    yaml.load(text, Loader=yaml.SafeLoader)
