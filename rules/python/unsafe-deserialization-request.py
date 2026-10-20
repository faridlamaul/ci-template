import json
import pickle

import yaml
from flask import request


def bad():
    # ruleid: shipguard.python.unsafe-deserialization-request
    pickle.loads(request.data)
    body = request.get_data()
    # ruleid: shipguard.python.unsafe-deserialization-request
    yaml.load(body, Loader=yaml.Loader)


def good():
    # ok: shipguard.python.unsafe-deserialization-request
    json.loads(request.data)
    # ok: shipguard.python.unsafe-deserialization-request
    yaml.safe_load(request.data)
    with open("model.pkl", "rb") as f:
        # ok: shipguard.python.unsafe-deserialization-request
        return pickle.load(f)
