from flask import request
import pickle, base64
def load_state():
    blob = request.args.get("state")
    return pickle.loads(base64.b64decode(blob))   # RCE via pickle; no taint rule covers this sink
