from flask import request
def download():
    name = request.args.get("file")
    with open("/var/data/" + name) as fh:
        return fh.read()
