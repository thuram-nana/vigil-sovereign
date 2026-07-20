from flask import request
import requests
def proxy():
    url = request.args.get("target")
    return requests.get(url, timeout=5).text
