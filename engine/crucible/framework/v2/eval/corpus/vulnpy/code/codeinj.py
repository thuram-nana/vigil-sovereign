from flask import request
def calc():
    expr = request.args.get("expr")
    return str(eval(expr))
