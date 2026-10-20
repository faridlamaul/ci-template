import ast


def bad(expr, code):
    # ruleid: shipguard.python.eval-exec
    eval(expr)
    # ruleid: shipguard.python.eval-exec
    exec(code)


def good(text):
    # ok: shipguard.python.eval-exec
    ast.literal_eval(text)
    # ok: shipguard.python.eval-exec
    eval("1 + 1")
