"""CWE-78 Case 07: Flask request parameter to os.popen (VULNERABLE).

Taint: request.args["host"] -> string concat -> os.popen
Classic web-application command injection.
"""

import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/dns")
def dns_lookup():
    host = request.args.get("host", "")
    result = os.popen("dig " + host).read()
    return f"<pre>{result}</pre>"


if __name__ == "__main__":
    app.run(debug=True)
