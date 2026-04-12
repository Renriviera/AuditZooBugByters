"""CWE-78 Case 03: Multi-function taint flow (VULNERABLE).

Taint: sys.argv[1] -> build_command() -> execute() -> os.system
The taint crosses two function boundaries.
"""

import os
import sys


def build_command(user_host):
    return "ping -c 4 " + user_host


def execute(cmd):
    os.system(cmd)


def main():
    host = sys.argv[1]
    cmd = build_command(host)
    execute(cmd)


if __name__ == "__main__":
    main()
