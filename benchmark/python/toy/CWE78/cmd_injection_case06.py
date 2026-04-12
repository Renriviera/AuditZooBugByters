"""CWE-78 Case 06: Environment variable source (VULNERABLE).

Taint: os.environ -> string format -> os.system
Environment variables can be attacker-controlled in shared hosting, CI/CD, etc.
"""

import os


def cleanup():
    log_dir = os.environ.get("LOG_DIR", "/var/log/app")
    os.system("rm -rf {}/*".format(log_dir))


if __name__ == "__main__":
    cleanup()
