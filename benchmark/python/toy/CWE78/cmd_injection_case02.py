"""CWE-78 Case 02: subprocess.run with shell=True and f-string (VULNERABLE).

Taint: input() -> f-string -> subprocess.run(shell=True)
"""

import subprocess


def search_logs(pattern):
    subprocess.run(f"grep {pattern} /var/log/syslog", shell=True)


def main():
    user_pattern = input("Enter search pattern: ")
    search_logs(user_pattern)


if __name__ == "__main__":
    main()
