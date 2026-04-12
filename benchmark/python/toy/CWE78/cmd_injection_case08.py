"""CWE-78 Case 08: Safe subprocess with list args (SAFE / TRUE NEGATIVE).

subprocess.run with a list of arguments and shell=False (default)
does not invoke a shell, so metacharacters are not interpreted.
"""

import subprocess
import sys


def main():
    filename = sys.argv[1]
    result = subprocess.run(
        ["cat", filename],
        capture_output=True,
        text=True,
        check=False,
    )
    print(result.stdout)


if __name__ == "__main__":
    main()
