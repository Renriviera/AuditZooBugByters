"""CWE-78 Case 04: Sanitized with shlex.quote (SAFE / TRUE NEGATIVE).

shlex.quote properly escapes shell metacharacters, neutralizing injection.
"""

import os
import shlex
import sys


def main():
    filename = sys.argv[1]
    safe_filename = shlex.quote(filename)
    os.system("cat " + safe_filename)


if __name__ == "__main__":
    main()
