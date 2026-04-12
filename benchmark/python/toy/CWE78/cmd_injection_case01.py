"""CWE-78 Case 01: Direct os.system with user input (VULNERABLE).

Taint: sys.argv[1] -> string concat -> os.system
"""

import os
import sys


def main():
    filename = sys.argv[1]
    os.system("cat " + filename)


if __name__ == "__main__":
    main()
