"""CWE-78 Case 05: Wrapper function indirection (VULNERABLE).

Taint: input() -> run_tool() -> subprocess.check_output(shell=True)
The wrapper obscures the dangerous call from simple grep-based scanners.
"""

import subprocess


def run_tool(tool_name, argument):
    """Generic tool runner -- thin wrapper around subprocess."""
    cmd = f"{tool_name} {argument}"
    return subprocess.check_output(cmd, shell=True)


def main():
    target = input("Enter target: ")
    output = run_tool("nmap", target)
    print(output.decode())


if __name__ == "__main__":
    main()
