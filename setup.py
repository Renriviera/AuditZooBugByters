"""Setup configuration for AuditZoo."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="auditzoo",
    version="0.1.0",
    author="AuditZoo Contributors",
    description="Pluggable, agent-based program analysis framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/auditzoo",  # Update with actual URL
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
    install_requires=[
        # Core dependencies
        # Note: Add autogen-core when integrating
        # "autogen-core>=0.2.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0",
            "mypy>=1.0",
            "flake8>=6.0",
        ],
        "joern": [
            # Dependencies for Joern backend
        ],
        "lsp": [
            # Dependencies for LSP backend
        ],
        "treesitter": [
            # Dependencies for TreeSitter backend
            # "tree-sitter>=0.20.0",
        ],
    },
)
