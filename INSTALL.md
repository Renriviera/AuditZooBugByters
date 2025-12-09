# AuditZoo Installation Guide

This guide covers installation for **users** who want to use AuditZoo for program analysis.

**For contributors**: See [DEVELOP.md](DEVELOP.md) for development setup.

## Prerequisites

- **Conda** (Miniconda or Anaconda) - [Install here](https://docs.conda.io/en/latest/miniconda.html)
- **Java 11+** (required by Joern)
- **Git**

Check your Java version:
```bash
java -version  # Should be 11 or higher
```

If Java is not installed:
```bash
# Install via conda (recommended)
conda install -c conda-forge openjdk=11
```

## Quick Installation (Recommended)

The easiest way to install AuditZoo:

```bash
# 1. Clone the repository
git clone https://github.com/your-org/auditzoo
cd auditzoo

# 2. Run the installation script
./install.sh

# 3. Activate the environment
conda activate auditzoo

# 4. Verify installation
which joern
python -c "import auditzoo; print('AuditZoo ready!')"
```

The installation script will:
- Create a conda environment named `auditzoo`
- Install all Python dependencies
- Download and install Joern in the conda environment
- Set up environment variables automatically
- Verify the installation

## Manual Installation

If you prefer to install manually or the script doesn't work:

```bash
# 1. Create conda environment
conda create -n auditzoo python=3.10
conda activate auditzoo

# 2. Clone repository
git clone https://github.com/your-org/auditzoo
cd auditzoo

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Install AuditZoo package
pip install .

# 5. Install Joern
mkdir -p $CONDA_PREFIX/opt/joern
cd $CONDA_PREFIX/opt/joern
wget https://github.com/joernio/joern/releases/latest/download/joern-install.sh
chmod +x joern-install.sh
./joern-install.sh --install-dir=$CONDA_PREFIX/opt/joern
cd -

# 6. Set up environment activation
mkdir -p $CONDA_PREFIX/etc/conda/activate.d
cat > $CONDA_PREFIX/etc/conda/activate.d/auditzoo.sh << 'EOF'
#!/bin/bash
export PATH="$CONDA_PREFIX/opt/joern/joern-cli:$PATH"
export AUDITZOO_JOERN_PATH="$CONDA_PREFIX/opt/joern"
EOF
chmod +x $CONDA_PREFIX/etc/conda/activate.d/auditzoo.sh

# 7. Reactivate environment to apply changes
conda deactivate
conda activate auditzoo

# 8. Verify installation
which joern
python -c "import auditzoo; print('Success!')"
```

## What Gets Installed

After installation, your conda environment will contain:

| Component | Location | Description |
|-----------|----------|-------------|
| Python 3.10 | `$CONDA_PREFIX/bin/python` | Python interpreter |
| AuditZoo | `$CONDA_PREFIX/lib/python3.10/site-packages/` | AuditZoo package |
| Joern | `$CONDA_PREFIX/opt/joern/` | Joern CPG framework |
| Dependencies | `$CONDA_PREFIX/lib/` | AutoGen, TreeSitter, etc. |

Environment variables set when activated:
- `CONDA_PREFIX` - Path to conda environment
- `AUDITZOO_JOERN_PATH` - Path to Joern installation

## Using AuditZoo

### Activate Environment

Always activate the conda environment before using AuditZoo:

```bash
conda activate auditzoo
```

### Generate CPG from Source Code

```bash
# Using Joern CLI
cd your_project
joern-parse --language c --output ./project.cpg ./src/

# Or programmatically
python << EOF
from auditzoo.backends.joern.client import JoernClient
import asyncio

async def main():
    client = JoernClient(joern_path="$AUDITZOO_JOERN_PATH")
    await client.create_cpg(
        source_path="./src",
        language="c",
        output_path="./project.cpg"
    )

asyncio.run(main())
EOF
```

### Run Analysis

See [README.md](README.md#basic-usage) for usage examples.

### Deactivate Environment

When done:
```bash
conda deactivate
```

## Troubleshooting

### Conda environment activation doesn't work

```bash
# Initialize conda for your shell
conda init bash  # or zsh, fish, etc.

# Restart your shell or run:
source ~/.bashrc  # or ~/.zshrc
```

### Joern not found after installation

```bash
# Reactivate the environment
conda deactivate
conda activate auditzoo

# Check if Joern is in PATH
which joern
echo $AUDITZOO_JOERN_PATH

# If still not found, manually add to PATH
export PATH="$CONDA_PREFIX/opt/joern/joern-cli:$PATH"
```

### Java version issues

```bash
# Check Java version (must be 11+)
java -version

# If version is too old, install via conda
conda install -c conda-forge openjdk=11

# Verify again
java -version
```

### Permission denied when running install.sh

```bash
# Make script executable
chmod +x install.sh

# Run again
./install.sh
```

### Installation fails on macOS

If you're on macOS and `wget` is not found:

```bash
# Install wget via conda
conda install wget

# Or use curl instead
curl -O https://github.com/joernio/joern/releases/latest/download/joern-install.sh
chmod +x joern-install.sh
./joern-install.sh --install-dir=$CONDA_PREFIX/opt/joern
```

### Python package import errors

```bash
# Ensure you're in the correct environment
conda activate auditzoo

# Reinstall AuditZoo
pip install --force-reinstall .

# Verify
python -c "import auditzoo; print('OK')"
```

## Updating AuditZoo

To update to the latest version:

```bash
# Activate environment
conda activate auditzoo

# Pull latest changes
cd auditzoo
git pull origin main

# Reinstall
pip install --upgrade .

# Verify
python -c "import auditzoo; print(auditzoo.__version__)"
```

## Uninstallation

To completely remove AuditZoo:

```bash
# Remove conda environment (this removes everything)
conda env remove -n auditzoo

# Remove cloned repository (optional)
cd ..
rm -rf auditzoo
```

## Additional Languages (TreeSitter)

For languages not supported by Joern, install TreeSitter grammars:

```bash
conda activate auditzoo

# Install TreeSitter (already included in requirements.txt)
# Install language grammars as needed:

pip install tree-sitter-rust      # For Rust
pip install tree-sitter-ruby       # For Ruby
pip install tree-sitter-go         # For Go (backup)
# ... more as needed
```

Note: TreeSitter support is limited compared to Joern (AST and basic call graph only).

## Getting Help

- Check [README.md](README.md) for usage examples
- See [docs/auditzoo_spec.md](docs/auditzoo_spec.md) for architecture details
- Report issues: https://github.com/your-org/auditzoo/issues

## Next Steps

After installation:

1. Read the [architecture specification](docs/auditzoo_spec.md)
2. Try the examples in [README.md](README.md#basic-usage)
3. Explore the built-in analyses in `auditzoo/analyses/`
4. Write your own custom analysis

Happy analyzing!
