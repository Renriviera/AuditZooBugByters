#!/bin/bash
# AuditZoo Development Environment Installation Script
# This script sets up a complete development environment for contributing to AuditZoo

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== AuditZoo Development Environment Setup ===${NC}"
echo ""

# Check if conda is installed
if ! command -v conda &> /dev/null; then
    echo -e "${RED}Error: Conda is not installed${NC}"
    echo "Please install Miniconda or Anaconda first:"
    echo "  https://docs.conda.io/en/latest/miniconda.html"
    exit 1
fi

# Check if git is configured
if ! git config user.name &> /dev/null || ! git config user.email &> /dev/null; then
    echo -e "${YELLOW}Warning: Git user is not configured${NC}"
    echo "Please configure git:"
    echo "  git config --global user.name \"Your Name\""
    echo "  git config --global user.email \"your.email@example.com\""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Environment name for development
ENV_NAME="auditzoo-dev"
PYTHON_VERSION="3.10"

# Check if environment already exists
if conda env list | grep -q "^${ENV_NAME} "; then
    echo -e "${YELLOW}Conda environment '${ENV_NAME}' already exists${NC}"
    read -p "Do you want to remove and recreate it? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing environment..."
        conda env remove -n ${ENV_NAME} -y
    else
        echo "Exiting. Please remove the environment manually or use a different name."
        exit 1
    fi
fi

# Create conda environment with Java
echo -e "${GREEN}Creating development conda environment '${ENV_NAME}' with Python ${PYTHON_VERSION} and Java 17...${NC}"
conda create -n ${ENV_NAME} -c conda-forge python=${PYTHON_VERSION} openjdk=17 -y

# Activate environment
echo -e "${GREEN}Activating conda environment...${NC}"
eval "$(conda shell.bash hook)"
conda activate ${ENV_NAME}

# Verify Java installation
JAVA_VERSION=$(java -version 2>&1 | head -n 1 | awk -F '"' '{print $2}')
echo -e "${GREEN}✓ Java version $JAVA_VERSION installed in conda environment${NC}"

# Install Python dependencies
echo -e "${GREEN}Installing Python dependencies...${NC}"
echo -e "${BLUE}  - Installing core dependencies${NC}"
pip install -r requirements.txt

echo -e "${BLUE}  - Installing development dependencies${NC}"
pip install -r requirements-dev.txt

# Install package in editable mode
echo -e "${BLUE}  - Installing AuditZoo in editable mode${NC}"
pip install -e .

# Install Joern
echo -e "${GREEN}Installing Joern...${NC}"
JOERN_DIR="${CONDA_PREFIX}/opt/joern"
mkdir -p "${JOERN_DIR}"
cd "${JOERN_DIR}"

# Download Joern installer
echo "Downloading Joern installer..."
wget -q https://github.com/joernio/joern/releases/latest/download/joern-install.sh
chmod +x joern-install.sh

# Install Joern
echo "Installing Joern to ${JOERN_DIR}..."
./joern-install.sh --install-dir="${JOERN_DIR}"

# Set up environment activation scripts
echo -e "${GREEN}Setting up environment activation scripts...${NC}"
mkdir -p "${CONDA_PREFIX}/etc/conda/activate.d"
mkdir -p "${CONDA_PREFIX}/etc/conda/deactivate.d"

# Create activation script
cat > "${CONDA_PREFIX}/etc/conda/activate.d/auditzoo.sh" << 'EOF'
#!/bin/bash
# Add Joern to PATH
export PATH="$CONDA_PREFIX/opt/joern/joern-cli:$PATH"

# Set default Joern path for AuditZoo
export AUDITZOO_JOERN_PATH="$CONDA_PREFIX/opt/joern"

# Development mode indicator
export AUDITZOO_DEV_MODE=1

echo "AuditZoo development environment activated"
echo "  - Joern: $AUDITZOO_JOERN_PATH"
echo "  - Python: $(which python)"
EOF

chmod +x "${CONDA_PREFIX}/etc/conda/activate.d/auditzoo.sh"

# Create deactivation script
cat > "${CONDA_PREFIX}/etc/conda/deactivate.d/auditzoo.sh" << 'EOF'
#!/bin/bash
# Cleanup environment variables
unset AUDITZOO_JOERN_PATH
unset AUDITZOO_DEV_MODE
EOF

chmod +x "${CONDA_PREFIX}/etc/conda/deactivate.d/auditzoo.sh"

# Go back to original directory
cd - > /dev/null

# Install pre-commit hooks
echo -e "${GREEN}Setting up pre-commit hooks...${NC}"
if command -v pre-commit &> /dev/null; then
    pre-commit install
    echo -e "${BLUE}  ✓ Pre-commit hooks installed${NC}"
    echo -e "${BLUE}    Run 'pre-commit run --all-files' to check all files${NC}"
else
    echo -e "${YELLOW}  ! pre-commit not found, skipping hook installation${NC}"
fi

# Verify installation
echo -e "${GREEN}Verifying installation...${NC}"

# Re-activate to apply environment scripts
conda deactivate
conda activate ${ENV_NAME}

# Check Joern
if command -v joern &> /dev/null; then
    echo -e "${GREEN}✓ Joern installed${NC}"
else
    echo -e "${RED}✗ Joern installation failed${NC}"
    exit 1
fi

# Check Python package
if python -c "import auditzoo" &> /dev/null; then
    echo -e "${GREEN}✓ AuditZoo Python package installed (editable mode)${NC}"
else
    echo -e "${RED}✗ AuditZoo Python package installation failed${NC}"
    exit 1
fi

# Check dev tools
echo -e "${GREEN}✓ Checking development tools:${NC}"
for tool in pytest mypy black ruff; do
    if command -v $tool &> /dev/null; then
        echo -e "${BLUE}  ✓ $tool${NC}"
    else
        echo -e "${YELLOW}  ✗ $tool not found${NC}"
    fi
done

# Create .gitignore if it doesn't exist
if [ ! -f .gitignore ]; then
    echo -e "${GREEN}Creating .gitignore...${NC}"
    cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
build/
develop-eggs/
dist/
downloads/
eggs/
.eggs/
lib64/
parts/
sdist/
var/
wheels/
*.egg-info/
.installed.cfg
*.egg

# Virtual environments
venv/
ENV/
env/

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Type checking
.mypy_cache/
.dmypy.json

# Joern
*.cpg
cpg_output/

# OS
.DS_Store
Thumbs.db

# Logs
*.log
EOF
fi

# Create initial test directory if it doesn't exist
if [ ! -d "tests" ]; then
    echo -e "${GREEN}Creating tests directory structure...${NC}"
    mkdir -p tests
    touch tests/__init__.py
    cat > tests/conftest.py << 'EOF'
"""Pytest configuration and fixtures for AuditZoo tests."""
import pytest

# Add common fixtures here
EOF
fi

# Installation complete
echo ""
echo -e "${GREEN}=== Development Environment Setup Complete! ===${NC}"
echo ""
echo -e "${BLUE}Development environment '${ENV_NAME}' is ready!${NC}"
echo ""
echo "To start developing:"
echo -e "${YELLOW}  1. Activate the environment:${NC}"
echo -e "     ${GREEN}conda activate ${ENV_NAME}${NC}"
echo ""
echo -e "${YELLOW}  2. Make your changes to the code${NC}"
echo ""
echo -e "${YELLOW}  3. Run tests:${NC}"
echo -e "     ${GREEN}pytest tests/ -v${NC}"
echo ""
echo -e "${YELLOW}  4. Run code quality checks:${NC}"
echo -e "     ${GREEN}black auditzoo/${NC}          # Format code"
echo -e "     ${GREEN}ruff check auditzoo/${NC}    # Lint code"
echo -e "     ${GREEN}mypy auditzoo/${NC}          # Type check"
echo ""
echo -e "${YELLOW}  5. Or run pre-commit on all files:${NC}"
echo -e "     ${GREEN}pre-commit run --all-files${NC}"
echo ""
echo -e "${YELLOW}  6. Create a branch and commit:${NC}"
echo -e "     ${GREEN}git checkout -b feature/my-feature${NC}"
echo -e "     ${GREEN}git add .${NC}"
echo -e "     ${GREEN}git commit -m \"Description of changes\"${NC}"
echo ""
echo "Useful commands:"
echo -e "  ${GREEN}pytest tests/${NC}                    # Run all tests"
echo -e "  ${GREEN}pytest tests/ --cov=auditzoo${NC}     # Run tests with coverage"
echo -e "  ${GREEN}pytest tests/ -k test_name${NC}       # Run specific test"
echo -e "  ${GREEN}which joern${NC}                      # Check Joern installation"
echo ""
echo -e "${GREEN}Happy coding!${NC}"
