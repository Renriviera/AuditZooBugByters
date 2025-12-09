#!/bin/bash
# AuditZoo Installation Script
# This script sets up AuditZoo with Joern in a conda environment

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== AuditZoo Installation Script ===${NC}"
echo ""

# Check if conda is installed
if ! command -v conda &> /dev/null; then
    echo -e "${RED}Error: Conda is not installed${NC}"
    echo "Please install Miniconda or Anaconda first:"
    echo "  https://docs.conda.io/en/latest/miniconda.html"
    exit 1
fi

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo -e "${YELLOW}Warning: Java is not installed${NC}"
    echo "Joern requires Java 11+. Please install Java before continuing."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Environment name
ENV_NAME="auditzoo"
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

# Create conda environment
echo -e "${GREEN}Creating conda environment '${ENV_NAME}' with Python ${PYTHON_VERSION}...${NC}"
conda create -n ${ENV_NAME} python=${PYTHON_VERSION} -y

# Activate environment (in subshell)
echo -e "${GREEN}Activating conda environment...${NC}"
eval "$(conda shell.bash hook)"
conda activate ${ENV_NAME}

# Install Python dependencies
echo -e "${GREEN}Installing Python dependencies...${NC}"
pip install -r requirements.txt
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
EOF

chmod +x "${CONDA_PREFIX}/etc/conda/activate.d/auditzoo.sh"

# Create deactivation script
cat > "${CONDA_PREFIX}/etc/conda/deactivate.d/auditzoo.sh" << 'EOF'
#!/bin/bash
# Cleanup environment variables
unset AUDITZOO_JOERN_PATH
EOF

chmod +x "${CONDA_PREFIX}/etc/conda/deactivate.d/auditzoo.sh"

# Go back to original directory
cd - > /dev/null

# Verify installation
echo -e "${GREEN}Verifying installation...${NC}"

# Re-activate to apply environment scripts
conda deactivate
conda activate ${ENV_NAME}

# Check Joern
if command -v joern &> /dev/null; then
    echo -e "${GREEN}✓ Joern installed successfully${NC}"
    echo -e "${BLUE}  Location: $(which joern)${NC}"
else
    echo -e "${RED}✗ Joern installation failed${NC}"
    exit 1
fi

# Check Python
if python -c "import auditzoo" &> /dev/null; then
    echo -e "${GREEN}✓ AuditZoo Python package installed${NC}"
else
    echo -e "${RED}✗ AuditZoo Python package installation failed${NC}"
    exit 1
fi

# Installation complete
echo ""
echo -e "${GREEN}=== Installation Complete! ===${NC}"
echo ""
echo "To use AuditZoo, activate the environment:"
echo -e "${YELLOW}  conda activate ${ENV_NAME}${NC}"
echo ""
echo "To verify the installation:"
echo -e "${YELLOW}  which joern${NC}"
echo -e "${YELLOW}  python -c 'import auditzoo; print(\"AuditZoo ready!\")'${NC}"
echo ""
echo "To deactivate when done:"
echo -e "${YELLOW}  conda deactivate${NC}"
echo ""
echo -e "${GREEN}Happy analyzing!${NC}"
