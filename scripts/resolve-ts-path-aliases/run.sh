#!/bin/bash

# Convert TypeScript project path aliases (like @/) to relative paths
# Usage: ./run.sh <project_root>
# WARNING: This script will MODIFY the project files directly!

set -e  # Exit immediately on error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check arguments
if [ $# -ne 1 ]; then
    echo -e "${RED}Error: Project directory path required${NC}"
    echo "Usage: $0 <project_root>"
    echo "Example: $0 /path/to/builders-hub"
    exit 1
fi

PROJECT_ROOT="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALIAS_SCRIPT="${SCRIPT_DIR}/alias-to-relative.mjs"

# Check if input directory exists
if [ ! -d "$PROJECT_ROOT" ]; then
    echo -e "${RED}Error: Directory does not exist: $PROJECT_ROOT${NC}"
    exit 1
fi

# Check if tsconfig.json exists
if [ ! -f "$PROJECT_ROOT/tsconfig.json" ]; then
    echo -e "${RED}Error: tsconfig.json not found: $PROJECT_ROOT/tsconfig.json${NC}"
    exit 1
fi

# Check if conversion script exists
if [ ! -f "$ALIAS_SCRIPT" ]; then
    echo -e "${RED}Error: Conversion script not found: $ALIAS_SCRIPT${NC}"
    exit 1
fi

# Check if node is installed
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: node command not found, please install Node.js first${NC}"
    exit 1
fi

# Install dependencies if not already installed
echo -e "${GREEN}Checking dependencies...${NC}"
cd "$SCRIPT_DIR"
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing dependencies (ts-morph, typescript)...${NC}"
    npm install --no-save ts-morph typescript
    echo -e "${GREEN}✓ Dependencies installed${NC}"
else
    echo -e "${GREEN}✓ Dependencies already installed${NC}"
fi
echo ""

# WARNING and confirmation
echo -e "${RED}========================================${NC}"
echo -e "${RED}⚠️  WARNING ⚠️${NC}"
echo -e "${RED}========================================${NC}"
echo -e "${YELLOW}This script will DIRECTLY MODIFY files in:${NC}"
echo -e "${YELLOW}  $PROJECT_ROOT${NC}"
echo ""
echo -e "${YELLOW}The project files will be changed permanently!${NC}"
echo -e "${YELLOW}Please ensure you have:${NC}"
echo -e "${YELLOW}  1. Committed all changes to git, OR${NC}"
echo -e "${YELLOW}  2. Made a backup of the project directory${NC}"
echo ""
read -p "$(echo -e ${RED}Do you want to continue? \(y/N\): ${NC})" -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}Operation cancelled by user${NC}"
    exit 1
fi
echo ""

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}TypeScript Alias Conversion Tool${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "Project directory: ${YELLOW}$PROJECT_ROOT${NC}"
echo -e "Conversion script: ${YELLOW}$ALIAS_SCRIPT${NC}"
echo ""

# Step 1: Count TypeScript files
echo -e "${GREEN}[1/2] Analyzing project structure...${NC}"
TS_COUNT=$(find "$PROJECT_ROOT" -type f \( -name "*.ts" -o -name "*.tsx" \) | wc -l)
ALIAS_COUNT=$(grep -r "from ['\"]@/" --include="*.ts" --include="*.tsx" "$PROJECT_ROOT" 2>/dev/null | wc -l)
echo -e "  TypeScript files: ${YELLOW}$TS_COUNT${NC}"
echo -e "  Imports with aliases: ${YELLOW}$ALIAS_COUNT${NC}"
echo ""

# Step 2: Run conversion script (loop until convergence)
echo -e "${GREEN}[2/2] Converting path aliases to relative paths...${NC}"
cd "$PROJECT_ROOT"

TOTAL_CHANGED_FILES=0
TOTAL_CHANGED_IMPORTS=0
ITERATION=0

while true; do
    ITERATION=$((ITERATION + 1))

    # Run conversion script
    OUTPUT=$(node "$ALIAS_SCRIPT" 2>&1)

    # Extract statistics
    CHANGED_FILES=$(echo "$OUTPUT" | grep "Changed files:" | grep -oE '[0-9]+' | head -1)
    CHANGED_IMPORTS=$(echo "$OUTPUT" | grep "changed imports:" | grep -oE '[0-9]+' | head -1)

    if [ -z "$CHANGED_FILES" ]; then
        CHANGED_FILES=0
    fi

    if [ "$CHANGED_FILES" -eq 0 ]; then
        echo -e "${GREEN}  ✓ Conversion complete, performed $ITERATION iterations${NC}"
        break
    fi

    TOTAL_CHANGED_FILES=$((TOTAL_CHANGED_FILES + CHANGED_FILES))
    TOTAL_CHANGED_IMPORTS=$((TOTAL_CHANGED_IMPORTS + CHANGED_IMPORTS))

    echo -e "  Iteration ${YELLOW}$ITERATION${NC}: Modified ${YELLOW}$CHANGED_FILES${NC} files, ${YELLOW}$CHANGED_IMPORTS${NC} imports"

    # Prevent infinite loop (max 100 iterations)
    if [ "$ITERATION" -ge 100 ]; then
        echo -e "${YELLOW}  Warning: Maximum iteration count reached (100), stopping conversion${NC}"
        break
    fi
done

echo ""

# Step 3: Statistics after conversion
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Conversion Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

REMAINING_ALIASES=$(grep -r "from ['\"]@/" --include="*.ts" --include="*.tsx" "$PROJECT_ROOT" 2>/dev/null | wc -l)
RELATIVE_IMPORTS=$(grep -r "from ['\"]\.\./" --include="*.ts" --include="*.tsx" "$PROJECT_ROOT" 2>/dev/null | wc -l)

echo -e "Total files modified: ${GREEN}$TOTAL_CHANGED_FILES${NC}"
echo -e "Total imports converted: ${GREEN}$TOTAL_CHANGED_IMPORTS${NC}"
echo -e "Remaining aliases: ${YELLOW}$REMAINING_ALIASES${NC}"
echo -e "Relative path imports: ${GREEN}$RELATIVE_IMPORTS${NC}"
echo ""

if [ "$REMAINING_ALIASES" -gt 0 ]; then
    echo -e "${YELLOW}Unconverted alias imports:${NC}"
    grep -r "from ['\"]@/" --include="*.ts" --include="*.tsx" "$PROJECT_ROOT" 2>/dev/null | \
        sed 's/.*from /  /' | sort | uniq | head -20

    if [ "$REMAINING_ALIASES" -gt 20 ]; then
        echo -e "  ${YELLOW}... and more${NC}"
    fi
    echo ""
fi

echo -e "Project directory: ${GREEN}$PROJECT_ROOT${NC}"
echo -e "${GREEN}All done!${NC}"
