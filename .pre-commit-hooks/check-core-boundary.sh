#!/usr/bin/env bash
# Pre-commit hook to ensure changes are either all inside core/ or all outside core/

set -e

# Get all staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR)

if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

# Count files inside and outside core/
INSIDE_CORE=0
OUTSIDE_CORE=0

while IFS= read -r file; do
    if [[ "$file" == auditzoo/core/* ]]; then
        INSIDE_CORE=$((INSIDE_CORE + 1))
    else
        OUTSIDE_CORE=$((OUTSIDE_CORE + 1))
    fi
done <<< "$STAGED_FILES"

# Check if we have cross-boundary changes
if [ $INSIDE_CORE -gt 0 ] && [ $OUTSIDE_CORE -gt 0 ]; then
    echo "ERROR: Cross-boundary commit detected!"
    echo ""
    echo "This commit contains changes both inside and outside core/:"
    echo ""
    echo "Files inside core/:"
    while IFS= read -r file; do
        if [[ "$file" == auditzoo/core/* ]]; then
            echo "  - $file"
        fi
    done <<< "$STAGED_FILES"
    echo ""
    echo "Files outside core/:"
    while IFS= read -r file; do
        if [[ "$file" != auditzoo/core/* ]]; then
            echo "  - $file"
        fi
    done <<< "$STAGED_FILES"
    echo ""
    echo "Please split your changes into separate commits:"
    echo "  - One commit for changes inside core/"
    echo "  - One commit for changes outside core/"
    exit 1
fi

exit 0
