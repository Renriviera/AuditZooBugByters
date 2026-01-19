# Resolve TypeScript Path Aliases

Automatically convert TypeScript path aliases (like `@/components/Button`) to relative paths (like `../../components/Button`).

## Description

This script scans all source files in a TypeScript project and replaces import statements using path aliases with relative paths, based on path mappings defined in `tsconfig.json`.

**Supported Syntax:**
- `import/export ... from '@/...'`
- Dynamic imports `import('@/...')`
- All TypeScript/JavaScript file types: `.ts`, `.tsx`, `.js`, `.jsx`, `.mts`, `.mjs`, `.cts`, `.cjs`

## Requirements

### Required Software

| Software | Minimum Version | Recommended | Notes |
|----------|----------------|-------------|-------|
| **Node.js** | >= 16.0.0 | >= 18.0.0 (LTS) | Must support ES modules (`.mjs`) |
| **npm** | >= 7.0.0 | >= 9.0.0 | For installing dependencies |

### npm Dependencies

The following dependencies are automatically installed when the script runs (no manual installation needed):

- `ts-morph` - TypeScript code analysis and transformation tool
- `typescript` - TypeScript compiler

## Usage

### Basic Usage

```bash
./run.sh <project_root>
```

### Parameters

- `<project_root>` - Required. Root directory path of the TypeScript project to process
  - Must contain a `tsconfig.json` file
  - Can be a relative or absolute path

### Examples

```bash
# Process current directory
./run.sh .

# Process a specific project
./run.sh /path/to/your/project

# Process a project with relative path
./run.sh ../../my-app
```

## Execution Flow

1. **Dependency Check** - Automatically detects and installs `ts-morph` and `typescript`
2. **Project Analysis** - Counts TypeScript files and alias imports
3. **User Confirmation** - Displays warning and requires user confirmation (files will be modified!)
4. **Conversion** - Iteratively converts all alias imports to relative paths
5. **Result Report** - Shows conversion statistics and remaining unconverted aliases

## Important Notes

### ⚠️ Warning

- **This script directly modifies project files!** Before running, ensure:
  1. All changes are committed to Git, OR
  2. Project directory is backed up

- The script automatically iterates until convergence (max 100 iterations) to handle chained references

### Use Cases

- Preparing npm packages for publishing (some tools don't support path aliases)
- Migrating to build tools that don't support path mappings
- Improving IDE navigation and refactoring compatibility
- Removing dependency on build tool path resolution

### Exclusion Rules

The script automatically skips:
- `node_modules/` directory
- `.next/` directory
- `dist/` directory
- `.d.ts` type definition files

## Troubleshooting

### Issue: "node command not found"

**Solution:** Install Node.js

```bash
# macOS (using Homebrew)
brew install node

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install nodejs npm

# Or use nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install --lts
```

### Issue: Some aliases not converted

**Possible Causes:**
1. Target file referenced by alias doesn't exist
2. Path mapping configuration is incorrect
3. External packages (like `@vercel/blob`) that shouldn't be converted

**Solution:** Check the "Failed to resolve" list in script output and handle these cases manually

### Issue: Script stuck in iteration loop

**Possible Cause:** Circular dependencies or special import patterns exist

**Solution:** Script will auto-stop after 100 iterations. Check the final output logs

## Technical Details

### How It Works

1. Reads project's `tsconfig.json` to extract `baseUrl` and `paths` configuration
2. Uses `ts-morph` to parse AST of all TypeScript source files
3. Traverses all import declarations and dynamic import expressions
4. Replaces module specifiers matching path aliases with relative paths
5. Saves modified files

### File Structure

```
resolve-ts-path-aliases/
├── README.md              # This document
├── run.sh                 # Main entry script (Bash)
└── alias-to-relative.mjs  # Core conversion logic (Node.js)
```

## Developer Information

- **Language:** Bash + JavaScript (ES Modules)
- **Core Dependencies:** ts-morph, typescript
- **Compatibility:** Linux, macOS (requires Bash environment)
