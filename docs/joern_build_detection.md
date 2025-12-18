# Joern Build Pipeline Auto-Detection

This document explains how Joern automatically detects and handles different build configurations.

## Overview

**Important: Joern automatically detects ALL languages** in a project by file extensions and creates a **unified CPG containing all languages**!

### Key Points:

1. ✅ **No language parameter needed** - Joern auto-detects by file extensions
2. ✅ **Multi-language projects work automatically** - One CPG contains all languages found
3. ✅ **Cross-language queries possible** - Query interactions between C++, Python, Java, etc.
4. ⚠️ **Build info optional** - For C/C++, providing `compile_commands.json` improves accuracy

## Language-Specific Build Detection

### C/C++

Joern can parse C/C++ code in two modes:

#### 1. **With `compile_commands.json` (Recommended for accuracy)**
If `compile_commands.json` is present in the source directory, Joern will:
- Use the exact compiler flags and include paths
- Properly handle preprocessor macros
- Resolve correct header file paths
- Handle conditional compilation accurately

**Generating `compile_commands.json`:**
```bash
# For CMake projects
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON .

# For Make projects (using Bear)
bear -- make

# For other build systems
compiledb make  # Using compiledb wrapper
```

#### 2. **Without `compile_commands.json` (Direct parsing)**
If no `compile_commands.json` is found, Joern will:
- Parse source files directly
- Use default include paths
- May miss some macro definitions
- Works well for simple projects without complex build requirements

**Example:**
```python
from auditzoo.backends.base import JoernConfig

# Option 1: With compile_commands.json
config = JoernConfig(
    language="c",
    source_path="/path/to/project",  # Directory containing compile_commands.json
)

# Option 2: Direct parsing (no compile_commands.json needed)
config = JoernConfig(
    language="c",
    source_path="/path/to/project",  # Joern will parse all .c/.cpp/.h files
)
```

### Java

Joern automatically handles Java projects in multiple ways:

1. **Source files (.java)**: Direct parsing
2. **Compiled bytecode (.class files)**: Decompiles and analyzes
3. **JAR files**: Extracts and analyzes all classes
4. **Maven/Gradle projects**: Can parse source or analyze built artifacts

**No build configuration needed!** Joern auto-detects:
- Package structures
- Dependencies (from .class files)
- Maven/Gradle project layout

**Example:**
```python
# Parse Java source
config = JoernConfig(language="java", source_path="/path/to/src")

# Or analyze compiled JARs
config = JoernConfig(language="java", source_path="/path/to/app.jar")
```

### JavaScript / TypeScript

Joern directly parses JavaScript and TypeScript:
- Auto-detects `.js`, `.jsx`, `.ts`, `.tsx` files
- Handles ES6+ syntax
- No build configuration required
- Works with npm/yarn projects (parses source, not node_modules)

**Example:**
```python
config = JoernConfig(language="javascript", source_path="/path/to/project")
```

### Python

Joern parses Python source directly:
- No build system needed
- Auto-detects `.py` files
- Handles Python 2 and Python 3 syntax

**Example:**
```python
config = JoernConfig(language="python", source_path="/path/to/project")
```

### Go

Joern parses Go source directly:
- Auto-detects `.go` files
- Understands Go module structure
- No `go.mod` required (but respected if present)

**Example:**
```python
config = JoernConfig(language="go", source_path="/path/to/project")
```

### Kotlin

Joern parses Kotlin source and compiled code:
- Direct parsing of `.kt` files
- Can also analyze `.jar` files containing Kotlin bytecode

**Example:**
```python
config = JoernConfig(language="kotlin", source_path="/path/to/project")
```

## Language Auto-Detection

If you don't specify a language, Joern auto-detects based on file extensions:

```python
# Joern will auto-detect language from file extensions
config = JoernConfig(source_path="/path/to/mixed/project")
```

## AuditZoo Usage Examples

### Example 1: Analyze a C project with build info
```python
from auditzoo.backends.joern.backend import JoernBackend
from auditzoo.backends.base import JoernConfig

# Assuming compile_commands.json exists in /path/to/project
config = JoernConfig(
    language="c",
    source_path="/path/to/project",
)

backend = JoernBackend(config)
await backend.connect()

# Now you can query the CPG
results = await backend.query("cpg.method.name.l")
```

### Example 2: Analyze Java JAR file
```python
config = JoernConfig(
    language="java",
    source_path="/path/to/application.jar",
)

backend = JoernBackend(config)
await backend.connect()  # Joern extracts and analyzes all classes
```

### Example 3: Use existing CPG database
```python
# If you already have a CPG database from a previous run
config = JoernConfig(
    language="c",
    cpg_path="/path/to/existing/cpg.bin",  # Skip parsing, load existing CPG
)

backend = JoernBackend(config)
await backend.connect()
```

### Example 4: Multi-language project
```python
# For a project with multiple languages, run separate analyses
configs = [
    JoernConfig(language="c", source_path="/path/to/c_code"),
    JoernConfig(language="java", source_path="/path/to/java_code"),
]

for config in configs:
    backend = JoernBackend(config)
    await backend.connect()
    # Analyze...
    await backend.disconnect()
```

## Summary

| Language | Auto-Detection | Build Config Support | Notes |
|----------|----------------|---------------------|-------|
| **C/C++** | ✅ (.c, .cpp, .h) | ✅ compile_commands.json | Recommended for complex projects |
| **Java** | ✅ (.java, .class, .jar) | ✅ Maven/Gradle layout | Works with source or bytecode |
| **JavaScript** | ✅ (.js, .jsx) | N/A | Direct parsing |
| **TypeScript** | ✅ (.ts, .tsx) | N/A | Direct parsing |
| **Python** | ✅ (.py) | N/A | Direct parsing |
| **Go** | ✅ (.go) | ⚠️ Respects go.mod | Direct parsing |
| **Kotlin** | ✅ (.kt, .jar) | N/A | Source or bytecode |

**Key Takeaway:** Joern works out-of-the-box for most languages. For C/C++, provide `compile_commands.json` for best results.
