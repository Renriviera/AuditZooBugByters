# AuditZoo Development Guide

This guide is for **contributors** who want to develop AuditZoo.

**For users**: See [INSTALL.md](INSTALL.md) for installation.

## Quick Development Setup

```bash
# 1. Fork the repository on GitHub

# 2. Clone your fork
git clone https://github.com/your-username/auditzoo
cd auditzoo

# 3. Run the development installation script
./install-dev.sh

# 4. Activate development environment
conda activate auditzoo-dev

# 5. Verify setup
pytest tests/ -v
which joern
```

The `install-dev.sh` script will:
- Create `auditzoo-dev` conda environment
- Install all dependencies (core + dev tools)
- Install AuditZoo in **editable mode** (`pip install -e .`)
- Install Joern in the conda environment
- Set up pre-commit hooks automatically
- Create test directory structure
- Verify the installation

## Manual Development Setup

If you prefer manual setup or the script doesn't work:

```bash
# 1. Create development environment
conda create -n auditzoo-dev python=3.10
conda activate auditzoo-dev

# 2. Clone your fork
git clone https://github.com/your-username/auditzoo
cd auditzoo

# 3. Install dependencies
pip install -r requirements.txt       # Core dependencies
pip install -r requirements-dev.txt   # Development tools

# 4. Install in editable mode
pip install -e .

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
export AUDITZOO_DEV_MODE=1
echo "AuditZoo development environment activated"
EOF
chmod +x $CONDA_PREFIX/etc/conda/activate.d/auditzoo.sh

# 7. Install pre-commit hooks
pre-commit install

# 8. Reactivate and verify
conda deactivate
conda activate auditzoo-dev
pytest tests/ -v
```

## Development Environment

### What's Included

The development environment (`auditzoo-dev`) includes:

| Tool | Purpose |
|------|---------|
| **pytest** | Testing framework |
| **pytest-asyncio** | Async test support |
| **pytest-cov** | Code coverage |
| **pytest-mock** | Mocking support |
| **mypy** | Static type checking |
| **black** | Code formatting |
| **ruff** | Fast linting |
| **isort** | Import sorting |
| **pre-commit** | Git pre-commit hooks |
| **sphinx** | Documentation generation |
| **jupyter** | Interactive development |

### Environment Variables

When `auditzoo-dev` is activated:
- `CONDA_PREFIX` - Path to conda environment
- `AUDITZOO_JOERN_PATH` - Path to Joern installation
- `AUDITZOO_DEV_MODE=1` - Indicates development mode

## Development Workflow

### 1. Create a Feature Branch

```bash
# Always work on a feature branch
git checkout -b feature/my-new-feature

# Or for bug fixes
git checkout -b fix/bug-description
```

### 2. Make Your Changes

Edit code in the `auditzoo/` directory. Since AuditZoo is installed in editable mode, changes are immediately reflected.

### 3. Run Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_facts.py -v

# Run tests matching a pattern
pytest tests/ -k "test_cpg" -v

# Run with coverage
pytest tests/ --cov=auditzoo --cov-report=html

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### 4. Format and Lint Code

```bash
# Format code with black
black auditzoo/

# Sort imports
isort auditzoo/

# Lint with ruff
ruff check auditzoo/

# Auto-fix linting issues
ruff check --fix auditzoo/

# Run all pre-commit checks manually
pre-commit run --all-files
```

### 5. Type Check

```bash
# Run mypy on the codebase
mypy auditzoo/

# Type check specific file
mypy auditzoo/core/ir/model.py
```

### 6. Commit Changes

```bash
# Stage changes
git add .

# Commit (pre-commit hooks will run automatically)
git commit -m "feat: add new CPG query helper"

# If pre-commit hooks fail, fix issues and commit again
```

**Commit Message Convention**:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

### 7. Push and Create Pull Request

```bash
# Push to your fork
git push origin feature/my-new-feature

# Create pull request on GitHub
```

## Code Quality Standards

### Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`. They check:

- **black**: Code formatting
- **isort**: Import sorting
- **ruff**: Linting
- **mypy**: Type checking
- **trailing-whitespace**: Remove trailing whitespace
- **end-of-file-fixer**: Ensure files end with newline
- **check-yaml**: Validate YAML files
- **bandit**: Security checks

To run manually:
```bash
pre-commit run --all-files
```

### Code Style

- Follow [PEP 8](https://pep8.org/)
- Use type hints for all functions
- Maximum line length: 88 characters (black default)
- Use docstrings for all public functions/classes
- Write meaningful commit messages

### Testing Guidelines

- Write tests for all new features
- Maintain or improve code coverage
- Use async tests for async code (`pytest-asyncio`)
- Mock external dependencies (Joern, file system)
- Test both success and error cases

Example test structure:
```python
import pytest
from auditzoo.core.ir.model import ProgramId, Function

class TestFunction:
    def test_function_creation(self):
        """Test basic function creation."""
        func = Function(
            cpg_id="node_123",
            program_id=ProgramId("test_program"),
            name="foo"
        )
        assert func.name == "foo"
        assert func.cpg_id == "node_123"

    @pytest.mark.asyncio
    async def test_async_function(self):
        """Test async functionality."""
        # Test async code here
        pass
```

## Project Structure

Understanding the codebase:

```
auditzoo/
├── core/
│   ├── ir/                 # CPG IR wrapper
│   │   ├── model.py       # Data models (Program, Function, etc.)
│   │   ├── backend_api.py # CPGBackend interface
│   │   └── view.py        # IRView (cached wrapper)
│   ├── agents/            # Core infrastructure agents
│   ├── protocol/          # Message types
│   └── runtime/           # AutoGen runtime integration
├── backends/
│   ├── joern/             # Joern backend (primary)
│   ├── treesitter/        # TreeSitter backend (fallback)
│   └── ingestion.py       # Backend selection
├── contracts/
│   ├── facts.py           # Fact types (CPG tag serializable)
│   └── capabilities.py    # Agent capabilities
├── sdk/                   # API for analysis authors
└── analyses/              # Built-in analyses
    ├── primitives/        # Low-level (slicing, taint)
    └── detectors/         # High-level (vulnerabilities)
```

## Common Development Tasks

### Adding a New Fact Type

1. Add to `auditzoo/contracts/facts.py`:
```python
@dataclass
class MyNewFact(Fact):
    cpg_node_id: str
    my_data: str

    def to_tag(self) -> dict:
        return {
            "type": "my_new_fact",
            "program_id": self.program_id,
            "node_id": self.cpg_node_id,
            "data": self.my_data,
        }

    @classmethod
    def from_tag(cls, tag_data: dict) -> "MyNewFact":
        return cls(
            program_id=tag_data["program_id"],
            cpg_node_id=tag_data["node_id"],
            my_data=tag_data["data"]
        )
```

2. Add to `FactType` enum
3. Update `IRView._deserialize_fact()` mapping
4. Write tests in `tests/test_facts.py`

### Adding a New Analysis Agent

1. Create new file in `auditzoo/analyses/`
2. Implement `BaseAnalysisAgent`
3. Use `@analysis_agent` decorator
4. Define capabilities
5. Write tests
6. Update documentation

See existing analyses for examples.

### Debugging Tips

```bash
# Run tests with verbose output
pytest tests/ -vv -s

# Run with debugger on failure
pytest tests/ --pdb

# Set PYTHONPATH for imports
export PYTHONPATH=$PWD:$PYTHONPATH

# Enable AuditZoo debug logging
export AUDITZOO_LOG_LEVEL=DEBUG
```

## Building Documentation

```bash
# Install documentation dependencies (included in requirements-dev.txt)
cd docs

# Build HTML documentation
make html

# View documentation
open _build/html/index.html
```

## Running Benchmarks

(To be added)

## Release Process

(To be added by maintainers)

## Getting Help

- **GitHub Issues**: https://github.com/your-org/auditzoo/issues
- **Discussions**: https://github.com/your-org/auditzoo/discussions
- **Architecture**: See [docs/auditzoo_spec.md](docs/auditzoo_spec.md)

## Contributing Guidelines

### Pull Request Process

1. **Fork the repository** on GitHub
2. **Clone your fork** locally
3. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
4. **Make your changes** with tests
5. **Run tests locally** (`pytest tests/`)
6. **Run pre-commit checks** (`pre-commit run --all-files`)
7. **Commit your changes** (`git commit -m 'feat: add amazing feature'`)
8. **Push to your fork** (`git push origin feature/amazing-feature`)
9. **Create a pull request** on GitHub

### Pull Request Checklist

Before submitting a pull request, ensure:

- [ ] **Tests added/updated** - All new code has tests
- [ ] **Tests pass** - `pytest tests/` runs without errors
- [ ] **Type hints added** - All functions have type annotations
- [ ] **Docstrings added** - Public functions have docstrings
- [ ] **Code formatted** - `black auditzoo/` and `isort auditzoo/`
- [ ] **Linting passes** - `ruff check auditzoo/` shows no errors
- [ ] **Type checking passes** - `mypy auditzoo/` shows no errors
- [ ] **Pre-commit hooks pass** - All hooks succeed
- [ ] **Documentation updated** - If adding features, update docs
- [ ] **CI checks pass** - All GitHub Actions workflows succeed

### What Happens After Submitting

1. **Automated CI runs** - GitHub Actions will run all checks
2. **Code review** - A maintainer will review your code
3. **Feedback** - Address any comments or requested changes
4. **Approval** - Maintainer approves the PR
5. **Merge** - PR is merged into main branch

### Code Review Requirements

All pull requests require:
- ✅ At least one approval from a maintainer
- ✅ All CI checks passing (green checkmarks)
- ✅ No merge conflicts with main branch
- ✅ Up-to-date with main branch

## License

[To be determined]

## Questions?

Feel free to open an issue or discussion on GitHub!

---

Thank you for contributing to AuditZoo! 🎉
