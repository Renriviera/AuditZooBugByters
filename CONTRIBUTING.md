# Contributing to AuditZoo

Thank you for your interest in contributing to AuditZoo! 🎉

This document provides guidelines for contributing to the project.

## Quick Links

- **Development Setup**: See [DEVELOP.md](DEVELOP.md)
- **Installation**: See [INSTALL.md](INSTALL.md)
- **Architecture**: See [docs/auditzoo_spec.md](docs/auditzoo_spec.md)

## Getting Started

### 1. Set Up Development Environment

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/your-username/auditzoo
cd auditzoo

# Run the development installation script
./install-dev.sh

# Activate environment
conda activate auditzoo-dev
```

See [DEVELOP.md](DEVELOP.md) for detailed setup instructions.

### 2. Find an Issue or Feature

- Check [open issues](https://github.com/your-org/auditzoo/issues)
- Look for issues labeled `good first issue` or `help wanted`
- Or propose a new feature by opening an issue first

### 3. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 4. Make Your Changes

- Write code following our [code style](#code-style)
- Add tests for your changes
- Update documentation if needed

### 5. Test Your Changes

```bash
# Run tests
pytest tests/ -v

# Run pre-commit checks
pre-commit run --all-files

# Run type checking
mypy auditzoo/
```

### 6. Commit Your Changes

```bash
git add .
git commit -m "feat: add amazing feature"
```

Use [conventional commits](https://www.conventionalcommits.org/):
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Adding tests
- `refactor:` - Code refactoring
- `chore:` - Maintenance tasks

### 7. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## Code Style

We use automated tools to maintain code quality:

- **black** - Code formatting
- **isort** - Import sorting
- **ruff** - Fast linting
- **mypy** - Type checking

Install pre-commit hooks to run these automatically:
```bash
pre-commit install
```

## Testing Guidelines

- Write tests for all new features
- Aim for high code coverage
- Use pytest for testing
- Test both success and failure cases

Example test:
```python
import pytest
from auditzoo.core.ir.model import Function, ProgramId

def test_function_creation():
    """Test that functions can be created with required fields."""
    func = Function(
        cpg_id="node_123",
        program_id=ProgramId("test"),
        name="foo"
    )
    assert func.name == "foo"
    assert func.cpg_id == "node_123"
```

## Documentation

- Add docstrings to all public functions/classes
- Use Google-style docstrings
- Update README.md if adding user-facing features
- Update docs/ for architecture changes

Example docstring:
```python
def my_function(param1: str, param2: int) -> bool:
    """Short description of what the function does.

    Longer description if needed, explaining the behavior
    in more detail.

    Args:
        param1: Description of param1
        param2: Description of param2

    Returns:
        Description of return value

    Raises:
        ValueError: When invalid input is provided
    """
    pass
```

## Pull Request Process

1. **Ensure all tests pass** locally
2. **Run pre-commit checks** (`pre-commit run --all-files`)
3. **Update documentation** if needed
4. **Create pull request** with clear description
5. **Wait for CI** to run automated checks
6. **Address review comments** if any
7. **Get approval** from maintainer
8. **Merge!** 🎉

## Pull Request Checklist

- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Code formatted (black, isort)
- [ ] Linting passes (ruff)
- [ ] Type checking passes (mypy)
- [ ] Documentation updated
- [ ] CI checks pass

## Community Guidelines

### Be Respectful

- Be kind and courteous
- Respect differing opinions
- Provide constructive feedback
- Focus on the code, not the person

### Be Collaborative

- Help others learn
- Share knowledge
- Ask questions
- Give credit where due

### Be Professional

- Follow the code of conduct
- Keep discussions on-topic
- Be patient with beginners
- Assume good intent

## Reporting Bugs

When reporting bugs, include:

1. **Description** - What happened vs. what you expected
2. **Steps to reproduce** - Minimal example to reproduce the issue
3. **Environment** - OS, Python version, AuditZoo version
4. **Logs/errors** - Any error messages or stack traces

Use the issue template if available.

## Suggesting Features

When suggesting features:

1. **Describe the problem** - What use case does this address?
2. **Proposed solution** - How should it work?
3. **Alternatives** - Other approaches you considered
4. **Additional context** - Screenshots, examples, etc.

## Questions?

- **GitHub Discussions**: For questions and discussions
- **GitHub Issues**: For bug reports and feature requests
- **Documentation**: Check [DEVELOP.md](DEVELOP.md) and [docs/](docs/)

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (TBD).

---

Thank you for contributing to AuditZoo! 🚀
