---
layout: default
title: Contributing to WAFIShield
---

# Contributing to WAFIShield

Thank you for your interest in contributing to WAFIShield! This document provides guidelines and instructions for contributing to the project.

## ⚠️ Development Status

WAFIShield is under active development and is not yet ready for production use. We welcome contributions to help improve the package.

## Code of Conduct

Please be respectful and considerate of others when contributing to WAFIShield.

## How to Contribute

### Reporting Issues

If you find a bug or have a suggestion for improving WAFIShield:

1. Check if the issue already exists in the [GitHub Issues](https://github.com/duestack/wafishield/issues)
2. If not, create a new issue with a clear title and description
3. Include steps to reproduce the issue if reporting a bug
4. Add relevant labels to the issue

### Pull Requests

1. Fork the repository
2. Create a new branch for your feature/bugfix
3. Make your changes
4. Add or update tests as necessary
5. Run the test suite to ensure all tests pass
6. Submit a pull request with a clear description of the changes

## Development Setup

1. Clone the repository:

```bash
git clone https://github.com/duestack/wafishield.git
cd wafishield
```

2. Set up a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

3. Install development dependencies:

```bash
pip install -e ".[dev]"
```

4. Install pre-commit hooks:

```bash
pre-commit install
```

## Testing

Run the test suite:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=wafishield
```

## Coding Style

- Follow PEP 8 guidelines
- Use docstrings following Google style
- Sort imports with isort
- Format code with black

## Documentation

- Update documentation when adding or modifying features
- Include docstrings for all public functions and classes
- Update relevant examples if needed

## Adding New Features

### Rules

When adding new rules:

1. Add the rule to the appropriate YAML file in `wafishield/rules/`
2. Ensure the rule follows the schema in `wafishield/schemas/rules_schema.json`
3. Add tests for the rule in `tests/test_rules_engine.py`

### Sanitizer Patterns

When adding new sanitizer patterns:

1. Add the pattern to the appropriate YAML file in `wafishield/patterns/`
2. Ensure the pattern follows the schema in `wafishield/schemas/patterns_schema.json`
3. Add tests for the pattern in `tests/test_sanitizer_engine.py`

## License

By contributing to WAFIShield, you agree that your contributions will be licensed under the MIT License.
