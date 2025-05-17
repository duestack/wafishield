# AI LLM Shield Project Rules

## 1. Project Structure & Modularity
1. Package Layout:
   - Single Top-Level Package: All source code lives under `wafishield/`, with an `__init__.py` entry point.
   - Subpackages by Domain: e.g., `wafishield/rules/`, `wafishield/abstraction/`, `wafishield/utils/`, `wafishield/models/` to separate concerns and avoid circular imports.
   - Tests Directory: A top-level `tests/` alongside `wafishield/`, mirroring package structure for easy discovery by pytest.
2. Module Guidelines:
   - Small, Focused Modules: Each module should encapsulate a single responsibility (e.g., tokenization, input sanitization, policy enforcement).
   - Clear Naming Conventions: Use `snake_case` for modules and functions, `CamelCase` for classes.
   - Avoid Cyclic Dependencies: Higher-level modules (e.g., API layers) depend on lower-level ones (e.g., core logic).

## 2. Twelve-Factor App Compliance
1. Codebase
   - One repository; multiple deploys via branches or tags.
2. Dependencies
   - Declare in `requirements.txt` or `pyproject.toml`; no implicit system libs.
3. Config
   - All configuration via environment variables (e.g., `LLM_API_KEY`, `LOG_LEVEL`).
4. Backing Services
   - Treat databases, caches, and external LLMs as attachable resources defined by URLs in env vars.
5. Build, Release, Run
   - Build: Container image build or artifact packaging.
   - Release: Tagging containers with semantic versions.
   - Run: Launch processes via a Procfile or Docker CMD, without code changes.
6. Processes
   - Stateless web/API processes; state persisted to backing services only.
7. Port Binding
   - Self-contained server binding to `$PORT` for HTTP endpoints.
8. Concurrency
   - Scale via process model (multiple workers, threads, or async loops).
9. Disposability
   - Fast startup/shutdown (handle `SIGTERM` gracefully).
10. Dev/Prod Parity
    - Keep environment gaps minimal; use container-based local emulation.
11. Logs
    - Write logs to stdout; let orchestration aggregate them.
12. Admin Processes
    - One-off tasks (migrations, policy audits) as CLI commands in source control.

## 3. Python-Specific Best Practices
1. Virtual Environments & Dependency Management
   - Use `venv` or `pipenv` to isolate project dependencies.
   - Lock dependencies with `pip freeze > requirements.txt` or `poetry.lock`.
2. Code Quality
   - Linting: Enforce PEP 8 via Flake8 or Ruff.
   - Formatting: Auto-format with Black.
   - Type Checking: Integrate MyPy for optional static types.
   - Docstrings: Follow NumPy or Google style; auto-generate docs with Sphinx.
3. Testing
   - Unit Tests: pytest with fixtures and mocks for LLM calls.
   - Integration Tests: Spin up temporary backing services (e.g., SQLite, Redis).
   - Coverage: Fail CI if coverage drops below threshold (e.g., 90%).

## 4. Community & Contribution Guidelines
- CONTRIBUTING.md: Outline code style, branching strategy (e.g., GitHub Flow), and pull request process.
- Code of Conduct: Adopt a standard open-source CoC.
- Issue Templates: Bug report, feature request, security disclosure.
- Pull Request Templates: Checklist for tests, docs, and changelog entries.
- Changelog: Keep `CHANGELOG.md` following Keep a Changelog format.


## 5. Security & LLM Shield Considerations
- Input Sanitization: Strictly validate prompts and metadata before passing to LLM.
- Rate Limiting & Throttling: Implement middleware to prevent abuse.
- Audit Logs: Record all requests and policy decisions to a secure, append-only store.
- Secrets Management: Never commit API keys; integrate with Vault or Kubernetes Secrets.
- Community Security Disclosure: Provide a `SECURITY.md` and ensure timely triage of vulnerabilities.

## 6. Rule Engine & Multilingual Support
1. Rule Format Standards:
   - YAML-based rule definitions with clear versioning
   - Support for regular expressions and semantic patterns
   - Metadata for rule categorization and severity levels
2. Multilingual Handling:
   - Unicode support for all text processing
   - Language-specific pattern libraries
   - Translation-safe rule matching
3. Extension Points:
   - Plugin architecture for custom rule modules
   - Hook system for pre/post processing
   - Standard interfaces for rule contributions
4. Performance Considerations:
   - Rule compilation and caching
   - Parallel pattern matching
   - Minimal overhead for common cases
