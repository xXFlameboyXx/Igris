# Contributing to Igris

Igris is in Phase 0. Contributions should improve foundation, safety, documentation,
tests, or maintainability without implementing Phase 1 analysis features.

## Standards

- Keep backend code typed and covered by focused tests.
- Use Ruff for formatting/linting and mypy for type checking.
- Use strict TypeScript in the frontend.
- Do not commit secrets, sample malware, proprietary binaries, or hostile test artifacts.
- Use benign synthetic files for tests.
- Do not add code that executes uploaded binaries on the developer host or application host.

## Workflow

1. Create a focused branch.
2. Run backend and frontend checks.
3. Update documentation when changing architecture, configuration, or security boundaries.
4. Keep pull requests small enough to review carefully.

## Security Issues

Do not open public issues for suspected vulnerabilities. Follow the process in
[SECURITY.md](SECURITY.md).

