# Coding Standards

## Backend

- Use typed Python and Pydantic schemas at API boundaries.
- Keep configuration centralized in `igris.core.config`.
- Use structured logging from `igris.core.logging`.
- Return normalized API errors from shared handlers.
- Keep hostile file handling out of request handlers.
- Prefer interfaces at component boundaries until implementation pressure is real.

## Frontend

- Use strict TypeScript.
- Keep API response types explicit.
- Avoid rendering untrusted text without escaping or validation.
- Keep operational screens compact and scannable.

## Security

- Never log secrets, tokens, passwords, or raw suspicious file contents.
- Never trust filenames, metadata, archive paths, or parser output.
- Never execute uploaded binaries on developer or application hosts.
- Keep dynamic execution confined to future disposable sandbox infrastructure.

