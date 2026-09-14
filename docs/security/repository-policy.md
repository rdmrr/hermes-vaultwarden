# Repository Safety and Portability Policy

## Allowed content

- portable source code and tests;
- generic configuration templates with placeholders;
- architecture and operator documentation that applies across installations;
- examples using reserved names such as `example.invalid`;
- synthetic, non-sensitive test values clearly identified as fixtures.

## Prohibited content

- passwords, tokens, session keys, private keys, API credentials, Vault exports,
  recovery material, or client authentication state;
- real usernames, home-directory paths, hostnames, internal domains, private
  network addresses, account labels, device identifiers, item UUIDs, or
  organization/collection identifiers;
- production logs, command output, screenshots, database dumps, process lists,
  journal excerpts, backup metadata, or deployment inventories;
- local absolute paths in documentation or examples;
- configuration copied from a real installation.

## Documentation convention

Describe interfaces and expected behavior, not the environment in which a test
was performed. Use variables such as `${HERMES_HOME}`, `${CREDENTIALS_DIRECTORY}`
and `${PROJECT_ROOT}`. Use reserved example domains. Record host-specific
evidence outside Git in the approved operational checkpoint store.

## Development workflow

1. Work from the registered project repository using one branch or Git worktree
   per Kanban task.
2. Never copy files wholesale from runtime profiles, service directories,
   credential stores, Vault clients, logs, or operational notes.
3. Add only explicit files; avoid blind `git add .` for security-sensitive work.
4. Run unit tests and `scripts/check_repository_safety.py`.
5. Inspect `git diff --cached --check` and the complete staged diff.
6. Commit only after all findings are resolved or a synthetic fixture has a
   narrowly scoped `repo-safety: allow` annotation.
7. Push through the authenticated coordination profile after review. Worker
   profiles do not receive GitHub credentials.

`.gitignore` is defense in depth. It does not make tracked or force-added files
safe and does not replace review, scanning, rotation, or history cleanup.
