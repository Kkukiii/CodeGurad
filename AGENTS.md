# AGENTS

## Project context

This repository is currently a minimal, greenfield workspace. There is no established app structure, framework, or build system yet. Treat this as a lightweight project that should stay easy to understand and evolve.

## Working conventions

- Prefer small, clear, well-scoped changes over broad refactors.
- Preserve a simple project structure; avoid adding framework or tooling complexity unless the repository already indicates a need.
- When a build, test, or run command is missing, do not invent a new stack without checking the repository state first.
- Keep documentation concise and practical. If a README or architecture doc is added later, update it instead of duplicating content here.
- Favor explicit names and straightforward interfaces for new code.

## Default expectations for agent work

- Start by confirming the current repository state before making assumptions about language, package manager, or app layout.
- If the repo is still empty or under-defined, prefer the lightest viable implementation and keep decisions easy to undo.
- Add tests or validation only when the project already has a testing pattern; otherwise, validate with the smallest relevant command available.
- Keep changes easy for a new contributor to discover from the repository root.

## When unsure

- Ask for clarification instead of guessing the project architecture.
- Prefer a minimal, reversible change over a premature “full solution.”
- Keep instructions and automation aligned with what is actually in the repo, not with assumptions from similar projects.
