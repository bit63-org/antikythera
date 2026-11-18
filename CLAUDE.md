# Antikythera — steering directives for Claude Code

Antikythera follows kythira's conventions so the two repositories work the
same way. Read `.kiro/steering/` first; specs are in `.kiro/specs/`.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):
`<type>(<optional scope>): <description>` with types `feat`, `fix`, `docs`,
`style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`.
Lowercase imperative description, no trailing period, body wrapped at 72
columns explaining why, every non-obvious decision, and each sub-change.
Do not add a `Co-Authored-By:` trailer.

## Copyright headers

Every new file that can carry a comment opens with

```
Copyright (c) <year> Clark Rawlins
SPDX-License-Identifier: Apache-2.0
```

in its native comment syntax, followed by a blank line: after a `#!` line
in scripts, above `#pragma once` in headers. Exempt: JSON, Markdown,
vendored content (including `vcpkg-overlays/*` portfiles), generated files.

## Code and tests

- `.kiro/steering/cpp-coding-standards.md` and
  `.kiro/steering/test-execution-standards.md` are inherited from kythira.
- Every parser of untrusted input returns `std::expected`, uses `ak::wire`,
  and has unit tests and a fuzz target.
- Run tests with `ctest`.

## Dependencies and caching

Follow kythira: vcpkg manifest mode with kythira's baseline, overlay ports
for anything not in the registry, QUIET optional dependencies exposed as
`AK_HAS_<DEP>`, every dependency in `DEPENDENCIES.md`, and the build cache
as an accelerant, never a dependency. See `.kiro/specs/build-and-ci/`.
