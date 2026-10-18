# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `permio check` with exit codes 0 (allowed), 1 (denied), 2+ (error) and
  `--explain`; `permio check batch` for many resources from arguments or stdin.
- `permio permissions`, `roles`, `grants` and `groups` (including
  `groups members`) commands for project-level objects. Roles can be referred
  to by ID or name.
- `permio access list` (scopes, prefixes, patterns, `--allows`) and
  `permio access who` (`--permission`, `--expand-groups`).
- Config as code: `permio plan`, `permio apply` (`--prune`, `--yes`) and
  `permio export` for `permio.yaml` files, with a JSON Schema in
  `schema/permio.schema.json`.
- Authentication with API keys (format and checksum validated locally) from
  `--api-key`, `PERMIO_API_KEY` or named profiles in
  `~/.config/permio/config.yaml`, managed with `permio config`.
- `--json` on every command, `--quiet`, JSON errors on stderr, and distinct exit
  codes for usage/API errors (2), authentication errors (3) and keys that lack
  permission (4).
- Retries with backoff for read-only calls.
- `permio version` and shell completion.
- Release configuration (GoReleaser, Homebrew cask, GitHub Actions) and an npm
  wrapper package in `npm/`.

### Fixed

- `permissions delete` of a permission that does not exist now succeeds, as
  documented, instead of failing with "failed to delete permission".
- Creating a permission or role whose name is already taken (with a different
  description or permissions) now reports `already_exists` with the existing
  object, instead of a bare "failed to create ...".
