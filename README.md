# permio

`permio` is the command-line interface for [perms.io](https://perms.io). Use it to
check permissions, manage permissions, roles, grants and groups, and keep a
whole project in a `permio.yaml` file (plan, apply, export).

It is built for scripts, CI and AI agents as well as people: every command
takes `--json`, exit codes are distinct and documented, and it never prompts
when stdin is not a terminal.

```console
$ permio check user_123 /projects/42/documents/7 document.edit --explain
denied: user_123 does not have document.edit on /projects/42/documents/7
  missing on /projects/42/documents/7: document.edit
$ echo $?
1
```

- [Install](#install)
- [Authentication and configuration](#authentication-and-configuration)
- [Concepts](#concepts)
- [Commands](#commands)
- [Config as code](#config-as-code)
- [Output, exit codes and errors](#output-exit-codes-and-errors)
- [Using with AI agents](#using-with-ai-agents)
- [Roadmap](#roadmap)
- [Development](#development)

## Install

Not released yet. Once it is:

```sh
# Homebrew (macOS, Linux)
brew install PrivateJAR/tap/permio

# npm / npx (downloads the prebuilt binary for your platform)
npx permio-cli --help
npm install -g permio-cli

# Go 1.24+
go install github.com/PrivateJAR/permio-cli/cmd/permio@latest
```

Prebuilt archives for macOS, Linux and Windows (amd64 and arm64), with a
`checksums.txt`, are attached to each
[GitHub release](https://github.com/PrivateJAR/permio-cli/releases).

Shell completion: `permio completion bash|zsh|fish|powershell --help` explains
how to load it.

## Authentication and configuration

`permio` authenticates with a perms.io **API key**. Create one in the dashboard
at [app.perms.io](https://app.perms.io). A key belongs to one organisation and
one project:

- a **check-only** key can run checks and read permissions, roles, grants and
  groups (enough for `check`, `access`, `list`/`get`, `plan` and `export`);
- a **full-access** key can also create, update and delete them (needed for
  `create`, `update`, `delete`, `grants add/remove`, `groups members add/remove`
  and `apply`).

Keys look like `perms_` followed by 38 letters and digits, and end in a
checksum, so `permio` rejects a mistyped or truncated key before making any
request. Legacy JWT keys are also accepted.

Settings, from highest to lowest precedence:

| Setting | Flag | Environment | Profile key | Default |
| --- | --- | --- | --- | --- |
| API key | `--api-key` | `PERMIO_API_KEY` | `api-key` | none |
| API URL | `--api-url` | `PERMIO_API_URL` | `api-url` | `api.perms.io:443` (production) |
| Project | `--project` | `PERMIO_PROJECT` | `project` | `default` |
| Profile | `--profile` | `PERMIO_PROFILE` | `permio config use` | `default` |

`--api-url` accepts `host`, `host:port`, `https://host[:port]`, or the aliases
`prod` and `dev` (`dev-api.perms.io:443`).

### Profiles

Profiles live in `~/.config/permio/config.yaml` (or `$XDG_CONFIG_HOME/permio/`,
or the path in `PERMIO_CONFIG`). The file is written with `0600` permissions
because it holds API keys.

```sh
permio config set api-key perms_...                      # default profile
printf '%s' "$KEY" | permio config set api-key -         # read the key from stdin
permio config set --profile dev api-url dev
permio config set --profile dev api-key perms_...
permio config set --profile dev project staging
permio config use dev                                    # make dev the current profile
permio config list                                       # profiles (keys redacted) and effective settings
permio config unset --profile dev project
permio config path
```

```yaml
# ~/.config/permio/config.yaml
current_profile: dev
profiles:
  default:
    api_key: perms_...
  dev:
    api_key: perms_...
    api_url: dev
    project: staging
```

`permio config list` shows where each effective value comes from (flag, env,
profile or default), which helps when a command uses an unexpected key.

## Concepts

- **Permissions** are named actions, such as `document.read`.
- **Roles** are named sets of permissions. The API identifies roles by ID; the
  CLI accepts a role's ID or its exact name everywhere.
- **Resources** are hierarchical URIs such as `/projects/42/documents/7`. A
  grant on a URI applies to that URI and everything below it. A `_` segment in a
  granted URI matches any one segment: a grant on `/projects/_/public` applies to
  `/projects/42/public/readme`.
- **Grants** give a principal (any user or service ID you choose) roles and/or
  permissions on a resource URI. Granting is additive.
- **Groups** are named sets of principals. Grant to the principal
  `group:<slug>` and every member holds the grant. Groups cannot contain groups.
- A **denied check is a normal answer** (`allowed: false`, exit code 1), not an
  error.

The full documentation is at [docs.perms.io](https://docs.perms.io)
([LLM-friendly version](https://docs.perms.io/llms-full.txt)).

## Commands

Every command has `--help` with examples. Global flags: `--api-key`,
`--api-url`, `--project`, `--profile`, `--json`, `--quiet`/`-q`, `--timeout`
(per request, default 15s).

```
permio
├── check <principal> <resource> <permission...> [--explain]
│   └── batch <principal> -p <permission>... [resource... | -]
├── permissions  list [--search] | get <name> | create <name...> [--description]
│                update <name> [--description] [--rename] | delete <name...>
├── roles        list [--search] | get <id|name> | create <name> -p <perm>... [--description]
│                update <id|name> [--name] [--description] [-p ...] [--add-permission ...] [--remove-permission ...]
│                delete <id|name...>
├── grants       list [--principal] [--resource]
│                add    --principal --resource [-r <role>...] [-p <perm>...]
│                remove --principal --resource [-r <role>...] [-p <perm>...] [--all]
├── groups       list [--search] | get <slug> | create <slug> [--description] [--member ...]
│                update <slug> --description | delete <slug...>
│                members list <slug> | add <slug> <principal...> | remove <slug> <principal...>
├── access       list --principal --permission --under [--allows <uri>...]
│                who  --resource [--permission] [--expand-groups]
├── plan   [-f permio.yaml] [--prune]
├── apply  [-f permio.yaml] [--prune] [--yes]
├── export [-o permio.yaml]
├── config set <key> <value> | unset <key> | use <profile> | list | path
├── version
└── completion bash|zsh|fish|powershell
```

### check

```sh
permio check user_123 /documents/42 document.read                 # exit 0 allowed, 1 denied
permio check user_123 /documents/42 document.read document.edit   # all must be held
permio check user_123 /documents/42 document.edit --explain       # list what is missing
permio check user_123 /documents/42 document.read -q && echo ok   # exit code only
permio check user_123 /documents/42 document.read --json
```

`check batch` answers many resources at once (one result each). Resources come
from arguments, or from stdin, one per line, when there are none or the only one
is `-`. It exits 0 only if every resource is allowed.

```sh
permio check batch user_123 -p document.read /documents/1 /documents/2
cat uris.txt | permio check batch user_123 -p document.read --json
```

### permissions

```sh
permio permissions list [--search document]
permio permissions get document.read
permio permissions create document.read document.edit --description "Document access"
permio permissions update document.read --description "Read any document"
permio permissions update doc.read --rename document.read
permio permissions delete document.delete
```

### roles

```sh
permio roles list
permio roles get editor                         # by name or ID
permio roles create editor -p document.read -p document.edit --description "Can edit"
permio roles update editor --add-permission document.delete
permio roles update editor --remove-permission document.delete
permio roles update editor -p document.read     # replace the whole permission list
permio roles update editor --name writer
permio roles delete writer
```

Remove a permission from roles before deleting the permission.

### grants

```sh
permio grants list --principal user_123                  # every grant to user_123
permio grants list --resource /documents/42              # every grant made on exactly /documents/42
permio grants list --principal user_123 --resource /documents/42
permio grants list                                       # every grant in the project

permio grants add --principal user_123 --resource /documents/42 --role editor
permio grants add --principal group:design --resource /projects/7 -r viewer -p comment.create
permio grants remove --principal user_123 --resource /documents/42 --role editor
permio grants remove --principal user_123 --resource /documents/42 --all
```

`grants list` shows grants made directly on a URI. To include inherited,
wildcard and group access, use `permio access who`.

### groups

```sh
permio groups create design --description "Design team" --member user_123 --member user_456
permio groups list
permio groups get design                     # with members
permio groups update design --description "Product design"
permio groups members list design
permio groups members add design user_789
permio groups members remove design user_456
permio groups delete design                  # also removes its memberships and grants
```

### access

`access list` answers *"where may this principal use this permission under this
URI?"*, counting direct, role, group, inherited and wildcard grants. Use it to
filter lists in your own database.

```sh
permio access list --principal user_123 --permission document.read --under /documents
permio access list --principal user_123 --permission document.read --under /documents \
  --allows /documents/42 --allows /documents/43     # exit 0 only if all are covered
```

The JSON output has `covers_all` (true: everything under `--under` is
allowed), `scopes` (`subtree` or `pattern`), `prefixes` (subtree URIs to match as
`path = p OR path LIKE p || '/%'`) and `patterns` (URIs with `_` segments).

`access who` answers *"who has access to this resource?"*:

```sh
permio access who --resource /documents/42
permio access who --resource /documents/42 --permission document.edit --expand-groups --json
```

## Config as code

Describe a project in `permio.yaml`, review the diff with `plan`, and make it so
with `apply`. `export` writes the project's current state in the same format.

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/PrivateJAR/permio-cli/main/schema/permio.schema.json
project: default
permissions:
  - document.read
  - { name: document.edit, description: Edit documents }
roles:
  editor: { description: Can edit, permissions: [document.read, document.edit] }
groups:
  design: { description: Design team, members: [user_123] }
grants:
  - { principal: group:design, resource: /projects/123, roles: [editor], permissions: [] }
```

```sh
permio export > permio.yaml              # start from the current state
permio plan -f permio.yaml               # + create, ~ update, - delete; changes nothing
permio apply -f permio.yaml              # shows the plan and asks for "yes"
permio apply -f permio.yaml --yes        # CI
permio plan  -f permio.yaml --prune      # also delete what is not in the file
permio apply -f permio.yaml --prune --yes
```

Rules:

- `project` is optional and defaults to the configured project. If it is set and
  `--project`/`PERMIO_PROJECT` names a different project, the command fails.
- Roles are keyed by **name** in the file; `permio` resolves them to IDs.
- A role's `permissions`, a group's `members` (when given) and a grant's
  `roles` and `permissions` are each the **full set**: entries not listed are
  removed, even without `--prune`. Leave out `members` to leave a group's
  members alone. Give a grant empty lists to revoke everything on that pair.
- An omitted `description` (or a bare permission name) leaves the description
  as it is.
- List each (principal, resource) pair once.
- Without `--prune`, `apply` only creates and updates. With `--prune` it also
  deletes permissions, roles, groups, and grants on (principal, resource) pairs
  that are not in the file.
- Changes run in dependency order: permissions, roles, groups, members, grants.
  Deletions run after, in reverse: grants, groups, roles, permissions.
- `apply` asks for confirmation. When stdin is not a terminal, with `--json`, or
  with `-f -`, it does not prompt and requires `--yes`.
- `apply` stops at the first failure. The changes before it stay applied, and
  running `apply` again continues from there. Applying the same file twice makes
  no further changes, and `plan` of an exported file shows no changes.

**Editor autocompletion:** the JSON Schema is
[`schema/permio.schema.json`](schema/permio.schema.json). Exported files start
with a `yaml-language-server` comment that points to it, which the YAML
extensions for VS Code, JetBrains IDEs and Neovim pick up. See
[`examples/permio.yaml`](examples/permio.yaml) for a complete example.

## Output, exit codes and errors

| Exit code | Meaning |
| --- | --- |
| `0` | Success. For `check`, `check batch` and `access list --allows`: allowed. |
| `1` | Denied (`check`, `check batch`, `access list --allows`). |
| `2` | Usage error, invalid input, or an API error (not found, unavailable, timeout...). |
| `3` | Authentication error: no API key, a malformed key, or a key the API rejected. |
| `4` | Permission denied for the key: e.g. a check-only key trying to write, or a key used with another project. |

**JSON.** With `--json`, results go to stdout as a single JSON document whose
shape is stable (fields may be added, never renamed or removed). Lists are
always arrays, never `null`. Examples:

```jsonc
// permio check user_123 /documents/42 document.read document.edit --json
{ "allowed": false, "principal": "user_123", "resource": "/documents/42",
  "permissions": ["document.read", "document.edit"],
  "missing": [{ "resource": "/documents/42", "permissions": ["document.edit"] }] }

// permio roles get editor --json
{ "id": "...", "name": "editor", "description": "Can edit", "permissions": ["document.edit", "document.read"] }

// permio grants list --principal user_123 --json
{ "grants": [{ "principal": "user_123", "resource": "/documents/42",
               "roles": [{ "id": "...", "name": "editor" }], "permissions": [] }] }

// permio plan -f permio.yaml --json
{ "project": "default", "prune": false,
  "changes": [{ "action": "create", "kind": "role", "name": "editor", "add_permissions": ["document.edit", "document.read"] }],
  "summary": { "create": 1, "update": 0, "delete": 0 } }
```

List commands wrap their items: `{"permissions": [...]}`, `{"roles": [...]}`,
`{"groups": [...]}`, `{"grants": [...]}`. `apply --json` prints
`{"project", "plan", "applied", "summary"}`, also when it stops on a failure.

**Errors** go to stderr. With `--json` they are JSON too:

```json
{ "error": { "kind": "permission_denied", "message": "permission denied for the API key",
             "grpc_code": "PermissionDenied", "exit_code": 4,
             "missing": [{ "resource": "/organisation/.../project/default", "permissions": ["permission.create"] }] } }
```

`kind` is one of `usage`, `config`, `auth`, `permission_denied`,
`invalid_argument`, `not_found`, `already_exists`, `unavailable`, `timeout`,
`error`.

**Quiet.** `--quiet` suppresses status messages. `check` prints nothing at all
(use the exit code); `list` commands print one identifier per line (`grants list`:
principal and resource, tab-separated).

**Retries.** Read-only calls are retried twice with backoff on `Unavailable`
and timeouts. Writes are never retried.

## Using with AI agents

Agents can use `permio` directly from a shell; no extra server is needed.

- Pass `--json` and read stdout; errors are JSON on stderr. Branch on the exit
  code: `0` allowed/success, `1` denied, `2` usage or API error, `3`
  authentication, `4` the key may not do this.
- Provide the key through `PERMIO_API_KEY` (and `PERMIO_PROJECT`), not on the
  command line.
- `permio --help` and `permio <command> --help` describe every command with
  examples, so an agent can discover the CLI without these docs.
- Prefer a **check-only** key for agents that only need to check and read, and
  `plan` before `apply`. `apply` never prompts without a terminal; it requires
  `--yes`.
- With npm available and nothing installed, `npx permio-cli ...` works the same
  way.

```sh
export PERMIO_API_KEY=perms_... PERMIO_PROJECT=default
permio check user_123 /documents/42 document.read --json; echo "exit=$?"
permio export --json
permio plan -f permio.yaml --json
```

## Roadmap

- **`permio login` (v2).** Organisation-level objects (projects, API keys, team
  members) need a dashboard user, not an API key. A browser-based
  `permio login` flow will add commands for them. v1 manages project-level
  objects with API keys only.

## Development

```sh
go vet ./...
go test -race ./...
```

The tests run every command end to end against an in-memory fake of the
PermissionsService (`pkg/fakeserver`) over `bufconn`. Live tests against a real
API run when `PERMIO_TEST_API_KEY` and `PERMIO_TEST_API_URL` are set
(`PERMIO_TEST_PROJECT` defaults to `default`); they only read unless
`PERMIO_TEST_WRITE=1` is also set, in which case they create uniquely named
objects and delete them again.

Layout:

| Path | Contents |
| --- | --- |
| `cmd/permio` | `main` |
| `internal/cli` | Cobra commands and output |
| `internal/settings` | config file, profiles and precedence |
| `pkg/permio` | gRPC client: auth, retries, typed errors, pagination helpers |
| `pkg/configsync` | `permio.yaml` parsing, export, plan and apply (reusable by other tools) |
| `pkg/apikey` | local API key format validation |
| `pkg/fakeserver` | in-memory PermissionsService for tests |
| `schema/` | JSON Schema for `permio.yaml` |
| `npm/` | npm wrapper package (`permio-cli`) |

The `pkg/` packages are pre-1.0 and may change.

Releases are built by GoReleaser (`.goreleaser.yaml`) from `v*` tags via
`.github/workflows/release.yml`.

## License

MIT
