# permio-cli

npm wrapper for [`permio`](https://github.com/PrivateJAR/permio-cli), the
perms.io command-line interface. It lets you (and AI agents) run the CLI with
`npx` without installing Go or a binary by hand:

```sh
npx permio-cli check user_123 /documents/42 document.read
npm install -g permio-cli && permio --help
```

## How it works

The package contains no binary. On install (`postinstall`), or on first run if
install scripts were skipped, it downloads
`permio_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) from the GitHub
release `v<version>` matching this package's version, checks its SHA-256
against the release's `checksums.txt`, and extracts `permio` into `vendor/`.
`bin/permio.js` then runs it with the same arguments, stdio and exit code.

Supported: macOS, Linux and Windows on x64 and arm64, Node 18+.

Environment variables:

| Variable | Effect |
| --- | --- |
| `PERMIO_CLI_DOWNLOAD_BASE` | Download from this base URL instead of GitHub releases (a mirror). |
| `PERMIO_CLI_BINARY` | Use this existing `permio` binary; nothing is downloaded. |

## Publishing (maintainers)

Not published yet. For each release:

1. Tag `vX.Y.Z` and let the release workflow build the binaries; publish the
   draft GitHub release (downloads only work once it is public).
2. Set `"version": "X.Y.Z"` in `npm/package.json` (it must equal the tag
   without the `v`).
3. `cd npm && npm publish --access public`.

The package is `permio-cli` because the name `permio` is the JavaScript SDK.
`npx permio-cli` runs the `permio` binary, the package's only command.
