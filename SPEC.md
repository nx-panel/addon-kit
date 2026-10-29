# The addon manifest, version 1

The contract between an NX addon and the panel, the directory at
`addons.nx-panel.org` and the panel's install wizard. The code that
enforces it is the `manifest` package of this module — the panel validates
with the same code — so when this file and the code disagree, the code is
right and this file is the bug. `api: 1` may still change until the first
release of NX Shop, when it is frozen.

## Where it lives

- **`nx-addon.json` at the root of the addon's public repository** — what
  the directory and the install wizard read before anything runs. For a
  closed addon that is its public distribution repository.
- **The same file served by the running addon** at
  `/.well-known/nx-addon.json`, which registration reads.
- **Signed**: an official addon by NX, a verified one with its
  developer's own key (`nx-addon keygen` / `sign`), which the
  directory's signed index vouches for. The signature covers every field but
  `signature`, re-encoded with keys sorted, so the file may be indented or
  reordered freely. An unsigned addon is registered by hand. A manifest that names one key twice in any object is refused: a map keeps the last and a struct merges them, so the two would be different documents.

## Fields

| Field | Required | Meaning |
| --- | --- | --- |
| `api` | yes | `1` (this document) or `0` (Phase F's; may not carry any field below marked v1) |
| `slug` | yes | the addon id: `a-z0-9_-`, starting with a letter or digit, at most 32 |
| `name` | yes | at most 64 characters |
| `version` | | the release, semver; the directory compares it for update badges |
| `publisher` | | at most 64 characters |
| `scopes` | one of scopes/webhook | `[{scope, purpose}]`, the API token's permissions, each with the reason shown on the consent screen |
| `events`, `webhook` | together | the events the addon hears and the path they are POSTed to. Each event is granted by the scope the panel's catalog names for it (`GET /api/events`), and that scope — or its `:write` — must be among `scopes`, or the panel refuses the manifest; `panel.addon_removed` is the exception, since an addon is told of its own removal whatever it holds. (Panels from G0-S5 on; before, an event's scope was not checked.) |
| `setup` | yes | the path the credentials are delivered to, with the claim code. `setup`, `webhook` and `health` are three different clean paths, none of them the manifest's own: each starts with `/`, has no empty, `.` or `..` segment (a trailing `/` is fine) and none of `? # % { } \` or spaces |
| `health` | | a path answering 200 when healthy; polled every minute |
| `ui` | | the entry point: a path or an absolute http(s) URL |
| `description` | v1 | by language (`en`, `fa`, `ru`, `zh`), English required when given, at most 500 each |
| `license` | v1 | an SPDX id or `proprietary`, at most 64 |
| `paid` | v1 | the addon is sold; its licence is its own, the panel checks nothing |
| `docs` | v1 | an absolute http(s) URL |
| `requires.panel` | v1 | `">=X.Y.Z"`; a panel older than that refuses the addon and says why |
| `install` | v1 | how it is installed, below; an addon without one can only be registered by its address |
| `rateLimit` | v1 | requests a minute the token may make, 1–600; absent is the panel's default, 120. Shown on the consent screen; a newer manifest asking more waits for approval |
| `signature` | | base64 Ed25519 |

## `install`

```json
"install": {
  "docker": { "image": "ghcr.io/nx-panel/shop", "compose": "deploy/compose.yml" },
  "binary": { "linux-amd64": "shop-linux-amd64.tar.gz", "linux-arm64": "shop-linux-arm64.tar.gz" },
  "options": [ … ]
}
```

- **`docker.image`** is a registry path **without a tag**: the release's
  version is the tag. **`docker.compose`** is a relative path in the
  repository and the release.
- **`binary`** maps a platform (`linux-amd64`, `linux-arm64`, `linux-armv7`,
  `linux-armv6`, `linux-armv5`, `linux-386`, `linux-s390x`, `linux-riscv64`)
  to a release asset's file name; the addon's install script puts it under
  systemd (`--method script`).
- At least one of the two.

### The release's checksums, signed

A release publishes **`SHA256SUMS`** — every asset, `install.sh` and the
binaries among them, as `sha256sum` writes it — and **`SHA256SUMS.sig`**,
the signature over it made with **the key that signs the manifest**, after
the build:

```sh
nx-addon sign-sums -key addon.key SHA256SUMS > SHA256SUMS.sig
gh release upload v1.2.3 SHA256SUMS.sig
```

The signature is the base64 Ed25519 signature of `nx-addon SHA256SUMS
v1\n` followed by the file's bytes (`manifest.SignSums`, `VerifySums`), so
it can never pass for a manifest's. The panel installs, updates or removes
an addon over SSH only when the release's `install.sh` — and, for a
script install, its binary — match a `SHA256SUMS` that the key which signed
the release's manifest signed; a release without `SHA256SUMS.sig` is
installed by its command. A script install the host downloads itself
(`source: host`) is handed the binary's checksum as `--sha256`, which the
install script checks. A Docker install's image is pulled by its tag and is
not covered. The manifest names no digest itself: an addon embeds its
manifest in its binary, so the binary's digest cannot be in it. (Panels
from GA-S10 on; before, only the unsigned `SHA256SUMS` was read.)

## `install.options`

The questions the install asks, at most 32, in the order shown:

```json
{ "key": "database", "type": "choice", "choices": ["sqlite", "postgres"], "default": "sqlite",
  "label": { "en": "Database", "fa": "پایگاه داده" } },
{ "key": "database_dsn", "type": "secret", "required": true, "when": { "database": "postgres" },
  "label": { "en": "PostgreSQL DSN" } }
```

| Field | Meaning |
| --- | --- |
| `key` | `a-z0-9_`, starting with a letter, at most 32; unique |
| `type` | `string`, `secret`, `password`, `number`, `port`, `bool`, `choice`, `url`, `path` — the whole list |
| `label` | by language, English required, at most 80 each |
| `help` | by language, at most 300 each |
| `default` | a JSON value of the option's type; never on a `secret` or a `password` |
| `required` | the install cannot go on without an answer |
| `choices` | a `choice`'s values, 1–32, each at most 64 |
| `when` | `{ "<key>": "<value>" }` — shown only while that option, declared **before** this one and a `choice` or `bool`, has that value (`"true"` / `"false"` for a bool) |

Answers reach the addon as **environment variables `NX_OPT_<KEY>`** (an
`.env` beside the compose file, or the systemd unit's `EnvironmentFile`),
beside **`NX_PANEL_URL`** and **`NX_CLAIM_CODE`**, the code the panel
issued for the install. A `bool` is `true` / `false`, a number in its
JSON spelling.

A **`password`** is a `secret` that becomes the addon's admin password: at
least 10 characters and at most 72 bytes, the rule the kit's sign-in
(`auth`) holds a password to, so the panel refuses a shorter one in its form
instead of the addon refusing it once installed. A panel older than the type
(before kit v0.4.2, panel 0.0.3) refuses such a manifest outright, as it
does a `path` — set `requires.panel` (`>=0.0.3`) all the same.

A new claim code over the data of an earlier install — the addon removed
without its data, then installed again — is a **new install**: the kit
drops the earlier registration it kept, so the panel that issued the code
can register the addon, and `Addon.NewInstall` tells the addon to apply the
answers it otherwise uses only once (its first admin's password); once
they are stored the addon calls `Addon.NewInstallApplied`, and a restart —
before the new install registers or after — is not a new install again. An
update keeps the claim code.

A **`path`** is the base path the addon serves its admin under: one segment
of letters, digits, `-` and `_` (at most 64), with or without slashes, or
empty for the root; at most one per manifest. The panel's install wizard
proposes a random one when the option has no `default`, and joins the
answer into the address it registers the addon at, as it does the `port`;
a script install draws one when the command gives none. The addon serves
its admin, its API and the routes the panel calls — the manifest, `setup`,
the webhook, `health` — under it, and the pages its customers open outside
it (`web.Mount`). A panel older than the type (before kit v0.3.0) refuses
such a manifest outright — "type must be one of …" — before it reads
`requires.panel`; set `requires.panel` all the same, and say in the release
notes which panel it needs.
