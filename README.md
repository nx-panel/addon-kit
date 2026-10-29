# NX addon kit

What every [NX](https://nx-panel.org) addon would otherwise write
again. An addon is a separate program — its own container or service, its own
database — that talks to the NX panel over the network only: a scoped API
token, signed webhook events, and the manifest that says what it needs.

| Package | What it does |
| --- | --- |
| [`manifest`](manifest) | The manifest (`nx-addon.json`), its validation, signature and the setup body — the same code the panel validates with. Spec: [SPEC.md](SPEC.md) |
| [`addon`](addon) | The running half: serves the manifest, takes the credentials at registration (claim code) — and drops an earlier install's when a new one brings another code (`NewInstall`) — verifies the panel's event deliveries, answers the health check, reads the install's answers (`NX_OPT_*`) |
| [`panel`](panel) | A small client for the panel's `/api/v1` with the addon's token, idempotency keys and a 429 wait |
| [`auth`](auth) | An addon's own admin sign-in: bcrypt passwords, session tokens kept as hashes, a TOTP second factor like the panel's, a limiter for failed attempts |
| [`telegram`](telegram) | A small Telegram Bot API client — messages, buttons, files, long polling — through the operator's proxy or a Bot API mirror; also Bale, whose Bot API is Telegram's at another address |
| [`web`](web) | An addon's admin under the install's base path with its public pages outside it, HTTPS for the public address — a certificate the panel holds for the addon (`panel`, fetched from it, so several addons share a host with no port 443 of their own), ACME by TLS-ALPN-01 or HTTP-01, or a self-signed certificate for an address by IP — and the check that the address reaches this very program |
| [`cmd/nx-addon`](cmd/nx-addon) | `check`, `keygen`, `sign` and `verify` a manifest; `sign-sums` and `verify-sums` a release's `SHA256SUMS` ([SPEC](SPEC.md#the-releases-checksums-signed)) |

```go
raw, _ := os.ReadFile("nx-addon.json")
a, err := addon.New(addon.Config{Manifest: raw, DataDir: "data"}.FromEnv())
if err != nil { log.Fatal(err) }
a.OnEvent(func(e addon.Event) { log.Printf("%s %s", e.Event, e.Data) })
mux := http.NewServeMux()
a.Mount(mux)
log.Fatal(http.ListenAndServe(":8090", mux))
```

Start from [`addon-template`](https://github.com/nx-panel/addon-template),
a complete minimal addon with a compose file, a binary release and an install
script. Addons are listed at [addons.nx-panel.org](https://addons.nx-panel.org)
as official, verified or unofficial.

Licensed under the Apache License 2.0, so an addon built on the kit may be
open or closed.
