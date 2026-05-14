# PlugDeflect

A Plug that deflects invalid traffic before it hits your router.

Vulnerability scanners, bots, and scripts constantly probe web apps for WordPress, PHP, .env files, and other non-Elixir targets.
PlugDeflect pattern-matches these requests and returns 404 immediately — no router, no controller, no wasted cycles.

## Installation

Add `plug_deflect` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:plug_deflect, github: "afomi/plug_deflect"}
  ]
end
```

## Usage

Add to your `endpoint.ex`, early in the pipeline:

```elixir
plug Plug.RequestId
plug PlugDeflect
plug Plug.Telemetry, event_prefix: [:phoenix, :endpoint]
```

That's it.
Deflected requests are logged at the `:warning` level:

```
[warning] Deflected: GET /wp-admin/install.php from 203.0.113.42
```

## What it deflects

- **Path traversal** — `../../etc/passwd`, including URL-encoded and double-encoded variants
- **Non-Elixir extensions** — `.php`, `.asp`, `.jsp`, `.cgi`, `.env`, `.bak`, `.sql`, `.log`, `.ini`, `.conf`, `.yml`, `.xml`, `.zip`, `.tar.gz`, and more
- **Scanner paths** — WordPress, Drupal, Joomla, Magento, Laravel, Django, Node, Tomcat, Jenkins, Grafana, Spring Boot, phpMyAdmin, CKEditor, and more
- **Dotfile access** — `.git`, `.aws`, `.docker`, `.kube`, `.ssh`, `.htaccess`, `.htpasswd`
- **Backup/dump probes** — `/dump`, `/backup.sql`, `/data.sql`, `/database`
- **Case-insensitive matching** — `/WP-ADMIN/setup.PHP` is caught

## Options

All options are set at compile time via plug opts.
No runtime config, no GenServers.

| Option | Type | Description |
|---|---|---|
| `:extra_extensions` | list of strings | Extensions to deflect in addition to the defaults. Example: `[".cfm", ".pl"]` |
| `:extra_paths` | list of strings | Path prefixes to deflect in addition to the defaults. Example: `["/legacy-admin"]` |
| `:only_extensions` | list of strings | Extensions to deflect, replacing defaults entirely. When set, `:extra_extensions` is ignored. |
| `:only_paths` | list of strings | Path prefixes to deflect, replacing defaults entirely. When set, `:extra_paths` is ignored. |

Extensions must start with `.` and paths must start with `/`.
Invalid values raise `ArgumentError` at compile time.

### Examples

```elixir
# Add to defaults
plug PlugDeflect,
  extra_paths: ["/legacy-admin"],
  extra_extensions: [".cfm"]

# Replace defaults entirely
plug PlugDeflect,
  only_paths: ["/wp-admin", "/xmlrpc"],
  only_extensions: [".php"]
```

## Note on broad extensions

The default extension list includes `.xml`, `.yml`, `.yaml`, and `.log`.
If your app serves these (RSS feeds, sitemaps, CI configs, structured logs), use `:only_extensions` to replace the defaults with a list that fits your app:

```elixir
plug PlugDeflect,
  only_extensions: PlugDeflect.default_extensions() -- [".xml", ".yml", ".yaml"]
```

## Inspecting defaults

```elixir
PlugDeflect.default_extensions()
PlugDeflect.default_paths()
```

## License

MIT — see [LICENSE](LICENSE).
