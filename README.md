# roundup

CLI tool for fetching and merging kubeconfigs from multiple [Rancher](https://www.rancher.com/) servers into a single file.

If you manage clusters across several Rancher instances, `roundup` authenticates to each one, discovers all clusters, downloads their kubeconfigs, handles naming conflicts, and writes a merged kubeconfig with secure file permissions.

## Install

### Homebrew

```sh
brew install imandrew/tap/roundup
```

### From source

```sh
cargo install --git https://github.com/imandrew/roundup --locked
```

## Quick start

```sh
# Add your Rancher servers
roundup add https://rancher.prod.example.com -u admin
roundup add https://rancher.staging.example.com -u admin

# Fetch and merge all kubeconfigs
roundup fetch

# Use the merged kubeconfig
export KUBECONFIG=~/.kube/roundup-config
kubectl get nodes
```

## Usage

```
roundup [OPTIONS] <COMMAND>
```

### Global options

| Flag | Description |
|---|---|
| `-v`, `-vv` | Verbose logging (info / debug) |
| `--config <PATH>` | Config file path (default: `~/.config/roundup/config.yaml`) |

### Commands

#### `add` - Add a Rancher server

```sh
roundup add <URL> -u <USERNAME> [-A <AUTHTYPE>]
```

Supported auth types: `local` (default), `openldap`, `activedirectory`, `github`, `googleoauth`, `azuread`, `keycloak`, `ping`, `okta`, `freeipa`, `shibboleth`.

#### `list` - List configured servers

```sh
roundup list
```

#### `remove` - Remove a server by URL or hostname

```sh
roundup remove <URL_OR_HOSTNAME>
```

#### `fetch` - Fetch and merge kubeconfigs

```sh
roundup fetch [-o <PATH>] [-x <PATTERN>]... [--insecure]
```

| Flag | Description |
|---|---|
| `-o`, `--output` | Output path (default: `~/.kube/roundup-config`) |
| `-x`, `--exclude` | Exclude clusters matching a regex (repeatable) |
| `--insecure` | Skip TLS certificate verification |

Examples:

```sh
# Exclude clusters matching a pattern
roundup fetch -x "^test-" -x "local"

# Write to a custom path
roundup fetch -o ~/my-kubeconfig
```

## How it works

1. **Authenticate** to each configured Rancher server, reusing cached tokens when valid and proactively rotating tokens expiring within 24 hours.
2. **Discover** all clusters from each server via the Rancher API.
3. **Download** kubeconfigs concurrently (up to 5 at a time) with automatic retries.
4. **Namespace** cluster/context/user names to avoid conflicts. Names that appear in more than one server get a `-<hostname>` suffix (e.g. `local` becomes `local-rancher-prod-example-com`). Unique names are left unchanged.
5. **Filter** clusters matching any `--exclude` regex patterns.
6. **Merge** everything into a single kubeconfig and write it with secure permissions (`0600` file, `0700` directory).

## Environment variables

| Variable | Description |
|---|---|
| `ROUNDUP_RANCHER_PASSWORD` | Password for non-interactive use (applies to all servers) |

## License

[MIT](LICENSE)
