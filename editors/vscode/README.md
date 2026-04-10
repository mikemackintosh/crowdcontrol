# CrowdControl Policy Language — VS Code Extension

Syntax highlighting, diagnostics, hover documentation, and completion for `.cc` CrowdControl policy files.

## Features

- **Syntax highlighting** — keywords (`forbid`, `warn`, `permit`, `unless`), operators, strings with `{interpolation}`, comments, field paths, numbers, booleans
- **Diagnostics** — real-time parse error reporting with line/column positions
- **Hover** — documentation for all keywords, operators, and built-in functions
- **Completion** — context-aware suggestions for rule blocks, conditions, and field paths

## Requirements

The extension uses `cc-lsp`, a Go-based language server. Build it from the CrowdControl repo:

```bash
# From the crowdcontrol repo root
go build -o bin/cc-lsp ./cmd/cc-lsp

# Add to PATH or configure crowdcontrol.lsp.path in VS Code settings
cp bin/cc-lsp /usr/local/bin/
```

## Installation

### From source

```bash
cd editors/vscode
npm install
npm run compile
```

Then open VS Code, run **Extensions: Install from VSIX** or symlink:

```bash
ln -s $(pwd) ~/.vscode/extensions/crowdcontrol-policy-language
```

### Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `crowdcontrol.lsp.path` | `cc-lsp` | Path to the cc-lsp binary |
| `crowdcontrol.lsp.enabled` | `true` | Enable/disable the language server |

## A note about the `.cc` extension

`.cc` is also the conventional file extension for C++ source. If you have a
C/C++ extension installed (clangd, Microsoft C/C++), it may compete with this
one for `.cc` files. To force CrowdControl as the language for a workspace:

```jsonc
// .vscode/settings.json
{
  "files.associations": {
    "*.cc": "crowdcontrol"
  }
}
```

## Syntax at a Glance

```crowdcontrol
# Forbid with metadata, conditions, unless, and message
forbid "no-public-prod-storage" {
  description "Production storage must not be public"
  owner       "platform-security"

  resource.type == "storage_bucket"
  resource.environment == "production"
  resource.acl in ["public-read", "public-read-write"]

  unless user.groups contains "platform-oncall"

  message "{user.name} cannot make {resource.name} public in prod"
}

# Aggregate check using count()
forbid "blast-radius" {
  count(plan.deletes) > 5
  message "too many deletes ({count(plan.deletes)})"
}

# Non-blocking warning
warn "large-change" {
  count(plan.creates) > 20
  message "large change: {count(plan.creates)} resources"
}

# Permit (override) — emits a message but does not block on its own
permit "platform-team-override" {
  user.groups contains "platform-oncall"
  request.labels contains "emergency"
  message "approved as emergency override"
}
```
