//! Zed extension for the CrowdControl policy language.
//!
//! Tells Zed how to launch the `cc-lsp` language server. The grammar
//! and highlight queries are configured declaratively in
//! `extension.toml` and `languages/crowdcontrol/` — the Rust code
//! here exists solely to resolve the LSP binary.
//!
//! Lookup order for the `cc-lsp` binary:
//!
//!   1. The `cc-lsp` key in Zed's `language_servers` settings if
//!      the user has configured an explicit path (future hook).
//!   2. `worktree.which("cc-lsp")` — PATH lookup via Zed's shell
//!      environment. Works when `cc-lsp` is in `/usr/local/bin`,
//!      `~/go/bin` (if GOPATH/bin is on PATH), or any other PATH
//!      directory.
//!   3. Well-known fallback locations: `$GOPATH/bin/cc-lsp`,
//!      `$HOME/go/bin/cc-lsp`, `/usr/local/bin/cc-lsp`,
//!      `/opt/homebrew/bin/cc-lsp`. These exist because `go install`
//!      puts binaries in `$GOPATH/bin` by default, which isn't
//!      always on the shell PATH that Zed inherits.
//!
//! If none of those work, we return an error that tells the user
//! exactly what to do. Phase B will add auto-download from GitHub
//! Releases once the release workflow has published its first tag.

use std::fs;
use zed_extension_api::{self as zed, LanguageServerId, Result};

struct CrowdControlExtension;

impl CrowdControlExtension {
    /// Resolve the `cc-lsp` binary by walking a list of candidate
    /// paths in order. Returns the first one that exists and is a
    /// file (symlink-aware via `fs::metadata`).
    fn find_cc_lsp(worktree: &zed::Worktree) -> Option<String> {
        // 1. PATH lookup via Zed's worktree shell environment.
        if let Some(path) = worktree.which("cc-lsp") {
            return Some(path);
        }

        // 2. Fallback locations. `go install` drops binaries at
        //    $GOPATH/bin which is often missing from Zed's inherited
        //    PATH; we resolve $HOME + known install dirs manually.
        let home = std::env::var("HOME").unwrap_or_default();
        let gopath = std::env::var("GOPATH").unwrap_or_else(|_| {
            if home.is_empty() {
                String::new()
            } else {
                format!("{home}/go")
            }
        });

        let candidates = [
            format!("{gopath}/bin/cc-lsp"),
            format!("{home}/go/bin/cc-lsp"),
            "/usr/local/bin/cc-lsp".to_string(),
            "/opt/homebrew/bin/cc-lsp".to_string(),
            "/usr/bin/cc-lsp".to_string(),
        ];

        for candidate in candidates {
            if candidate.is_empty() {
                continue;
            }
            if fs::metadata(&candidate)
                .map(|m| m.is_file())
                .unwrap_or(false)
            {
                return Some(candidate);
            }
        }
        None
    }
}

impl zed::Extension for CrowdControlExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        let path = Self::find_cc_lsp(worktree).ok_or_else(|| {
            "cc-lsp not found. Install it with:\n  \
             go install github.com/mikemackintosh/crowdcontrol/cmd/cc-lsp@latest\n\
             \n\
             Then make sure $(go env GOPATH)/bin is on your PATH, \
             or symlink the binary into /usr/local/bin. Pre-built \
             binaries are available at \
             https://github.com/mikemackintosh/crowdcontrol/releases"
                .to_string()
        })?;

        Ok(zed::Command {
            command: path,
            args: vec!["--stdio".to_string()],
            env: Default::default(),
        })
    }
}

zed::register_extension!(CrowdControlExtension);
