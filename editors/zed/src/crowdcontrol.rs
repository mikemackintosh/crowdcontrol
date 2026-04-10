//! Zed extension for the CrowdControl policy language.
//!
//! This extension tells Zed two things:
//!
//!   1. How to find the `cc-lsp` binary — the CrowdControl language
//!      server that ships as a sibling of `cc` in the reference
//!      distribution. We look up the binary on `$PATH` so a user who
//!      ran `go install github.com/mikemackintosh/crowdcontrol/cmd/cc-lsp@latest`
//!      gets language server support for free.
//!
//!   2. Where the tree-sitter grammar and highlight queries live —
//!      that part is declared in `extension.toml`, not here.
//!
//! The extension does nothing clever — no auto-downloading, no
//! version checks, no settings. If the binary isn't on PATH, we
//! return an error message pointing the user at the install
//! instructions. Phase B will add auto-download from GitHub
//! Releases once the release workflow has published its first tag.

use zed_extension_api::{self as zed, LanguageServerId, Result};

struct CrowdControlExtension;

impl zed::Extension for CrowdControlExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        _language_server_id: &LanguageServerId,
        worktree: &zed::Worktree,
    ) -> Result<zed::Command> {
        // Look for `cc-lsp` on PATH. If the user has `cc-lsp` in their
        // GOPATH/bin (from `go install`), or installed from a release
        // archive into /usr/local/bin, we'll find it here.
        let path = worktree.which("cc-lsp").ok_or_else(|| {
            "cc-lsp not found on PATH. Install it with: \
             go install github.com/mikemackintosh/crowdcontrol/cmd/cc-lsp@latest \
             — or grab a pre-built binary from \
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
