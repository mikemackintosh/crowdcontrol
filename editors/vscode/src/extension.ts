import * as path from "path";
import { workspace, ExtensionContext } from "vscode";
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  Executable,
} from "vscode-languageclient/node";

let client: LanguageClient;

export function activate(context: ExtensionContext) {
  const config = workspace.getConfiguration("crowdcontrol.lsp");
  const enabled = config.get<boolean>("enabled", true);

  if (!enabled) {
    return;
  }

  const lspPath = config.get<string>("path", "cc-lsp");

  const serverExecutable: Executable = {
    command: lspPath,
    args: ["--stdio"],
  };

  const serverOptions: ServerOptions = {
    run: serverExecutable,
    debug: serverExecutable,
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [{ scheme: "file", language: "crowdcontrol" }],
    synchronize: {
      fileEvents: workspace.createFileSystemWatcher("**/*.cc"),
    },
  };

  client = new LanguageClient(
    "crowdcontrol-lsp",
    "CrowdControl Policy Language",
    serverOptions,
    clientOptions
  );

  client.start();
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}
