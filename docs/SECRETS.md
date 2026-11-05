# Secrets And API Keys

The gateway reads its XSIAM API key from environment variables. Where those
variables come from is the operator's choice, and the usual shortcut, a `.env`
file with the key typed into it, is the weakest one. This page explains why
and shows how to keep the key in 1Password, the macOS Keychain or the Windows
SecretStore, so that it is released to the gateway only when it starts and
only after a person has approved the read.

## Why Not A `.env` File

A plaintext `.env` file is readable by every process that runs as your user:
every editor extension, every package you install, every AI coding agent with
file access, and every backup or sync client. It is copied whenever the
repository folder is copied, it shows up in `grep`, and it is one mistaken
`git add` away from a public commit. An XSIAM API key is a bearer credential.
Whoever holds it can read whatever the key's role can read, from anywhere,
until the key is revoked in the tenant, and the gateway's audit log then names
the gateway's principal, not the person who took the key.

A `.env` file is still the right place for settings that are not secret:
transport, policies, limits and the tenant API URL. Keep those there, and keep
the secrets out of it.

## Which Settings Are Secrets

| Variable | Why |
| --- | --- |
| `CORTEX_MCP_PAPI_AUTH_HEADER` | The XSIAM API key. Grants everything the key's role allows. |
| `CORTEX_MCP_PAPI_AUTH_ID` | The key id. An identifier rather than a secret, but it belongs with the key. |
| The variables named by `api_key_env` and `api_key_id_env` in `XSIAM_CREDENTIAL_PROFILES` | Role-scoped XSIAM API keys for the credential broker. |
| `DATASET_QUERY_CURSOR_SECRET` | Encrypts and authenticates continuation cursors. |
| `MCP_GATEWAY_SHARED_SECRET` | HMAC key for signed identity headers from an AI gateway. |
| `AUDIT_LOG_XSIAM_HTTP_COLLECTOR_API_KEY` | Writes to the tenant's HTTP log collector. |
| `XSIAM_LIVE_API_KEY`, `XSIAM_LIVE_API_KEY_ID` | Credentials for the opt-in live test suite. |

`CORTEX_MCP_PAPI_URL` is not a secret, but it names your tenant. Keep it out of
anything you publish.

## How The Gateway Reads Them

Settings are loaded by pydantic-settings: process environment variables first,
then a `.env` file in the working directory. A variable set in the environment
always wins over the same variable in `.env`. The pattern on this page follows
from that: non-secret settings in `.env`, secrets injected into the
environment by a tool that stores them encrypted and asks before releasing
them.

Do not pass the key on the command line. `src/cli.py start` accepts
`--api_key_secret` for compatibility with the upstream server, but arguments
are visible to every other process on the machine and are kept in shell
history. Use the environment variable.

## Option 1: 1Password CLI (macOS, Windows, Linux)

[1Password CLI](https://developer.1password.com/docs/cli/) resolves
`op://vault/item/field` references when a command starts and hands the values
to that one child process as environment variables. Nothing is written to
disk. With the [desktop app integration](https://developer.1password.com/docs/cli/app-integration/)
the CLI unlocks the way the app unlocks: Touch ID on macOS, Windows Hello on
Windows, or the account password. While the app is locked, `op` waits for a
person to approve, so the gateway cannot start without one.

### Store the key

In the 1Password app, create an API Credential item in a vault shared only
with the people who may run the gateway. Name it after the tenant and the
key's role, for example `XSIAM dev tenant Tier1`, paste the key into
`credential`, and add text fields `auth_id` (the key id) and `url` (the
tenant API URL).

To do the same from a terminal, read the key from a hidden prompt so that it
never appears in shell history or in the process list:

```bash
stty -echo; printf 'XSIAM API key: '; read -r KEY; stty echo; printf '\n'
printf '%s' "$KEY" | jq -Rs \
  --arg title "XSIAM dev tenant Tier1" \
  --arg url "https://api-your-xsiam-tenant.example" \
  --arg id "12" \
  '{title: $title, category: "API_CREDENTIAL", fields: [
     {id: "credential", type: "CONCEALED", label: "credential", value: .},
     {id: "auth_id", type: "STRING", label: "auth_id", value: $id},
     {id: "url", type: "STRING", label: "url", value: $url}]}' \
  | op item create --vault "Security Engineering" - --format json \
  | jq -r '"stored \(.vault.name)/\(.id)"'
unset KEY
```

The last `jq` prints the vault and item id only. To check an item later,
list its field labels, never its values:

```bash
op item get "XSIAM dev tenant Tier1" --vault "Security Engineering" --format json \
  | jq -r '.fields[] | "\(.label)\t\(.type)"'
```

### Reference it

Copy `.env.op.example` to `.env.op` (git ignores `.env.*`) and point the
three references at your vault and item:

```bash
CORTEX_MCP_PAPI_URL=op://Security Engineering/XSIAM dev tenant Tier1/url
CORTEX_MCP_PAPI_AUTH_HEADER=op://Security Engineering/XSIAM dev tenant Tier1/credential
CORTEX_MCP_PAPI_AUTH_ID=op://Security Engineering/XSIAM dev tenant Tier1/auth_id
```

Item titles can repeat, so in a file other people will use, put the item id
in place of the title (`op item get "<title>" --format json | jq -r .id`).
Credential broker profiles resolve the same way: add a line for each variable
named in `XSIAM_CREDENTIAL_PROFILES`.

### Run

```bash
MCP_TRANSPORT=stdio MCP_IDENTITY_AUTH_MODE=none LOG_SEARCH_DEFAULT_GROUPS=Tier1 \
  op run --env-file=.env.op -- poetry run python src/main.py
```

PowerShell:

```powershell
$env:MCP_TRANSPORT = 'stdio'; $env:MCP_IDENTITY_AUTH_MODE = 'none'; $env:LOG_SEARCH_DEFAULT_GROUPS = 'Tier1'
op run --env-file=.env.op -- poetry run python src/main.py
```

`op` asks the 1Password app for the three values. If the app is locked, it
prompts for Touch ID, Windows Hello or the account password. Once approved,
`op` starts the gateway with the values in its environment and masks them in
everything the gateway prints. The `.env` file in the working directory is
still read for the non-secret settings.

### Register the server in an MCP client

MCP clients start a stdio server from a command in their own configuration
file. That file is plaintext too, so never put the key in its `env` block.
Point the client at `op run` instead and let 1Password prompt when the client
starts the server.

Claude Code:

```bash
claude mcp add cortex-xsiam \
  -e MCP_TRANSPORT=stdio -e MCP_IDENTITY_AUTH_MODE=none -e LOG_SEARCH_DEFAULT_GROUPS=Tier1 \
  -- sh -c 'cd /path/to/cortex-xsiam-mcp-gateway && exec op run --env-file=.env.op -- .venv/bin/python src/main.py'
```

Claude Desktop and other clients that take JSON:

```json
{
  "mcpServers": {
    "cortex-xsiam": {
      "command": "sh",
      "args": [
        "-c",
        "cd /path/to/cortex-xsiam-mcp-gateway && exec op run --env-file=.env.op -- .venv/bin/python src/main.py"
      ],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "MCP_IDENTITY_AUTH_MODE": "none",
        "LOG_SEARCH_DEFAULT_GROUPS": "Tier1"
      }
    }
  }
}
```

On Windows use `"command": "pwsh"` with
`"args": ["-NoProfile", "-Command", "Set-Location C:\\src\\cortex-xsiam-mcp-gateway; op run --env-file=.env.op -- .venv\\Scripts\\python.exe src\\main.py"]`.

The `cd` matters because `.env` is read from the working directory. Desktop
applications start with a short `PATH`, so if the client reports that `op`
was not found, write its full path (`/opt/homebrew/bin/op`,
`/usr/local/bin/op` or `C:\Program Files\1Password CLI\op.exe`). The approval
prompt appears when the client starts the server; if nobody approves before
the client's start-up timeout, the server fails to start. Unlock 1Password and
reconnect the server from the client.

### Docker

```bash
op run --env-file=.env.op -- docker run --rm -i \
  -e CORTEX_MCP_PAPI_URL -e CORTEX_MCP_PAPI_AUTH_HEADER -e CORTEX_MCP_PAPI_AUTH_ID \
  --env-file .env cortex-xsiam-mcp-gateway
```

`-e NAME` with no value copies that variable from the host environment, which
`op run` has just populated. The `.env` passed with `--env-file` holds the
non-secret settings only.

### Things to know

- **Masking.** `op run` replaces every resolved value in the child's output
  with `<concealed by 1Password>`. A short key id such as `12` is masked
  wherever those digits appear, which corrupts numbers in logs and in results
  printed to a terminal. If that bites, move `CORTEX_MCP_PAPI_AUTH_ID` from
  `.env.op` to `.env`; it is an identifier, not a secret. Do not reach for
  `--no-masking`, which also unmasks the key.
- **A locked app blocks.** `op` waits until someone approves. Wrap scripted
  runs in `timeout` (`timeout 300 op run ...`) so an unattended run fails
  instead of hanging.
- **Unattended hosts.** Personal vaults and biometric prompts are for people.
  For servers and CI use a [service account](https://developer.1password.com/docs/service-accounts/)
  scoped to one vault, or the platform's secret manager (see below).
- **Never reveal the value.** No `op read` into a terminal, no `--reveal`, no
  `printenv` in a session that an AI agent or a screen share can see. The
  transcript is stored.

## Option 2: macOS Keychain

The Keychain ships with macOS and needs no extra software. Items live
encrypted in the login keychain, and each item carries an access control list
that decides which programs may read it without asking. Removing every
program from that list makes macOS show an Allow / Deny dialog on every read,
which is the approval step.

### Store the key

```bash
security add-generic-password -a "$USER" -s cortex-xsiam/dev/api-key \
  -l "Cortex XSIAM dev API key" -j "Tier1 read-only, created 2026-11-05" -T "" -U -w
security add-generic-password -a "$USER" -s cortex-xsiam/dev/api-key-id \
  -l "Cortex XSIAM dev API key id" -T "" -U -w
```

`security` prompts for the value twice and does not echo it. `-w` must be the
final argument for the prompt to appear (any argument after it, including a
keychain path, is taken as the password), so the items go in your default
login keychain. `-T ""` removes the default trust that would let the
`security` tool itself read the item silently. `-U` updates an existing item,
which is how you rotate.

To confirm an item exists without showing its value:

```bash
security find-generic-password -a "$USER" -s cortex-xsiam/dev/api-key
```

### Run

Save a wrapper outside the repository, or in it as an untracked file, and make
it executable:

```sh
#!/bin/sh
# Starts the gateway with the XSIAM key read from the login keychain.
# macOS asks you to allow each read: choose Allow, not Always Allow.
set -eu
cd /path/to/cortex-xsiam-mcp-gateway
CORTEX_MCP_PAPI_AUTH_HEADER="$(security find-generic-password -a "$USER" -s cortex-xsiam/dev/api-key -w)"
CORTEX_MCP_PAPI_AUTH_ID="$(security find-generic-password -a "$USER" -s cortex-xsiam/dev/api-key-id -w)"
export CORTEX_MCP_PAPI_AUTH_HEADER CORTEX_MCP_PAPI_AUTH_ID
exec .venv/bin/python src/main.py
```

Each read shows the dialog "security wants to use your confidential
information stored in ... in your keychain". Choose **Allow**. **Always
Allow** adds the `security` tool to the item's access list and ends the
prompting for every future read, which is the approval you set out to keep.
Register the wrapper in your MCP client as the command, with the same `env`
block as in the 1Password example. The dialog is graphical, so it appears
even when a desktop client starts the server.

The login keychain is unlocked when you log in and normally stays unlocked.
To also lock it when the Mac sleeps and after fifteen idle minutes:

```bash
security set-keychain-settings -l -u -t 900 ~/Library/Keychains/login.keychain-db
```

This applies to every item in the login keychain, so other applications will
ask for your login password after idle periods too.

## Option 3: Windows SecretStore

Windows Credential Manager stores secrets encrypted with DPAPI, but its
command line tool, `cmdkey`, can only write them: there is no supported
command to read one back, and `cmdkey /pass:` puts the key in the process
list and in history. Use Microsoft's
[SecretManagement](https://learn.microsoft.com/en-us/powershell/utility-modules/secretmanagement/overview)
and [SecretStore](https://learn.microsoft.com/en-us/powershell/utility-modules/secretmanagement/how-to/manage-secretstore)
modules instead. SecretStore is an encrypted per-user store that requires a
password, prompts for it when locked, and locks again after a timeout. It
runs in PowerShell 7 on Windows, macOS and Linux.

### Set up the store once

```powershell
Install-Module Microsoft.PowerShell.SecretManagement, Microsoft.PowerShell.SecretStore -Scope CurrentUser
Register-SecretVault -Name CortexXsiam -ModuleName Microsoft.PowerShell.SecretStore -DefaultVault
Set-SecretStoreConfiguration -Authentication Password -Interaction Prompt -PasswordTimeout 900
```

The first command that touches the store asks you to choose its password.
With this configuration the store asks for that password whenever it has been
locked for fifteen minutes, which is the approval step.

### Store the key

```powershell
Set-Secret -Name CortexXsiamDevApiKey -Secret (Read-Host -AsSecureString 'XSIAM API key')
Set-Secret -Name CortexXsiamDevApiKeyId -Secret (Read-Host -AsSecureString 'XSIAM API key id')
```

`Read-Host -AsSecureString` hides the input, and nothing lands in history.
`Get-SecretInfo` lists what is stored without revealing values.

### Run

```powershell
# run-gateway.ps1: starts the gateway with the XSIAM key read from SecretStore.
# SecretStore asks for its password when it is locked.
$ErrorActionPreference = 'Stop'
Set-Location 'C:\src\cortex-xsiam-mcp-gateway'
$env:CORTEX_MCP_PAPI_AUTH_HEADER = Get-Secret -Name CortexXsiamDevApiKey -AsPlainText
$env:CORTEX_MCP_PAPI_AUTH_ID = Get-Secret -Name CortexXsiamDevApiKeyId -AsPlainText
& .\.venv\Scripts\python.exe src\main.py
```

The values exist in this PowerShell process and in the gateway it starts, and
nowhere else. Run it from a terminal with `pwsh -NoProfile -File
run-gateway.ps1`, or for the live tests replace the last line with the
`pytest` command.

SecretStore's password prompt is a console prompt. When a desktop MCP client
starts the gateway there is no console, `Get-Secret` fails with
`PasswordRequiredException`, and an `Unlock-SecretStore` in another window
does not help, because the unlock applies only to that PowerShell session. For
a desktop client on Windows, use 1Password CLI, whose Windows Hello prompt is
graphical. If 1Password is not available, a Credential Manager extension vault
for SecretManagement (for example `SecretManagement.JustinGrote.CredMan`)
keeps the same `Get-Secret` commands and releases the value without a prompt
once you are logged in. That drops the approval step, but the key is still
encrypted at rest and never in a file.

## Linux

[`secret-tool`](https://manpages.debian.org/testing/libsecret-tools/secret-tool.1.en.html)
(libsecret) stores items in the desktop's Secret Service, which GNOME Keyring
and KWallet provide, and prompts for the value when run from a terminal:

```bash
secret-tool store --label="Cortex XSIAM dev API key" service cortex-xsiam key dev-api-key
CORTEX_MCP_PAPI_AUTH_HEADER="$(secret-tool lookup service cortex-xsiam key dev-api-key)"
```

The Secret Service unlocks with your login session and does not prompt on
each read. 1Password CLI runs on Linux as well, and its desktop app
integration prompts with the system authentication dialog.

## Servers, Containers And CI

Shared hosts should not depend on a person's vault or fingerprint. Inject the
secrets from the platform's secret manager (AWS Secrets Manager, Azure Key
Vault, Kubernetes secrets, or a 1Password service account) into the container
or service environment at start, as [Enterprise Deployment](ENTERPRISE_DEPLOYMENT.md)
expects. In GitHub Actions, map encrypted repository secrets to environment
variables in the job; the live tests read `XSIAM_LIVE_*` from the environment
and nothing else.

## Checklist

- `git ls-files | grep '^\.env'` lists only `.env.example` and
  `.env.op.example`.
- Your `.env` contains no `*_AUTH_HEADER`, `*_KEY`, `*_SECRET` or
  `*_API_KEY` value. `chmod 600 .env` even so; it names your tenant.
- Secrets are typed at hidden prompts (`-w` last, `Read-Host -AsSecureString`,
  `stty -echo`), never on a command line.
- One key per person or per role, least privilege in XSIAM, separate keys for
  development and production tenants, rotated on a schedule. A leaked key is
  revoked in the XSIAM console under Settings, Configurations, API Keys.
- Nothing prints a secret: no `printenv`, `op read`, `--reveal`,
  `--no-masking` or `find-generic-password -w` in a visible terminal.

## Verify

Start the gateway through the path you chose and call `get_tenant_info` or
`get_xql_query_quota` from your MCP client. With a wrong or missing key the
call fails with an authentication error from XSIAM; `src/cli.py start` refuses
to start at all when the key is missing. Audit events record which credential
profile served a call, never the key.
