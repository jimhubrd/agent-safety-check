# Agent Safety Check

A free, open-source safety check for people who have connected Claude to their email, files and work tools. It runs on your own computer and writes a plain-language report:

- **Your setup's operating style:** Hands-on, Guided or Autopilot, read from your settings. You choose the level you want.
- **Things to be aware of, decided once:** for each one, guard it with a rule, remove it, or say you are OK with it. Accepted items stay quiet unless they change. There is no grade.
- **What Claude may do without asking:** your standing approvals and block rules, in plain words.
- **Access map:** every connector, and what it lets Claude read, create, change, delete, send and spend.
- **What changed since last time:** new connectors, new abilities, changed rules.
- **Fire drill:** three planted instructions, handled by a helper that can only read. Would your agent go along?
- **Versions and secrets:** out-of-date software, known security problems, and keys stored in plain text.

> **Early release, version 0.1.** This is brand new and there will be bugs. If something in your report looks wrong, please open an issue, and don't rely on it as your only safety check.

Website: the `site/` folder. Install kit: the `kit/` folder.

## Before you install: have your own AI review this code

Paste the prompt in [REVIEW-PROMPT.md](REVIEW-PROMPT.md) into Claude or Codex. Please do this. A safety tool should earn your trust, not ask for it.

## What it touches

| | |
| --- | --- |
| **Reads** | Claude configuration files only: `~/.claude.json`, `~/.claude/settings*.json`, the project's `.claude/settings*.json` and `.mcp.json`, the desktop app's `claude_desktop_config.json`, and the version number in desktop extension manifests. Plus the names of tools Claude can see; it never calls them. |
| **Never reads** | Email, messages, documents, calendars, other files, browser data, passwords or keychains. Secret values are never stored; the report shows only where a secret is and its first four characters. |
| **Writes** | Only inside `~/agent-safety-check/`. |
| **Contacts** | Only `registry.npmjs.org`, `pypi.org` and `api.osv.dev`, sending package names and version numbers. Any other address is refused in code (`kit/scripts/versions.py`). `--offline` contacts nothing. |
| **Changes** | Nothing. It never edits settings, installs, updates, sends, shares or deletes. Uninstall removes only its own files, after you confirm. |

### The kit's own access map

| Part | Can do |
| --- | --- |
| `kit/SKILL.md` | Tells Claude the steps. Forbids changing anything or opening connector content. |
| `kit/agents/asc-drill-reader.md` | The fire drill helper. Its only tool is `Read`. |
| `kit/scripts/*.py` | Python standard library only. No third-party packages. |

## Install

Needs Claude Code (the Code tab in the Claude desktop app works) and Python 3.9 or newer (3.12 or newer on Windows). Paste into Claude Code:

> Install Agent Safety Check version 0.1.0 for me. Download https://github.com/jimhubrd/agent-safety-check/releases/download/v0.1.0/agent-safety-check-kit-0.1.0.zip into a new temporary folder. Check that the file's SHA-256 checksum is 43ca93549458d7ab9bf3a5d054212809adbbd0c868c2e80a61ccaa8578248024. If it is different, stop and tell me. Otherwise unzip it, copy its kit folder to ~/.claude/skills/agent-safety-check, and copy kit/agents/asc-drill-reader.md to ~/.claude/agents/. Then run: python3 ~/.claude/skills/agent-safety-check/scripts/asc.py selftest (on Windows use python or py instead of python3). Change nothing else, and tell me the result.

The checksum proves the download is exactly the reviewed release: `43ca93549458d7ab9bf3a5d054212809adbbd0c868c2e80a61ccaa8578248024`.

Then quit and reopen Claude, and say: **"Run my agent safety check."**

Remove it with: **"Uninstall Agent Safety Check."**

## How it works

1. Claude writes the names of the tools it can see to `~/agent-safety-check/inventory.json`.
2. The read-only helper handles the three drill files; its replies are saved word for word.
3. `asc.py run` reads your configuration, sorts every action by the words in its name (a write word always outranks a read word, and unclear names count as changes), compares with your last check, checks versions, scores the drills and writes the report.

## Limits

- Actions are sorted by name. Unclear names count as changes, so the numbers lean cautious.
- It sees the connectors in the Claude Code session it runs in. Connectors that live only in another app or on the web may not appear.
- Vendor-hosted connectors publish no version; they are watched through changes to their actions.
- Guard scripts are detected, not read. It cannot tell what a guard script actually blocks.
- The fire drill tests three known patterns. Passing does not prove nothing else could get through.
- Information, not a security audit.

## Tests

```
python3 -m unittest tests/test_asc.py
```

The tests include: no address outside the three is ever contacted, offline mode contacts nothing, the drill helper can only read, every drill address ends in `.invalid`, secret values never appear in results, and the report escapes everything it shows.

## Contributing

Suggestions and fixes are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Security problems: see [SECURITY.md](SECURITY.md).

Built by Jim Hubbard as a project in Allie K. Miller's AI Agent Mastermind. MIT license.
