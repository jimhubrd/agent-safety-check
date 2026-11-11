# Review this code before you install it

Paste this into Claude, Codex or another AI you trust, in a new chat.

```
Please review the open-source project at https://github.com/jimhubrd/agent-safety-check before I install it. I am not a programmer, so explain in plain words.

Check every file and tell me:
1. Every internet address it contacts, and what it sends there.
2. Every file it reads, and every file it writes or deletes.
3. Anything that runs other programs, changes settings, sends messages, or installs anything.
4. Whether anything it does goes beyond what its README says.
5. Your overall verdict: safe to install, or not, and why.

Red flags to call out: contacting any address other than registry.npmjs.org, pypi.org or api.osv.dev; reading email, documents or passwords; writing anywhere other than an agent-safety-check folder; hidden or scrambled code.
The only official copy is at github.com/jimhubrd/agent-safety-check. Warn me if what I am looking at came from anywhere else.
```

## What a good answer looks like

- The only internet addresses are registry.npmjs.org, pypi.org and api.osv.dev, and only package names and versions are sent.
- It reads Claude configuration files and writes only to `~/agent-safety-check`.
- It runs only fixed version commands (`claude --version`, `node --version`) and nothing else.
- The fire drill helper's only tool is Read.
- Nothing sends, shares, deletes or changes settings. Uninstall removes only its own files after you confirm.

## Red flags

If your AI reports any of these, do not install, and please open an issue:

- Any other internet address, or anything sent beyond package names and versions.
- Reading email, documents, browser data, passwords or keychains.
- Code that is scrambled, encoded or downloaded at run time.
- A copy of this project hosted anywhere other than github.com/jimhubrd/agent-safety-check.
