"""Read Claude configuration files. Read only: nothing here writes or runs anything.

What this reads:
  - Claude Code's user file (~/.claude.json): connector definitions
  - Claude Code settings (~/.claude/settings.json and settings.local.json,
    plus the same two files in the current project): permission rules, hooks
  - The Claude desktop app's connector file (claude_desktop_config.json)
  - A project connector file (.mcp.json) in the current folder, if present
  - manifest.json of desktop extensions, only to read their version number

Secret values are never returned. The secrets check reports the file, the
connector, the setting name and a masked hint only.
"""

import json
import os
import platform
import re
from pathlib import Path

HOME = Path.home()


def desktop_dir():
    system = platform.system()
    if system == "Darwin":
        return HOME / "Library" / "Application Support" / "Claude"
    if system == "Windows":
        return Path(os.environ.get("APPDATA", HOME / "AppData" / "Roaming")) / "Claude"
    return HOME / ".config" / "Claude"


def _load(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def config_files(cwd=None):
    """Every file this tool may read, with a plain description. Shown on the trust page."""
    cwd = Path(cwd or os.getcwd())
    return [
        (HOME / ".claude.json", "Claude Code connectors"),
        (HOME / ".claude" / "settings.json", "Claude Code settings"),
        (HOME / ".claude" / "settings.local.json", "Claude Code local settings"),
        (cwd / ".claude" / "settings.json", "Project settings"),
        (cwd / ".claude" / "settings.local.json", "Project local settings"),
        (cwd / ".mcp.json", "Project connectors"),
        (desktop_dir() / "claude_desktop_config.json", "Claude desktop app connectors"),
    ]


# ---------------------------------------------------------------- connectors

def _package_and_version(spec, sep="@"):
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3'); 'name' -> ('name', None)."""
    if sep == "@":
        if spec.startswith("@"):
            body = spec[1:]
            if "@" in body:
                name, ver = body.rsplit("@", 1)
                return "@" + name, ver
            return spec, None
        if "@" in spec:
            name, ver = spec.split("@", 1)
            return name, ver
        return spec, None
    for s in ("==", "@"):
        if s in spec:
            name, ver = spec.split(s, 1)
            return name, ver
    return spec, None


def describe_source(server):
    """Work out where a connector comes from and which version it runs."""
    kind = (server.get("type") or "").lower()
    url = server.get("url")
    cmd = server.get("command") or ""
    args = [str(a) for a in (server.get("args") or [])]
    base = os.path.basename(cmd).lower()
    info = {"source": "Local install", "ecosystem": None, "package": None,
            "version": None, "pinned": None}

    if url or kind in ("http", "sse", "streamable-http"):
        info["source"] = "Vendor-hosted"
        return info

    joined = " ".join([cmd] + args)
    m = re.search(r"Claude Extensions[\\/]+([^\\/\s]+)", joined)
    if m:
        info["source"] = "Desktop app extension"
        ext_dir = desktop_dir() / "Claude Extensions" / m.group(1)
        manifest = _load(ext_dir / "manifest.json") or {}
        info["package"] = manifest.get("name") or m.group(1)
        info["version"] = manifest.get("version")
        info["pinned"] = True
        return info

    rest = [a for a in args if not a.startswith("-")]
    if base in ("npx", "npx.cmd", "bunx", "pnpx") or (base in ("pnpm", "npm") and rest[:1] in (["dlx"], ["exec"])):
        if base in ("pnpm", "npm"):
            rest = rest[1:]
        if rest:
            pkg, ver = _package_and_version(rest[0], "@")
            info.update(ecosystem="npm", package=pkg, version=ver)
            info["pinned"] = bool(ver) and ver != "latest"
            info["source"] = "Pinned version" if info["pinned"] else "Unpinned: newest code every start"
        return info

    if base in ("uvx", "uvx.exe", "pipx"):
        if base == "pipx" and rest[:1] == ["run"]:
            rest = rest[1:]
        if rest:
            pkg, ver = _package_and_version(rest[0], "==")
            info.update(ecosystem="PyPI", package=pkg, version=ver)
            info["pinned"] = bool(ver)
            info["source"] = "Pinned version" if info["pinned"] else "Unpinned: newest code every start"
        return info

    if base in ("docker", "podman") and rest:
        image = rest[-1]
        tag = image.split(":", 1)[1] if ":" in image else "latest"
        info.update(source="Container", package=image.split(":", 1)[0], version=tag,
                    pinned=tag != "latest")
        return info

    return info


def connectors(cwd=None):
    """All connectors defined in configuration, keyed by name."""
    found = {}
    cwd = Path(cwd or os.getcwd())

    def add(name, server, where):
        entry = describe_source(server)
        entry["defined_in"] = where
        found.setdefault(name, entry)

    user = _load(HOME / ".claude.json") or {}
    for name, srv in (user.get("mcpServers") or {}).items():
        add(name, srv, "Claude Code (all projects)")
    proj = (user.get("projects") or {}).get(str(cwd)) or {}
    for name, srv in (proj.get("mcpServers") or {}).items():
        add(name, srv, "Claude Code (this project)")
    for name, srv in ((_load(cwd / ".mcp.json") or {}).get("mcpServers") or {}).items():
        add(name, srv, "Project file .mcp.json")
    for name, srv in ((_load(desktop_dir() / "claude_desktop_config.json") or {}).get("mcpServers") or {}).items():
        add(name, srv, "Claude desktop app")
    return found


# ---------------------------------------------------------------- settings

def settings(cwd=None):
    """Permission rules and hook matchers from every settings file."""
    cwd = Path(cwd or os.getcwd())
    out = {"allow": [], "ask": [], "deny": [], "mode": None, "hooks": [], "files": []}
    for path in (HOME / ".claude" / "settings.json", HOME / ".claude" / "settings.local.json",
                 cwd / ".claude" / "settings.json", cwd / ".claude" / "settings.local.json"):
        data = _load(path)
        if not data:
            continue
        out["files"].append(str(path))
        perms = data.get("permissions") or {}
        for key in ("allow", "ask", "deny"):
            out[key].extend(str(r) for r in (perms.get(key) or []))
        mode = perms.get("defaultMode") or data.get("defaultMode")
        if mode:
            out["mode"] = mode
        for event, groups in (data.get("hooks") or {}).items():
            if event != "PreToolUse":
                continue
            for group in groups or []:
                matcher = group.get("matcher") or "*"
                cmds = " ".join(str(h.get("command", "")) for h in (group.get("hooks") or []) if isinstance(h, dict))
                out["hooks"].append(matcher)
                out.setdefault("hook_details", []).append({"matcher": matcher, "role": hook_role(cmds)})
    return out


def hook_role(command):
    """Guess what a guard script is for, from its file name only. The script itself is not read."""
    name = os.path.basename(command.strip().split()[-1] if command.strip() else "").lower()
    if re.search(r"(send|firewall|block|guard|deny|protect|egress)", name):
        return "send-guard"
    if re.search(r"(log|audit|record|telemetry|track)", name):
        return "logger"
    return "unknown"


# ---------------------------------------------------------------- secrets

SECRET_NAME = re.compile(r"(key|token|secret|password|passwd|pwd|auth|bearer|credential)", re.I)
SECRET_VALUE = re.compile(
    r"(sk-ant-[A-Za-z0-9_\-]{8,}|sk-proj-[A-Za-z0-9_\-]{8,}|sk-[A-Za-z0-9]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9\-]{10,}|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{30,})")


def _mask(value):
    value = str(value)
    return (value[:4] + "…") if len(value) > 6 else "…"


def secrets(cwd=None):
    """Plain-text secrets inside connector definitions. Never returns a value."""
    findings = []
    for path, label in config_files(cwd):
        data = _load(path)
        if not data:
            continue
        servers = dict(data.get("mcpServers") or {})
        for proj in (data.get("projects") or {}).values():
            if isinstance(proj, dict):
                servers.update(proj.get("mcpServers") or {})
        for name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            pairs = list((srv.get("env") or {}).items()) + list((srv.get("headers") or {}).items())
            pairs += [("argument", a) for a in (srv.get("args") or [])]
            for key, val in pairs:
                val = str(val)
                if not val or val.startswith("${") or val.startswith("$"):
                    continue
                if re.search(r"(_ID|ID|_URL|_URI)$", str(key)) and not SECRET_VALUE.search(val):
                    continue    # identifiers and addresses are not secrets
                looks_secret = SECRET_VALUE.search(val) or (
                    SECRET_NAME.search(str(key)) and len(val) >= 16 and " " not in val
                    and not val.startswith(("/", "~", "http", ".")))
                if looks_secret:
                    findings.append({"file": label, "connector": name,
                                     "setting": str(key), "hint": _mask(val)})
    return findings
