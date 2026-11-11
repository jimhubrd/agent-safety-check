"""Read Claude configuration files. Read only: nothing here writes or runs anything.

What this reads:
  - Claude Code's user file (~/.claude.json): connector definitions
  - Claude Code settings (~/.claude/settings.json and settings.local.json,
    plus the same two files in the current project): permission rules, hooks
  - The Claude desktop app's connector file (claude_desktop_config.json)
  - A project connector file (.mcp.json) in the current folder, if present
  - manifest.json of desktop extensions, only to read their version number

Secret values are never returned. The secrets check reports the file, the
connector, the setting name and a masked hint only, and every rule that is
stored or shown passes through mask() first.
"""

import json
import os
import platform
import re
from pathlib import Path

HOME = Path.home()

# Package names and versions that are safe to look up. Anything else, such as
# a git address, a local path or a value with a login in it, is never sent.
NPM_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
PYPI_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+([.+-][0-9A-Za-z.]+)?$")


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


# ---------------------------------------------------------------- masking

SECRET_NAME = re.compile(r"(key|token|secret|password|passwd|pwd|auth|bearer|credential)", re.I)
SECRET_VALUE = re.compile(
    r"(sk-ant-[A-Za-z0-9_\-]{8,}|sk-proj-[A-Za-z0-9_\-]{8,}|sk-[A-Za-z0-9]{20,}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abpr]-[A-Za-z0-9\-]{10,}|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{30,})")
URL_LOGIN = re.compile(r"(://)([^/\s:@]+):([^/\s@]+)@")
LONG_TOKEN = re.compile(r"[A-Za-z0-9_\-+/=]{24,}")


def _mask_value(value):
    value = str(value)
    return (value[:4] + "…") if len(value) > 6 else "…"


def mask(text):
    """Hide anything that looks like a key, token or password inside a string."""
    text = str(text)
    text = SECRET_VALUE.sub(lambda m: _mask_value(m.group(0)), text)
    text = URL_LOGIN.sub(lambda m: m.group(1) + m.group(2) + ":…@", text)
    text = re.sub(r"(?i)(bearer\s+)\S+", lambda m: m.group(1) + "…", text)
    text = re.sub(r"(?i)((?:api[-_]?key|token|secret|password)[=:]\s*)[^\s\"')]+", lambda m: m.group(1) + "…", text)
    text = LONG_TOKEN.sub(lambda m: m.group(0) if m.group(0).startswith("mcp__") else _mask_value(m.group(0)), text)
    return text[:160]


# ---------------------------------------------------------------- connectors

def rule_summary(rule):
    """Connector rules are kept whole (masked). For command and web rules, keep only
    the command or domain, never the arguments, so nothing secret is stored or shown."""
    rule = str(rule).strip()
    m = re.match(r"^(\w+)\((.*)\)$", rule, re.S)
    if rule.startswith("mcp__") or not m:
        return mask(rule)
    tool, inner = m.group(1), m.group(2).strip()
    if inner in ("*", ":*", ""):
        return "%s(%s)" % (tool, inner)
    if tool == "WebFetch" and inner.startswith("domain:"):
        return "WebFetch(%s)" % mask(inner.split()[0])
    words = re.split(r"[\s:]+", inner)
    head = words[0]
    if head in ("git", "gh", "npm", "aws", "gcloud", "az", "docker", "kubectl") and len(words) > 1 and re.match(r"^[a-z][a-z-]*$", words[1]):
        head += " " + words[1]
    return "%s(%s%s)" % (tool, re.sub(r"[^A-Za-z0-9._/ -]", "", head)[:40], " \u2026" if len(words) > 1 or ":" in inner else "")


def _split_spec(spec, ecosystem):
    """Return (name, version) only when the name is safe to look up; else (None, None)."""
    if ecosystem == "npm":
        if spec.startswith("@"):
            body = spec[1:]
            name, ver = ("@" + body.rsplit("@", 1)[0], body.rsplit("@", 1)[1]) if "@" in body else (spec, None)
        else:
            name, ver = spec.split("@", 1) if "@" in spec else (spec, None)
        if not NPM_NAME.match(name):
            return None, None
    else:
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?(?:(==|@)(.+))?$", spec)
        if not m or not PYPI_NAME.match(m.group(1)):
            return None, None
        name, ver = m.group(1), m.group(3)
    if ver is not None and not re.match(r"^[0-9A-Za-z.+_^~*-]{1,64}$", ver):
        return name, "unsafe"
    return name, ver


DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network",
                      "--env-file", "-w", "--workdir", "-u", "--user", "--mount", "--entrypoint",
                      "-l", "--label", "--platform", "--add-host", "-h", "--hostname"}


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
    if m and m.group(1) not in (".", ".."):
        info["source"] = "Desktop app extension"
        root = (desktop_dir() / "Claude Extensions").resolve()
        ext_dir = (root / m.group(1)).resolve()
        manifest = (_load(ext_dir / "manifest.json") if str(ext_dir).startswith(str(root)) else None) or {}
        ver = str(manifest.get("version") or "")
        info["version"] = ver if EXACT_VERSION.match(ver) else None
        info["pinned"] = True
        return info

    rest = [a for a in args if not a.startswith("-")]
    if base in ("npx", "npx.cmd", "bunx", "pnpx") or (base in ("pnpm", "npm") and rest[:1] in (["dlx"], ["exec"])):
        if base in ("pnpm", "npm"):
            rest = rest[1:]
        if rest:
            name, ver = _split_spec(rest[0], "npm")
            if not name:
                info["source"] = "Installed from a git address or local folder"
                return info
            info.update(ecosystem="npm", package=name)
            info["version"] = ver if ver and ver != "unsafe" else None
            info["pinned"] = bool(ver and EXACT_VERSION.match(ver))
            info["source"] = "Pinned version" if info["pinned"] else "Unpinned: newest code every start"
        return info

    if base in ("uvx", "uvx.exe", "pipx"):
        if base == "pipx" and rest[:1] == ["run"]:
            rest = rest[1:]
        if rest:
            name, ver = _split_spec(rest[0], "pypi")
            if not name:
                info["source"] = "Installed from a git address or local folder"
                return info
            info.update(ecosystem="PyPI", package=name)
            info["version"] = ver if ver and ver != "unsafe" else None
            info["pinned"] = bool(ver and EXACT_VERSION.match(ver))
            info["source"] = "Pinned version" if info["pinned"] else "Unpinned: newest code every start"
        return info

    if base in ("docker", "podman"):
        it = iter(args[args.index("run") + 1:] if "run" in args else args)
        image = None
        for a in it:
            if a in DOCKER_VALUE_FLAGS:
                next(it, None)
                continue
            if a.startswith("-"):
                continue
            image = a
            break
        info["source"] = "Container"
        if image and re.match(r"^[a-z0-9]+([._/-][a-z0-9]+)*(:[A-Za-z0-9._-]{1,64})?(@sha256:[a-f0-9]{64})?$", image):
            tag = image.split("@")[0].split(":", 1)[1] if ":" in image.split("@")[0] else "latest"
            info.update(version=tag, pinned=tag != "latest" or "@sha256:" in image)
        return info

    return info


def connectors(cwd=None):
    """All connectors defined in configuration, keyed by name."""
    found = {}
    cwd = Path(cwd or os.getcwd())

    def add(name, server, where):
        if not isinstance(server, dict):
            return
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

def hook_role(command):
    """Guess what a guard script is for, from the words in its file name only.
    The script itself is never read, so the report says this is a guess."""
    parts = command.strip().split()
    name = os.path.basename(parts[-1] if parts else "").lower()
    words = set(re.split(r"[^a-z]+", re.sub(r"\.(py|sh|js|ts|ps1|cmd|bat)$", "", name)))
    if words & {"guard", "firewall", "block", "blocker", "deny", "protect", "egress", "allowlist"}:
        return "send-guard"
    if words & {"log", "logger", "logging", "audit", "auditor", "recorder", "telemetry"}:
        return "logger"
    return "unknown"


def settings(cwd=None):
    """Permission rules and hook matchers from every settings file. Rules are masked."""
    cwd = Path(cwd or os.getcwd())
    out = {"allow": [], "ask": [], "deny": [], "mode": None, "hooks": [], "hook_details": [], "files": []}
    for path in (HOME / ".claude" / "settings.json", HOME / ".claude" / "settings.local.json",
                 cwd / ".claude" / "settings.json", cwd / ".claude" / "settings.local.json"):
        data = _load(path)
        if not isinstance(data, dict):
            continue
        out["files"].append(str(path))
        perms = data.get("permissions") or {}
        for key in ("allow", "ask", "deny"):
            out[key].extend(rule_summary(r) for r in (perms.get(key) or []))
        mode = perms.get("defaultMode") or data.get("defaultMode")
        if mode:
            out["mode"] = str(mode)[:40]
        for event, groups in (data.get("hooks") or {}).items():
            if event != "PreToolUse":
                continue
            for group in groups or []:
                if not isinstance(group, dict):
                    continue
                matcher = str(group.get("matcher") or "*")
                cmds = " ".join(str(h.get("command", "")) for h in (group.get("hooks") or []) if isinstance(h, dict))
                out["hooks"].append(matcher)
                parts = cmds.strip().split()
                out["hook_details"].append({"matcher": matcher, "role": hook_role(cmds),
                                            "script": os.path.basename(parts[-1]) if parts else ""})
    for key in ("allow", "ask", "deny"):
        out[key] = list(dict.fromkeys(out[key]))
    return out


# ---------------------------------------------------------------- secrets

KEY_FLAG = re.compile(r"^--?(api[-_]?key|token|secret|password|auth)(=(.*))?$", re.I)


def _secret_like(key, val):
    val = str(val)
    if not val or val.startswith("$"):
        return False
    if SECRET_VALUE.search(val) or URL_LOGIN.search(val) or re.match(r"(?i)^bearer\s+\S{8,}", val):
        return True
    if re.search(r"(_ID|ID|_URL|_URI)$", str(key)):
        return False
    return bool(SECRET_NAME.search(str(key)) and len(val) >= 16 and " " not in val
                and not val.startswith(("/", "~", "http", ".")))


def secrets(cwd=None):
    """Plain-text secrets inside connector definitions and settings. Never returns a value."""
    findings = []

    def hit(label, connector, setting, val):
        findings.append({"file": label, "connector": connector, "setting": str(setting)[:60],
                         "hint": _mask_value(val)})

    for path, label in config_files(cwd):
        data = _load(path)
        if not isinstance(data, dict):
            continue
        for key, val in (data.get("env") or {}).items():
            if _secret_like(key, val):
                hit(label, "(settings env)", key, val)
        servers = dict(data.get("mcpServers") or {})
        for proj in (data.get("projects") or {}).values():
            if isinstance(proj, dict):
                servers.update(proj.get("mcpServers") or {})
        for name, srv in servers.items():
            if not isinstance(srv, dict):
                continue
            pairs = list((srv.get("env") or {}).items()) + list((srv.get("headers") or {}).items())
            if srv.get("url"):
                pairs.append(("url", srv["url"]))
            args = [str(a) for a in (srv.get("args") or [])]
            skip = set()
            for i, a in enumerate(args):
                m = KEY_FLAG.match(a)
                if m:
                    value = m.group(3) if m.group(2) else (args[i + 1] if i + 1 < len(args) else "")
                    if not m.group(2):
                        skip.add(i + 1)
                    if value and not value.startswith("$") and len(value) >= 8:
                        hit(label, name, m.group(1), value)
                elif i not in skip:
                    pairs.append(("argument", a))
            for key, val in pairs:
                if _secret_like(key, val):
                    hit(label, name, key, val)
    return findings
