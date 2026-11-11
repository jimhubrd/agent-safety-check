"""Check versions against public sources.

This is the only file that uses the network. It may contact exactly these
three public addresses, and it refuses any other:

    registry.npmjs.org   latest version of npm packages
    pypi.org             latest version of Python packages
    api.osv.dev          known security problems for a package version

It sends only a package name and a version number. Nothing about your
setup, your files or your accounts is sent.
"""

import json
import os
import platform
import re
import shutil
import subprocess
import urllib.parse
import urllib.request

ALLOWED_HOSTS = {"registry.npmjs.org", "pypi.org", "api.osv.dev"}
TIMEOUT = 8


class _CheckRedirect(urllib.request.HTTPRedirectHandler):
    """Re-check every redirect against the allowed addresses."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlparse(newurl).hostname not in ALLOWED_HOSTS:
            raise PermissionError("Blocked redirect to %s" % urllib.parse.urlparse(newurl).hostname)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# No proxy settings are honoured, so traffic goes only where the code says.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _CheckRedirect())

SAFE_NAME = re.compile(r"^(@[a-z0-9][a-z0-9._~-]*/)?[A-Za-z0-9][A-Za-z0-9._~-]{0,213}$")
SAFE_VERSION = re.compile(r"^[0-9][0-9A-Za-z.+-]{0,63}$")


def _get(url, body=None):
    host = urllib.parse.urlparse(url).hostname
    if host not in ALLOWED_HOSTS or not url.startswith("https://"):
        raise PermissionError("Blocked: %s is not an allowed address" % host)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={
        "User-Agent": "agent-safety-check", "Content-Type": "application/json"})
    with _OPENER.open(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read(2_000_000).decode("utf-8"))


def latest(ecosystem, package):
    if not package or not SAFE_NAME.match(package):
        return None
    try:
        if ecosystem == "npm":
            return _get("https://registry.npmjs.org/%s/latest" % urllib.parse.quote(package, safe="@"))["version"]
        if ecosystem == "PyPI":
            return _get("https://pypi.org/pypi/%s/json" % urllib.parse.quote(package))["info"]["version"]
    except Exception:          # includes a refused redirect: mark it "not checked"
        return None
    return None


def advisories(ecosystem, package, version):
    """Known security problems for this exact version. Returns a list of ids, or None if unknown."""
    if not (ecosystem and package and version) or not SAFE_NAME.match(package) or not SAFE_VERSION.match(version):
        return None
    try:
        res = _get("https://api.osv.dev/v1/query",
                   {"version": version, "package": {"name": package, "ecosystem": ecosystem}})
        return [v.get("id") for v in res.get("vulns", [])]
    except Exception:
        return None


def _newer(a, b):
    """True if version b is newer than a. Simple numeric comparison."""
    def parts(v):
        out = []
        for p in str(v).replace("-", ".").split("."):
            out.append(int(p) if p.isdigit() else 0)
        return out
    try:
        return parts(b) > parts(a)
    except Exception:
        return False


def local_tool_version(program):
    """Ask a well-known program for its version. Only these fixed programs, only --version."""
    if program not in ("claude", "node"):
        return None
    search = os.environ.get("PATH", "")
    if platform.system() == "Windows":   # never pick up a program from the current folder
        os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
        search = os.pathsep.join(p for p in search.split(os.pathsep) if p and os.path.abspath(p) != os.getcwd())
    path = shutil.which(program, path=search)
    if not path:
        return None
    try:
        out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=10, cwd=os.path.expanduser("~"))
        for word in (out.stdout or out.stderr).strip().split():
            w = word.lstrip("v")
            if w[:1].isdigit():
                return w[:40]
    except Exception:
        return None
    return None


def check(connectors, offline=False):
    """Version rows for the report."""
    rows = []
    cc = local_tool_version("claude")
    rows.append({"name": "Claude Code", "how": "App", "running": cc or "not found",
                 "ecosystem": "npm", "package": "@anthropic-ai/claude-code"})
    node = local_tool_version("node")
    if node:
        rows.append({"name": "Node.js", "how": "Installed program", "running": node})
    rows.append({"name": "Python", "how": "Installed program", "running": platform.python_version()})

    for name, c in sorted(connectors.items()):
        rows.append({"name": name, "how": c["source"], "running": c.get("version") or "",
                     "ecosystem": c.get("ecosystem"), "package": c.get("package"),
                     "pinned": c.get("pinned")})

    for r in rows:
        r.setdefault("latest", None)
        r.setdefault("advisories", None)
        if offline or not r.get("ecosystem") or not r.get("package"):
            continue
        r["latest"] = latest(r["ecosystem"], r["package"])
        if r.get("running") and SAFE_VERSION.match(r["running"]):
            r["advisories"] = advisories(r["ecosystem"], r["package"], r["running"])

    for r in rows:
        running, newest, adv = r.get("running"), r.get("latest"), r.get("advisories")
        if r["how"] == "Vendor-hosted":
            r["call"] = ("watch", "No version published; watched by changes to its actions")
        elif adv:
            r["call"] = ("bad", "Known security problem in this version: update after reviewing")
        elif r.get("pinned") is False:
            r["call"] = ("warn", "Not pinned: it runs whatever is newest each time it starts")
        elif r["how"].startswith("Installed from"):
            r["call"] = ("muted", "Not checked: installed from a git address or a folder")
        elif newest and running and _newer(running, newest):
            r["call"] = ("warn", "Newer version available: review what changed, then update")
        elif newest and running:
            r["call"] = ("ok", "Current")
        else:
            r["call"] = ("muted", "Latest version not checked")
    return rows
