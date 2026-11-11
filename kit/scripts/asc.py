#!/usr/bin/env python3
"""Agent Safety Check: command line entry point.

    python3 asc.py selftest                      check this computer can run the tool
    python3 asc.py files                         list every file the tool may read
    python3 asc.py run --inventory FILE [--drills DIR] [--offline]
    python3 asc.py open                          print the path of the newest report
    python3 asc.py uninstall [--confirm] [--remove-reports]

The tool reads configuration and writes only inside its own folder:
    ~/agent-safety-check/   (reports and snapshots)
It never changes settings, never installs anything and never sends messages.
"""

import argparse
import datetime as dt
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyze      # noqa: E402
import config       # noqa: E402
import report       # noqa: E402
import versions     # noqa: E402

VERSION = "0.1.0"
DATA = Path.home() / "agent-safety-check"
SKILL_DIR = Path.home() / ".claude" / "skills" / "agent-safety-check"
AGENT_FILE = Path.home() / ".claude" / "agents" / "asc-drill-reader.md"


def load_inventory(path):
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw.get("tools", raw) if isinstance(raw, dict) else raw
    tools = []
    for t in items:
        name = t if isinstance(t, str) else t.get("name")
        if name and name.startswith("mcp__"):
            tools.append({"name": name})
    seen, unique = set(), []
    for t in tools:
        if t["name"] not in seen:
            seen.add(t["name"])
            unique.append(t)
    return unique


def latest_snapshot():
    snaps = sorted((DATA / "snapshots").glob("*.json")) if (DATA / "snapshots").exists() else []
    if not snaps:
        return None, None
    with open(snaps[-1], "r", encoding="utf-8") as fh:
        return json.load(fh), snaps[-1].stem


def read_drills(folder):
    results = []
    for drill in analyze.DRILLS:
        text = None
        if folder:
            p = Path(folder) / ("drill-%d-output.txt" % drill["id"])
            if p.exists():
                text = p.read_text(encoding="utf-8", errors="replace")
        results.append((drill, analyze.score_drill(drill, text)))
    return results


def analyse(tools, connector_cfg, rules, vrows, secret_rows, drill_results, prev, prev_name, now, sample=False):
    amap = analyze.access_map(tools, connector_cfg, rules)
    legs = analyze.overall_legs(amap)
    snap = analyze.snapshot(amap, connector_cfg, rules)
    change_rows = analyze.changes(prev, snap)
    score, letter, fixes = analyze.grade_and_fixes(amap, legs, vrows, secret_rows, drill_results, change_rows)
    snap["grade"] = letter
    snap["score"] = score
    data = {
        "when": now.strftime("%A %d %B %Y, %H:%M"),
        "compared": ("Compared with the check on %s" % prev_name) if prev_name else "First check on this computer",
        "compared_when": prev_name, "score": score, "letter": letter, "fixes": fixes,
        "previous_grade": (prev or {}).get("grade"), "amap": amap, "legs": legs,
        "approvals": analyze.approvals(rules), "mode": rules.get("mode"),
        "guard_words": analyze.GUARD_WORDS, "changes": change_rows, "drills": drill_results,
        "versions": vrows, "secrets": secret_rows, "version": VERSION, "sample": sample,
    }
    return data, snap


def cmd_run(args):
    now = dt.datetime.now()
    tools = load_inventory(args.inventory)
    if not tools:
        print("No connector actions were found in the inventory file. Nothing to check.")
        return 1
    connector_cfg = config.connectors()
    rules = config.settings()
    vrows = versions.check(connector_cfg, offline=args.offline)
    secret_rows = config.secrets()
    drill_results = read_drills(args.drills)
    prev, prev_name = latest_snapshot()
    data, snap = analyse(tools, connector_cfg, rules, vrows, secret_rows, drill_results, prev, prev_name, now)

    (DATA / "snapshots").mkdir(parents=True, exist_ok=True)
    (DATA / "reports").mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y-%m-%d-%H%M")
    with open(DATA / "snapshots" / (stamp + ".json"), "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=1)
    out = DATA / "reports" / ("report-%s.html" % stamp)
    out.write_text(report.build(data), encoding="utf-8")

    print("Grade: %s (%d of 100)" % (data["letter"], data["score"]))
    for i, f in enumerate(data["fixes"][:3], 1):
        print("%d. %s" % (i, f["title"]))
    print("Report: %s" % out)
    return 0


def cmd_selftest(_):
    ok = True
    print("Agent Safety Check %s" % VERSION)
    if sys.version_info < (3, 9):
        print("FAIL Python 3.9 or newer is needed. This is %s." % sys.version.split()[0])
        ok = False
    else:
        print("ok   Python %s" % sys.version.split()[0])
    print("ok   Scripts found in %s" % HERE)
    print(("ok   " if AGENT_FILE.exists() else "note ") + "Fire drill helper %s" % ("installed" if AGENT_FILE.exists() else "not installed: the fire drill will be skipped"))
    found = [str(p) for p, _ in config.config_files() if p.exists()]
    print("ok   %d configuration file%s found to read" % (len(found), "" if len(found) == 1 else "s"))
    print("ok   Reports will be saved in %s" % DATA)
    print("RESULT %s" % ("ready" if ok else "not ready"))
    return 0 if ok else 1


def cmd_files(_):
    print("Files this tool may read (only those that exist are opened):")
    for p, label in config.config_files():
        print("  %-34s %s%s" % (label, p, "" if p.exists() else "  (not present)"))
    print("Plus manifest.json of desktop app extensions, for their version number only.")
    print("Network: only registry.npmjs.org, pypi.org and api.osv.dev, with package names and versions.")
    print("Writes: only inside %s" % DATA)
    return 0


def cmd_open(_):
    reps = sorted((DATA / "reports").glob("report-*.html")) if (DATA / "reports").exists() else []
    print(reps[-1] if reps else "No reports yet.")
    return 0


def cmd_uninstall(args):
    targets = [SKILL_DIR, AGENT_FILE] + ([DATA] if args.remove_reports else [])
    print("Uninstall will remove:")
    for t in targets:
        print("  %s%s" % (t, "" if t.exists() else "  (not present)"))
    if not args.remove_reports:
        print("Your reports in %s are kept. Add --remove-reports to delete them too." % DATA)
    if not args.confirm:
        print("Nothing removed yet. Run again with --confirm to remove these.")
        return 0
    for t in targets:
        if t.is_dir():
            shutil.rmtree(t)
        elif t.exists():
            t.unlink()
    print("Removed.")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="asc", description="Agent Safety Check")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--inventory", required=True, help="JSON list of the tools Claude can see")
    r.add_argument("--drills", help="folder holding drill-N-output.txt files")
    r.add_argument("--offline", action="store_true", help="skip version lookups")
    sub.add_parser("selftest")
    sub.add_parser("files")
    sub.add_parser("open")
    u = sub.add_parser("uninstall")
    u.add_argument("--confirm", action="store_true")
    u.add_argument("--remove-reports", action="store_true")
    args = p.parse_args(argv)
    return {"run": cmd_run, "selftest": cmd_selftest, "files": cmd_files,
            "open": cmd_open, "uninstall": cmd_uninstall}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
