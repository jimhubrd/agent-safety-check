#!/usr/bin/env python3
"""Agent Safety Check: command line entry point.

    python3 asc.py selftest                     check this computer can run the tool
    python3 asc.py files                        list every file the tool may read
    python3 asc.py run --inventory FILE [--drills DIR] [--offline]
    python3 asc.py accept FINDING_ID            record that you are OK with a finding
    python3 asc.py unaccept FINDING_ID          bring a finding back
    python3 asc.py level hands-on|guided|autopilot   record the operating style you want
    python3 asc.py open                         print the path of the newest report
    python3 asc.py uninstall [--confirm] [--remove-reports]

The tool reads configuration and writes only inside its own folder,
~/agent-safety-check. It never changes settings, installs anything or sends messages.
"""

import sys
sys.dont_write_bytecode = True   # leave no cache files next to the scripts

import argparse          # noqa: E402
import datetime as dt    # noqa: E402
import hashlib           # noqa: E402
import json              # noqa: E402
import os                # noqa: E402
import shutil            # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyze      # noqa: E402
import config       # noqa: E402
import report       # noqa: E402
import versions     # noqa: E402

VERSION = "0.1.0"
DATA = Path.home() / "agent-safety-check"
MARKER = DATA / ".agent-safety-check"
CHOICES = DATA / "choices.json"
SKILL_DIR = Path.home() / ".claude" / "skills" / "agent-safety-check"
AGENT_FILE = Path.home() / ".claude" / "agents" / "asc-drill-reader.md"
OWN_ENTRIES = {".agent-safety-check", "reports", "snapshots", "drills", "inventory.json", "choices.json"}


def ensure_data():
    DATA.mkdir(parents=True, exist_ok=True)
    if not MARKER.exists():
        MARKER.write_text("Folder created by Agent Safety Check.\n", encoding="utf-8")


def load_choices():
    try:
        with open(CHOICES, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return {"accepted": data.get("accepted", {}), "level": data.get("level"),
                "last_fingerprints": data.get("last_fingerprints", {})}
    except (OSError, ValueError):
        return {"accepted": {}, "level": None, "last_fingerprints": {}}


def save_choices(ch):
    ensure_data()
    with open(CHOICES, "w", encoding="utf-8") as fh:
        json.dump(ch, fh, indent=1)


def folder_key(cwd=None):
    return hashlib.sha256(str(Path(cwd or os.getcwd()).resolve()).encode()).hexdigest()[:10]


def load_inventory(path):
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    items = raw.get("tools", raw) if isinstance(raw, dict) else raw
    seen, tools = set(), []
    for t in items:
        name = t if isinstance(t, str) else (t or {}).get("name")
        if isinstance(name, str) and name.startswith("mcp__") and len(name) < 200 and name not in seen:
            seen.add(name)
            tools.append({"name": name})
    return tools


def latest_snapshot(key):
    folder = DATA / "snapshots" / key
    snaps = sorted(folder.glob("*.json")) if folder.exists() else []
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
                text = p.read_text(encoding="utf-8", errors="replace")[:20000]
        results.append((drill, analyze.score_drill(drill, text)))
    return results


def analyse(tools, connector_cfg, rules, vrows, secret_rows, drill_results, prev, prev_name, now,
            choices=None, sample=False):
    choices = choices or {"accepted": {}, "level": None}
    amap = analyze.access_map(tools, connector_cfg, rules)
    paths = analyze.other_paths(rules)
    legs = analyze.overall_legs(amap, paths)
    missing = analyze.missing_connectors(amap, connector_cfg)
    detected = analyze.detect_level(amap, paths, rules)
    chosen = choices.get("level")
    found = analyze.findings(amap, paths, vrows, secret_rows, drill_results, missing, choices.get("accepted"))
    found = analyze.apply_level(found, chosen or "guided")
    snap = analyze.snapshot(amap, rules)
    snap["detected_level"] = detected
    data = {
        "when": now.strftime("%A %d %B %Y, %H:%M"),
        "compared": ("Compared with the check on %s" % prev_name) if prev_name else "First check from this folder",
        "compared_when": prev_name, "findings": found, "detected": detected, "chosen": chosen,
        "levels": analyze.LEVELS, "amap": amap, "paths": paths, "legs": legs, "missing": missing,
        "approvals": analyze.approvals(rules), "mode": rules.get("mode"),
        "guard_words": analyze.GUARD_WORDS, "changes": analyze.changes(prev, snap), "drills": drill_results,
        "versions": vrows, "secrets": secret_rows, "version": VERSION, "sample": sample,
    }
    return data, snap


def nice_stamp(stem):
    try:
        return dt.datetime.strptime(stem, "%Y-%m-%d_%H%M%S").strftime("%A %d %B %Y, %H:%M")
    except ValueError:
        return stem


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
    key = folder_key()
    prev, prev_name = latest_snapshot(key)
    choices = load_choices()
    data, snap = analyse(tools, connector_cfg, rules, vrows, secret_rows, drill_results, prev,
                         nice_stamp(prev_name) if prev_name else None, now, choices)

    ensure_data()
    (DATA / "snapshots" / key).mkdir(parents=True, exist_ok=True)
    (DATA / "reports").mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y-%m-%d_%H%M%S")
    with open(DATA / "snapshots" / key / (stamp + ".json"), "w", encoding="utf-8") as fh:
        json.dump(snap, fh, indent=1)
    out = DATA / "reports" / ("report-%s.html" % stamp)
    out.write_text(report.build(data), encoding="utf-8")
    choices["last_fingerprints"] = {f["id"]: f["fingerprint"] for f in data["findings"]}
    save_choices(choices)

    open_ = [f for f in data["findings"] if f["state"] != "accepted" and f["level"] != "info"]
    lvl = analyze.LEVELS[data["detected"]][0]
    print("Your setup's operating style: %s%s" % (lvl, "" if data["chosen"] else " (you have not chosen an operating style yet)"))
    print("Things to be aware of: %d new or changed, %d accepted by you" % (
        len(open_), sum(1 for f in data["findings"] if f["state"] == "accepted")))
    for f in open_[:3]:
        print("- %s [%s]" % (f["title"], f["id"]))
    print("Report: %s" % out)
    return 0


def cmd_accept(args):
    if not analyze.SAFE_ID.match(args.id):
        print("That is not a valid finding id. Nothing recorded.")
        return 1
    ch = load_choices()
    fp = ch["last_fingerprints"].get(args.id)
    if not fp:
        print("No finding with the id \"%s\" in your latest report. Nothing recorded." % args.id)
        return 1
    ch["accepted"][args.id] = {"fingerprint": fp, "when": dt.date.today().isoformat()}
    save_choices(ch)
    print("Recorded: you are OK with \"%s\". It will stay quiet unless it changes." % args.id)
    return 0


def cmd_unaccept(args):
    ch = load_choices()
    if ch["accepted"].pop(args.id, None) is None:
        print("\"%s\" was not accepted. Nothing changed." % args.id)
        return 1
    save_choices(ch)
    print("\"%s\" will show again in your next report." % args.id)
    return 0


def cmd_level(args):
    ch = load_choices()
    ch["level"] = args.level
    save_choices(ch)
    name, desc = analyze.LEVELS[args.level]
    print("Recorded: your operating style is %s. %s Your next report will measure against it." % (name, desc))
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
    print(("ok   " if AGENT_FILE.exists() else "note ") + "Fire drill helper %s" % (
        "installed" if AGENT_FILE.exists() else "not installed: the fire drill will be skipped"))
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
    targets = [SKILL_DIR, AGENT_FILE]
    print("Uninstall will remove:")
    for t in targets:
        print("  %s%s" % (t, "" if t.exists() else "  (not present)"))
    data_ok = True
    if args.remove_reports and DATA.exists():
        extra = sorted(e.name for e in DATA.iterdir() if e.name not in OWN_ENTRIES)
        if not MARKER.exists() or extra:
            data_ok = False
            print("  NOT removing %s: it holds files this tool did not create (%s)." % (DATA, ", ".join(extra[:5]) or "no marker"))
        else:
            print("  %s (your reports and history)" % DATA)
    elif not args.remove_reports:
        print("Your reports in %s are kept. Add --remove-reports to delete them too." % DATA)
    if not args.confirm:
        print("Nothing removed yet. Run again with --confirm to remove these.")
        return 0
    for t in targets:
        if t.is_symlink() or t.is_file():
            t.unlink()
        elif t.is_dir():
            shutil.rmtree(t)
    if args.remove_reports and data_ok and DATA.exists():
        for e in DATA.iterdir():
            if e.name in OWN_ENTRIES:
                shutil.rmtree(e) if e.is_dir() and not e.is_symlink() else e.unlink()
        try:
            DATA.rmdir()
        except OSError:
            pass
    print("Removed.")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="asc", description="Agent Safety Check")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--inventory", required=True, help="JSON list of the tools Claude can see")
    r.add_argument("--drills", help="folder holding drill-N-output.txt files")
    r.add_argument("--offline", action="store_true", help="skip version lookups")
    a = sub.add_parser("accept")
    a.add_argument("id")
    ua = sub.add_parser("unaccept")
    ua.add_argument("id")
    lv = sub.add_parser("level")
    lv.add_argument("level", choices=analyze.CHOOSABLE)
    sub.add_parser("selftest")
    sub.add_parser("files")
    sub.add_parser("open")
    u = sub.add_parser("uninstall")
    u.add_argument("--confirm", action="store_true")
    u.add_argument("--remove-reports", action="store_true")
    args = p.parse_args(argv)
    return {"run": cmd_run, "accept": cmd_accept, "unaccept": cmd_unaccept, "level": cmd_level,
            "selftest": cmd_selftest, "files": cmd_files, "open": cmd_open,
            "uninstall": cmd_uninstall}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
