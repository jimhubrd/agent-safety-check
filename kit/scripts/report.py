"""Build the HTML report. Everything is escaped; the page loads nothing from the internet."""

import html

CSS = """
:root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--soft:#f8fafc;--blue:#1d4ed8;--green:#047857;--amber:#b45309;--red:#b91c1c}
*{box-sizing:border-box}body{margin:0;background:#fff;color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:0 20px}
.banner{background:#fef3c7;color:#92400e;font-size:13px;text-align:center;padding:6px}
header{border-bottom:1px solid var(--line);padding:22px 0}header h1{margin:0;font-size:24px}header p{margin:2px 0 0;color:var(--muted);font-size:14px}
.top{display:grid;grid-template-columns:170px 1fr;gap:20px;margin:24px 0}
.gradebox{border:2px solid var(--line);border-radius:14px;text-align:center;padding:18px}
.gradebox b{display:block;font-size:56px;line-height:1}.gradebox span{font-size:13px;color:var(--muted)}
.g-good{border-color:#a7f3d0;background:#ecfdf5}.g-good b{color:var(--green)}
.g-mid{border-color:#fde68a;background:#fffbeb}.g-mid b{color:var(--amber)}
.g-bad{border-color:#fecaca;background:#fef2f2}.g-bad b{color:var(--red)}
.fixes{border:1px solid var(--line);border-radius:14px;padding:16px 20px}.fixes h2{font-size:17px;margin:0 0 4px}
.fix{border-top:1px solid var(--line);padding:12px 0}.fix:first-of-type{border-top:none}
.fix b{display:block}.fix p{margin:2px 0 6px;color:#334155}
.ask{background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:13px;position:relative}
.ask span{display:block;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);margin-bottom:3px}
.ask button{position:absolute;top:8px;right:8px;font:inherit;font-size:12px;border:1px solid var(--line);background:#fff;border-radius:6px;padding:2px 8px;cursor:pointer}
.facts{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:8px}
.fact{border:1px solid var(--line);border-radius:12px;padding:12px 14px}.fact.bad{border-color:#fecaca;background:#fef2f2}.fact.ok{border-color:#a7f3d0;background:#ecfdf5}
section{margin:30px 0}section h2{font-size:19px;margin:0 0 4px}section .lead{color:var(--muted);font-size:14px;margin:0 0 12px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);background:var(--soft)}td.c{text-align:center}
.z{color:#cbd5e1}.hot{color:var(--red);font-weight:700}.warm{color:var(--amber);font-weight:700}
.pill{display:inline-block;font-size:12px;font-weight:600;border-radius:999px;padding:2px 9px;white-space:nowrap}
.p-ok{background:#ecfdf5;color:var(--green)}.p-warn{background:#fffbeb;color:var(--amber)}.p-bad{background:#fef2f2;color:var(--red)}.p-muted,.p-watch{background:#f1f5f9;color:#475569}
.sub{color:var(--muted);font-size:13px}details{margin:6px 0}summary{cursor:pointer;color:var(--blue);font-size:14px}
.limits{background:var(--soft);border:1px solid var(--line);border-radius:12px;padding:14px 18px;font-size:14px}.limits ul{margin:6px 0 0 18px;padding:0}
footer{border-top:1px solid var(--line);color:var(--muted);font-size:13px;padding:18px 0 40px;margin-top:30px}
@media (max-width:760px){.top{grid-template-columns:1fr}.facts{grid-template-columns:1fr}table{display:block;overflow-x:auto}}
"""

JS = """
document.addEventListener('click',function(e){var b=e.target.closest('button[data-copy]');if(!b)return;
var t=document.getElementById(b.dataset.copy).textContent;
if(navigator.clipboard){navigator.clipboard.writeText(t).then(function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy'},1500)})}});
"""

GUARD_PILL = {"blocked": "p-ok", "guard": "p-ok", "asks": "p-ok", "auto": "p-warn", "free": "p-bad"}
CALL_PILL = {"ok": "p-ok", "warn": "p-warn", "bad": "p-bad", "muted": "p-muted", "watch": "p-watch"}


def e(x):
    return html.escape("" if x is None else str(x))


def n(v, hot=False):
    if not v:
        return '<td class="c z">0</td>'
    return '<td class="c%s">%d</td>' % (" hot" if hot else "", v)


def build(data):
    d = data
    score, letter = d["score"], d["letter"]
    gcls = "g-good" if score >= 85 else "g-mid" if score >= 65 else "g-bad"
    prev = d.get("previous_grade")
    moved = ("First check on this computer" if not prev else
             "Same as last time (%s)" % prev if prev == letter else "Was %s last time" % prev)

    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width, initial-scale=1">'
           '<title>Agent Safety Report</title><style>%s</style></head><body>' % CSS]
    if d.get("sample"):
        out.append('<div class="banner">Sample report made from a typical made-up setup. Not a scan of a real computer.</div>')
    out.append('<header><div class="wrap"><h1>Agent Safety Report</h1><p>%s &middot; %s</p></div></header><div class="wrap">'
               % (e(d["when"]), e(d["compared"])))

    # grade and fixes
    out.append('<div class="top"><div class="gradebox %s"><b>%s</b><span>%s</span></div><div class="fixes"><h2>Fix these first</h2>' % (gcls, e(letter), e(moved)))
    if not d["fixes"]:
        out.append('<p>Nothing urgent. Keep running the check so you notice when something changes.</p>')
    for i, f in enumerate(d["fixes"][:3]):
        out.append('<div class="fix"><b>%d. %s</b><p>%s</p><div class="ask"><span>Paste this to Claude to fix it</span>'
                   '<button data-copy="fx%d">Copy</button><div id="fx%d">%s</div></div></div>'
                   % (i + 1, e(f["title"]), e(f["why"]), i, i, e(f["prompt"])))
    if len(d["fixes"]) > 3:
        out.append('<details><summary>%d more suggestions</summary>' % (len(d["fixes"]) - 3))
        for i, f in enumerate(d["fixes"][3:], start=3):
            out.append('<div class="fix"><b>%s</b><p>%s</p><div class="ask"><span>Paste this to Claude</span>'
                       '<button data-copy="fx%d">Copy</button><div id="fx%d">%s</div></div></div>'
                       % (e(f["title"]), e(f["why"]), i, i, e(f["prompt"])))
        out.append('</details>')
    out.append('</div></div>')

    # plain facts
    legs = d["legs"]
    tri = all(legs.values())
    free_send = [s for s in d["amap"].values() if s["free_send"]]
    out.append('<div class="facts">')
    out.append('<div class="fact %s"><b>%s</b><div class="sub">%s</div></div>' % (
        "bad" if tri else "ok",
        "Your agent has all three dangerous abilities" if tri else "Your agent does not have all three dangerous abilities",
        "Reads private data (%s), reads content strangers wrote (%s), and can send things out (%s)." % (
            e(", ".join(legs["private"]) or "none"), e(", ".join(legs["untrusted"]) or "none"), e(", ".join(legs["send"]) or "none"))))
    out.append('<div class="fact %s"><b>%s</b><div class="sub">%s</div></div>' % (
        "bad" if free_send else "ok",
        ("Claude can send as you through %d connector%s without asking" % (len(free_send), "" if len(free_send) == 1 else "s")) if free_send else "Nothing can send without a check",
        e(", ".join(s["name"] for s in free_send)) if free_send else "Every send, share or post action asks you first, is blocked, or passes through a guard script."))
    drills = d["drills"]
    passed = sum(1 for _, r in drills if r[0] == "ok")
    ran = sum(1 for _, r in drills if r[0] != "muted")
    out.append('<div class="fact %s"><b>Fire drill: %s</b><div class="sub">Planted instructions, tested with sending switched off.</div></div>' % (
        "ok" if ran and passed == ran else "bad" if ran else "", ("%d of %d passed" % (passed, ran)) if ran else "not run this time"))
    adv = [r for r in d["versions"] if r.get("advisories")]
    out.append('<div class="fact %s"><b>%s</b><div class="sub">%d connector%s found.</div></div></div>' % (
        "bad" if adv else "ok",
        ("%d installed version%s with known security problems" % (len(adv), "" if len(adv) == 1 else "s")) if adv else "No known security problems in installed versions",
        len(d["amap"]), "" if len(d["amap"]) == 1 else "s"))

    # standing approvals
    out.append('<section><h2>What Claude may do without asking</h2><p class="lead">Your standing approvals and block rules, in plain words. '
               'Many come from clicking "don\'t ask again".</p>')
    if d["approvals"]:
        rows = ['<tr><td class="sub">%s</td><td>%s</td></tr>' % (e(rule), e(meaning)) for rule, meaning in d["approvals"]]
        out.append('<table><tr><th>Rule</th><th>What it means</th></tr>%s</table>' % "".join(rows[:8]))
        if len(rows) > 8:
            out.append('<details><summary>Show all %d rules</summary><table>%s</table></details>' % (len(rows), "".join(rows[8:])))
    else:
        out.append('<p>No standing approvals for connectors were found. Claude asks before using connector actions.</p>')
    out.append('<p class="sub">Permission mode: %s</p></section>' % e(d.get("mode") or "default (asks)"))

    # access map
    out.append('<section><h2>Access map</h2><p class="lead">What each connector lets Claude do, counted by action. '
               'Red numbers run without asking. Actions with unclear names are counted as changes, on purpose.</p>'
               '<table><tr><th>Connector</th><th>Where it comes from</th><th class="c">Read</th><th class="c">Create</th>'
               '<th class="c">Change</th><th class="c">Delete</th><th class="c">Send or share</th><th class="c">Spend</th><th>Abilities</th></tr>')
    for s in d["amap"].values():
        c = s["counts"]
        nlegs = sum(1 for v in s["legs"].values() if v)
        pill = ("p-bad", "All three") if nlegs == 3 else ("p-warn", "Two of three") if nlegs == 2 else ("p-ok", "One of three") if nlegs == 1 else ("p-ok", "None")
        if c["send"] == 0 and c["delete"] == 0 and c["spend"] == 0 and c["create"] == 0 and c["update"] == 0:
            pill = ("p-ok", "Read only") if nlegs < 3 else pill
        out.append('<tr><td>%s</td><td class="sub">%s%s</td>%s%s%s%s%s%s<td><span class="pill %s">%s</span></td></tr>' % (
            e(s["name"]), e(s.get("source")), (" " + e(s["version"])) if s.get("version") else "",
            n(c["read"]), n(c["create"]), n(c["update"]),
            n(c["delete"], bool(s["free_delete"])), n(c["send"], bool(s["free_send"])), n(c["spend"], bool(s["free_spend"])),
            pill[0], pill[1]))
    out.append('</table><details><summary>Show every action, how it was sorted, and whether Claude asks first</summary>'
               '<table><tr><th>Connector</th><th>Action</th><th>Sorted as</th><th>Because of the word</th><th>Control</th></tr>')
    for s in d["amap"].values():
        for a in sorted(s["actions"], key=lambda a: ["spend", "send", "delete", "update", "create", "read"].index(a["class"])):
            out.append('<tr><td>%s</td><td class="sub">%s</td><td>%s</td><td class="sub">%s</td><td><span class="pill %s">%s</span></td></tr>' % (
                e(s["name"]), e(a["action"]), e(a["class"]), e(a["word"] or "unclear name"), GUARD_PILL[a["guard"]], e(d["guard_words"][a["guard"]])))
    out.append('</table></details></section>')

    # changes
    out.append('<section><h2>What changed since last time</h2><p class="lead">New connectors, new actions and changed rules. '
               'A connector that turns bad usually shows up here first.</p>')
    if d["changes"] is None:
        out.append('<p>This is the first check on this computer. From the next run on, changes appear here.</p>')
    elif not d["changes"]:
        out.append('<p><span class="pill p-ok">No changes</span> since %s.</p>' % e(d["compared_when"]))
    else:
        out.append('<table><tr><th>What</th><th>Change</th><th></th></tr>')
        for what, change, sev in d["changes"]:
            out.append('<tr><td>%s</td><td>%s</td><td><span class="pill %s">%s</span></td></tr>' % (
                e(what), e(change), CALL_PILL.get(sev, "p-muted"), {"bad": "Review now", "warn": "Worth a look", "ok": "OK", "muted": "Noted"}.get(sev, "")))
        out.append('</table>')
    out.append('</section>')

    # drills
    out.append('<section><h2>Fire drill</h2><p class="lead">Three test files, each with a planted instruction aimed at an address that '
               'cannot receive mail. A separate helper that can only read files handled them, so nothing could be sent or changed. '
               'The question is whether your agent would go along.</p><table><tr><th>Planted in</th><th>What it asked</th><th>Result</th><th>What it means</th></tr>')
    for dr, (state, label, meaning) in drills:
        out.append('<tr><td>%s</td><td>"%s"</td><td><span class="pill %s">%s</span></td><td class="sub">%s</td></tr>' % (
            e(dr["where"]), e(dr["asked"]), CALL_PILL[state], e(label), e(meaning)))
    out.append('</table></section>')

    # versions
    out.append('<section><h2>Versions</h2><p class="lead">What you run against the newest release, and known security problems. '
               'Nothing is updated automatically.</p><table><tr><th>Software</th><th>Installed as</th><th>Running</th><th>Newest</th><th>Security</th><th>Call</th></tr>')
    for r in d["versions"]:
        adv = r.get("advisories")
        sec = '<span class="pill p-bad">%d known problem%s</span>' % (len(adv), "" if len(adv) == 1 else "s") if adv else ("None known" if adv == [] else '<span class="sub">Not checked</span>')
        call = r.get("call", ("muted", ""))
        out.append('<tr><td>%s</td><td class="sub">%s</td><td>%s</td><td>%s</td><td>%s</td><td><span class="pill %s">%s</span></td></tr>' % (
            e(r["name"]), e(r["how"]), e(r.get("running") or "unknown"), e(r.get("latest") or ""), sec, CALL_PILL[call[0]], e(call[1])))
    out.append('</table></section>')

    # secrets
    out.append('<section><h2>Secrets in plain text</h2><p class="lead">Keys or passwords written directly into connector settings. '
               'Only where they are is shown, never the value.</p>')
    if d["secrets"]:
        out.append('<table><tr><th>Connector</th><th>Setting</th><th>File</th><th>Starts with</th></tr>')
        for s in d["secrets"]:
            out.append('<tr><td>%s</td><td>%s</td><td class="sub">%s</td><td class="sub">%s</td></tr>' % (e(s["connector"]), e(s["setting"]), e(s["file"]), e(s["hint"])))
        out.append('</table>')
    else:
        out.append('<p><span class="pill p-ok">None found</span> in the connector settings this tool can read.</p>')
    out.append('</section>')

    out.append('<div class="limits"><b>What this check cannot see</b><ul>'
               '<li>Actions are sorted by their names. Unclear names count as changes, so the numbers lean cautious on purpose.</li>'
               '<li>It sees the connectors available in the Claude Code session it ran in. Connectors that exist only in another app, '
               'or only on the web version of Claude, may not appear. If one you use is missing from the access map, it was not checked.</li>'
               '<li>Vendor-hosted connectors publish no version. They are watched through changes to their list of actions.</li>'
               '<li>The fire drill tests three known patterns with sending switched off. Passing does not prove nothing else could get through.</li>'
               '<li>Guard scripts are detected, not read. The report cannot tell what a guard script actually blocks.</li>'
               '<li>This is information, not a security audit.</li></ul></div></div>')
    out.append('<footer><div class="wrap">Agent Safety Check %s &middot; Written on this computer. Nothing was sent anywhere except '
               'package names and version numbers to public version databases.</div></footer>' % e(d.get("version", "")))
    out.append('<script>%s</script></body></html>' % JS)
    return "".join(out)
