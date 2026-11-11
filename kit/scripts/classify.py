"""Sort each connector action into a class, from the words in its name.

Classes, from most to least serious:
    spend   purchase, deploy, upgrade
    send    send, share, post, publish (ways data can leave)
    delete  delete, remove, trash
    update  change something that exists
    create  make something new
    read    look only

A more serious word always wins. "find_and_replace_doc" is an update,
not a read, because "replace" outranks "find".

If no known word is found, the action counts as an update and is marked
"unclear", so the report leans toward caution on purpose.
"""

import re

CLASSES = ["spend", "send", "delete", "update", "create", "read"]

WORDS = {
    "spend": {
        "purchase", "buy", "pay", "payment", "checkout", "subscribe",
        "upgrade", "deploy", "redeploy", "promote", "rollback", "transfer",
    },
    "send": {
        "send", "reply", "forward", "post", "publish", "share", "invite",
        "notify", "broadcast", "comment", "react", "reaction", "submit",
        "email", "message", "tweet", "dm",
    },
    "delete": {
        "delete", "remove", "trash", "purge", "destroy", "erase", "revoke",
        "unlink", "unpublish", "drop", "wipe", "clear",
    },
    "update": {
        "update", "edit", "modify", "set", "patch", "move", "rename",
        "replace", "manage", "change", "apply", "merge", "label", "mark",
        "toggle", "enable", "disable", "reset", "assign", "accept",
        "decline", "respond", "sync", "configure", "pin", "unpin", "archive",
        "restore", "transition", "approve", "reject", "close", "reopen",
        "format", "sort", "batch", "unlabel", "unmark", "untrash", "unarchive", "unstar", "star",
        "snooze", "mute", "unmute", "follow", "unfollow", "subscribe_to", "click", "type", "press", "drag",
        "fill", "select", "navigate", "scroll", "key",
    },
    "create": {
        "create", "add", "new", "insert", "upload", "write", "draft",
        "make", "copy", "import", "generate", "append", "start", "run",
        "execute", "invoke", "kickstart", "trigger", "schedule", "book",
        "save", "duplicate", "clone", "fork", "record",
    },
    "read": {
        "get", "list", "read", "search", "find", "fetch", "query", "view",
        "describe", "show", "check", "count", "download", "retrieve",
        "lookup", "aggregate", "inspect", "analyze", "analyse", "resolve",
        "parse", "verify", "preview", "browse", "summarize", "summary",
        "status", "info", "whoami", "me", "export", "screenshot", "zoom",
        "wait", "transcript", "transcripts", "context", "guide", "help",
    },
}

# "send" words that are really reads when paired with a read word, e.g.
# "list_messages", "get_email", "search_messages".
NOUN_LIKE = {"message", "email", "comment", "post", "reaction", "dm"}


def split_words(name):
    """Split a tool name into lower-case words: camelCase, snake, kebab."""
    name = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [w for w in re.split(r"[^A-Za-z0-9]+", name.lower()) if w]


def action_part(tool_name):
    """mcp__server__tool -> tool. Anything else is returned unchanged."""
    if tool_name.startswith("mcp__") and "__" in tool_name[5:]:
        return tool_name[5:].split("__", 1)[1]
    return tool_name


def server_part(tool_name):
    """mcp__server__tool -> server. Returns None for built-in tools."""
    if tool_name.startswith("mcp__") and "__" in tool_name[5:]:
        return tool_name[5:].split("__", 1)[0]
    return None


def classify(tool_name):
    """Return (class, deciding_word, unclear)."""
    words = split_words(action_part(tool_name))
    found = {}
    for cls in CLASSES:
        for w in words:
            if w in WORDS[cls]:
                found.setdefault(cls, w)
    # A noun such as "message" or "email" is not a send by itself:
    # "list_messages" reads, "untrash_message" changes. Only a real send verb counts.
    if "send" in found and found["send"] in NOUN_LIKE:
        verbs = [w for w in words if w in WORDS["send"] and w not in NOUN_LIKE]
        if verbs:
            found["send"] = verbs[0]
        else:
            del found["send"]
    # Creating a deployment launches code or a site: treat it like spending.
    if "create" in found and any(w in ("deployment", "deployments") for w in words):
        found["spend"] = "deployment"
    # "send_message_draft" only makes a draft; "send_draft" really sends one.
    if found.get("send") and words and words[-1] in ("draft", "drafts"):
        del found["send"]
        found.setdefault("create", words[-1])
    for cls in CLASSES:
        if cls in found:
            return cls, found[cls], False
    return "update", None, True
