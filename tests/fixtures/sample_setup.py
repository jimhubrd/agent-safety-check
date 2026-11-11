"""A typical cohort member's setup, made up for the sample report and the tests."""

TOOLS = {
    "claude_ai_Gmail": ["search_threads", "get_thread", "get_message", "list_labels", "create_draft",
                        "send_message", "reply", "label_message", "trash_message", "download_attachment"],
    "claude_ai_Google_Calendar": ["list_events", "get_event", "search_events", "create_event",
                                  "update_event", "delete_event", "respond_to_event", "suggest_time"],
    "claude_ai_Google_Drive": ["search_files", "read_file_content", "get_file_metadata", "create_file",
                               "update_file", "copy_file", "share_file", "trash_file"],
    "claude_ai_Slack": ["search_public", "read_channel", "read_thread", "list_user_channels",
                        "send_message", "schedule_message", "add_reaction", "create_canvas"],
    "claude_ai_Notion": ["search", "fetch", "create_pages", "update_page", "move_pages",
                         "duplicate_page", "create_database", "get_comments", "create_comment"],
    "filesystem": ["read_file", "list_directory", "search_files", "write_file", "edit_file", "move_file"],
    "web-research": ["web_search", "fetch_page"],
}

CONNECTORS = {
    "filesystem": {"source": "Pinned version", "ecosystem": "npm",
                   "package": "@modelcontextprotocol/server-filesystem", "version": "2025.8.21", "pinned": True},
    "web-research": {"source": "Unpinned: newest code every start", "ecosystem": "npm",
                     "package": "web-research-mcp", "version": None, "pinned": False},
}

RULES = {"allow": ["mcp__claude_ai_Gmail", "mcp__claude_ai_Google_Calendar__list_events", "mcp__filesystem"],
         "ask": [], "deny": [], "mode": "default", "hooks": []}


def inventory():
    return [{"name": "mcp__%s__%s" % (s, a)} for s, acts in TOOLS.items() for a in acts]
