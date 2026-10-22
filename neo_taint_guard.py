#!/usr/bin/env python3
"""neo_taint_guard — Claude Code PreToolUse hook for phantombot turns.

Model: a turn becomes TAINTED the moment it pulls in outside content
(WebFetch/WebSearch, any MCP tool, curl/wget, logs, ...). From then on
privileged / exfil-capable / obfuscating tool calls are DENIED. Confirmation =
Ronald starts a fresh turn with that action (new session_id = clean).

Scope: only active inside phantombot turns (PHANTOMBOT_TURN_ID set), unless
NEO_GUARD_ALL=1. Untrusted-tier turns (scratch path .../scratch/untrusted/...)
start tainted. Fails CLOSED inside a phantombot turn.

Limits (soft boundary, runs as the same user): variable indirection
(K=kubectl; $K delete), exfil via GET query strings, and anything the regexes
do not anticipate. This raises the bar; OS isolation is the hard boundary.
"""
import json, os, re, sys, time

TAINT_DIR = os.path.expanduser(os.environ.get("NEO_GUARD_DIR", "~/.cache/neo-taint"))
HOME = os.path.expanduser("~")
# Kill switch: if this file exists the hook does nothing. A tainted turn cannot
# create it (writes to ~/.claude and the name itself are denied below).
OFF_FILE = os.path.expanduser(os.environ.get("NEO_GUARD_OFF", "~/.claude/neo-guard.off"))

# ---- taint sources -------------------------------------------------------
TAINT_TOOLS = re.compile(r"^(WebFetch|WebSearch)$|^mcp__")
TAINT_BASH = re.compile(
    r"\b(curl|wget|http|https|xh|lynx|w3m)\b"
    r"|\bkubectl\b.*\blogs\b"
    r"|\baz\s+(monitor|rest)\b"
    r"|\bgh\s+(issue|pr|api|run)\b"
    r"|\b(Downloads|mail-quarantine)/"
)
TAINT_READ_PATHS = re.compile(r"/(Downloads|mail-quarantine)/")

# ---- denied while tainted (Bash) ----------------------------------------
DENY_BASH = [
    ("kubectl write/exec", r"\b(kubectl|oc)\b.*\b(apply|create|delete|edit|patch|replace|scale|rollout|exec|cp|drain|cordon|uncordon|taint|label|annotate|set|run|expose|autoscale|debug|attach|port-forward|proxy|certificate)\b"),
    ("kubeconfig change", r"\bkubectl\s+config\s+(set|use|delete|rename)"),
    ("helm write", r"\bhelm\s+(install|upgrade|uninstall|delete|rollback)\b"),
    ("az write", r"\baz\b.*\b(create|delete|update|set|add|remove|assign|start|stop|restart|deploy|invoke|run-command|reset|purge|import|upload|grant|revoke|login|logout|activate|elevate)\b"),
    ("az token", r"\baz\s+account\s+get-access-token\b"),
    ("az rest write", r"\baz\s+rest\b.*(--body|-b\s|--method\s+(post|put|patch|delete)|-m\s+(post|put|patch|delete))"),
    ("aws non-read", r"\baws\s+\S+\s+(?!describe-|list-|get-caller-identity)\S"),
    ("aws secret", r"\baws\b.*\b(get-secret-value|get-session-token|get-parameter)"),
    ("http write/upload", r"\b(curl|xh|http|https)\b.*(\s-X\s*(POST|PUT|PATCH|DELETE)|\s--request\s+(POST|PUT|PATCH|DELETE)|\s-d\s|\s--data|\s-F\s|\s--form|\s-T\s|\s--upload-file|\s--json)"),
    ("wget post", r"\bwget\b.*--post"),
    ("mail send", r"sendMail|/send\b|Mail\.Send|\b(sendmail|mailx?|msmtp)\b"),
    ("git push", r"\bgit\b.*\bpush\b"),
    ("gh write", r"\bgh\s+(pr|issue|release|repo|secret|gist)\s+(create|edit|merge|close|delete|comment|set)|\bgh\s+api\b.*(-X|--method|\s-f\s|\s-F\s)"),
    ("remote shell/copy", r"\b(ssh|scp|sftp|rsync|nc|ncat|socat|telnet)\b"),
    ("phantombot privileged", r"\bphantombot\s+(task\s+add|vault|mcp\s+(call|add)|config)\b"),
    ("interpreter/obfuscation", r"\b(python[0-9.]*|perl|ruby|node|bun|deno|osascript|eval|exec|source)\b|\b(ba|z|k|da)?sh\b|base64\s+(-d|-D|--decode)|\bxxd\s+-r"),
    ("keychain", r"\bsecurity\s+(find|dump|export)"),
    ("credential/config files", r"(\.claude/|\.azure/|\.kube/|\.aws/|\.ssh/|\.gnupg/|neo-taint|neo_taint_guard|neo-guard\.off|identity\.json|msal_)"),
    ("crontab/launchd", r"\b(crontab|launchctl)\b"),
]
DENY_BASH = [(n, re.compile(p, re.I if n in ("az write", "az rest write") else 0)) for n, p in DENY_BASH]

# ---- denied while tainted (file-writing tools) --------------------------
DENY_WRITE_PATHS = re.compile(
    r"(/\.claude/|/\.azure/|/\.kube/|/\.aws/|/\.ssh/|/\.zshrc|/\.bashrc|/\.profile|/\.zprofile"
    r"|/\.git/hooks/|/package\.json$|/Makefile$|/\.envrc$|/\.vscode/|/LaunchAgents/|\.(sh|py|js|ts|command)$)"
)
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def norm(cmd: str) -> str:
    # defeat trivial quoting tricks: k"ube"ctl, k\ubectl
    return re.sub(r"[\"'\\]", "", cmd)


def key(ev: dict) -> str:
    sid = ev.get("session_id") or os.environ.get("PHANTOMBOT_TURN_ID") or "unknown"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", sid)[:128]


def marker(ev):
    return os.path.join(TAINT_DIR, key(ev))


def is_tainted(ev) -> bool:
    if "/scratch/untrusted/" in os.environ.get("PHANTOMBOT_SCRATCH", ""):
        return True
    return os.path.exists(marker(ev))


def taint(ev, why: str):
    os.makedirs(TAINT_DIR, mode=0o700, exist_ok=True)
    with open(marker(ev), "a") as f:
        f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {why}\n")


def cleanup():
    try:
        cutoff = time.time() - 2 * 86400
        for n in os.listdir(TAINT_DIR):
            p = os.path.join(TAINT_DIR, n)
            if os.path.getmtime(p) < cutoff:
                os.remove(p)
    except OSError:
        pass


def deny(reason: str):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason":
            f"neo-guard: {reason}. This turn has read outside content (tainted). "
            "Do NOT retry or work around this. Stop and tell Ronald exactly which "
            "action you want to run; he confirms by starting a fresh turn.",
    }}))
    sys.exit(0)


def main():
    if os.path.exists(OFF_FILE):
        sys.exit(0)
    in_turn = bool(os.environ.get("PHANTOMBOT_TURN_ID"))
    if not in_turn and os.environ.get("NEO_GUARD_ALL") != "1":
        sys.exit(0)
    ev = json.load(sys.stdin)
    tool = ev.get("tool_name", "")
    inp = ev.get("tool_input") or {}

    # 1. taint sources (marked BEFORE the call, so "curl x | kubectl apply -f -"
    #    in one command is already caught by step 2)
    cmd = norm(inp.get("command", "")) if tool == "Bash" else ""
    path = inp.get("file_path") or inp.get("notebook_path") or inp.get("path") or ""
    if TAINT_TOOLS.search(tool):
        taint(ev, tool)
    elif tool == "Bash" and TAINT_BASH.search(cmd):
        taint(ev, "bash: " + cmd[:200].replace("\n", " "))
    elif tool == "Read" and TAINT_READ_PATHS.search(path):
        taint(ev, "read: " + path)

    if not is_tainted(ev):
        sys.exit(0)

    # 2. privileged actions while tainted
    if tool == "Bash":
        for name, rx in DENY_BASH:
            if rx.search(cmd):
                deny(f"blocked '{name}'")
    elif tool in WRITE_TOOLS:
        if DENY_WRITE_PATHS.search(os.path.abspath(os.path.expanduser(path))):
            deny(f"blocked write to {path}")
    sys.exit(0)


if __name__ == "__main__":
    try:
        cleanup()
        main()
    except SystemExit:
        raise
    except Exception as e:  # fail closed inside phantombot turns
        if os.environ.get("PHANTOMBOT_TURN_ID"):
            print(f"neo-guard error, failing closed: {e}", file=sys.stderr)
            sys.exit(2)
        sys.exit(0)
