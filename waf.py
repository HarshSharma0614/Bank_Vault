"""
Cyber-Sentinel v1 — Ganton Bank Intrusion Filter
--------------------------------------------------
A "smart" WAF the bank's IT intern bolted onto the login and search
terminals after the last break-in attempt. It strips known-bad SQL
keywords out of anything a user types, once, and calls it a day.

(That single word "once" is the whole ballgame.)
"""

import re

BLOCKED_PATTERNS = [
    "union",
    "select",
    "insert",
    "update",
    "delete",
    "drop",
    "or",
    "and",
    "sleep",
    "benchmark",
    "--",
    "/*",
    "*/",
    "#",
]


def waf_filter(user_input: str) -> str:
    """
    Removes each blocked pattern from the input, ONE non-recursive
    pass per pattern, case-insensitive. Whatever survives this pass
    is what actually gets sent to the database.
    """
    if user_input is None:
        return ""
    cleaned = user_input
    for pattern in BLOCKED_PATTERNS:
        cleaned = re.sub(re.escape(pattern), "", cleaned, flags=re.IGNORECASE)
    return cleaned


def _strip_once(text: str, pattern: str) -> str:
    """Naive single non-recursive pass -- same trick as waf_filter
    above. Vulnerable to the double-write bypass: stripping the one
    "real" occurrence out of a sandwiched pattern like "oorr" leaves
    a freshly-reconstructed "or" behind."""
    return re.sub(re.escape(pattern), "", text, flags=re.IGNORECASE)


def _strip_robust(text: str, pattern: str) -> str:
    """Loops until the pattern is completely gone. NOT bypassable by
    doubling it up -- a second pass catches whatever the first pass's
    removal would have reconstructed."""
    prev = None
    while prev != text:
        prev = text
        text = re.sub(re.escape(pattern), "", text, flags=re.IGNORECASE)
    return text


def login_waf_filter(text: str, field: str, mode: int) -> str:
    """
    Exactly one (field, technique) combination is ever vulnerable at a
    time, decided by `mode` (1-4, see LOGIN_BYPASS_MODE):

      1 - OR/AND double-write bypass, USERNAME field only
      2 - OR/AND double-write bypass, PASSWORD field only
      3 - Comments (--  /*  */  #) are not filtered at all this run
      4 - OR/AND completely unfiltered, USERNAME field only (no
          double-write needed)

    union/select/insert/update/delete/drop/sleep/benchmark are always
    robustly blocked here regardless of mode -- none of the four modes
    need them, so leaving a fifth way in would defeat the point.
    Whichever (field, technique) ISN'T the active one this run gets the
    robust (loop-until-gone) treatment, so a payload built for a
    different mode reliably breaks instead of accidentally working.
    """
    if text is None:
        return ""

    naive_field = {1: "username", 2: "password"}.get(mode)
    plain_field = "username" if mode == 4 else None
    allow_comments = mode == 3

    cleaned = text
    for pattern in ("union", "select", "insert", "update", "delete", "drop", "sleep", "benchmark"):
        cleaned = _strip_robust(cleaned, pattern)

    if field == plain_field:
        pass
    elif field == naive_field:
        cleaned = _strip_once(cleaned, "or")
        cleaned = _strip_once(cleaned, "and")
    else:
        cleaned = _strip_robust(cleaned, "or")
        cleaned = _strip_robust(cleaned, "and")

    for pattern in ("--", "/*", "*/", "#"):
        if not allow_comments:
            cleaned = _strip_robust(cleaned, pattern)

    return cleaned
