"""Work out, for a regex, a piece of plain text that every match must contain.

The scanner uses these to skip almost every log line with a few substring checks instead of
running ~100 regexes on it. The extraction is deliberately conservative: it only uses text that is
certain to be present, and when it cannot find any it says so, and the pattern is then always
tested in full. A wrong answer here would silently hide a finding, so tests compare the fast
path against the full one.
"""
from __future__ import annotations

MIN_LEN = 4
_SPECIAL = set(".^$*+?{}[]()|\\")


def _branches(rx: str) -> list[str]:
    """Split on top-level '|' (outside any group or character class)."""
    parts: list[str] = []
    depth = 0
    in_class = False
    cur: list[str] = []
    i = 0
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            cur.append(rx[i : i + 2])
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append("".join(cur))
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    parts.append("".join(cur))
    return parts


def _group_end(text: str, start: int) -> int:
    """Index of the ')' that closes the group opened at `start`."""
    depth = 0
    in_class = False
    i = start
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text) - 1


def _longest_required_run(branch: str) -> str:
    """Longest run of plain characters that must appear, ignoring anything inside groups
    (except named capture groups, which are just wrappers) or character classes."""
    runs: list[str] = []
    cur: list[str] = []
    stack: list[bool] = []  # True when a group is a transparent named-capture wrapper
    hidden = 0              # number of enclosing non-transparent groups
    in_class = False
    i = 0

    def flush():
        nonlocal cur
        if cur:
            runs.append("".join(cur))
        cur = []

    while i < len(branch):
        c = branch[i]
        if in_class:
            if c == "\\":
                i += 2
                continue
            if c == "]":
                in_class = False
            i += 1
            continue
        if c == "\\":
            nxt = branch[i + 1] if i + 1 < len(branch) else ""
            if nxt in _SPECIAL and not hidden:
                cur.append(nxt)          # escaped literal such as \. or \(
            else:
                flush()                  # \s \d \w \b etc.
            i += 2
            continue
        if c == "[":
            flush()
            in_class = True
            i += 1
            continue
        if c == "(":
            flush()
            transparent = branch.startswith("(?P<", i)
            if transparent:
                # A named group is only a wrapper if it holds a single alternative.
                inner = branch[branch.find(">", i) + 1 : _group_end(branch, i)]
                transparent = len(_branches(inner)) == 1
            stack.append(transparent)
            if not transparent:
                hidden += 1
            # skip the group header: "(?:", "(?P<name>", lookaheads etc.
            if branch.startswith("(?P<", i):
                i = branch.find(">", i) + 1
            elif branch.startswith("(?", i):
                i += 2
                # consume the flag/lookahead marker chars (":", "=", "!", "<=", "<!")
                while i < len(branch) and branch[i] in ":=!<":
                    i += 1
            else:
                i += 1
            continue
        if c == ")":
            flush()
            if stack and not stack.pop():
                hidden -= 1
            i += 1
            # a quantifier after a group makes the whole group optional/repeated: nothing to do,
            # because we never took literals from non-transparent groups anyway
            continue
        if c in "*?{":
            if cur and not hidden:
                cur.pop()                # the quantified character is optional (or repeated)
            flush()
            if c == "{":                 # skip the whole {n,m} quantifier
                end = branch.find("}", i)
                i = end + 1 if end != -1 else i + 1
            else:
                i += 1
            continue
        if c == "+":
            flush()
            i += 1
            continue
        if c in ".^$|":
            flush()
            i += 1
            continue
        if not hidden:
            cur.append(c)
        i += 1
    flush()
    runs = [r for r in runs if r]
    return max(runs, key=len) if runs else ""


def _first_required_group(branch: str) -> str | None:
    """Contents of the first top-level group that must match (not made optional by ? * or {0,)."""
    depth = 0
    in_class = False
    start = -1
    i = 0
    while i < len(branch):
        c = branch[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
        elif c == "(":
            if depth == 0 and not branch.startswith("(?P<", i):
                start = i
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0 and start >= 0:
                nxt = branch[i + 1 : i + 4]
                optional = nxt[:1] in ("?", "*") or nxt.startswith("{0")
                if not optional:
                    inner = branch[start:i]
                    if inner.startswith("(?:"):
                        return inner[3:]
                start = -1
        i += 1
    return None


def _literals_for_branch(branch: str, depth: int = 0) -> list[str] | None:
    lit = _longest_required_run(branch).lower()
    if len(lit) >= MIN_LEN:
        return [lit]
    inner = _first_required_group(branch)
    if inner is None or depth > 2:
        return None
    out: list[str] = []
    for sub in _branches(inner):
        got = _literals_for_branch(sub, depth + 1)
        if got is None:
            return None
        out += got
    return out


def required_literals(rx: str) -> list[str] | None:
    """Lower-case strings such that every match of `rx` contains at least one of them.
    None means no safe literal could be found, so the regex must always be tested."""
    out: list[str] = []
    for branch in _branches(rx):
        got = _literals_for_branch(branch)
        if got is None:
            return None
        out += got
    return out
