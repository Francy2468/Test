import discord
from discord.ext import commands
import requests
import os
import io
import urllib.parse
import subprocess
import uuid
import time
import re
import asyncio
import functools
import struct as _struct
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()

# ---------------- CONFIG ----------------
TOKEN = os.environ.get("TOKEN_BOT", "")

PREFIX = "."
DUMPER_PATH = "catlogger.lua"

MAX_FILE_SIZE = 5 * 1024 * 1024
DUMP_TIMEOUT = 35  # Must exceed catlogger.lua TIMEOUT_SECONDS (30) to allow proper cleanup
PREVIEW_LINES = 10
PREVIEW_MAX_CHARS = 900

LUA_INTERPRETERS = ["luau", "lua5.4", "luajit", "lua"]

DISCORD_RETRY_ATTEMPTS = 3
DISCORD_RETRY_DELAY = 2.0  # seconds between retries on 503

async def _send_with_retry(coro_factory):
    """Call a coroutine that sends a Discord message, retrying up to
    DISCORD_RETRY_ATTEMPTS times when a transient 503 DiscordServerError occurs."""
    for attempt in range(DISCORD_RETRY_ATTEMPTS):
        try:
            return await coro_factory()
        except discord.errors.DiscordServerError:
            if attempt < DISCORD_RETRY_ATTEMPTS - 1:
                await asyncio.sleep(DISCORD_RETRY_DELAY * (attempt + 1))
            else:
                raise

def _requests_get(url, **kwargs):
    """requests.get wrapper with browser-like headers to avoid HTTP 403."""
    kwargs.setdefault("timeout", 8)
    default_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    if "headers" in kwargs:
        merged = dict(default_headers)
        merged.update(kwargs["headers"])
        kwargs["headers"] = merged
    else:
        kwargs["headers"] = default_headers
    return requests.get(url, **kwargs)

# ---------------- BOT ----------------
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents)

_executor = ThreadPoolExecutor(max_workers=32)

# ---------------- LUA DETECTION ----------------
def _find_lua() -> str:
    for interp in LUA_INTERPRETERS:
        try:
            r = subprocess.run([interp, "-v"], capture_output=True, timeout=3)
            if r.returncode == 0:
                return interp
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return LUA_INTERPRETERS[0]

_lua_interp = _find_lua()


# ---------------- HELPERS ----------------
def extract_links(text):

    url_pattern = r"https?://[^\s\"']+"
    links = re.findall(url_pattern, text)

    seen=set()
    result=[]

    for x in links:
        if x not in seen:
            seen.add(x)
            result.append(x)

    return result

def extract_first_url(text):

    m = re.search(r"https?://[^\s\"')]+", text)
    return m.group(0) if m else None

def get_filename_from_url(url):

    filename = url.split("/")[-1].split("?")[0]
    filename = urllib.parse.unquote(filename)

    if filename and "." in filename:
        return filename

    return "script.lua"

def _strip_loop_markers(code: str) -> str:
    """Remove '-- Detected loops N' comment lines injected by the dumper.

    These markers are diagnostic annotations that clutter the output and
    prevent the script from being used cleanly.  Strip them so only
    executable Lua code (and meaningful comments) remains.
    """
    _LOOP_MARKER_RE = re.compile(r"^\s*--\s*Detected loops\s+\d+\s*$")
    cleaned = [line for line in code.splitlines() if not _LOOP_MARKER_RE.match(line)]
    return "\n".join(cleaned)

# Pattern that strips trailing numeric counter suffixes from lowercase identifiers
# (e.g. tween2 → tween, frame3 → frame) while leaving Roblox type names like
# UDim2, Color3, Vector3 unchanged (they start with an uppercase letter).
_COUNTER_SUFFIX_RE = re.compile(r'\b([a-z][A-Za-z_]*)\d+\b')

# How many copies of a repeated block to keep before suppressing the rest.
_MAX_UNROLLED_REPS = 3


def _normalize_counters(line: str) -> str:
    """Strip trailing numeric suffixes from lowercase-starting identifiers."""
    return _COUNTER_SUFFIX_RE.sub(r'\1', line)


def _collapse_loop_unrolls(code: str, max_reps: int = _MAX_UNROLLED_REPS) -> str:
    """Collapse unrolled loop bodies where only counter-variable suffixes differ.

    When consecutive N-line blocks (1 ≤ N ≤ 50) repeat more than *max_reps*
    times and are structurally identical except for trailing digits on
    lowercase identifiers (e.g. tween, tween2, tween3 …), keep the first
    *max_reps* copies and replace the remainder with a single comment so the
    output stays readable without losing the essential loop structure.

    Any trailing partial copy of the same block that follows the last complete
    repetition is also absorbed into the omission so it does not appear as a
    stray orphan line in the output.
    """
    lines = code.splitlines()
    n = len(lines)
    if n == 0:
        return code

    # Pre-compute normalized versions of all lines once to avoid repeated regex
    # calls during the inner comparison loops.
    norm_lines = [_normalize_counters(ln) for ln in lines]

    result: list[str] = []
    i = 0

    while i < n:
        best_block_size = 0
        best_reps = 0

        for block_size in range(1, min(51, n - i + 1)):
            # Ensure a full block is available before proceeding.
            if i + block_size > n:
                break
            norm_block = norm_lines[i:i + block_size]

            # For single-line blocks, only collapse if the line is non-empty
            # and has meaningful content (not just whitespace or a bare 'end').
            if block_size == 1:
                stripped = norm_block[0].strip()
                if not stripped or stripped in ("end", "do", "then"):
                    continue

            # Count consecutive repetitions of this normalised pattern.
            reps = 1
            j = i + block_size
            while j + block_size <= n:
                if norm_lines[j:j + block_size] == norm_block:
                    reps += 1
                    j += block_size
                else:
                    break

            if reps > max_reps and reps > best_reps:
                best_reps = reps
                best_block_size = block_size

        if best_block_size and best_reps > max_reps:
            norm_block = norm_lines[i:i + best_block_size]
            # Preserve the indentation of the first non-empty line in the first
            # copy of the block before advancing i.
            first_nonempty = next(
                (ln for ln in lines[i:i + best_block_size] if ln.strip()), ""
            )
            indent_str = " " * (len(first_nonempty) - len(first_nonempty.lstrip()))
            # Emit the first max_reps copies verbatim.
            for rep in range(max_reps):
                result.extend(lines[i + rep * best_block_size:i + (rep + 1) * best_block_size])
            omitted = best_reps - max_reps
            i += best_reps * best_block_size

            # Absorb any trailing partial copy of the same block so it doesn't
            # appear as an orphaned stray line after the omission comment.
            partial = 0
            while partial < best_block_size and i + partial < n:
                if norm_lines[i + partial] == norm_block[partial]:
                    partial += 1
                else:
                    break
            if partial > 0:
                omitted += 1
                i += partial

            result.append(
                f"{indent_str}-- [similar block repeated {omitted} more time(s), omitted for clarity]"
            )
        else:
            result.append(lines[i])
            i += 1

    return "\n".join(result)


def _remove_trailing_whitespace(code: str) -> str:
    """Strip trailing whitespace from every line of *code*."""
    return "\n".join(line.rstrip() for line in code.splitlines())


def _collapse_blank_lines(code: str) -> str:
    """Replace three or more consecutive blank lines with at most two blank lines."""
    return re.sub(r"\n{3,}", "\n\n", code)


def _normalize_all_counters(code: str) -> str:
    """Strip trailing numeric suffixes from every lowercase identifier in the output.

    Applies _normalize_counters to each line so that loop-variable copies such
    as tween2, tween3, conn4, taskWait2, etc. are all reduced to their base name
    (tween, conn, taskWait).  Uppercase-starting identifiers (Vector3, UDim2,
    Color3, Part) are untouched.

    Call AFTER _collapse_loop_unrolls so the best representative copies have
    already been selected before names are normalised.  Running
    _collapse_loop_unrolls again after this step collapses further repetitions
    that are now structurally identical.
    """
    return "\n".join(_normalize_counters(ln) for ln in code.splitlines())


# Regex to detect a plain local declaration at any indent level.
_LOCAL_DECL_RE = re.compile(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=")
# Regex for lines that open a new Lua function body (introducing a new scope).
_FUNC_OPEN_RE = re.compile(r"\bfunction\b")
# Regex for lines that close a Lua block.
_BLOCK_CLOSE_RE = re.compile(r"^\s*(end|until)\b")
# Regex for lines that open non-function Lua blocks (if/for/while/do/repeat).
_NONFUNC_OPEN_RE = re.compile(r"\b(then|do)\s*(?:--.*)?$|\brepeat\b")


# How many lines ahead to scan when deciding whether a local variable is
# "ephemeral" (only used within this window → safe to wrap in do…end).
# Larger values wrap more aggressively; smaller values are more conservative.
# 12 covers typical fire-and-forget patterns (tween:Play(), conn:Connect(), …)
# without accidentally wrapping service locals referenced many lines later.
_SCOPE_LOOKAHEAD = 12


def _scope_group_locals(code: str, max_locals: int = 185) -> str:
    """Wrap ephemeral local-variable groups in ``do … end`` blocks.

    An *ephemeral* local is one whose name is never referenced more than
    *_SCOPE_LOOKAHEAD* lines after its declaration.  Wrapping such locals in
    ``do … end`` removes them from the enclosing function's local-variable
    count, keeping it below *max_locals* so the output is directly executable.

    Long-lived locals (game services, player references, etc.) that are
    referenced far into the script remain at the outer scope and are not
    wrapped.
    """

    lines = code.splitlines()
    n = len(lines)
    if n == 0:
        return code

    # -----------------------------------------------------------------------
    # Phase 1 – For each local declaration find whether the variable is only
    # used within the lookahead window (i.e., ephemeral).
    # -----------------------------------------------------------------------
    ephemeral: dict[int, int] = {}   # decl_line_idx → last_use_line_idx

    for i, line in enumerate(lines):
        m = _LOCAL_DECL_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        pat = re.compile(r"\b" + re.escape(name) + r"\b")

        last = i
        found_far = False
        for j in range(i + 1, n):
            if pat.search(lines[j]):
                if j <= i + _SCOPE_LOOKAHEAD:
                    last = j
                else:
                    found_far = True
                    break   # referenced beyond window → not ephemeral

        if not found_far:
            ephemeral[i] = last

    # -----------------------------------------------------------------------
    # Phase 2 – Merge adjacent ephemeral groups and emit with do … end.
    # -----------------------------------------------------------------------
    result: list[str] = []
    i = 0

    while i < n:
        if i in ephemeral:
            # Greedily extend this group to absorb all consecutive ephemerals
            # whose last-use falls within the current group window.
            group_end = ephemeral[i]
            j = i + 1
            # The upper bound `group_end + 1` intentionally peeks one line past
            # the current group end so that an immediately adjacent ephemeral
            # declaration (e.g. the very next local statement) is chained into
            # the same do…end block rather than generating a separate one.
            # This is safe because do…end does not restrict visibility of outer
            # variables; only the newly declared inner variables become scoped.
            while j <= group_end + 1 and j < n:
                if j in ephemeral:
                    group_end = max(group_end, ephemeral[j])
                j += 1

            indent = " " * (len(lines[i]) - len(lines[i].lstrip()))
            result.append(indent + "do")
            for k in range(i, group_end + 1):
                result.append(lines[k])
            result.append(indent + "end")
            i = group_end + 1
        else:
            result.append(lines[i])
            i += 1

    return "\n".join(result)


# The one comment line that must be kept verbatim at the top of every dump.
_CATMIO_HEADER_RE = re.compile(
    r"^--\s*generated with catmio\b.*$", re.IGNORECASE
)

# Long-bracket Lua comments: --[[ ... ]] or --[=[ ... ]=]  (inline fragments)
_INLINE_LONG_COMMENT_RE = re.compile(r"--\[=*\[.*?\]=*\]", re.DOTALL)


def _strip_inline_trailing_comment(line: str) -> str:
    """Remove a trailing short ``-- ...`` comment from a Lua code line.

    Skips ``--`` sequences that appear inside single- or double-quoted string
    literals to avoid accidentally truncating string values like ``"foo -- bar"``.
    Returns the line with the trailing comment and any preceding whitespace removed.
    """
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        # Enter a quoted string — advance past it without touching its contents.
        if ch in ('"', "'"):
            quote = ch
            i += 1
            while i < n:
                c2 = line[i]
                if c2 == '\\':
                    i += 2 if i + 1 < n else 1  # skip escape sequence (bounds-safe)
                elif c2 == quote:
                    i += 1
                    break
                else:
                    i += 1
        # Short comment start (not inside a string).
        elif ch == '-' and i + 1 < n and line[i + 1] == '-':
            return line[:i].rstrip()
        else:
            i += 1
    return line


def _strip_comments(code: str) -> str:
    """Remove all Lua comments from *code* except the catmio/discord header line.

    Handles:
    * Whole-line comments: any line whose first non-whitespace characters are ``--``
      is removed entirely (keeping only the catmio header).
    * Inline long-bracket comments: ``--[[...]]`` fragments embedded inside a code
      line are stripped, leaving the surrounding code intact.
    * Short trailing inline comments: ``  -- remark`` at the end of a code line are
      removed while respecting quoted string literals so that string values
      containing ``--`` (e.g. ``"foo -- bar"``) are not corrupted.
    """
    result: list[str] = []
    for line in code.splitlines():
        stripped = line.lstrip()
        # 1. Preserve the catmio/discord header exactly.
        if _CATMIO_HEADER_RE.match(stripped):
            result.append(line)
            continue
        # 2. Drop whole-line comments (lines whose entire content is a comment).
        if stripped.startswith("--"):
            continue
        # 3. Remove long-bracket inline comments embedded in code lines.
        line = _INLINE_LONG_COMMENT_RE.sub("", line)
        # 4. Remove short trailing inline comments, respecting string literals.
        line = _strip_inline_trailing_comment(line)
        result.append(line)
    return "\n".join(result)


# Matches two adjacent double-quoted Lua string literals joined by ..
# Handles backslash escapes inside both strings.
_STR_CONCAT_RE = re.compile(r'"((?:[^"\\]|\\.)*)"\s*\.\.\s*"((?:[^"\\]|\\.)*)"')


def _fold_string_concat(code: str) -> str:
    """Fold adjacent double-quoted string-literal concatenations.

    Repeatedly replaces ``"foo" .. "bar"`` with ``"foobar"`` until no further
    folds are possible.  Only simple double-quoted literals are handled; long
    strings and single-quoted strings are left untouched to stay safe.
    """
    prev = None
    while prev != code:
        prev = code
        code = _STR_CONCAT_RE.sub(lambda m: '"' + m.group(1) + m.group(2) + '"', code)
    return code


# Regex fragment that matches a Lua double-quoted string literal
# (handles backslash-escaped characters inside the string).
_LUA_STR_VAL = r'"(?:[^"\\]|\\.)*"'

# Constants that are runtime-captured (not pre-extracted string pools).
# _ref_N / _url_N / _webhook_N come from actual execution and may be referenced
# in the VM output above them; _s_N / _wad_N are pre-extracted pools that are
# intentional reference tables and should be preserved as-is.
# _xor_N constants are inlined by _rename_by_name_property and the inline pass.
_RUNTIME_CONST_RE = re.compile(
    r"^[ \t]*local\s+(_ref_\d+|_url_\d+|_webhook_\d+)\s*=\s*(\"(?:[^\"\\]|\\.)*\")\s*$",
    re.MULTILINE,
)


def _inline_single_use_constants(code: str) -> str:
    """Inline or remove runtime-captured string constants used ≤ 1 time.

    The catlogger emits runtime-captured string references as declarations::

        local _ref_1  = "some-captured-value"
        local _url_2  = "https://example.com"
        local _webhook_3 = "https://discord.com/api/webhooks/..."

    * A constant referenced **zero** times is dead code and is silently removed.
    * A constant referenced **exactly once** is inlined (the literal value
      replaces the identifier and the declaration is deleted), making it
      immediately clear what the value is without a separate lookup.
    * Constants referenced **two or more** times are kept as-is.

    Note: pre-extracted string pools (_s_N, _xor_N, _wad_N) are intentional
    reference tables and are deliberately left untouched by this function.
    """
    constants: dict[str, str] = {}
    for m in _RUNTIME_CONST_RE.finditer(code):
        constants[m.group(1)] = m.group(2)

    if not constants:
        return code

    result = code

    for name, value in constants.items():
        pat = re.compile(r"\b" + re.escape(name) + r"\b")
        total = len(pat.findall(result))
        uses = total - 1  # subtract the declaration itself

        if uses == 0:
            # Dead constant – remove the declaration line.
            result = re.sub(
                r"^[ \t]*local\s+" + re.escape(name) + r"\s*=\s*" + _LUA_STR_VAL + r"[ \t]*\n?",
                "",
                result,
                flags=re.MULTILINE,
            )
        elif uses == 1:
            # Single use – inline the literal and remove the declaration.
            decl_re = re.compile(
                r"^[ \t]*local\s+" + re.escape(name) + r"\s*=\s*(" + _LUA_STR_VAL + r")[ \t]*$",
                re.MULTILINE,
            )
            decl_m = decl_re.search(result)
            if decl_m:
                after = result[decl_m.end():]
                repl = value
                after = pat.sub(lambda _: repl, after, count=1)
                result = result[: decl_m.end()] + after
            result = re.sub(
                r"^[ \t]*local\s+" + re.escape(name) + r"\s*=\s*" + _LUA_STR_VAL + r"[ \t]*\n?",
                "",
                result,
                flags=re.MULTILINE,
            )

    return result


# Lua reserved words that must never be used as variable names.
_LUA_KEYWORDS = frozenset({
    "and", "break", "do", "else", "elseif", "end", "false", "for",
    "function", "goto", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
})


def _name_to_camel_id(raw: str) -> str:
    """Convert an arbitrary Name string (e.g. ``"ScanBeam"``) to a
    camelCase Lua identifier.

    Non-alphanumeric characters are treated as word separators.  The
    first word is lower-cased; subsequent words are title-cased.  Returns
    an empty string when the result would be invalid or a Lua keyword.
    """
    parts = [p for p in re.sub(r"[^a-zA-Z0-9]+", " ", raw).split() if p]
    if not parts:
        return ""
    first = parts[0]
    result = first[0].lower() + first[1:] + "".join(p.capitalize() for p in parts[1:])
    # Ensure valid identifier start
    if result and result[0].isdigit():
        result = "_" + result
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", result):
        return ""
    if result in _LUA_KEYWORDS:
        return ""
    return result


def _rename_by_name_property(code: str) -> str:
    """Rename local variables to reflect their ``.Name = "X"`` property
    assignment, greatly improving readability of deobfuscated Roblox GUIs.

    For every pattern::

        local frame2 = Instance.new("Frame")   -- or any other constructor
        ...
        frame2.Name = "ScanBeam"

    the variable ``frame2`` is renamed to ``scanBeam`` (camelCase of the
    Name value) throughout the whole output.  Only variables whose
    derived new name does not collide with any existing identifier are
    renamed.

    When no ``.Name`` assignment is found anywhere in the script but the
    declaration is ``Instance.new("TypeName")``, a unique fallback name is
    derived from the type (e.g. ``frame3`` with type ``Frame`` →
    ``frame_3``) so that counter-suffixed duplicates remain distinguishable
    after ``_normalize_all_counters`` runs.

    The scan for a ``.Name`` assignment is unbounded — the entire remaining
    script is searched — because Roblox GUI scripts routinely set properties
    many lines (or hundreds of lines) after the variable declaration.

    This pass must run **before** ``_normalize_all_counters`` so that
    numbered duplicates (``frame``, ``frame2``, ``frame3`` …) are still
    distinct identifiers and can each receive their own descriptive name.
    """
    lines = code.splitlines()
    n = len(lines)

    # Collect every identifier already present in the output to detect
    # collisions before committing a rename.
    existing: set[str] = set()
    for line in lines:
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", line):
            existing.add(m.group(1))

    renames: dict[str, str] = {}  # old_name → new_name

    # Pattern to detect Instance.new("TypeName") on the RHS of a declaration.
    _INSTANCE_NEW_RE = re.compile(r'Instance\.new\s*\(\s*"([A-Za-z][A-Za-z0-9]*)"\s*\)')

    for i, line in enumerate(lines):
        m = re.match(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
        if not m:
            continue
        var = m.group(1)
        if var in renames:
            continue  # already scheduled for rename

        # Scan the ENTIRE remaining script for VAR.Name = "SomeName".
        # Roblox GUI construction scripts routinely set .Name far below the
        # declaration, so a small fixed lookahead would miss most renames.
        found_name = False
        for j in range(i + 1, n):
            nm = re.match(
                r"^\s*" + re.escape(var) + r"\s*\.\s*Name\s*=\s*\"([^\"]+)\"",
                lines[j],
            )
            if nm:
                new_name = _name_to_camel_id(nm.group(1))
                if (
                    new_name
                    and new_name != var
                    and new_name not in renames.values()
                    and new_name not in existing
                ):
                    renames[var] = new_name
                found_name = True
                break  # stop after first .Name assignment for this var

        # Fallback: if the variable has a numeric suffix (frame2, textLabel3 …)
        # and was created with Instance.new() but has no .Name assignment, derive
        # a unique name from the type and suffix so it survives
        # _normalize_all_counters without colliding with other same-type locals.
        if not found_name:
            suffix_m = re.match(r"^([a-zA-Z_][a-zA-Z_]*)(\d+)$", var)
            inst_m = _INSTANCE_NEW_RE.search(line)
            if suffix_m and inst_m:
                type_name = inst_m.group(1)
                suffix = suffix_m.group(2)
                base = _name_to_camel_id(type_name)
                if base:
                    candidate = base + "_" + suffix
                    if (
                        candidate not in renames.values()
                        and candidate not in existing
                    ):
                        renames[var] = candidate
            # Fallback for underscore-suffixed variables: frame_, frame__,
            # uICorner_, uIGradient_, textLabel_, textButton_, etc.
            # Convert the trailing underscore count to an alphabetic suffix
            # (a, b … z, aa, ab …) so the new name does NOT end in a digit and
            # therefore survives _normalize_all_counters (which only strips
            # trailing digit sequences).  Using base-26 letter strings avoids
            # collisions even when the same type has more than 26 instances.
            elif inst_m:
                under_m = re.match(r"^([a-zA-Z][a-zA-Z0-9]*)(_+)$", var)
                if under_m:
                    type_name = inst_m.group(1)
                    underscore_count = len(under_m.group(2))
                    base = _name_to_camel_id(type_name)
                    if base:
                        # Build a base-26 letter string: 1→'a', 26→'z', 27→'aa', etc.
                        n = underscore_count
                        letters = ""
                        while n > 0:
                            n -= 1
                            letters = chr(ord("a") + (n % 26)) + letters
                            n //= 26
                        candidate = base + "_" + letters
                        if (
                            candidate not in renames.values()
                            and candidate not in existing
                        ):
                            renames[var] = candidate

    if not renames:
        return code

    # Apply all renames with word-boundary guards so only complete
    # identifiers are replaced (not sub-strings of longer names).
    # Sort longest-first to avoid partial replacement of shorter names.
    result = "\n".join(lines)
    for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
        result = re.sub(
            r"(?<![a-zA-Z0-9_])" + re.escape(old) + r"(?![a-zA-Z0-9_])",
            new,
            result,
        )

    return result


# ---------------- LUA SYNTAX FIXER ----------------

# Keywords that open a new Lua block scope (each requires a matching 'end').
_LUA_BLOCK_OPEN_RE = re.compile(r"\b(function|do|repeat)\b")
# Multi-line openers: if/for/while need a trailing 'then'/'do' to open a block.
_LUA_COND_OPEN_RE = re.compile(r"\b(if|for|while)\b")
_LUA_COND_CLOSE_RE = re.compile(r"\b(then|do)\s*(?:--.*)?$")
_LUA_BLOCK_CLOSE_RE_FIX = re.compile(r"^\s*(end|until)\b")


def _fix_lua_do_end(code: str) -> str:
    """Append missing 'end' keywords to balance unmatched Lua block openers.

    Parses each line tracking nesting depth using the same heuristics as
    ``_beautify_lua``.  If the script ends with an open block (depth > 0),
    the required number of ``end`` statements are appended so that the
    output is syntactically complete.

    This is safe to run on already-balanced scripts: when depth reaches 0
    at the end of the file nothing is appended.
    """
    depth = 0
    for raw_line in code.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue
        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        # Closers decrease depth before we inspect the line.
        if first_kw in ("end", "until"):
            depth = max(0, depth - 1)

        # Openers increase depth after the line.
        if first_kw in ("function", "do", "repeat"):
            depth += 1
        elif first_kw in ("if", "for", "while"):
            if _LUA_COND_CLOSE_RE.search(line):
                depth += 1
        elif first_kw == "then":
            depth += 1
        elif re.search(r"\bfunction\b", line) and not re.search(
            r"\bend\b\s*(?:--.*)?$", line
        ):
            # Handles 'local function', 'local x = function()', etc.
            depth += 1

    if depth > 0:
        code = code.rstrip() + "\n" + "end\n" * depth
    return code


def _fix_extra_ends(code: str) -> str:
    """Remove 'end' (or 'end)') lines that exceed the current nesting depth.

    Scans the code line-by-line tracking block-nesting depth with the same
    heuristics used by ``_fix_lua_do_end`` and ``_beautify_lua``.  Whenever
    an ``end`` or ``until`` would push the depth below zero the line is
    silently dropped so that mismatched closers do not cause syntax errors.

    This is the complement of ``_fix_lua_do_end``: that function adds missing
    ``end`` keywords; this function removes superfluous ones.  Running both in
    sequence produces balanced blocks from either direction of imbalance.
    """
    lines = code.splitlines()
    result: list[str] = []
    depth = 0

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("--"):
            result.append(raw_line)
            continue

        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        if first_kw in ("end", "until"):
            if depth <= 0:
                # Extra closer with nothing to close — drop this line.
                continue
            depth -= 1
            result.append(raw_line)
            continue

        # Track openers for non-closer lines.
        if first_kw in ("function", "do", "repeat"):
            depth += 1
        elif first_kw in ("if", "for", "while"):
            if _LUA_COND_CLOSE_RE.search(line):
                depth += 1
        elif first_kw == "then":
            depth += 1
        elif re.search(r"\bfunction\b", line) and not re.search(
            r"\bend\b\s*(?:--.*)?$", line
        ):
            depth += 1

        result.append(raw_line)

    return "\n".join(result)


# Detects a :Connect(function… opening that leaves at least one unclosed '('.
_CONN_FUNC_OPEN_RE = re.compile(r":Connect\s*\(.*\bfunction\b")


def _fix_connect_end_parens(code: str) -> str:
    """Add missing ')' to the 'end' that closes a :Connect(function…) block.

    A common deobfuscation artifact is::

        button.MouseButton1Click:Connect(function()
            doSomething()
        end          -- missing closing ')' for the Connect call

    This function detects each ``:Connect(function…`` opener that leaves an
    unclosed ``(`` from the Connect call and appends the required ``)`` to the
    ``end`` line that closes the inner function body, turning ``end`` into
    ``end)``.

    The matching is depth-based: the ``end`` that brings the block depth back
    to the level it was at when the Connect call opened is the one that needs
    the extra ``)``'s.
    """
    lines = code.splitlines()
    result = list(lines)

    # Stack entries: (line_index, block_depth_at_open, unclosed_paren_count)
    connect_stack: list[tuple[int, int, int]] = []
    block_depth = 0

    for idx, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line or line.startswith("--"):
            continue

        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        if first_kw in ("end", "until"):
            # Check whether this end closes a tracked Connect function.
            if connect_stack and block_depth - 1 == connect_stack[-1][1]:
                _, _, missing_parens = connect_stack.pop()
                existing_close = line.count(")")
                needed = missing_parens - existing_close
                if needed > 0:
                    indent = len(raw_line) - len(raw_line.lstrip())
                    result[idx] = raw_line[:indent] + "end" + ")" * needed
            block_depth = max(0, block_depth - 1)
        else:
            # Detect :Connect(function… openers.
            if _CONN_FUNC_OPEN_RE.search(line):
                paren_delta = line.count("(") - line.count(")")
                if paren_delta > 0:
                    connect_stack.append((idx, block_depth, paren_delta))

            # Track openers.
            if first_kw in ("function", "do", "repeat"):
                block_depth += 1
            elif first_kw in ("if", "for", "while"):
                if _LUA_COND_CLOSE_RE.search(line):
                    block_depth += 1
            elif first_kw == "then":
                block_depth += 1
            elif re.search(r"\bfunction\b", line) and not re.search(
                r"\bend\b\s*(?:--.*)?$", line
            ):
                block_depth += 1

    return "\n".join(result)


def _fix_ui_variable_shadowing(code: str) -> str:
    """Ensure every ``local var = Instance.new(…)`` declaration has a unique name.

    When the same variable name is declared more than once for a UI element
    (e.g. two separate ``local frame = Instance.new("Frame")`` lines), each
    subsequent re-declaration is renamed by appending an incrementing numeric
    suffix (``frame``, ``frame_2``, ``frame_3`` …).  The rename is applied
    throughout the lines that follow the re-declaration up until the next
    re-declaration of the same base name, so each block of code continues to
    reference the correct object.

    This pass runs **before** ``_rename_by_name_property`` so that unique
    suffixed names are available when the Name-based renaming looks for
    ``.Name = "…"`` assignments.
    """
    _INST_NEW_DECL_RE = re.compile(
        r"^(\s*local\s+)([a-zA-Z_][a-zA-Z0-9_]*)(\s*=\s*Instance\.new\s*\()"
    )

    lines = code.splitlines()
    # Map: base_name → number of times seen so far
    seen_count: dict[str, int] = {}

    result: list[str] = []
    # Pending renames: list of (original_name, new_name, start_line_index)
    # We apply each rename only to lines after the declaration.
    renames: list[tuple[str, str, int]] = []

    for idx, raw_line in enumerate(lines):
        m = _INST_NEW_DECL_RE.match(raw_line)
        if m:
            prefix, var_name, suffix = m.group(1), m.group(2), m.group(3)
            count = seen_count.get(var_name, 0)
            seen_count[var_name] = count + 1
            if count > 0:
                # This is a re-declaration — give it a unique name.
                new_name = f"{var_name}_{count + 1}"
                raw_line = prefix + new_name + suffix + raw_line[m.end():]
                renames.append((var_name, new_name, idx))

        # Apply active renames: replace uses of the original name in lines
        # after the re-declaration (word-boundary safe substitution).
        # We only apply the *most recent* rename for each base name so later
        # blocks reference the latest object, not an earlier one.
        active: dict[str, str] = {}
        for orig, new, start in renames:
            if start < idx:
                active[orig] = new  # later rename wins

        for orig, new in sorted(active.items(), key=lambda kv: -len(kv[0])):
            raw_line = re.sub(
                r"(?<![a-zA-Z0-9_])" + re.escape(orig) + r"(?![a-zA-Z0-9_])",
                new,
                raw_line,
            )

        result.append(raw_line)

    return "\n".join(result)


# Matches the opening line of a :Connect() event binding, capturing the
# object+event portion (e.g. "button.MouseButton1Click").
_CONN_OPEN_RE = re.compile(r"^\s*(\w[\w.]*\.\w+):Connect\s*\(")


def _dedup_connections(code: str) -> str:
    """Remove duplicate :Connect() event handler bindings.

    When the same ``obj.Event:Connect(...)`` appears more than once in the
    script (a common artifact of deobfuscation), only the first binding is
    kept.  Subsequent duplicates — including their full handler body up to
    the matching closing ``end)`` — are silently dropped.

    Detection is based on the ``obj.Event`` portion of the opening line; two
    connections are considered duplicates when they share the same
    object-and-event key regardless of whitespace differences in the rest of
    the line.
    """
    lines = code.splitlines()
    seen: set[str] = set()
    result: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _CONN_OPEN_RE.match(line)
        if m:
            conn_key = m.group(1)
            if conn_key in seen:
                # Skip this duplicate handler: walk forward until the
                # parenthesis/block opened on this line is fully closed.
                depth = line.count("(") - line.count(")")
                i += 1
                while i < len(lines) and depth > 0:
                    depth += lines[i].count("(") - lines[i].count(")")
                    i += 1
                continue
            seen.add(conn_key)
        result.append(line)
        i += 1
    return "\n".join(result)


# ---------------- REFERENCE MESSAGE HELPER ----------------
async def _fetch_reference_content(ctx):
    """Return (content_bytes, filename) from the message that ctx.message replies to.

    Returns (None, None) if:
    - The message is not a reply.
    - The referenced message has no attachments and no detectable URL in its content.
    """
    ref = ctx.message.reference
    if not ref:
        return None, None

    # Resolve the referenced message (may already be cached).
    try:
        if ref.resolved and isinstance(ref.resolved, discord.Message):
            ref_msg = ref.resolved
        else:
            ref_msg = await ctx.channel.fetch_message(ref.message_id)
    except Exception:
        return None, None

    # Prefer attachments over links.
    if ref_msg.attachments:
        att = ref_msg.attachments[0]
        if att.size > MAX_FILE_SIZE:
            return None, None
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200:
            return r.content, att.filename
        return None, None

    # Fall back to the first URL found in the message text.
    url = extract_first_url(ref_msg.content or "")
    if url:
        filename = get_filename_from_url(url)
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, url))
        if r.status_code == 200:
            if len(r.content) > MAX_FILE_SIZE:
                return None, None
            return r.content, filename

    return None, None

# ---------------- PASTEFY ----------------
def upload_to_pastefy(content, title="Dumped Script"):

    payload = {
        "title": title,
        "content": content,
        "visibility": "PUBLIC"
    }

    try:
        resp = requests.post(
            "https://pastefy.app/api/v2/paste",
            json=payload,
            timeout=10
        )
        if resp.status_code in (200, 201):
            data = resp.json()
            pid = (data.get("paste") or {}).get("id") or data.get("id")
            return (
                f"https://pastefy.app/{pid}",
                f"https://pastefy.app/{pid}/raw"
            )
    except Exception as e:
        print(f"[pastefy] upload failed: {e}")

    return None, None

# ---------------- DUMPER ----------------
def _run_dumper_blocking(lua_content):

    uid=str(uuid.uuid4())

    input_file=f"input_{uid}.lua"
    output_file=f"output_{uid}.lua"

    try:

        with open(input_file,"wb") as f:
            f.write(lua_content)

        start=time.time()

        result=subprocess.run(
            [_lua_interp,"-E",DUMPER_PATH,input_file,output_file],
            capture_output=True,
            timeout=DUMP_TIMEOUT
        )

        exec_ms=(time.time()-start)*1000

        stdout=result.stdout.decode(errors="ignore")

        loops=0
        lines=0

        m=re.search(r"Loops:\s*(\d+)",stdout)
        if m:
            loops=int(m.group(1))

        m=re.search(r"Lines:\s*(\d+)",stdout)
        if m:
            lines=int(m.group(1))

        if os.path.exists(output_file):

            with open(output_file,"rb") as f:
                dumped=f.read()

            return dumped,exec_ms,loops,lines,None

        stderr=result.stderr.decode(errors="ignore").strip()
        lua_err=re.search(r"\[LUA_LOAD_FAIL\][^\n]*",stdout)
        if lua_err:
            detail=lua_err.group(0).replace("[LUA_LOAD_FAIL] ","",1).strip()
        elif stderr:
            detail=stderr.splitlines()[-1].strip()
        else:
            detail=""
        msg="Output not generated"
        if detail:
            msg=f"Output not generated: {detail}"
        return None,0,0,0,msg

    except subprocess.TimeoutExpired:

        return None,0,0,0,"Dump timeout"

    except Exception as e:

        return None,0,0,0,str(e)

    finally:

        for p in (input_file,output_file):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except:
                pass

async def run_dumper(lua_content):

    loop=asyncio.get_event_loop()

    return await loop.run_in_executor(
        _executor,
        functools.partial(_run_dumper_blocking,lua_content)
    )

# ---------------- EVENTS ----------------
@bot.event
async def on_ready():
    print(f"Logged as {bot.user} | Lua {_lua_interp}")

# ---------------- COMMAND .l ----------------
@bot.command(name="l")
async def process_link(ctx,link=None):

    content=None
    original_filename="file"

    # Acknowledge the command immediately so the user sees activity right away
    try:
        status=await _send_with_retry(lambda: ctx.send("⚙️ dumping"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    if ctx.message.attachments:

        att=ctx.message.attachments[0]

        original_filename=att.filename

        if att.size>MAX_FILE_SIZE:
            await status.edit(content="❌ File too large")
            return

        loop=asyncio.get_event_loop()
        r=await loop.run_in_executor(_executor,functools.partial(_requests_get,att.url))

        if r.status_code==200:
            content=r.content

    elif link:

        original_filename=get_filename_from_url(link)

        loop=asyncio.get_event_loop()
        r=await loop.run_in_executor(_executor,functools.partial(_requests_get,link))

        if r.status_code==200:

            if len(r.content)>MAX_FILE_SIZE:
                await status.edit(content="❌ File too large")
                return

            content=r.content

    else:
        # No attachment or link provided — check if this is a reply to a message
        # that contains a file or link.
        ref_content, ref_filename = await _fetch_reference_content(ctx)
        if ref_content is not None:
            content = ref_content
            original_filename = ref_filename or "file"
        else:
            await status.edit(content="Provide a link, file, or reply to a message that contains one.")
            return

    if not content:
        await status.edit(content="❌ Failed to get content.")
        return

    # Auto-detect Lua bytecode: decompile .luac before running the dumper
    if _luac_version(content) is not None:
        try:
            decomp_text = await asyncio.get_event_loop().run_in_executor(
                _executor, functools.partial(decompile_luac, content))
            content = decomp_text.encode('utf-8')
            await _send_with_retry(lambda: status.edit(
                content="🔍 Lua bytecode detected — decompiled, now dumping..."))
        except ValueError as e:
            await _send_with_retry(lambda: status.edit(
                content=f"❌ Luac decompile failed: {e}"))
            return

    dumped,exec_ms,loops,lines,error=await run_dumper(content)

    if error:
        await status.edit(content=f"❌ {error}")
        return

    dumped_text=dumped.decode("utf-8",errors="ignore")
    dumped_text=_strip_loop_markers(dumped_text)
    dumped_text=_collapse_loop_unrolls(dumped_text)
    dumped_text=_fold_string_concat(dumped_text)
    dumped_text=_inline_single_use_constants(dumped_text)
    # Rename locals using their .Name property assignment (scanning the entire
    # script, not just a small window) before normalising counter suffixes —
    # frame2/frame3 are still distinct at this point and each can receive its
    # own descriptive name (backdrop, scanBeam, window…).  Variables whose
    # .Name is set far below their declaration (common in Roblox GUI scripts)
    # are now correctly renamed.  Counter-suffixed Instance.new() variables
    # that have no .Name assignment receive a type-based fallback name
    # (e.g. frame2 → frame_2) so they stay unique after normalization.
    # Underscore-suffixed variables (frame_, frame__, uICorner_, etc.) that
    # lack a .Name assignment get a letter-suffixed fallback (frame_a, frame_b …)
    # which survives _normalize_all_counters (letter endings, not digit endings).
    dumped_text=_rename_by_name_property(dumped_text)
    # Remove duplicate :Connect() event handler bindings produced by the
    # deobfuscator before normalising names so that we don't have to re-check
    # after counter suffixes have been collapsed.
    dumped_text=_dedup_connections(dumped_text)
    # Balance any unmatched do/end blocks introduced by deobfuscation
    # (appends missing 'end' statements).
    dumped_text=_fix_lua_do_end(dumped_text)
    # Normalise all counter-suffixed variable names (tween2→tween, conn3→conn …)
    # then run collapse again — after normalisation many more blocks are identical.
    dumped_text=_normalize_all_counters(dumped_text)
    dumped_text=_collapse_loop_unrolls(dumped_text)
    # Wrap ephemeral local groups in do…end so the output is directly executable.
    dumped_text=_scope_group_locals(dumped_text)
    dumped_text=_strip_comments(dumped_text)
    dumped_text=_collapse_blank_lines(dumped_text)
    dumped_text=_remove_trailing_whitespace(dumped_text)

    loop=asyncio.get_event_loop()
    paste,raw=await loop.run_in_executor(
        _executor,
        functools.partial(upload_to_pastefy,dumped_text,title=original_filename)
    )

    preview="\n".join(dumped_text.splitlines()[:10])

    embed=discord.Embed(
        title=f"✅ Finished {exec_ms:.2f} ms",
        description=f"Paste: {raw}" if raw else "⚠️ Paste upload failed",
        color=0x2b2d31
    )

    embed.add_field(
        name="Preview",
        value=f"```lua\n{preview}\n```",
        inline=False
    )

    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")

    try:
        await _send_with_retry(lambda: ctx.send(
            embed=embed,
            file=discord.File(
                io.BytesIO(dumped_text.encode("utf-8")),
                filename=original_filename+".txt"
            )
        ))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send result: {e}")
        try:
            await status.edit(content=f"❌ Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass

# ---------------- BEAUTIFIER ----------------
def _beautify_lua(code: str) -> str:
    """Normalize indentation of Lua source code.
    Tries lua-format / luafmt first, then falls back to a built-in normalizer."""

    for cmd in (["lua-format", "--stdin"], ["luafmt", "-"]):
        try:
            proc = subprocess.run(
                cmd, input=code.encode(),
                capture_output=True, timeout=15
            )
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout.decode("utf-8", errors="ignore")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Built-in indentation normalizer
    output = []
    indent = 0

    for raw_line in code.splitlines():
        line = raw_line.strip()

        if not line:
            output.append("")
            continue

        m = re.match(r"^(\w+)", line)
        first_kw = m.group(1) if m else ""

        # Decrease before printing closers
        if first_kw in ("end", "until"):
            indent = max(0, indent - 1)
        elif first_kw in ("else", "elseif"):
            indent = max(0, indent - 1)

        output.append("    " * indent + line)

        # Increase after the line
        if first_kw in ("else", "elseif"):
            indent += 1
        elif first_kw in ("function", "do", "repeat"):
            indent += 1
        elif first_kw in ("if", "for", "while"):
            # Heuristic: increase if the line ends with 'then' or 'do' (may not handle multi-line conditions)
            if re.search(r"\b(then|do)\s*(?:--.*)?$", line):
                indent += 1
        elif first_kw == "then":
            indent += 1
        elif re.search(r"\bfunction\b", line) and not re.search(r"\bend\b\s*(?:--.*)?$", line):
            # Handles "local function", "local x = function()", etc.
            indent += 1

    return "\n".join(output)

# ---------------- LUA COMPATIBILITY FIXER ----------------
def _fix_lua_compat(code: str) -> str:
    """Replace common non-Lua syntax with Lua-compatible equivalents.

    Substitutions applied (in order):
      !=          ->  ~=     (inequality operator)
      &&          ->  and    (logical AND)
      ||          ->  or     (logical OR)
      !expr       ->  not    (logical NOT; only bare '!' not followed by '=')
      null        ->  nil    (whole word)
      undefined   ->  nil    (whole word)
      else if     ->  elseif (Lua uses a single keyword)
    """
    # != must come before ! so that '!=' is not split into 'not ='
    code = code.replace("!=", "~=")
    # Normalise surrounding whitespace so 'a && b' becomes 'a and b'
    code = re.sub(r"\s*&&\s*", " and ", code)
    code = re.sub(r"\s*\|\|\s*", " or ", code)
    # Replace bare '!' (logical NOT) — '!=' has already been handled above.
    # Only match '!' not immediately preceded by a word character so that '!'
    # inside string literals (e.g. "hello!") is left untouched.
    code = re.sub(r"(?<!\w)!", "not ", code)
    code = re.sub(r"\bnull\b", "nil", code)
    code = re.sub(r"\bundefined\b", "nil", code)
    code = re.sub(r"\belse\s+if\b", "elseif", code)
    return code

# ======== LUAC DECOMPILER (Lua 5.1 / 5.3 / 5.4) ========
# Converts compiled Lua bytecode (.luac) back to human-readable pseudocode.

_LUAC_MAGIC = b'\x1bLua'

# ---- Opcode tables ----
_OP_51 = [
    'MOVE', 'LOADK', 'LOADBOOL', 'LOADNIL', 'GETUPVAL',
    'GETGLOBAL', 'GETTABLE', 'SETGLOBAL', 'SETUPVAL', 'SETTABLE',
    'NEWTABLE', 'SELF', 'ADD', 'SUB', 'MUL', 'DIV', 'MOD', 'POW',
    'UNM', 'NOT', 'LEN', 'CONCAT', 'JMP', 'EQ', 'LT', 'LE',
    'TEST', 'TESTSET', 'CALL', 'TAILCALL', 'RETURN',
    'FORLOOP', 'FORPREP', 'TFORLOOP', 'SETLIST', 'CLOSE',
    'CLOSURE', 'VARARG',
]
_OP_53 = [
    'MOVE', 'LOADK', 'LOADKX', 'LOADBOOL', 'LOADNIL', 'GETUPVAL',
    'GETTABUP', 'GETTABLE', 'SETTABUP', 'SETUPVAL', 'SETTABLE',
    'NEWTABLE', 'SELF',
    'ADD', 'SUB', 'MUL', 'MOD', 'POW', 'DIV', 'IDIV',
    'BAND', 'BOR', 'BXOR', 'SHL', 'SHR',
    'UNM', 'BNOT', 'NOT', 'LEN', 'CONCAT', 'JMP',
    'EQ', 'LT', 'LE', 'TEST', 'TESTSET',
    'CALL', 'TAILCALL', 'RETURN',
    'FORLOOP', 'FORPREP', 'TFORCALL', 'TFORLOOP',
    'SETLIST', 'CLOSURE', 'VARARG', 'EXTRAARG',
]
_OP_54 = [
    'MOVE', 'LOADI', 'LOADF', 'LOADK', 'LOADKX', 'LOADFALSE',
    'LFALSESKIP', 'LOADTRUE', 'LOADNIL', 'GETUPVAL', 'SETUPVAL',
    'GETTABUP', 'GETTABLE', 'GETI', 'GETFIELD',
    'SETTABUP', 'SETTABLE', 'SETI', 'SETFIELD',
    'NEWTABLE', 'SELF',
    'ADDI', 'ADDK', 'SUBK', 'MULK', 'MODK', 'POWK', 'DIVK', 'IDIVK',
    'BANDK', 'BORK', 'BXORK', 'SHRI', 'SHLI',
    'ADD', 'SUB', 'MUL', 'MOD', 'POW', 'DIV', 'IDIV',
    'BAND', 'BOR', 'BXOR', 'SHL', 'SHR',
    'MMBIN', 'MMBINI', 'MMBINK',
    'UNM', 'BNOT', 'NOT', 'LEN', 'CONCAT', 'CLOSE', 'TBC', 'JMP',
    'EQ', 'LT', 'LE', 'EQK', 'EQI', 'LTI', 'LEI', 'GTI', 'GEI',
    'TEST', 'TESTSET',
    'CALL', 'TAILCALL', 'RETURN', 'RETURN0', 'RETURN1',
    'FORLOOP', 'FORPREP', 'TFORPREP', 'TFORCALL', 'TFORLOOP',
    'SETLIST', 'CLOSURE', 'VARARG', 'VARARGPREP', 'EXTRAARG',
]

_BINOP_SYM = {
    'ADD': '+', 'SUB': '-', 'MUL': '*', 'DIV': '/',
    'MOD': '%', 'POW': '^', 'IDIV': '//',
    'BAND': '&', 'BOR': '|', 'BXOR': '~',
    'SHL': '<<', 'SHR': '>>', 'CONCAT': '..',
}
_UNOP_SYM  = {'UNM': '-', 'NOT': 'not ', 'LEN': '#', 'BNOT': '~'}
_CMPOP_SYM = {'EQ': '==', 'LT': '<', 'LE': '<=', 'EQK': '==', 'EQI': '==',
               'LTI': '<', 'LEI': '<=', 'GTI': '>', 'GEI': '>='}

# ---- Binary reader ----

class _LR:
    """Stateful binary reader for Lua bytecode."""
    __slots__ = ('_d', '_p', '_le', '_is', '_ss', '_li', '_ln', '_st')

    def __init__(self, data: bytes, le: bool = True,
                 int_size: int = 4, sizet_size: int = 8,
                 lu_int_size: int = 8, lu_num_size: int = 8):
        self._d  = data
        self._p  = 0
        self._le = le
        self._is = int_size
        self._ss = sizet_size
        self._li = lu_int_size   # lua_Integer size
        self._ln = lu_num_size   # lua_Number  size
        self._st: list[str] = []  # Lua 5.4 string back-reference table

    @property
    def pos(self) -> int:
        return self._p

    def u8(self) -> int:
        v = self._d[self._p]; self._p += 1; return v

    def _u(self, fmt: str, n: int):
        v = _struct.unpack_from(fmt, self._d, self._p)[0]
        self._p += n; return v

    def u32(self)  -> int:   return self._u('<I' if self._le else '>I', 4)
    def i32(self)  -> int:   return self._u('<i' if self._le else '>i', 4)
    def u64(self)  -> int:   return self._u('<Q' if self._le else '>Q', 8)
    def i64(self)  -> int:   return self._u('<q' if self._le else '>q', 8)
    def f32(self)  -> float: return self._u('<f' if self._le else '>f', 4)
    def f64(self)  -> float: return self._u('<d' if self._le else '>d', 8)

    def uint(self) -> int:
        fmt = ('<' if self._le else '>') + ('I' if self._is == 4 else 'Q')
        return self._u(fmt, self._is)

    def sizet(self) -> int:
        fmt = ('<' if self._le else '>') + ('I' if self._ss == 4 else 'Q')
        return self._u(fmt, self._ss)

    def lu_integer(self) -> int:
        return self.i64() if self._li == 8 else self.i32()

    def lu_number(self) -> float:
        return self.f64() if self._ln == 8 else self.f32()

    def skip(self, n: int) -> None:
        self._p += n

    # Lua 5.4 variable-length integer:
    # Bytes are emitted MSBs-first; the last byte has its high bit SET.
    def varint(self) -> int:
        x = 0
        while True:
            b = self.u8()
            x = (x << 7) | (b & 0x7F)
            if b & 0x80:
                break
        return x

    def varint_int(self) -> int:
        """Signed: stored as cast_sizet (two's complement reinterpret)."""
        v = self.varint()
        return v - (1 << 64) if v >= (1 << 63) else v

    def varint_float(self) -> float:
        """Float stored as bit-cast uint64, then varint-encoded."""
        raw = self.varint()
        return _struct.unpack('<d', _struct.pack('<Q', raw & 0xFFFFFFFFFFFFFFFF))[0]

    # Lua 5.1: size_t length prefix (includes the NUL), then bytes without NUL.
    def str51(self) -> 'str | None':
        sz = self.sizet()
        if sz == 0: return None
        s = self._d[self._p:self._p + sz - 1]
        self._p += sz - 1   # only sz-1 bytes are actually stored (no NUL in file)
        return s.decode('utf-8', errors='replace')

    # Lua 5.3: 1-byte size (or 0xFF + size_t for long strings), then bytes.
    def str53(self) -> 'str | None':
        b = self.u8()
        if b == 0: return None
        sz = (self.sizet() if b == 0xFF else b) - 1
        s = self._d[self._p:self._p + sz]
        self._p += sz
        return s.decode('utf-8', errors='replace')

    # Lua 5.4: varint size with back-reference deduplication table.
    # varint == 0              → NULL
    # varint <= len(strtab)    → back-reference (index = varint - 1, 0-based)
    # varint > len(strtab)     → new string (content length = varint - 1)
    def str54(self) -> 'str | None':
        sz = self.varint()
        if sz == 0: return None
        st = self._st
        if sz <= len(st):
            return st[sz - 1]
        actual = sz - 1
        s = self._d[self._p:self._p + actual].decode('utf-8', errors='replace')
        self._p += actual
        st.append(s)
        return s


# ---- Constant formatter ----

def _fmtk(v) -> str:
    """Format any Lua constant value as a valid Lua literal."""
    if v is None:    return 'nil'
    if v is True:    return 'true'
    if v is False:   return 'false'
    if isinstance(v, int):   return str(v)
    if isinstance(v, float):
        if v != v:              return '(0/0)'
        if v ==  float('inf'): return '(1/0)'
        if v == -float('inf'): return '(-1/0)'
        r = repr(v)
        return r if ('.' in r or 'e' in r) else r + '.0'
    if isinstance(v, str):
        esc = (v.replace('\\', '\\\\')
                .replace('"',  '\\"')
                .replace('\n', '\\n')
                .replace('\r', '\\r')
                .replace('\0', '\\0'))
        return f'"{esc}"'
    return repr(v)


# ---- Instruction field decoders ----

def _dec51(i: int) -> tuple:
    """Lua 5.1/5.3 instruction → (op, A, B, C, Bx, sBx)."""
    op  = i & 0x3F
    a   = (i >> 6)  & 0xFF
    c   = (i >> 14) & 0x1FF
    b   = (i >> 23) & 0x1FF
    bx  = (i >> 14) & 0x3FFFF
    sbx = bx - 131071
    return op, a, b, c, bx, sbx

def _dec54(i: int) -> tuple:
    """Lua 5.4 instruction → (op, A, k, B, C, Bx, sBx, sJ)."""
    op  = i & 0x7F
    a   = (i >> 7)  & 0xFF
    k   = (i >> 15) & 0x1
    b   = (i >> 16) & 0xFF
    c   = (i >> 24) & 0xFF
    bx  = (i >> 15) & 0x1FFFF
    sbx = bx - 65535
    sj  = ((i >> 7) & 0x1FFFFFF) - 16777215
    return op, a, k, b, c, bx, sbx, sj


# ---- Proto parsers ----

def _parse_proto_51(r: _LR) -> dict:
    """Parse one Lua 5.1 function prototype."""
    p: dict = {}
    p['src']    = r.str51()
    p['ldef']   = r.uint()
    p['lldef']  = r.uint()
    p['nups']   = r.u8()
    p['npar']   = r.u8()
    p['vararg'] = r.u8()
    p['maxst']  = r.u8()

    n = r.uint(); p['code'] = [r.u32() for _ in range(n)]

    n = r.uint(); ks = []
    for _ in range(n):
        t = r.u8()
        if   t == 0: ks.append(None)
        elif t == 1: ks.append(bool(r.u8()))
        elif t == 3: ks.append(r.f64())
        elif t == 4: ks.append(r.str51())
        else:        ks.append(f'<k:{t}>')
    p['k'] = ks

    n = r.uint(); p['subs'] = [_parse_proto_51(r) for _ in range(n)]

    n = r.uint(); p['li'] = [r.uint() for _ in range(n)]
    n = r.uint(); p['lv'] = [{'n': r.str51(), 's': r.uint(), 'e': r.uint()} for _ in range(n)]

    n = r.uint(); unames = [r.str51() for _ in range(n)]
    p['uv'] = [{'name': unames[i] if i < len(unames) else None,
                'instack': 0, 'idx': i} for i in range(p['nups'])]
    return p


def _parse_proto_53(r: _LR) -> dict:
    """Parse one Lua 5.3 function prototype."""
    p: dict = {}
    p['src']    = r.str53()
    p['ldef']   = r.uint()
    p['lldef']  = r.uint()
    p['npar']   = r.u8()
    p['vararg'] = r.u8()
    p['maxst']  = r.u8()

    n = r.uint(); p['code'] = [r.u32() for _ in range(n)]

    n = r.uint(); ks = []
    for _ in range(n):
        t = r.u8()
        if t == 0:          ks.append(None)
        elif t == 1:        ks.append(bool(r.u8()))
        elif t == 3:        ks.append(r.lu_integer() if r.u8() else r.lu_number())
        elif t in (4, 20):  ks.append(r.str53())
        else:               ks.append(f'<k:{t}>')
    p['k'] = ks

    n = r.uint()
    uvs = [{'instack': r.u8(), 'idx': r.u8(), 'name': None} for _ in range(n)]
    p['nups'] = n; p['uv'] = uvs

    n = r.uint(); p['subs'] = [_parse_proto_53(r) for _ in range(n)]

    n = r.uint(); p['li'] = [r.uint() for _ in range(n)]
    n = r.uint(); p['lv'] = [{'n': r.str53(), 's': r.uint(), 'e': r.uint()} for _ in range(n)]

    n = r.uint()
    for i in range(n):
        nm = r.str53()
        if i < len(uvs): uvs[i]['name'] = nm
    return p


def _parse_proto_54(r: _LR) -> dict:
    """Parse one Lua 5.4 function prototype."""
    p: dict = {}
    p['src']    = r.str54()
    p['ldef']   = r.varint()
    p['lldef']  = r.varint()
    p['npar']   = r.u8()
    p['vararg'] = r.u8()
    p['maxst']  = r.u8()

    n = r.varint(); p['code'] = [r.u32() for _ in range(n)]

    n = r.varint(); ks = []
    for _ in range(n):
        t = r.u8()
        if   t == 0x00:       ks.append(None)            # LUA_VNIL
        elif t == 0x01:       ks.append(False)           # LUA_VFALSE
        elif t == 0x11:       ks.append(True)            # LUA_VTRUE
        elif t == 0x03:       ks.append(r.varint_float()) # LUA_VNUMFLT
        elif t == 0x13:       ks.append(r.varint_int())   # LUA_VNUMINT
        elif t in (0x04, 0x14): ks.append(r.str54())      # string
        else:                 ks.append(f'<k:{t:#x}>')
    p['k'] = ks

    n = r.varint()
    uvs = [{'instack': r.u8(), 'idx': r.u8(), 'kind': r.u8(), 'name': None}
           for _ in range(n)]
    p['nups'] = n; p['uv'] = uvs

    n = r.varint(); p['subs'] = [_parse_proto_54(r) for _ in range(n)]

    # lineinfo: one signed byte per instruction (relative line delta)
    n = r.varint()
    p['li'] = list(r._d[r._p:r._p + n]); r._p += n
    # abslineinfo
    n = r.varint()
    p['abs_li'] = [{'pc': r.i32(), 'line': r.i32()} for _ in range(n)]
    # locals
    n = r.varint()
    p['lv'] = [{'n': r.str54(), 's': r.varint(), 'e': r.varint()} for _ in range(n)]
    # upvalue names
    n = r.varint()
    for i in range(n):
        nm = r.str54()
        if i < len(uvs): uvs[i]['name'] = nm
    return p


# ---- RK helper (5.1 / 5.3: bit 8 of 9-bit B/C field selects K) ----

def _rk(x: int, ks: list, upvals: list = None, uv_idx: int = -1) -> str:
    """Format an RK operand for Lua 5.1/5.3 (register or constant)."""
    if x >= 256:
        ki = x - 256
        return _fmtk(ks[ki]) if ki < len(ks) else f'K{ki}'
    return f'r{x}'


def _uv_name(idx: int, uvs: list) -> str:
    if idx < len(uvs):
        return uvs[idx].get('name') or f'U{idx}'
    return f'U{idx}'


def _local_at(reg: int, pc: int, lv: list) -> 'str | None':
    """Return the debug name for a local register at a given pc, if known."""
    # locvars are in register order: the first live locvar at this pc is r0, etc.
    live = [loc for loc in lv if loc.get('s', 0) <= pc < loc.get('e', pc + 1)]
    if reg < len(live):
        return live[reg].get('n')
    return None


# ---- Core decompiler ----

def _emit_proto(proto: dict, ver: str, depth: int = 0,
                func_idx: 'int | str' = 'main') -> list:
    """Emit human-readable pseudocode for one function prototype.

    Returns a flat list of output strings (without trailing newlines).
    """
    PAD = '    ' * depth
    out: list[str] = []

    def w(s: str = '') -> None:
        out.append(PAD + s)

    src    = proto.get('src') or '?'
    ldef   = proto.get('ldef', 0)
    lldef  = proto.get('lldef', 0)
    npar   = proto.get('npar', 0)
    vararg = proto.get('vararg', 0)
    maxst  = proto.get('maxst', 0)
    code   = proto.get('code', [])
    ks     = proto.get('k', [])
    uvs    = proto.get('uv', [])
    lv     = proto.get('lv', [])
    subs   = proto.get('subs', [])
    li_raw = proto.get('li', [])

    # Resolve line numbers (5.4 uses relative byte deltas; 5.1/5.3 absolute ints)
    if ver == '5.4' and li_raw:
        abs_li = proto.get('abs_li', [])
        # Reconstruct absolute line numbers from relative deltas + anchor points
        linemap: list[int] = []
        cur_line = ldef
        abs_map  = {entry['pc']: entry['line'] for entry in abs_li}
        for pc_i in range(len(code)):
            if pc_i in abs_map:
                cur_line = abs_map[pc_i]
            elif pc_i < len(li_raw):
                delta = li_raw[pc_i]
                # signed byte
                cur_line += delta if delta < 128 else delta - 256
            linemap.append(cur_line)
    else:
        linemap = li_raw  # already absolute ints for 5.1/5.3

    # ---- Header ----
    bar = '=' * 58
    w(f'-- {bar}')
    w(f'-- Function {func_idx!r}  [{src}:{ldef}-{lldef}]  (Lua {ver})')
    w(f'-- params={npar}  vararg={bool(vararg)}  upvalues={len(uvs)}  maxstack={maxst}')
    w(f'-- {bar}')

    if uvs:
        w(f'-- Upvalues ({len(uvs)}):')
        for i, uv in enumerate(uvs):
            nm  = uv.get('name') or '?'
            ins = uv.get('instack', 0)
            idx = uv.get('idx', i)
            w(f'--   U{i} = {nm!r}  ({"stack" if ins else "upval"}[{idx}])')

    if ks:
        w(f'-- Constants ({len(ks)}):')
        for i, k in enumerate(ks):
            w(f'--   K{i} = {_fmtk(k)}')

    if lv:
        w(f'-- Locals ({len(lv)}):')
        for i, loc in enumerate(lv):
            nm = loc.get('n') or f'v{i}'
            s, e = loc.get('s', 0), loc.get('e', 0)
            w(f'--   r{i}  [{s}..{e}]  {nm!r}')

    if subs:
        w(f'-- Sub-functions: {len(subs)}')

    w()
    w('-- Instructions:')
    w('--  [pc] op             operands                  ; comment')
    w('-- ' + '-' * 58)

    # ---- Register expression tracker for reconstruction ----
    regs: dict[int, str] = {}

    def rname(r: int, pc: int = 0) -> str:
        """Return the best name for register r at pc (reads regs for expressions)."""
        nm = _local_at(r, pc, lv)
        if nm:
            return nm
        return regs.get(r, f'r{r}')

    def tgtname(r: int, pc: int) -> str:
        """Return the assignment-target name for register r — never uses regs,
        so it always produces a clean 'r{N}' or debug-local name."""
        nm = _local_at(r, pc, lv)
        return nm if nm else f'r{r}'

    def assign(r: int, expr: str, pc_: int) -> None:
        """Emit  target = expr  and update regs[r], using the pre-update name."""
        tgt = tgtname(r, pc_)
        regs[r] = expr
        ri(f'{tgt} = {expr}')

    opcodes = _OP_51 if ver == '5.1' else (_OP_53 if ver == '5.3' else _OP_54)

    # Pass 1 – collect jump targets so we can emit labels
    jump_targets: set[int] = set()
    for pc, instr in enumerate(code):
        if ver in ('5.1', '5.3'):
            op, a, b, c, bx, sbx = _dec51(instr)
            opn = opcodes[op] if op < len(opcodes) else f'OP{op}'
            if opn in ('JMP', 'FORPREP'):
                jump_targets.add(pc + 1 + sbx)
            elif opn in ('FORLOOP', 'TFORLOOP'):
                jump_targets.add(pc + 1 + sbx)
        else:
            op, a, k54, b, c, bx, sbx, sj = _dec54(instr)
            opn = opcodes[op] if op < len(opcodes) else f'OP{op}'
            if opn in ('JMP', 'FORPREP', 'TFORPREP'):
                jump_targets.add(pc + 1 + sj)
            elif opn in ('FORLOOP', 'TFORLOOP'):
                jump_targets.add(pc + 1 + sbx)

    # Reconstruction accumulator
    recon: list[str] = []
    indent = 0
    open_blocks: list[str] = []  # stack of block types

    def ri(s: str) -> None:
        recon.append('    ' * indent + s)

    # Pass 2 – disassemble and reconstruct
    for pc, instr in enumerate(code):
        lineno = linemap[pc] if pc < len(linemap) else '?'

        if pc in jump_targets:
            w(f'  ::lbl_{pc}::')

        if ver in ('5.1', '5.3'):
            op, a, b, c, bx, sbx = _dec51(instr)
            opn = opcodes[op] if op < len(opcodes) else f'OP{op}'

            def rk(x: int) -> str:
                if x >= 256:
                    ki = x - 256
                    return _fmtk(ks[ki]) if ki < len(ks) else f'K{ki}'
                return rname(x, pc)

            # ---- disassembly line ----
            raw = f'[{pc:03d}] {opn:<12}'
            comment = ''

            if opn == 'MOVE':
                comment = f'r{a} = r{b}'
                src_expr = rname(b, pc)
                assign(a, src_expr, pc)

            elif opn == 'LOADK':
                val = _fmtk(ks[bx]) if bx < len(ks) else f'K{bx}'
                comment = f'r{a} = {val}'
                assign(a, val, pc)

            elif opn == 'LOADBOOL':
                val = 'true' if b else 'false'
                comment = f'r{a} = {val}' + (f'; skip next' if c else '')
                assign(a, val, pc)

            elif opn == 'LOADNIL':
                comment = f'r{a}..r{b} = nil'
                for rr in range(a, b + 1):
                    assign(rr, 'nil', pc)

            elif opn == 'GETUPVAL':
                uname = _uv_name(b, uvs)
                comment = f'r{a} = upvalue[{b}] ({uname})'
                assign(a, uname, pc)

            elif opn == 'GETGLOBAL':
                gname = _fmtk(ks[bx]) if bx < len(ks) else f'K{bx}'
                comment = f'r{a} = _G[{gname}]'
                assign(a, f'_G[{gname}]', pc)

            elif opn == 'GETTABUP':
                # 5.3: r[A] = UpValue[B][RK(C)]
                uname = _uv_name(b, uvs)
                key   = rk(c)
                expr  = f'{uname}[{key}]'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'GETTABLE':
                tbl = rname(b, pc)
                key = rk(c)
                expr = f'{tbl}[{key}]'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'SETGLOBAL':
                gname = _fmtk(ks[bx]) if bx < len(ks) else f'K{bx}'
                val   = rname(a, pc)
                comment = f'_G[{gname}] = {val}'
                ri(f'_G[{gname}] = {val}')

            elif opn == 'SETTABUP':
                # 5.3: UpValue[A][RK(B)] = RK(C)
                uname = _uv_name(a, uvs)
                key   = rk(b)
                val   = rk(c)
                comment = f'{uname}[{key}] = {val}'
                ri(f'{uname}[{key}] = {val}')

            elif opn == 'SETUPVAL':
                uname = _uv_name(b, uvs)
                comment = f'upvalue[{b}] ({uname}) = r{a}'
                ri(f'{uname} = {rname(a, pc)}')

            elif opn == 'SETTABLE':
                tbl = rname(a, pc)
                key = rk(b)
                val = rk(c)
                comment = f'{tbl}[{key}] = {val}'
                ri(f'{tbl}[{key}] = {val}')

            elif opn == 'NEWTABLE':
                comment = f'r{a} = {{}}  (array={b}, hash={c})'
                assign(a, '{}', pc)

            elif opn == 'SELF':
                obj  = rname(b, pc)
                meth = rk(c)
                comment = f'r{a+1} = r{b}; r{a} = r{b}[{meth}]'
                regs[a + 1] = obj
                regs[a]     = f'{obj}[{meth}]'

            elif opn in _BINOP_SYM:
                sym  = _BINOP_SYM[opn]
                lhs  = rk(b)
                rhs  = rk(c)
                expr = f'({lhs} {sym} {rhs})'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn in _UNOP_SYM:
                sym  = _UNOP_SYM[opn]
                expr = f'{sym}{rname(b, pc)}'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'CONCAT':
                parts = [rname(i, pc) for i in range(b, c + 1)]
                expr  = ' .. '.join(parts)
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'JMP':
                tgt = pc + 1 + sbx
                comment = f'goto lbl_{tgt}'
                if a:
                    comment += f'; close upvals from r{a}'
                ri(f'goto lbl_{tgt}')

            elif opn in _CMPOP_SYM:
                sym = _CMPOP_SYM[opn]
                lv_eq = 'not ' if a == 0 else ''
                comment = f'if {lv_eq}({rk(b)} {sym} {rk(c)}) then skip'
                ri(f'-- cmp: if {lv_eq}({rk(b)} {sym} {rk(c)}) then skip next')

            elif opn == 'TEST':
                comment = f'if r{a} ~= {bool(c)} then skip'
                ri(f'-- test: if r{a} ~= {bool(c)} then skip next')

            elif opn == 'TESTSET':
                comment = f'if r{b} ~= {bool(c)} then r{a}=r{b} else skip'
                ri(f'-- testset: r{a} = r{b} if r{b} ~= {bool(c)}')

            elif opn in ('CALL', 'TAILCALL'):
                fn   = rname(a, pc)
                narg = b - 1 if b > 0 else '...'
                nret = c - 1 if c > 0 else '...'
                args = ', '.join(rname(a + 1 + i, pc)
                                 for i in range(b - 1)) if b > 1 else ''
                call_expr = f'{fn}({args})'
                comment = f'call {call_expr}; {nret} result(s)'
                # Assign results to registers
                if c > 1:
                    _tgt = tgtname(a, pc)
                    for rr in range(c - 1):
                        regs[a + rr] = f'{call_expr}_ret{rr}' if rr else call_expr
                    ri(f'{_tgt} = {call_expr}')
                else:
                    ri(f'{call_expr}')

            elif opn == 'RETURN':
                if b == 0:
                    comment = 'return ...'
                    ri('return ...')
                elif b == 1:
                    comment = 'return'
                    ri('return')
                else:
                    rets = ', '.join(rname(a + i, pc) for i in range(b - 1))
                    comment = f'return {rets}'
                    ri(f'return {rets}')

            elif opn == 'FORPREP':
                comment = f'for prep: r{a}=init-step; goto lbl_{pc+1+sbx}'
                ri(f'for {tgtname(a, pc)} = {rname(a, pc)}, {rname(a+1, pc)}, {rname(a+2, pc)} do')
                indent += 1
                open_blocks.append('for')

            elif opn == 'FORLOOP':
                comment = f'for loop: r{a}+=r{a+2}; if r{a}<=r{a+1} goto lbl_{pc+1+sbx}'
                indent = max(0, indent - 1)
                if open_blocks and open_blocks[-1] == 'for':
                    open_blocks.pop()
                ri('end')

            elif opn == 'TFORLOOP':
                comment = f'generic for loop; if r{a+1} ~= nil goto lbl_{pc+1+sbx}'
                indent = max(0, indent - 1)
                if open_blocks and open_blocks[-1] == 'for':
                    open_blocks.pop()
                ri('end')

            elif opn == 'TFORCALL':
                comment = f'generic for call: r{a}(r{a+1}, r{a+2}) -> r{a+4}..r{a+3+c}'

            elif opn == 'SETLIST':
                comment = f'r{a}[({c-1}*FPF+1)..] = r{a+1}..r{a+b}'

            elif opn == 'CLOSURE':
                sub_fn = subs[bx] if bx < len(subs) else None
                comment = f'r{a} = function#{bx}'
                if sub_fn:
                    sub_src = sub_fn.get('src') or '?'
                    sub_ldef = sub_fn.get('ldef', 0)
                    comment += f'  (defined at {sub_src}:{sub_ldef})'
                _tgt = tgtname(a, pc)
                regs[a] = f'function#{bx}'
                ri(f'{_tgt} = function#{bx}  -- see sub-function {bx} below')

            elif opn == 'VARARG':
                comment = f'r{a}..r{a+b-2} = vararg'
                if b == 2:
                    assign(a, '...', pc)
                else:
                    ri(f'-- vararg: load {b-1} values into r{a}..')

            elif opn == 'CLOSE':
                comment = f'close upvalues from r{a} upward'

            elif opn == 'LOADKX':
                comment = f'r{a} = <EXTRAARG constant>'

            elif opn == 'EXTRAARG':
                comment = f'extra arg: {bx}'

            else:
                comment = f'A={a} B={b} C={c} Bx={bx} sBx={sbx}'

            w(f'  {raw}  A={a:<3} B={b:<3} C={c:<3} Bx={bx:<6} sBx={sbx:<7}  ; ln={lineno} {comment}')

        else:  # Lua 5.4
            op, a, k54, b, c, bx, sbx, sj = _dec54(instr)
            opn = opcodes[op] if op < len(opcodes) else f'OP{op}'

            raw     = f'[{pc:03d}] {opn:<14}'
            comment = ''

            def kv(idx: int) -> str:
                return _fmtk(ks[idx]) if idx < len(ks) else f'K{idx}'

            # 5.4: B/C are plain 8-bit; k bit selects K table for some ops
            def bkv() -> str:
                return kv(b) if k54 else rname(b, pc)

            if opn == 'MOVE':
                comment = f'r{a} = r{b}'
                assign(a, rname(b, pc), pc)

            elif opn == 'LOADI':
                # sBx holds the integer
                comment = f'r{a} = {sbx}'
                assign(a, str(sbx), pc)

            elif opn == 'LOADF':
                val = float(sbx); comment = f'r{a} = {val}'
                assign(a, str(val), pc)

            elif opn == 'LOADK':
                val = kv(bx); comment = f'r{a} = {val}'
                assign(a, val, pc)

            elif opn in ('LOADFALSE', 'LFALSESKIP'):
                comment = f'r{a} = false'
                assign(a, 'false', pc)

            elif opn == 'LOADTRUE':
                comment = f'r{a} = true'
                assign(a, 'true', pc)

            elif opn == 'LOADNIL':
                comment = f'r{a}..r{a+b} = nil'
                for rr in range(a, a + b + 1):
                    assign(rr, 'nil', pc)

            elif opn == 'GETUPVAL':
                uname = _uv_name(b, uvs)
                comment = f'r{a} = upvalue[{b}] ({uname})'
                assign(a, uname, pc)

            elif opn == 'SETUPVAL':
                uname = _uv_name(b, uvs)
                comment = f'upvalue[{b}] ({uname}) = r{a}'
                ri(f'{uname} = {rname(a,pc)}')

            elif opn == 'GETTABUP':
                uname = _uv_name(b, uvs)
                key   = kv(c) if k54 else rname(c, pc)
                expr  = f'{uname}[{key}]'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'GETTABLE':
                expr = f'{rname(b,pc)}[{rname(c,pc)}]'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'GETI':
                expr = f'{rname(b,pc)}[{c}]'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'GETFIELD':
                expr = f'{rname(b,pc)}[{kv(c)}]'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'SETTABUP':
                uname = _uv_name(a, uvs)
                key   = kv(b) if k54 else rname(b, pc)
                val   = kv(c) if k54 else rname(c, pc)
                comment = f'{uname}[{key}] = {val}'
                ri(f'{uname}[{key}] = {val}')

            elif opn == 'SETTABLE':
                key = rname(b, pc); val = kv(c) if k54 else rname(c, pc)
                comment = f'{rname(a,pc)}[{key}] = {val}'
                ri(f'{rname(a,pc)}[{key}] = {val}')

            elif opn == 'SETI':
                val = kv(c) if k54 else rname(c, pc)
                comment = f'{rname(a,pc)}[{b}] = {val}'
                ri(f'{rname(a,pc)}[{b}] = {val}')

            elif opn == 'SETFIELD':
                val = kv(c) if k54 else rname(c, pc)
                comment = f'{rname(a,pc)}[{kv(b)}] = {val}'
                ri(f'{rname(a,pc)}[{kv(b)}] = {val}')

            elif opn == 'NEWTABLE':
                comment = f'r{a} = {{}}'
                assign(a, '{}', pc)

            elif opn == 'SELF':
                obj  = rname(b, pc); meth = kv(c) if k54 else rname(c, pc)
                regs[a+1] = obj; regs[a] = f'{obj}[{meth}]'
                comment = f'r{a+1}=r{b}; r{a}=r{b}[{meth}]'

            elif opn in _BINOP_SYM:
                sym  = _BINOP_SYM[opn]
                lhs  = rname(b, pc); rhs = rname(c, pc)
                expr = f'({lhs} {sym} {rhs})'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn in ('ADDI', 'ADDK', 'SUBK', 'MULK', 'MODK', 'POWK', 'DIVK',
                         'IDIVK', 'BANDK', 'BORK', 'BXORK'):
                base_op  = opn[:-1] if opn.endswith('K') else opn[:-1]
                sym_map  = {'ADD': '+', 'SUB': '-', 'MUL': '*', 'DIV': '/',
                            'MOD': '%', 'POW': '^', 'IDIV': '//',
                            'BAND': '&', 'BOR': '|', 'BXOR': '~'}
                sym  = sym_map.get(base_op, opn)
                rhs  = kv(c) if opn.endswith('K') else str(c)
                lhs  = rname(b, pc)
                expr = f'({lhs} {sym} {rhs})'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn in ('SHRI', 'SHLI'):
                sym  = '>>' if opn == 'SHRI' else '<<'
                expr = f'({rname(b,pc)} {sym} {c})'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn in _UNOP_SYM:
                sym  = _UNOP_SYM[opn]
                expr = f'{sym}{rname(b,pc)}'
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'CONCAT':
                parts = [rname(a + i, pc) for i in range(b)]
                expr  = ' .. '.join(parts)
                comment = f'r{a} = {expr}'
                assign(a, expr, pc)

            elif opn == 'JMP':
                tgt = pc + 1 + sj
                comment = f'goto lbl_{tgt}'
                ri(f'goto lbl_{tgt}')

            elif opn in _CMPOP_SYM:
                sym = _CMPOP_SYM[opn]
                if opn in ('EQK', 'EQI', 'LTI', 'LEI', 'GTI', 'GEI'):
                    rhs = kv(b) if opn == 'EQK' else str(b)
                    cond = f'{rname(a,pc)} {sym} {rhs}'
                else:
                    cond = f'{rname(a,pc)} {sym} {rname(b,pc)}'
                neg = 'not ' if k54 == 0 else ''
                comment = f'if {neg}({cond}) then skip'
                ri(f'-- cmp: if {neg}({cond}) then skip next')

            elif opn == 'TEST':
                comment = f'if r{a} {"==" if k54 else "~="} false then skip'
                ri(f'-- test: if r{a} {"==" if k54 else "~="} false then skip next')

            elif opn == 'TESTSET':
                comment = f'if r{b} {"==" if k54 else "~="} false then r{a}=r{b}; else skip'
                ri(f'-- testset: r{a} = r{b} if condition')

            elif opn in ('CALL', 'TAILCALL'):
                fn   = rname(a, pc)
                args = ', '.join(rname(a+1+i, pc) for i in range(b-1)) if b > 1 else ('' if b == 1 else '...')
                call_expr = f'{fn}({args})'
                nret = c - 1 if c > 0 else '...'
                comment = f'call {call_expr}; {nret} result(s)'
                if c > 1:
                    _tgt = tgtname(a, pc)
                    regs[a] = call_expr
                    ri(f'{_tgt} = {call_expr}')
                else:
                    ri(f'{call_expr}')

            elif opn == 'RETURN':
                if b == 0:
                    comment = 'return ...'
                    ri('return ...')
                elif b == 1:
                    comment = 'return'
                    ri('return')
                else:
                    rets = ', '.join(rname(a+i,pc) for i in range(b-1))
                    comment = f'return {rets}'
                    ri(f'return {rets}')

            elif opn == 'RETURN0':
                comment = 'return'; ri('return')

            elif opn == 'RETURN1':
                comment = f'return r{a}'
                ri(f'return {rname(a,pc)}')

            elif opn == 'FORPREP':
                tgt = pc + 1 + sj
                comment = f'numeric for setup; to lbl_{tgt}'
                ri(f'for {tgtname(a,pc)} = {rname(a,pc)}, {rname(a+1,pc)}, {rname(a+2,pc)} do')
                indent += 1; open_blocks.append('for')

            elif opn == 'FORLOOP':
                comment = f'numeric for step; if loop goto lbl_{pc+1+sbx}'
                indent = max(0, indent - 1)
                if open_blocks and open_blocks[-1] == 'for':
                    open_blocks.pop()
                ri('end')

            elif opn == 'TFORPREP':
                tgt = pc + 1 + sj
                comment = f'generic for prep; to lbl_{tgt}'
                ri(f'for ... in {rname(a,pc)} do')
                indent += 1; open_blocks.append('for')

            elif opn == 'TFORCALL':
                comment = f'generic for call r{a}(r{a+1},r{a+2}) -> r{a+4}..r{a+3+c}'

            elif opn == 'TFORLOOP':
                comment = f'generic for loop; if r{a+2} ~= nil goto lbl_{pc+1+sbx}'
                indent = max(0, indent - 1)
                if open_blocks and open_blocks[-1] == 'for':
                    open_blocks.pop()
                ri('end')

            elif opn == 'SETLIST':
                comment = f'{rname(a,pc)}[1..{b}] = r{a+1}..r{a+b}'

            elif opn == 'CLOSURE':
                sub_fn = subs[bx] if bx < len(subs) else None
                comment = f'r{a} = function#{bx}'
                if sub_fn:
                    comment += f'  (at {sub_fn.get("src","?")}:{sub_fn.get("ldef",0)})'
                _tgt = tgtname(a, pc)
                regs[a] = f'function#{bx}'
                ri(f'{_tgt} = function#{bx}  -- see sub-function {bx} below')

            elif opn == 'VARARG':
                n_want = c - 1
                comment = f'r{a}..r{a+n_want-1} = ...' if n_want > 0 else f'r{a}.. = ...'
                assign(a, '...', pc)

            elif opn == 'VARARGPREP':
                comment = f'vararg prep: {a} fixed params'

            elif opn in ('CLOSE', 'TBC'):
                comment = f'close upvalues from r{a} upward'

            elif opn in ('MMBIN', 'MMBINI', 'MMBINK'):
                comment = f'metamethod call r{a} op#{c} r{b}'

            else:
                comment = f'A={a} k={k54} B={b} C={c} Bx={bx} sBx={sbx} sJ={sj}'

            w(f'  {raw}  A={a:<3} k={k54} B={b:<3} C={c:<3} Bx={bx:<6} sBx={sbx:<7}  ; ln={lineno} {comment}')

    # ---- Reconstructed source ----
    w()
    w('-- Reconstructed source:')
    w('-- ' + '-' * 58)

    # Build function signature for non-main functions
    if func_idx != 'main':
        pnames = []
        for i in range(npar):
            nm = (_local_at(i, 0, lv) or f'a{i}')
            pnames.append(nm)
        if vararg:
            pnames.append('...')
        w(f'local function function_{func_idx}({", ".join(pnames)})')
        for line in recon:
            w('    ' + line)
        w('end')
    else:
        for line in recon:
            w(line)

    w()

    # Recurse into sub-functions
    for si, sub in enumerate(subs):
        out.extend(_emit_proto(sub, ver, depth, func_idx=si))

    return out


# ---- Top-level entry point ----

def _luac_version(data: bytes) -> 'str | None':
    """Return '5.1', '5.3', or '5.4' if *data* looks like Lua bytecode."""
    if not data.startswith(_LUAC_MAGIC) or len(data) < 6:
        return None
    return {0x51: '5.1', 0x53: '5.3', 0x54: '5.4'}.get(data[4])


def decompile_luac(data: bytes) -> str:
    """Decompile Lua bytecode to human-readable pseudocode.

    Supports Lua 5.1, 5.3, and 5.4 binary formats.  Returns the decompiled
    source as a UTF-8 string.  Raises ``ValueError`` for unsupported formats.
    """
    if not data.startswith(_LUAC_MAGIC):
        raise ValueError("Not a Lua bytecode file (wrong magic bytes)")
    if len(data) < 6:
        raise ValueError("Lua bytecode header is truncated")

    ver_byte = data[4]
    ver = {0x51: '5.1', 0x53: '5.3', 0x54: '5.4'}.get(ver_byte)
    if ver is None:
        raise ValueError(f"Unsupported Lua version byte 0x{ver_byte:02x}")

    try:
        if ver == '5.1':
            # Header: magic(4) ver(1) fmt(1) endian(1) int_sz(1) sizet_sz(1)
            #         instr_sz(1) num_sz(1) integral(1) = 12 bytes total
            if len(data) < 12:
                raise ValueError("Lua 5.1 header truncated")
            le        = data[6] == 1
            int_size  = data[7]
            sizet_size = data[8]
            r = _LR(data, le=le, int_size=int_size, sizet_size=sizet_size)
            r.skip(12)
            proto = _parse_proto_51(r)

        elif ver == '5.3':
            # Header: magic(4) ver(1) fmt(1) LUAC_DATA(6)
            #         int_sz(1) sizet_sz(1) instr_sz(1) int_sz(1) num_sz(1)
            #         LUAC_INT(8) LUAC_NUM(8) = 33 bytes; then nupvals(1)
            if len(data) < 34:
                raise ValueError("Lua 5.3 header truncated")
            int_size   = data[12]
            sizet_size = data[13]
            lu_int     = data[15]
            lu_num     = data[16]
            # Endianness: Lua 5.3 removed the endian byte; verify via LUAC_INT
            # LUAC_INT = 0x5678; stored at offset 17 as lua_Integer (8 bytes LE)
            raw_int    = _struct.unpack_from('<q', data, 17)[0]
            le         = (raw_int == 0x5678)
            r = _LR(data, le=le, int_size=int_size, sizet_size=sizet_size,
                    lu_int_size=lu_int, lu_num_size=lu_num)
            r.skip(33)
            r.skip(1)  # nupvalues byte (always 1 for _ENV)
            proto = _parse_proto_53(r)

        else:  # 5.4
            # Header: magic(4) ver(1) fmt(1) LUAC_DATA(6)
            #         instr_sz(1) int_sz(1) num_sz(1) = 15 fixed bytes
            # Followed by LUAC_INT (varint) + LUAC_NUM (varint) then nupvals(1)
            if len(data) < 16:
                raise ValueError("Lua 5.4 header truncated")
            r = _LR(data, le=True)  # Lua 5.4 always little-endian
            r.skip(15)
            r.varint()   # skip LUAC_INT verification value
            r.varint()   # skip LUAC_NUM verification value
            r.skip(1)    # nupvalues
            proto = _parse_proto_54(r)

    except Exception as exc:
        raise ValueError(f"Failed to parse Lua {ver} bytecode: {exc}") from exc

    lines = _emit_proto(proto, ver, depth=0, func_idx='main')
    header = [
        f'-- Luac Decompiler | Cat Logger',
        f'-- Lua {ver} bytecode  ({len(data)} bytes)',
        f'-- ' + '=' * 56,
        '',
    ]
    return '\n'.join(header + lines)


# ---------------- COMMAND .rename ----------------
@bot.command(name="rename")
async def rename_file(ctx, *, args=None):

    if not args:
        await ctx.send("Usage: `.rename <new_name>` (with attachment or as a reply) or `.rename <link> <new_name>`")
        return

    content = None
    new_name = None

    if ctx.message.attachments:
        new_name = args.strip()
        att = ctx.message.attachments[0]
        if att.size > MAX_FILE_SIZE:
            await ctx.send("❌ File too large")
            return
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200:
            content = r.content
    else:
        parts = args.split(None, 1)
        # Check if first token looks like a URL
        if len(parts) >= 2 and re.match(r"https?://", parts[0]):
            link, new_name = parts[0], parts[1].strip()
            loop = asyncio.get_event_loop()
            r = await loop.run_in_executor(_executor, functools.partial(_requests_get, link))
            if r.status_code == 200:
                if len(r.content) > MAX_FILE_SIZE:
                    await ctx.send("❌ File too large")
                    return
                content = r.content
        else:
            # No URL and no attachment — try the referenced message for content
            new_name = args.strip()
            ref_content, _ = await _fetch_reference_content(ctx)
            if ref_content is not None:
                content = ref_content
            else:
                await ctx.send("Usage: `.rename <new_name>` (with attachment or as a reply) or `.rename <link> <new_name>`")
                return

    if not content:
        await ctx.send("❌ Failed to get content.")
        return

    if "." not in new_name:
        new_name = new_name + ".lua"

    # Fix Lua-incompatible syntax in the file content before sending
    try:
        fixed_text = _fix_lua_compat(content.decode("utf-8", errors="ignore"))
        content = fixed_text.encode("utf-8")
    except Exception:
        pass  # Keep original bytes if processing fails

    await ctx.send(
        content=f"✅ Renamed to `{new_name}`",
        file=discord.File(io.BytesIO(content), filename=new_name)
    )

# ---------------- COMMAND .bf ----------------
@bot.command(name="bf")
async def beautify(ctx, link=None):

    content = None
    original_filename = "script"

    try:
        status = await _send_with_retry(lambda: ctx.send("✨ beautifying"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        original_filename = att.filename
        if att.size > MAX_FILE_SIZE:
            await status.edit(content="❌ File too large")
            return
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200:
            content = r.content

    elif link:
        original_filename = get_filename_from_url(link)
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, link))
        if r.status_code == 200:
            if len(r.content) > MAX_FILE_SIZE:
                await status.edit(content="❌ File too large")
                return
            content = r.content

    else:
        ref_content, ref_filename = await _fetch_reference_content(ctx)
        if ref_content is not None:
            content = ref_content
            original_filename = ref_filename or "script"
        else:
            await status.edit(content="Provide a link, file, or reply to a message that contains one.")
            return

    if not content:
        await status.edit(content="❌ Failed to get content.")
        return

    lua_text = content.decode("utf-8", errors="ignore")

    loop = asyncio.get_event_loop()
    beautified = await loop.run_in_executor(
        _executor,
        functools.partial(_beautify_lua, lua_text)
    )

    paste, raw = await loop.run_in_executor(
        _executor,
        functools.partial(upload_to_pastefy, beautified, title=f"[BF] {original_filename}")
    )

    preview = "\n".join(beautified.splitlines()[:PREVIEW_LINES])

    embed = discord.Embed(
        title="✨ Beautified",
        description=f"Paste: {raw}" if raw else "⚠️ Paste upload failed",
        color=0x2b2d31
    )
    embed.add_field(
        name="Preview",
        value=f"```lua\n{preview[:PREVIEW_MAX_CHARS]}\n```",
        inline=False
    )

    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")

    try:
        await _send_with_retry(lambda: ctx.send(
            embed=embed,
            file=discord.File(
                io.BytesIO(beautified.encode("utf-8")),
                filename=os.path.splitext(original_filename)[0] + "_bf.lua"
            )
        ))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send beautified result: {e}")
        try:
            await status.edit(content=f"❌ Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass

# ---------------- COMMAND .fix ----------------
@bot.command(name="fix")
async def fix_lua(ctx, link=None):
    """Apply a full Roblox/Lua syntax repair pipeline to the supplied script.

    Fixes applied (in order):
    1. Non-Lua operators (``!=``, ``&&``, ``||``, ``!``, ``null``, ``else if``)
    2. Missing ``)`` on ``:Connect(function…end)`` blocks
    3. Extra / misplaced ``end`` keywords
    4. Remaining missing ``end`` keywords (appended at EOF)
    5. Duplicate ``:Connect()`` event-handler bindings
    6. Shadowed UI-element variable names (``local frame = Instance.new(…)``
       declared more than once)
    7. Rename locals to reflect their ``.Name`` property assignment
    8. Re-indent (beautify)
    """

    content = None
    original_filename = "script"

    try:
        status = await _send_with_retry(lambda: ctx.send("🔧 fixing"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        original_filename = att.filename
        if att.size > MAX_FILE_SIZE:
            await status.edit(content="❌ File too large")
            return
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200:
            content = r.content

    elif link:
        original_filename = get_filename_from_url(link)
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, link))
        if r.status_code == 200:
            if len(r.content) > MAX_FILE_SIZE:
                await status.edit(content="❌ File too large")
                return
            content = r.content

    else:
        ref_content, ref_filename = await _fetch_reference_content(ctx)
        if ref_content is not None:
            content = ref_content
            original_filename = ref_filename or "script"
        else:
            await status.edit(content="Provide a link, file, or reply to a message that contains one.")
            return

    if not content:
        await status.edit(content="❌ Failed to get content.")
        return

    lua_text = content.decode("utf-8", errors="ignore")

    def _run_fix_pipeline(code: str) -> str:
        code = _fix_lua_compat(code)
        code = _fix_connect_end_parens(code)
        code = _fix_extra_ends(code)
        code = _fix_lua_do_end(code)
        code = _dedup_connections(code)
        code = _fix_ui_variable_shadowing(code)
        code = _rename_by_name_property(code)
        code = _beautify_lua(code)
        return code

    loop = asyncio.get_event_loop()
    fixed = await loop.run_in_executor(
        _executor,
        functools.partial(_run_fix_pipeline, lua_text)
    )

    paste, raw = await loop.run_in_executor(
        _executor,
        functools.partial(upload_to_pastefy, fixed, title=f"[FIX] {original_filename}")
    )

    preview = "\n".join(fixed.splitlines()[:PREVIEW_LINES])

    embed = discord.Embed(
        title="🔧 Fixed",
        description=f"Paste: {raw}" if raw else "⚠️ Paste upload failed",
        color=0x2b2d31
    )
    embed.add_field(
        name="Preview",
        value=f"```lua\n{preview[:PREVIEW_MAX_CHARS]}\n```",
        inline=False
    )

    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")

    try:
        await _send_with_retry(lambda: ctx.send(
            embed=embed,
            file=discord.File(
                io.BytesIO(fixed.encode("utf-8")),
                filename=os.path.splitext(original_filename)[0] + "_fixed.lua"
            )
        ))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send fixed result: {e}")
        try:
            await status.edit(content=f"❌ Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass

# ---------------- COMMAND .dc (Luac decompiler) ----------------
@bot.command(name="dc")
async def decompile_command(ctx, *, link: str = None):
    """Decompile a Lua bytecode file (.luac) and return the pseudocode.

    Usage:
      .dc <url>           – decompile bytecode from a URL
      .dc                 – decompile bytecode from an attached file
      .dc                 – decompile bytecode from a replied-to attachment/message
    """
    try:
        status = await _send_with_retry(lambda: ctx.send("🔍 decompiling luac..."))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    raw: bytes | None = None
    fname = "output.lua"

    try:
        # ---- 1. Try URL argument ----
        if link:
            url = link.strip()
            try:
                resp = await asyncio.get_event_loop().run_in_executor(
                    _executor, functools.partial(_requests_get, url))
                resp.raise_for_status()
                raw = resp.content
                fname = os.path.basename(urllib.parse.urlparse(url).path) or "output.luac"
            except Exception as e:
                await _send_with_retry(lambda: status.edit(content=f"❌ Failed to download: {e}"))
                return

        # ---- 2. Try attachment on this message ----
        elif ctx.message.attachments:
            att = ctx.message.attachments[0]
            if att.size > MAX_FILE_SIZE:
                await _send_with_retry(lambda: status.edit(
                    content=f"❌ File too large ({att.size} bytes, max {MAX_FILE_SIZE})."))
                return
            raw_bytes = await att.read()
            raw = raw_bytes
            fname = att.filename

        # ---- 3. Try replied-to message ----
        elif ctx.message.reference:
            ref = ctx.message.reference.resolved
            if ref is None:
                try:
                    ref = await ctx.channel.fetch_message(ctx.message.reference.message_id)
                except discord.errors.NotFound:
                    pass
            if ref is not None:
                if ref.attachments:
                    att = ref.attachments[0]
                    raw_bytes = await att.read()
                    raw = raw_bytes
                    fname = att.filename
                elif ref.content:
                    raw = ref.content.encode('latin-1', errors='replace')
                    fname = "input.luac"

        if raw is None:
            await _send_with_retry(lambda: status.edit(
                content="❌ No input: attach a .luac file, reply to one, or give a URL."))
            return

        # ---- Decompile ----
        ver = _luac_version(raw)
        if ver is None:
            await _send_with_retry(lambda: status.edit(
                content="❌ Not a Lua bytecode file (invalid magic bytes). "
                        "Expected a compiled .luac file."))
            return

        result = await asyncio.get_event_loop().run_in_executor(
            _executor, functools.partial(decompile_luac, raw))

        # ---- Send result ----
        base = os.path.splitext(fname)[0]
        out_name = base + "_decompiled.lua"
        encoded = result.encode('utf-8')

        if len(encoded) <= 1900:
            await _send_with_retry(lambda: status.edit(
                content=f"```lua\n{result[:1890]}\n```"))
        else:
            buf = io.BytesIO(encoded)
            buf.name = out_name
            await _send_with_retry(lambda: status.edit(content=f"✅ Lua {ver} decompiled:"))
            await _send_with_retry(lambda: ctx.send(
                file=discord.File(fp=io.BytesIO(encoded), filename=out_name)))

    except ValueError as e:
        await _send_with_retry(lambda: status.edit(content=f"❌ Decompile error: {e}"))
    except Exception as e:
        await _send_with_retry(lambda: status.edit(content=f"❌ Unexpected error: {e}"))
        raise


# ---------------- COMMAND GET ----------------
@bot.command(name="get")
async def get_link_content(ctx,*,link=None):

    try:
        status=await _send_with_retry(lambda: ctx.send("⬇️ downloading"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    try:

        # If no link given, try to pull the URL from a replied-to message.
        if not link:
            ref_content, ref_filename = await _fetch_reference_content(ctx)
            if ref_content is not None:
                fname = ref_filename or "file.txt"
                if not fname.endswith(".txt"):
                    fname = os.path.splitext(fname)[0] + ".txt"
                await status.delete()
                await _send_with_retry(lambda: ctx.send(
                    content=f"✅ from reply",
                    file=discord.File(io.BytesIO(ref_content), filename=fname)
                ))
                return
            await status.edit(content="Usage: .get <link>  (or reply to a message with a file/link)")
            return

        link=extract_first_url(link) or link

        loop=asyncio.get_event_loop()
        r=await loop.run_in_executor(_executor,functools.partial(_requests_get,link))

        if r.status_code==200:

            filename=get_filename_from_url(link)

            if not filename.endswith(".txt"):
                filename=os.path.splitext(filename)[0]+".txt"

            await status.delete()

            await _send_with_retry(lambda: ctx.send(
                content=f"✅ {link}",
                file=discord.File(io.BytesIO(r.content),filename=filename)
            ))

        else:
            await status.edit(content=f"❌ HTTP {r.status_code}")

    except discord.errors.DiscordServerError as e:
        print(f"Warning: Discord server error in get command: {e}")
        try:
            await status.edit(content=f"❌ Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass
    except Exception as e:
        try:
            await status.edit(content=f"❌ {e}")
        except discord.errors.HTTPException:
            pass

# ---------------- START ----------------
if __name__=="__main__":

    if not TOKEN:
        print("BOT_TOKEN missing")
        exit()

    bot.run(TOKEN)
