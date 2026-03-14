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
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

try:
    from openai import OpenAI as _OpenAI
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

load_dotenv()

# ---------------- CONFIG ----------------
TOKEN = os.environ.get("TOKEN_BOT", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = "gpt-4o-mini"
# Maximum characters to send to the AI renamer; larger scripts use the
# heuristic fallback to avoid excessive token usage.
AI_RENAME_MAX_CHARS = 80_000

PREFIX = "."
DUMPER_PATH = "catlogger.lua"

MAX_FILE_SIZE = 5 * 1024 * 1024
DUMP_TIMEOUT = 130  # Must exceed catlogger.lua TIMEOUT_SECONDS (120) to allow proper cleanup
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

class _FailedResponse:
    """Returned by _requests_get when a network error occurs."""
    status_code = 0
    content = b""


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
    try:
        return requests.get(url, **kwargs)
    except requests.exceptions.RequestException as e:
        print(f"Warning: request to {url!r} failed: {e}")
        return _FailedResponse()

# ---------------- BOT ----------------
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

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

# Matches Lua double- or single-quoted string literals (with simple escape handling).
_LUA_STRING_LITERAL_RE = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')


def _sub_identifier_outside_strings(old: str, new: str, code: str) -> str:
    """Replace the identifier *old* with *new* in *code*, skipping string literals.

    Applies a word-boundary–aware substitution (``old`` must appear as a
    complete identifier token) but leaves occurrences of *old* that appear
    inside quoted Lua string literals untouched.  This prevents renaming a
    variable from accidentally mutating the type-name argument of
    ``Instance.new("OldName")`` or similar string values.
    """
    pat = re.compile(
        r"(?<![a-zA-Z0-9_])" + re.escape(old) + r"(?![a-zA-Z0-9_])"
    )
    segments: list[str] = []
    pos = 0
    for m in _LUA_STRING_LITERAL_RE.finditer(code):
        # Replace in the code segment before this string literal.
        segments.append(pat.sub(new, code[pos:m.start()]))
        # Preserve the string literal verbatim.
        segments.append(m.group(0))
        pos = m.end()
    # Replace in the code after the last string literal.
    segments.append(pat.sub(new, code[pos:]))
    return "".join(segments)


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


# ---------------- SMART RENAME ----------------

# Maps Roblox Instance types to short, readable camelCase prefixes.
_INSTANCE_TYPE_PREFIXES: dict[str, str] = {
    "Frame": "frame",
    "TextButton": "button",
    "TextLabel": "label",
    "TextBox": "textBox",
    "ScrollingFrame": "scroll",
    "ScreenGui": "gui",
    "UICorner": "corner",
    "UIListLayout": "listLayout",
    "UIGridLayout": "gridLayout",
    "UIStroke": "stroke",
    "UIAspectRatioConstraint": "aspectRatio",
    "UITableLayout": "tableLayout",
    "UIPageLayout": "pageLayout",
    "UIPadding": "padding",
    "UIScale": "uiScale",
    "UIGradient": "gradient",
    "UISizeConstraint": "sizeConstraint",
    "UITextSizeConstraint": "textConstraint",
    "UIFlexItem": "flexItem",
    "ImageLabel": "imageLabel",
    "ImageButton": "imageButton",
    "ViewportFrame": "viewport",
    "BillboardGui": "billboard",
    "SurfaceGui": "surfaceGui",
    "Part": "part",
    "RemoteEvent": "remote",
    "RemoteFunction": "remoteFunc",
    "BindableEvent": "bindEvent",
    "BindableFunction": "bindFunc",
    "LocalScript": "localScript",
    "Script": "script",
    "ModuleScript": "moduleScript",
    "Folder": "folder",
    "Model": "model",
    "Configuration": "config",
    "StringValue": "strVal",
    "NumberValue": "numVal",
    "BoolValue": "boolVal",
    "IntValue": "intVal",
    "ObjectValue": "objVal",
    "SelectionBox": "selBox",
    "WeldConstraint": "weld",
    "Motor6D": "motor6D",
    "Humanoid": "humanoid",
    "Animator": "animator",
    "Animation": "animation",
    "Sound": "sound",
    "SoundGroup": "soundGroup",
    "Camera": "camera",
}

# Instance types that expose a meaningful .Text property.
_TEXT_PROPERTY_TYPES: frozenset[str] = frozenset({"TextButton", "TextLabel", "TextBox"})

# Suffix pattern that makes a variable name "generic" (auto-dumper artifact).
# Matches: empty, "_", "__", "2", "_2", "_a", "_b", "_aa" etc.
# Uses a simple linear character-class (no nested quantifiers) to avoid ReDoS.
_GENERIC_SUFFIX_RE = re.compile(r"^[_a-z\d]*$")


def _is_generic_var_for_type(var: str, type_name: str) -> bool:
    """Return True when *var* looks like an auto-generated name for *type_name*.

    Detects patterns produced by simple Roblox script dumpers::

        frame, frame_, frame__, frame2, frame_a   →  type Frame
        textButton, textButton_, textButton__     →  type TextButton
        uICorner_                                 →  type UICorner

    Very short names (1–2 characters) such as ``B``, ``F``, or ``Gb`` are
    always treated as auto-generated abbreviations regardless of type.

    Human-written descriptive names such as ``mainFrame``, ``closeButton``,
    or ``searchBox`` return False.
    """
    # Single- or double-character names are always abbreviated/auto-generated.
    if len(var) <= 2:
        return True
    bases = set()
    prefix = _INSTANCE_TYPE_PREFIXES.get(type_name)
    if prefix:
        bases.add(prefix)
    type_camel = _name_to_camel_id(type_name)
    if type_camel:
        bases.add(type_camel)
    for base in bases:
        if var.startswith(base) and _GENERIC_SUFFIX_RE.fullmatch(var[len(base):]):
            return True
    return False


def _smart_rename_variables(code: str) -> str:
    """Rename poorly-named Lua variables using Instance type information.

    Strategy (in priority order) for each ``local var = Instance.new("Type")``
    declaration found in *code*:

    1. ``var.Name = "X"`` assignment found anywhere in the script
       → rename ``var`` to camelCase of X.
    2. ``var.Text = "X"`` assignment found (TextButton / TextLabel / TextBox
       only) AND ``var`` looks like an auto-generated name for its type
       → rename to camelCase of X.
    3. ``var`` looks like an auto-generated name (e.g. ``frame``, ``frame_``,
       ``frame__``, ``frame2``) AND the type has a known short prefix
       → rename to ``prefix``, ``prefix2``, ``prefix3`` … (first free slot).
    4. Otherwise keep the current name.

    Additionally, connection locals that have generic names (``conn``,
    ``conn_``, ``conn2`` …) are renamed to ``<resolvedSource>Conn``.

    All renames are applied with word-boundary guards so partial matches
    inside longer identifiers are never touched.
    """
    lines = code.splitlines()

    # Collect every identifier currently present to guard against collisions.
    existing: set[str] = set()
    for line in lines:
        for m in re.finditer(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", line):
            existing.add(m.group(1))

    # ── Pass 1: collect Instance.new() declarations ──────────────────────────
    _INST_RE = re.compile(
        r'Instance\.new\s*\(\s*"([A-Za-z][A-Za-z0-9]*)"\s*\)'
    )
    var_types: dict[str, str] = {}  # var → Instance type name
    for line in lines:
        m = re.match(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
        if not m:
            continue
        var = m.group(1)
        inst_m = _INST_RE.search(line)
        if inst_m and var not in var_types:
            var_types[var] = inst_m.group(1)

    # ── Pass 2: scan .Name / .Text property assignments ─────────────────────
    # Use finditer (not match) so assignments on the same line as the
    # Instance.new() declaration are also detected, e.g.:
    #   local Gui=Instance.new("ScreenGui")Gui.Name="XGUI"Gui.Parent=...
    _PROP_RE = re.compile(
        r"(?<![a-zA-Z0-9_])([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*(Name|Text)\s*=\s*\"([^\"]+)\""
    )
    var_name_prop: dict[str, str] = {}  # var → .Name value
    var_text_prop: dict[str, str] = {}  # var → .Text value
    for line in lines:
        for pm in _PROP_RE.finditer(line):
            var, prop, val = pm.group(1), pm.group(2), pm.group(3)
            if var not in var_types:
                continue
            if prop == "Name" and var not in var_name_prop:
                var_name_prop[var] = val
            elif (
                prop == "Text"
                and var not in var_text_prop
                and var_types.get(var) in _TEXT_PROPERTY_TYPES
            ):
                var_text_prop[var] = val

    # ── Pass 3: collect generic connection locals ────────────────────────────
    _CONN_DECL_RE = re.compile(
        r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"
        r"([a-zA-Z_][a-zA-Z0-9_]*)\s*\.\s*[A-Za-z][A-Za-z0-9]*\s*:\s*Connect\s*\("
    )
    conn_src: dict[str, str] = {}  # conn_var → source_var
    # Linear pattern: anything that starts with "conn" or "connection"
    # (case-insensitive).  No nested quantifiers → no ReDoS risk.
    _GENERIC_CONN_RE = re.compile(r"^conn\w*$", re.IGNORECASE)
    for line in lines:
        cm = _CONN_DECL_RE.match(line)
        if not cm:
            continue
        conn_var, src_var = cm.group(1), cm.group(2)
        if _GENERIC_CONN_RE.match(conn_var) and conn_var not in conn_src:
            conn_src[conn_var] = src_var

    # ── Pass 4: allocate new names ───────────────────────────────────────────
    # Seed the pool with every existing name, then free the slots occupied by
    # variables we might rename so those slots are available as new targets.
    renameable: set[str] = set(var_types) | set(conn_src)
    used_names: set[str] = existing - renameable

    def _alloc(base: str) -> str:
        """Return *base* if free, else *base2*, *base3* … (first free slot).

        A slot is considered free only if it is neither in *used_names* nor a
        key already present in *renames*.  The second guard prevents the
        chain-rename trap where variable A is renamed to B and variable C is
        later also renamed to B (which would then itself get renamed to
        something else when the B→… substitution is applied).
        """
        if base not in used_names and base not in renames:
            used_names.add(base)
            return base
        c = 2
        while True:
            candidate = f"{base}{c}"
            if candidate not in used_names and candidate not in renames:
                used_names.add(candidate)
                return candidate
            c += 1

    renames: dict[str, str] = {}

    for var, type_name in var_types.items():
        # Priority 1: .Name property
        if var in var_name_prop:
            new = _name_to_camel_id(var_name_prop[var])
            if new:
                new = _alloc(new)
                if new != var:
                    renames[var] = new
            else:
                used_names.add(var)  # invalid .Name → keep current
            continue

        # Priority 2: .Text property (text-capable types, generic names only)
        if var in var_text_prop and _is_generic_var_for_type(var, type_name):
            new = _name_to_camel_id(var_text_prop[var])
            if new:
                new = _alloc(new)
                if new != var:
                    renames[var] = new
                # else already added to used_names by _alloc
            else:
                used_names.add(var)
            continue

        # Priority 3: type-prefix sequential numbering (generic names only)
        if _is_generic_var_for_type(var, type_name):
            prefix = _INSTANCE_TYPE_PREFIXES.get(type_name)
            if prefix:
                new = _alloc(prefix)
                if new != var:
                    renames[var] = new
                # else already added to used_names by _alloc
            else:
                used_names.add(var)  # unknown type → keep
        else:
            # Descriptive name already present → keep
            used_names.add(var)

    # Connection variables (after instance renames are resolved)
    for conn_var, src_var in conn_src.items():
        resolved_src = renames.get(src_var, src_var)
        new = _alloc(resolved_src + "Conn")
        if new != conn_var:
            renames[conn_var] = new
        # else already added by _alloc

    if not renames:
        return code

    # ── Pass 5: apply renames with word-boundary guards ──────────────────────
    # Substitution skips string literals so that type-name arguments such as
    # Instance.new("Folder") are never mutated when the variable is renamed.
    result = "\n".join(lines)
    for old, new in sorted(renames.items(), key=lambda kv: -len(kv[0])):
        result = _sub_identifier_outside_strings(old, new, result)
    return result


_AI_SYSTEM_PROMPT = """\
You are an expert Lua developer and code refactoring assistant.
Your task is to analyze the provided Lua script and fully repair, refactor, \
and improve it while preserving its intended functionality.

Carefully review the entire script and perform a full code improvement process.

Objectives:

1. Detect and fix all syntax errors, runtime errors, and logical issues.
2. Correct any broken or invalid Lua syntax.
3. Ensure all parentheses, brackets, and code blocks are properly closed.
4. Fix incorrect API usage or invalid function calls.
5. Improve the overall structure and organization of the script.
6. Refactor messy, duplicated, or poorly structured code into cleaner and more maintainable patterns.
7. Remove redundant, duplicated, or unnecessary code.
8. Simplify overly complex or deeply nested logic.
9. Improve naming of variables, functions, and objects to make them meaningful and readable.
10. Fix variable scope issues and ensure variables are declared in appropriate places.
11. Ensure services and commonly used objects are stored properly and reused instead of repeatedly retrieved.
12. Optimize loops and event connections to prevent performance issues.
13. Prevent infinite loops, unnecessary event connections, or memory leaks.
14. Improve GUI creation logic so elements are organized and structured properly.
15. Ensure all references to objects are validated before use.
16. Apply good Lua programming practices and consistent formatting.
17. Improve indentation, spacing, and overall readability of the code.
18. Reduce excessive nesting and repeated patterns by introducing helper functions if necessary.
19. Ensure the final script is stable and runs without errors.
20. Keep the original features and behavior of the script as much as possible.

Additional guidelines:

- Do not remove functionality unless it is clearly broken.
- Do not leave placeholder code.
- Do not leave syntax errors.
- Ensure the final script is clean, readable, and well organized.
- Prefer clear and maintainable code over overly compact code.

Output requirements:

- Return the FULL corrected and refactored Lua script.
- Ensure the final code is properly formatted.
- Ensure the script can run without obvious errors.
- Do not include explanations unless necessary.
- No markdown fences, no extra text whatsoever.\
"""

# Lazy-initialised OpenAI client (None until first use).
_openai_client = None


def _get_openai_client():
    """Return a cached OpenAI client, or None if unavailable."""
    global _openai_client
    if _openai_client is not None:
        return _openai_client
    if not _OPENAI_AVAILABLE or not OPENAI_API_KEY:
        return None
    try:
        _openai_client = _OpenAI(
            api_key=OPENAI_API_KEY,
        )
    except Exception as exc:
        print(f"[OpenAI] client init failed: {exc}")
        _openai_client = None
    return _openai_client


def _ai_rename_variables(code: str) -> str:
    """Send *code* to ChatGPT and return the AI-renamed Lua source.

    Falls back to ``_smart_rename_variables`` if:
    * The ``openai`` package is not installed.
    * ``OPENAI_API_KEY`` is not set.
    * The script exceeds ``AI_RENAME_MAX_CHARS``.
    * The API call raises any exception.
    * The response appears to be empty or non-Lua.
    """
    if len(code) > AI_RENAME_MAX_CHARS:
        return _smart_rename_variables(code)

    client = _get_openai_client()
    if client is None:
        return _smart_rename_variables(code)

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": _AI_SYSTEM_PROMPT},
                {"role": "user", "content": code},
            ],
            stream=False,
            timeout=60,
        )
        result = response.choices[0].message.content or ""
        # Strip accidental markdown code fences the model may emit.
        result = re.sub(r"^```[a-zA-Z]*\n?", "", result.strip())
        result = re.sub(r"\n?```$", "", result)
        result = result.strip()
        if not result:
            return _smart_rename_variables(code)
        return result
    except Exception as exc:
        print(f"[OpenAI] rename failed: {exc}")
        return _smart_rename_variables(code)


# .fix uses the same comprehensive prompt as .rename.
_AI_FIX_SYSTEM_PROMPT = _AI_SYSTEM_PROMPT


def _ai_fix_lua(code: str) -> str:
    """Send *code* to ChatGPT for comprehensive repair and refactoring.

    Applies the full suite of fixes described in ``_AI_FIX_SYSTEM_PROMPT``
    (syntax repair, naming, structure, formatting).

    Falls back to the heuristic pipeline (``_run_heuristic_fix_pipeline``) if:
    * The ``openai`` package is not installed.
    * ``OPENAI_API_KEY`` is not set.
    * The script exceeds ``AI_RENAME_MAX_CHARS``.
    * The API call raises any exception.
    * The response appears to be empty or non-Lua.
    """
    if len(code) > AI_RENAME_MAX_CHARS:
        return _run_heuristic_fix_pipeline(code)

    client = _get_openai_client()
    if client is None:
        return _run_heuristic_fix_pipeline(code)

    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=[
                {"role": "system", "content": _AI_FIX_SYSTEM_PROMPT},
                {"role": "user", "content": code},
            ],
            stream=False,
            timeout=90,
        )
        result = response.choices[0].message.content or ""
        # Strip accidental markdown code fences the model may emit.
        result = re.sub(r"^```[a-zA-Z]*\n?", "", result.strip())
        result = re.sub(r"\n?```$", "", result)
        result = result.strip()
        if not result:
            return _run_heuristic_fix_pipeline(code)
        return result
    except Exception as exc:
        print(f"[OpenAI] fix failed: {exc}")
        return _run_heuristic_fix_pipeline(code)




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


def _fix_for_missing_do(code: str) -> str:
    """Insert a missing ``do`` keyword into *for*-loop headers.

    Handles numeric for loops of the form::

        for i = 1, 10 body   →   for i = 1, 10 do body

    and generic for loops whose ``in``-expression ends with a closing
    parenthesis::

        for k, v in pairs(t) body   →   for k, v in pairs(t) do body

    For-loop headers that already contain ``do`` are left unchanged.

    This pass must run **before** ``_fix_extra_ends`` and ``_fix_lua_do_end``
    so that those passes count the newly-opened for blocks correctly.
    """
    # Numeric for: for var = start, limit [, step] <body without do>
    # Each range token is matched with \S+ (non-whitespace) so that simple
    # literals, variables, and short expressions (e.g. #t, -1) are handled.
    # Complex range expressions containing spaces are not modified; those
    # cases are expected to already have a valid 'do' keyword.
    _NUM_FOR_NO_DO_RE = re.compile(
        r"(\bfor\s+[a-zA-Z_]\w*\s*=\s*\S+\s*,\s*\S+(?:\s*,\s*\S+)?)"
        r"(\s+)(?!\s*\bdo\b)"
    )
    # Generic for: for vars in expr <body without do>
    # The iterator expression is matched greedily up to the last ')' on the
    # line to handle common patterns like pairs(t), ipairs(t), etc.
    _GEN_FOR_NO_DO_RE = re.compile(
        r"(\bfor\s+(?:[a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s+in\s+[^\n]+\))"
        r"(\s+)(?!\s*\bdo\b)"
    )
    code = _NUM_FOR_NO_DO_RE.sub(r"\1 do\2", code)
    code = _GEN_FOR_NO_DO_RE.sub(r"\1 do\2", code)
    return code


def _fix_local_missing_assign(code: str) -> str:
    """Fix ``local var N`` declarations where the ``=`` sign is absent.

    Detects patterns of the form::

        local y 20   →   local y = 20

    where a bare numeric literal (integer or decimal) follows a variable name
    without the required assignment operator.  Only simple numeric literals
    are handled; multi-variable declarations and non-numeric initialisers are
    left untouched.
    """
    _LOCAL_MISSING_ASSIGN_RE = re.compile(
        r"\blocal\s+([a-zA-Z_]\w*)\s+(-?\d+(?:\.\d+)?)\b"
    )
    return _LOCAL_MISSING_ASSIGN_RE.sub(r"local \1 = \2", code)


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
                # Also update any inline references to var_name in the rest of
                # this same line (e.g. "B.Text=..." following the declaration).
                # String literals are skipped so Instance.new("Folder") is not
                # corrupted when renaming the variable called Folder.
                rest_of_line = _sub_identifier_outside_strings(
                    var_name, new_name, raw_line[m.end():]
                )
                raw_line = prefix + new_name + suffix + rest_of_line
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
            raw_line = _sub_identifier_outside_strings(orig, new, raw_line)

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

    Always fetches the referenced message fresh (rather than using the cached
    ``ref.resolved``) so that Discord attachment CDN tokens are up-to-date.

    Returns (None, None) if:
    - The message is not a reply.
    - The referenced message has no attachments and no detectable URL in its content.
    - Any network or API error occurs.
    """
    ref = ctx.message.reference
    if not ref:
        return None, None

    # Always fetch the message fresh to ensure CDN attachment URLs are valid.
    try:
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
        if r.status_code == 200 and r.content:
            return r.content, att.filename
        return None, None

    # Fall back to the first URL found in the message text.
    url = extract_first_url(ref_msg.content or "")
    if url:
        filename = get_filename_from_url(url)
        loop = asyncio.get_event_loop()
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, url))
        if r.status_code == 200 and r.content:
            if len(r.content) > MAX_FILE_SIZE:
                return None, None
            return r.content, filename

    return None, None


async def _get_content(ctx, link=None):
    """Resolve script content bytes + filename from the invoking message.

    Priority order:
      1. Attachment attached to the current message.
      2. Explicit URL provided as ``link``.
         If the URL download fails but the message is also a reply, falls back
         to step 3 before giving up.
      3. Attachment or URL found in the replied-to message.

    Returns ``(content, filename, error)`` where:
      - ``content`` is ``bytes`` on success, ``None`` on failure.
      - ``filename`` is a best-effort filename string.
      - ``error`` is ``None`` on success, or a human-readable error string.
    """
    loop = asyncio.get_event_loop()

    # 1. Attachment in the current message.
    if ctx.message.attachments:
        att = ctx.message.attachments[0]
        if att.size > MAX_FILE_SIZE:
            return None, att.filename, "File too large"
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, att.url))
        if r.status_code == 200 and r.content:
            return r.content, att.filename, None
        return None, att.filename, f"Failed to download attachment (HTTP {r.status_code})"

    # 2. Explicit URL provided in the command argument.
    if link:
        url = extract_first_url(link) or link
        filename = get_filename_from_url(url)
        r = await loop.run_in_executor(_executor, functools.partial(_requests_get, url))
        if r.status_code == 200 and r.content:
            if len(r.content) > MAX_FILE_SIZE:
                return None, filename, "File too large"
            return r.content, filename, None
        # URL failed — try reply as fallback before reporting failure.
        url_err = f"HTTP {r.status_code}" if r.status_code != 0 else "network error"
        ref_content, ref_filename = await _fetch_reference_content(ctx)
        if ref_content:
            return ref_content, ref_filename or filename, None
        return None, filename, f"Failed to get content ({url_err})"

    # 3. Reply to another message.
    ref_content, ref_filename = await _fetch_reference_content(ctx)
    if ref_content:
        return ref_content, ref_filename or "file", None

    return None, "file", "Provide a link, file, or reply to a message that contains one."

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

# ---------------- COMMAND .help ----------------
@bot.command(name="help")
async def show_help(ctx):
    """Show available bot commands."""
    embed = discord.Embed(
        title="Commands",
        description=f"Prefix: `{PREFIX}`",
        color=0x2b2d31,
    )
    embed.add_field(
        name=f"{PREFIX}l [link]",
        value=(
            "Deobfuscate/dump a Lua script.\n"
            "Attach a file, provide a URL, or reply to a message with a file/link."
        ),
        inline=False,
    )
    embed.add_field(
        name=f"{PREFIX}get [link]",
        value=(
            "Fetch a file from a URL and send it as a text attachment.\n"
            "Attach a file, provide a URL, or reply to a message with a file/link."
        ),
        inline=False,
    )
    embed.add_field(
        name=f"{PREFIX}bf [link]",
        value=(
            "Beautify/reformat a Lua script.\n"
            "Attach a file, provide a URL, or reply to a message with a file/link."
        ),
        inline=False,
    )
    embed.add_field(
        name=f"{PREFIX}darklua [link]",
        value=(
            "Apply Lua code transformations interactively.\n"
            "Attach a file, provide a URL, or reply to a message with a file/link."
        ),
        inline=False,
    )
    try:
        await _send_with_retry(lambda: ctx.send(embed=embed))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send help message: {e}")


# ---------------- COMMAND .l ----------------
@bot.command(name="l")
async def process_link(ctx, *, link=None):

    # Acknowledge the command immediately so the user sees activity right away
    try:
        status=await _send_with_retry(lambda: ctx.send("dumping"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    content, original_filename, err = await _get_content(ctx, link)
    if err:
        await status.edit(content=err)
        return

    dumped,exec_ms,loops,lines,error=await run_dumper(content)

    if error:
        await status.edit(content=f"{error}")
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
        title=f"Finished {exec_ms:.2f} ms",
        description=f"Paste: {raw}" if raw else "Paste upload failed",
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
            await status.edit(content=f"Discord error, please retry: {e}")
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
      !expr       ->  not    (logical NOT; only bare '!' followed by an
                             identifier or '(' — not punctuation in strings)
      null        ->  nil    (whole word)
      undefined   ->  nil    (whole word)
      else if     ->  elseif (Lua uses a single keyword; see note below)

    Note on "else if" collapsing: the transformation is skipped for the
    pattern "end … else … if" (on the same line) because that is genuine Lua
    syntax where the "end" closes the then-clause and "else if" opens a new
    nested if-block.  Collapsing it would remove a required structural "end"
    and produce the error "'end' expected near 'elseif'".
    """
    # != must come before ! so that '!=' is not split into 'not ='
    code = code.replace("!=", "~=")
    # Normalise surrounding whitespace so 'a && b' becomes 'a and b'
    code = re.sub(r"\s*&&\s*", " and ", code)
    code = re.sub(r"\s*\|\|\s*", " or ", code)
    # Replace bare '!' (logical NOT) — '!=' has already been handled above.
    # Require '!' to be followed by an identifier character or '(' so that '!'
    # used as punctuation in string literals (e.g. "hello!", "done!") and at
    # line endings is left untouched.  This prevents corrupting string values
    # while still catching all practical uses of the JS logical-NOT operator.
    code = re.sub(r"(?<!\w)!(?=[a-zA-Z_(])", "not ", code)
    code = re.sub(r"\bnull\b", "nil", code)
    code = re.sub(r"\bundefined\b", "nil", code)
    # Collapse "else if" -> "elseif" but protect "end … else … if" first.
    # The WeAreDevs VM (and similar obfuscated Lua) writes genuine
    # else-blocks-with-nested-if as "end else if" on a single line.
    _PROTECT = "\x00CATMIO_ELSEIF\x00"
    code = re.sub(
        r"\bend([ \t]+)else([ \t]+)if\b",
        lambda m: f"end{m.group(1)}else{m.group(2)}{_PROTECT}",
        code,
    )
    code = re.sub(r"\belse[ \t]+if\b", "elseif", code)
    code = code.replace(_PROTECT, "if")
    return code



# ---------------- HEURISTIC FIX PIPELINE ----------------

def _run_heuristic_fix_pipeline(code: str) -> str:
    """Apply the full heuristic-based Lua repair pipeline without AI.

    This is the fallback used by ``_ai_fix_lua`` when ChatGPT is unavailable
    or the script is too large for the AI call, and it is also used directly
    by the ``.fix`` command when no API key is configured.

    Steps (in order):
    1. Non-Lua operator substitution (!=, &&, ||, !, null, else if)
    2. Insert missing 'do' into for-loop headers
    3. Fix 'local var N' → 'local var = N' (missing assignment operator)
    4. Add missing ')' to :Connect(function…end) blocks
    5. Remove extra / misplaced 'end' keywords
    6. Append missing 'end' keywords at EOF
    7. Remove duplicate :Connect() event-handler bindings
    8. De-shadow re-declared UI-element variable names
    9. Rename locals using .Name / .Text / type-prefix heuristics
    10. Fold adjacent string-literal concatenations
    11. Collapse repeated identical code blocks (loop-unroll artifacts)
    12. Re-indent (beautify)
    13. Remove excessive blank lines and trailing whitespace
    """
    code = _fix_lua_compat(code)
    code = _fix_for_missing_do(code)
    code = _fix_local_missing_assign(code)
    code = _fix_connect_end_parens(code)
    code = _fix_extra_ends(code)
    code = _fix_lua_do_end(code)
    code = _dedup_connections(code)
    code = _fix_ui_variable_shadowing(code)
    code = _smart_rename_variables(code)
    code = _fold_string_concat(code)
    code = _collapse_loop_unrolls(code)
    code = _beautify_lua(code)
    code = _collapse_blank_lines(code)
    code = _remove_trailing_whitespace(code)
    return code


# ---------------- COMMAND .bf ----------------
@bot.command(name="bf")
async def beautify(ctx, *, link=None):

    try:
        status = await _send_with_retry(lambda: ctx.send("beautifying"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    content, original_filename, err = await _get_content(ctx, link)
    if err:
        await status.edit(content=err)
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
        title="Beautified",
        description=f"Paste: {raw}" if raw else "Paste upload failed",
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
            await status.edit(content=f"Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass

# ---------------- COMMAND .darklua ----------------

# Canonical order in which transformations are applied (regardless of selection order).
_DARKLUA_TRANSFORM_ORDER = [
    "strip_comments",
    "fix_syntax",
    "rename_vars",
    "fold_strings",
    "inline_constants",
    "beautify",
]

_DARKLUA_OPTIONS = [
    discord.SelectOption(
        label="Remove Comments",
        value="strip_comments",
        description="Remove all Lua comments from the code",
    ),
    discord.SelectOption(
        label="Rename Variables",
        value="rename_vars",
        description="Intelligently rename Instance.new() variables",
    ),
    discord.SelectOption(
        label="Fold String Concatenations",
        value="fold_strings",
        description='Collapse "a" .. "b" into "ab"',
    ),
    discord.SelectOption(
        label="Inline Single-Use Constants",
        value="inline_constants",
        description="Inline constants that are referenced only once",
    ),
    discord.SelectOption(
        label="Beautify / Reformat",
        value="beautify",
        description="Normalize indentation and formatting",
    ),
    discord.SelectOption(
        label="Fix Syntax Errors",
        value="fix_syntax",
        description="Apply heuristic Lua syntax repair pipeline",
    ),
]


class _DarkluaView(discord.ui.View):
    """Interactive view for selecting and applying Lua code transformations."""

    def __init__(self, code: str, filename: str, author_id: int):
        super().__init__(timeout=120)
        self.code = code
        self.filename = filename
        self.author_id = author_id
        self.selected: list[str] = []
        self.message = None  # set after the menu message is sent

    async def on_timeout(self):
        for child in self.children:
            child.disabled = True
        if self.message:
            try:
                await self.message.edit(view=self)
            except discord.errors.HTTPException:
                pass

    @discord.ui.select(
        placeholder="Choose transformations…",
        min_values=1,
        max_values=len(_DARKLUA_OPTIONS),
        options=_DARKLUA_OPTIONS,
    )
    async def select_transforms(
        self,
        interaction: discord.Interaction,
        select: discord.ui.Select,
    ):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the command author can use this menu.", ephemeral=True
            )
            return
        self.selected = select.values
        await interaction.response.defer()

    @discord.ui.button(label="Apply", style=discord.ButtonStyle.primary)
    async def apply_button(
        self,
        interaction: discord.Interaction,
        button: discord.ui.Button,
    ):
        if interaction.user.id != self.author_id:
            await interaction.response.send_message(
                "Only the command author can use this menu.", ephemeral=True
            )
            return
        if not self.selected:
            await interaction.response.send_message(
                "Please select at least one transformation first.", ephemeral=True
            )
            return

        # Disable all components and show a processing state.
        for child in self.children:
            child.disabled = True
        await interaction.response.edit_message(content="processing…", view=self)
        self.stop()

        code = self.code
        loop = asyncio.get_event_loop()
        selected_set = set(self.selected)

        # Apply transformations in a fixed canonical order.
        for key in _DARKLUA_TRANSFORM_ORDER:
            if key not in selected_set:
                continue
            if key == "strip_comments":
                code = _strip_comments(code)
            elif key == "fix_syntax":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_run_heuristic_fix_pipeline, code)
                )
            elif key == "rename_vars":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_smart_rename_variables, code)
                )
            elif key == "fold_strings":
                code = _fold_string_concat(code)
            elif key == "inline_constants":
                code = _inline_single_use_constants(code)
            elif key == "beautify":
                code = await loop.run_in_executor(
                    _executor, functools.partial(_beautify_lua, code)
                )

        # Upload result to pastefy.
        paste, raw = await loop.run_in_executor(
            _executor,
            functools.partial(
                upload_to_pastefy, code, title=f"[darklua] {self.filename}"
            ),
        )

        labels = ", ".join(
            o.label for o in _DARKLUA_OPTIONS if o.value in selected_set
        )
        preview = "\n".join(code.splitlines()[:PREVIEW_LINES])

        embed = discord.Embed(
            title="darklua",
            description=(
                f"Applied: **{labels}**\n"
                + (f"Paste: {raw}" if raw else "Paste upload failed")
            ),
            color=0x5865F2,
        )
        embed.add_field(
            name="Preview",
            value=f"```lua\n{preview[:PREVIEW_MAX_CHARS]}\n```",
            inline=False,
        )
        embed.set_footer(text="🐱")

        out_filename = os.path.splitext(self.filename)[0] + "_darklua.lua"
        try:
            await interaction.followup.send(
                embed=embed,
                file=discord.File(
                    io.BytesIO(code.encode("utf-8")),
                    filename=out_filename,
                ),
            )
        except discord.errors.DiscordServerError as e:
            print(f"Warning: failed to send darklua result: {e}")
            try:
                await interaction.followup.send(
                    content=f"Discord error, please retry: {e}"
                )
            except discord.errors.HTTPException:
                pass


@bot.command(name="darklua")
async def darklua_cmd(ctx, *, link=None):
    """Apply Lua code transformations interactively."""
    try:
        status = await _send_with_retry(lambda: ctx.send("downloading"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    content, filename, err = await _get_content(ctx, link)
    if err:
        try:
            await status.edit(content=err)
        except discord.errors.HTTPException:
            pass
        return

    lua_text = content.decode("utf-8", errors="ignore")

    embed = discord.Embed(
        title="darklua",
        description=(
            f"File: **{filename}**  •  {len(lua_text):,} chars\n\n"
            "Select the transformations to apply, then click **Apply**."
        ),
        color=0x5865F2,
    )
    embed.set_footer(text="🐱 • Expires in 2 minutes")

    view = _DarkluaView(lua_text, filename, ctx.author.id)

    try:
        await status.delete()
    except discord.errors.HTTPException as e:
        print(f"Warning: failed to delete status message: {e}")

    try:
        msg = await _send_with_retry(lambda: ctx.send(embed=embed, view=view))
        view.message = msg
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send darklua menu: {e}")


# ---------------- COMMAND GET ----------------
@bot.command(name="get")
async def get_link_content(ctx, *, link=None):

    try:
        status = await _send_with_retry(lambda: ctx.send("downloading"))
    except discord.errors.DiscordServerError as e:
        print(f"Warning: failed to send status message: {e}")
        return

    try:
        content, filename, err = await _get_content(ctx, link)
        if err:
            await status.edit(content=err)
            return

        if not filename.endswith(".txt"):
            filename = os.path.splitext(filename)[0] + ".txt"

        await status.delete()

        source_label = link if link else "from reply"
        await _send_with_retry(lambda: ctx.send(
            content=source_label,
            file=discord.File(io.BytesIO(content), filename=filename)
        ))

    except discord.errors.DiscordServerError as e:
        print(f"Warning: Discord server error in get command: {e}")
        try:
            await status.edit(content=f"Discord error, please retry: {e}")
        except discord.errors.HTTPException:
            pass
    except Exception as e:
        try:
            await status.edit(content=f"{e}")
        except discord.errors.HTTPException:
            pass

# ---------------- START ----------------
if __name__=="__main__":

    if not TOKEN:
        print("BOT_TOKEN missing")
        exit()

    bot.run(TOKEN)
