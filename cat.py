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


# How many lines after a local declaration to search for a .Name = "X" assignment.
_NAME_PROP_LOOKAHEAD = 10

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

    for i, line in enumerate(lines):
        m = re.match(r"^\s*local\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=", line)
        if not m:
            continue
        var = m.group(1)
        if var in renames:
            continue  # already scheduled for rename

        # Look ahead for VAR.Name = "SomeName"
        for j in range(i + 1, min(i + _NAME_PROP_LOOKAHEAD + 1, n)):
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
                break  # stop after first .Name assignment for this var

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

    dumped,exec_ms,loops,lines,error=await run_dumper(content)

    if error:
        await status.edit(content=f"❌ {error}")
        return

    dumped_text=dumped.decode("utf-8",errors="ignore")
    dumped_text=_strip_loop_markers(dumped_text)
    dumped_text=_collapse_loop_unrolls(dumped_text)
    dumped_text=_fold_string_concat(dumped_text)
    dumped_text=_inline_single_use_constants(dumped_text)
    # Rename locals using their .Name property assignment before normalising
    # counter suffixes — frame2/frame3 are still distinct at this point and
    # each can receive its own descriptive name (backdrop, scanBeam, window…).
    dumped_text=_rename_by_name_property(dumped_text)
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
