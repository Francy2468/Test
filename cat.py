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
import random
import threading
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

LUA_INTERPRETERS = ["lua5.4", "luajit", "lua"]

# ---------------- PROXY POOL ----------------
_PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt",
    "https://raw.githubusercontent.com/almroot/proxylist/master/list.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks4.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/SOCKS5.txt",
    "https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/UptimerBot/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/http.txt",
    "https://raw.githubusercontent.com/saschazesiger/Free-Proxies/master/proxies/socks5.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks4.txt",
    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/socks5.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",
]

_proxy_pool: list = []
_proxy_lock = threading.Lock()

def _fetch_one_source(url):
    """Fetch proxies from a single source. Returns a set of valid IP:port strings."""
    found = set()
    try:
        r = requests.get(url, timeout=6)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line and re.match(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):\d{1,5}$", line):
                    found.add(line)
    except Exception:
        pass
    return found

def _load_proxies():
    """Fetch proxies from multiple public sources concurrently and populate the pool."""
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(_fetch_one_source, _PROXY_SOURCES))
    found = set()
    for s in results:
        found.update(s)
    with _proxy_lock:
        _proxy_pool.clear()
        _proxy_pool.extend(list(found))
    return len(_proxy_pool)

def _get_proxy_dict():
    """Return a random proxy dict for requests, or None if pool is empty."""
    with _proxy_lock:
        if not _proxy_pool:
            return None
        addr = random.choice(_proxy_pool)
    proxy = f"http://{addr}"
    return {"http": proxy, "https": proxy}

def _requests_get(url, **kwargs):
    """requests.get with proxy rotation and automatic fallback."""
    timeout = kwargs.pop("timeout", 8)
    proxies = _get_proxy_dict()
    if proxies:
        try:
            return requests.get(url, proxies=proxies, timeout=timeout, **kwargs)
        except Exception:
            pass
    return requests.get(url, timeout=timeout, **kwargs)

# Load proxies in a background thread so startup is not blocked.
threading.Thread(target=_load_proxies, daemon=True).start()

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

    When consecutive N-line blocks (3 ≤ N ≤ 50) repeat more than *max_reps*
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

        for block_size in range(3, min(51, n - i + 1)):
            # Ensure a full block is available before proceeding.
            if i + block_size > n:
                break
            norm_block = norm_lines[i:i + block_size]

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
# in the VM output above them; _s_N / _xor_N / _wad_N are pre-extracted pools
# that are intentional reference tables and should be preserved as-is.
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

    for proxies in (_get_proxy_dict(), None):
        try:
            resp = requests.post(
                "https://pastefy.app/api/v2/paste",
                json=payload,
                proxies=proxies,
                timeout=10
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                pid = (data.get("paste") or {}).get("id") or data.get("id")
                return (
                    f"https://pastefy.app/{pid}",
                    f"https://pastefy.app/{pid}/raw"
                )
        except Exception:
            continue

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
    print(f"Logged as {bot.user} | Lua {_lua_interp} | Proxies {len(_proxy_pool)}")

# ---------------- COMMAND .proxies ----------------
@bot.command(name="proxies")
@commands.is_owner()
async def reload_proxies(ctx):
    msg = await ctx.send("⏳ Reloading proxy pool...")
    count = await asyncio.get_event_loop().run_in_executor(_executor, _load_proxies)
    await msg.edit(content=f"✅ Proxy pool refreshed — {count} proxies loaded.")

# ---------------- COMMAND .l ----------------
@bot.command(name="l")
async def process_link(ctx,link=None):

    content=None
    original_filename="file"

    # Acknowledge the command immediately so the user sees activity right away
    status=await ctx.send("⚙️ dumping")

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
        description=f"Paste: {raw}",
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

    await ctx.send(
        embed=embed,
        file=discord.File(
            io.BytesIO(dumped_text.encode("utf-8")),
            filename=original_filename+".txt"
        )
    )

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

    status = await ctx.send("✨ beautifying")

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

    await status.delete()

    await ctx.send(
        embed=embed,
        file=discord.File(
            io.BytesIO(beautified.encode("utf-8")),
            filename=os.path.splitext(original_filename)[0] + "_bf.lua"
        )
    )

# ---------------- COMMAND GET ----------------
@bot.command(name="get")
async def get_link_content(ctx,*,link=None):

    status=await ctx.send("⬇️ downloading")

    try:

        # If no link given, try to pull the URL from a replied-to message.
        if not link:
            ref_content, ref_filename = await _fetch_reference_content(ctx)
            if ref_content is not None:
                fname = ref_filename or "file.txt"
                if not fname.endswith(".txt"):
                    fname = os.path.splitext(fname)[0] + ".txt"
                await status.delete()
                await ctx.send(
                    content=f"✅ from reply",
                    file=discord.File(io.BytesIO(ref_content), filename=fname)
                )
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

            await ctx.send(
                content=f"✅ {link}",
                file=discord.File(io.BytesIO(r.content),filename=filename)
            )

        else:
            await status.edit(content=f"❌ HTTP {r.status_code}")

    except Exception as e:
        await status.edit(content=f"❌ {e}")

# ---------------- START ----------------
if __name__=="__main__":

    if not TOKEN:
        print("BOT_TOKEN missing")
        exit()

    bot.run(TOKEN)
