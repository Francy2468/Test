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
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
PREFIX = "."
DUMPER_PATH = "catlogger.lua"

MAX_FILE_SIZE = 5 * 1024 * 1024
DUMP_TIMEOUT = 60

LUA_INTERPRETERS = ["lua5.3", "lua5.4", "luajit", "lua"]

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
]

_proxy_pool: list = []
_proxy_lock = threading.Lock()

def _load_proxies():
    """Fetch proxies from multiple public sources and populate the pool."""
    found = set()
    for url in _PROXY_SOURCES:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if line and re.match(r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?):\d{1,5}$", line):
                        found.add(line)
        except Exception:
            continue
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
    proxies = _get_proxy_dict()
    if proxies:
        try:
            return requests.get(url, proxies=proxies, timeout=kwargs.pop("timeout", 10), **kwargs)
        except Exception:
            pass
    return requests.get(url, timeout=kwargs.pop("timeout", 10), **kwargs)

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

# ---------------- SECURITY ----------------
_THREAT_PATTERNS = [

# ENV
re.compile(r"os\.getenv", re.I),
re.compile(r"getenv\(", re.I),

# SHELL
re.compile(r"os\.execute", re.I),
re.compile(r"io\.popen", re.I),

# DIRECTORY
re.compile(r"\bls\b", re.I),
re.compile(r"\bdir\b", re.I),
re.compile(r"\bpwd\b", re.I),

# FILESYSTEM
re.compile(r"io\.open", re.I),
re.compile(r"require\(['\"]lfs['\"]\)", re.I),
re.compile(r"lfs\.", re.I),

# DEBUG
re.compile(r"debug\.getinfo", re.I),
re.compile(r"debug\.getregistry", re.I),
re.compile(r"debug\.getupvalue", re.I),

# FFI
re.compile(r"require\(['\"]ffi['\"]\)", re.I),

# PATHS - Unix
re.compile(r"/home/", re.I),
re.compile(r"/root/", re.I),
re.compile(r"/etc/", re.I),
re.compile(r"/proc/", re.I),
re.compile(r"/sys/", re.I),
re.compile(r"/var/", re.I),
re.compile(r"/tmp/", re.I),

# PATHS - Windows malicious
re.compile(r"[A-Za-z]:\\\\", re.I),
re.compile(r"[A-Za-z]:/", re.I),
re.compile(r"\\\\AppData\\\\", re.I),
re.compile(r"AppData[/\\\\]Roaming", re.I),
re.compile(r"AppData[/\\\\]Local", re.I),
re.compile(r"\\\\Users\\\\", re.I),
re.compile(r"\\\\System32\\\\", re.I),
re.compile(r"\\\\Windows\\\\", re.I),
re.compile(r"\\\\Program Files", re.I),
re.compile(r"NTUSER\.DAT", re.I),
re.compile(r"\\\\Temp\\\\", re.I),

# COMMANDS
re.compile(r"\bwhoami\b", re.I),
re.compile(r"\buname\b", re.I),
re.compile(r"\bid\b", re.I),
re.compile(r"\bnetstat\b", re.I),
re.compile(r"\bipconfig\b", re.I),
re.compile(r"\bifconfig\b", re.I),
re.compile(r"\bcmd\.exe\b", re.I),
re.compile(r"\bpowershell\b", re.I),

# ROBLOX EXPLOITS - getgenv / syn env / other executor globals
re.compile(r"\bgetgenv\s*\(", re.I),
re.compile(r"\bgetrenv\s*\(", re.I),
re.compile(r"\bgetfenv\s*\(", re.I),
re.compile(r"\bsetfenv\s*\(", re.I),
re.compile(r"\bgetrawmetatable\s*\(", re.I),
re.compile(r"\bsetrawmetatable\s*\(", re.I),
re.compile(r"\bhookfunction\s*\(", re.I),
re.compile(r"\bnewcclosure\s*\(", re.I),
re.compile(r"\biscclosure\s*\(", re.I),
re.compile(r"\bsynapse\s*\.\s*\w+", re.I),
re.compile(r"\bsyn\s*\.", re.I),
re.compile(r"\bfluxus\s*\.\s*\w+", re.I),
re.compile(r"\bscript-ware\b", re.I),

# ROBLOX EXPLOIT DETECTORS / ENV LOGGERS
re.compile(r"UELD[_\s]*DETECTOR", re.I),
re.compile(r"ENV[_\s]*LOGGER", re.I),
re.compile(r"ENV LOGGER DETECTED", re.I),
re.compile(r"env logger is currently running", re.I),
re.compile(r"this env logger", re.I),
re.compile(r"luau cli\s*/\s*standalone", re.I),

# ROBLOX SERVICES abused by exploits (combined with executor globals above)
re.compile(r"BindableEvent", re.I),

]

def detect_threats(text: str):
    for pat in _THREAT_PATTERNS:
        if pat.search(text):
            return True, pat.pattern
    return False, None

# ---------------- SANITIZE ----------------
def sanitize_output(text: str):

    text = re.sub(r"/home/[^\s]+", "/home/REDACTED", text)
    text = re.sub(r"/root/[^\s]+", "/root/REDACTED", text)
    text = re.sub(r"/etc/[^\s]+", "/etc/REDACTED", text)
    text = re.sub(r"/proc/[^\s]+", "/proc/REDACTED", text)
    text = re.sub(r"/sys/[^\s]+", "/sys/REDACTED", text)
    text = re.sub(r"/var/[^\s]+", "/var/REDACTED", text)

    text = re.sub(r"[A-Za-z]:\\\\[^\s]+", r"DRIVE:\\REDACTED", text, flags=re.I)
    text = re.sub(r"AppData[/\\\\][^\s]+", "AppData\\REDACTED", text, flags=re.I)

    text = re.sub(r"HOME=.*", "HOME=REDACTED", text)
    text = re.sub(r"USER=.*", "USER=REDACTED", text)
    text = re.sub(r"USERNAME=.*", "USERNAME=REDACTED", text)

    return text

# ---------------- WEBHOOK ----------------
def send_to_webhook(user_id, user_name, action, details, preview=None):

    if not WEBHOOK_URL:
        return

    embed = {
        "title": "🚨 Security Alert",
        "color": 0xff0000,
        "fields": [
            {"name": "User", "value": f"{user_name} (`{user_id}`)"},
            {"name": "Action", "value": action},
            {"name": "Matched Pattern", "value": f"`{details.replace('`', '\u02cb')}`"},
        ],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    if preview:
        embed["fields"].append({
            "name": "Preview",
            "value": f"```lua\n{preview[:800]}\n```"
        })

    try:
        requests.post(WEBHOOK_URL, json={"embeds": [embed]}, timeout=5)
    except Exception:
        pass

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
            if resp.status_code == 200:
                pid = resp.json()["paste"]["id"]
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

        return None,0,0,0,"Output not generated"

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
    loop = asyncio.get_event_loop()
    count = await loop.run_in_executor(_executor, _load_proxies)
    await msg.edit(content=f"✅ Proxy pool refreshed — {count} proxies loaded.")

# ---------------- COMMAND .l ----------------
@bot.command(name="l")
async def process_link(ctx,link=None):

    content=None
    original_filename="file"

    if ctx.message.attachments:

        att=ctx.message.attachments[0]

        original_filename=att.filename

        if att.size>MAX_FILE_SIZE:
            await ctx.send("❌ File too large")
            return

        r=_requests_get(att.url)

        if r.status_code==200:
            content=r.content

    elif link:

        original_filename=get_filename_from_url(link)

        r=_requests_get(link)

        if r.status_code==200:

            if len(r.content)>MAX_FILE_SIZE:
                await ctx.send("❌ File too large")
                return

            content=r.content

    else:
        await ctx.send("Provide a link or file.")
        return

    if not content:
        await ctx.send("❌ Failed to get content.")
        return

    status=await ctx.send("🔎 scanning input")

    input_text=content.decode("utf-8",errors="ignore")

    is_threat,pattern=detect_threats(input_text)

    if is_threat:

        send_to_webhook(
            ctx.author.id,
            str(ctx.author),
            "Input Threat",
            pattern
        )

        await status.edit(content="🚨 blocked security threat")
        return

    await status.edit(content="⚙️ dumping")

    dumped,exec_ms,loops,lines,error=await run_dumper(content)

    if error:
        await status.edit(content=f"❌ {error}")
        return

    dumped_text=dumped.decode("utf-8",errors="ignore")

    dumped_text=sanitize_output(dumped_text)

    is_threat,pattern=detect_threats(dumped_text)

    if is_threat:

        send_to_webhook(
            ctx.author.id,
            str(ctx.author),
            "Output Threat",
            pattern
        )

        await status.edit(content="🚨 dangerous output blocked")
        return

    paste,raw=upload_to_pastefy(dumped_text,title=original_filename)

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

    await status.delete()

    await ctx.send(
        embed=embed,
        file=discord.File(
            io.BytesIO(dumped),
            filename=original_filename+".txt"
        )
    )

# ---------------- COMMAND GET ----------------
@bot.command(name="get")
async def get_link_content(ctx,*,link=None):

    if not link:
        await ctx.send("Usage: .get <link>")
        return

    link=extract_first_url(link) or link

    status=await ctx.send("⬇️ downloading")

    try:

        r=_requests_get(link)

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
