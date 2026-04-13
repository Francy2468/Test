-- ============================================================
--  CatMio v1.0.0  –  Roblox Script Env-Logger & Deobfuscator
--  Sandboxes and analyses obfuscated Roblox Lua source code.
--  Logs remotes, instances, string pools, and decoded payloads.
--  Pure Lua 5.1 compatible – no C extensions required.
-- ============================================================

-- ============================================================
--  LUA 5.1 / 5.2 COMPATIBILITY SHIM
-- ============================================================
-- Provide a unified load_chunk(src, name, env) that works on
-- both Lua 5.1 (loadstring + setfenv) and Lua 5.2+ (load).
local function load_chunk(src, chunkname, sandbox_env)
    local chunk, err
    -- Lua 5.2+: load accepts a string and an env table directly
    local ok = pcall(function()
        chunk = load(src, chunkname, "t", sandbox_env)
    end)
    if ok and chunk then
        return chunk, nil
    end
    -- Lua 5.1 fallback: loadstring + setfenv
    local ls = rawget(_G, "loadstring") or load
    chunk, err = ls(src, chunkname)
    if chunk and sandbox_env and setfenv then
        setfenv(chunk, sandbox_env)
    end
    return chunk, err
end

-- ============================================================
--  SECTION 1 – CONFIGURATION
-- ============================================================
local CFG = {
    MIN_DEOBF_LENGTH         = 4,
    MAX_INLINE_STRING        = 200,
    MAX_OUTPUT_LINES         = 4000,
    INSTRUCTION_LIMIT        = 5000000,
    DUMP_DECODED_STRINGS     = true,
    DUMP_REMOTE_SUMMARY      = true,
    DUMP_INSTANCE_CREATIONS  = true,
    DUMP_SCRIPT_LOADS        = true,
    DUMP_GC_SCAN             = false,
    MAX_DEOBF_PASSES         = 8,
    OBFUSCATION_THRESHOLD    = 0.30,
    EMIT_BINARY_STRINGS      = true,
    OUTER_HEADER_BYTES       = 12288,
    MAX_SCRIPT_LOAD_SNIPPET  = 300,
    MAX_GC_SCAN_FUNCTIONS    = 200,
    MAX_UPVALUES_PER_FUNCTION= 64,
    CONSTANT_COLLECTION      = true,
    UI_PATTERN_MATCHING      = true,
    CONSTANT_FOLD            = true,
}

-- ============================================================
--  SECTION 2 – BLOCKED OUTPUT PATTERNS
-- ============================================================
local BLOCKED_OUTPUT_PATTERNS = {
    "discord%.gg/",
    "roblosecurity",
    "authorization:",
    "api%.ipify",
    "webhook%.site",
    "pastebin%.com/raw",
    "raw%.githubusercontent",
    "token%s*=%s*['\"][%w%-_%.]+['\"]",
    "password%s*=",
    "secret%s*=",
    "Bearer%s+[%w%-_%.]+",
}

local function is_blocked(line)
    local lower = string.lower(line)
    for _, pat in ipairs(BLOCKED_OUTPUT_PATTERNS) do
        if string.find(lower, pat) then
            return true
        end
    end
    return false
end

-- ============================================================
--  SECTION 3 – STATE
-- ============================================================
local state = {
    output_lines        = 0,
    string_refs         = {},   -- decoded strings found during execution
    call_graph          = {},   -- remote call records
    instance_creations  = {},   -- Instance.new() records
    script_loads        = {},   -- loadstring / require records
    deferred_hooks      = {},   -- task.defer / spawn records
    registry            = {},   -- misc key-value store
    property_store      = {},   -- instance property writes
    string_pool         = {},   -- extracted from obfuscated preamble
    obfuscation_score   = 0,
    obfuscator_name     = nil,
    gc_functions        = {},   -- functions found via getgc scan
    constants_collected = {},   -- constants from bytecode inspection
}

local function reset_state()
    state.output_lines        = 0
    state.string_refs         = {}
    state.call_graph          = {}
    state.instance_creations  = {}
    state.script_loads        = {}
    state.deferred_hooks      = {}
    state.registry            = {}
    state.property_store      = {}
    state.string_pool         = {}
    state.obfuscation_score   = 0
    state.obfuscator_name     = nil
    state.gc_functions        = {}
    state.constants_collected = {}
end

-- ============================================================
--  SECTION 4 – OUTPUT HELPERS
-- ============================================================
local output_buffer = {}

local function emit(line)
    if state.output_lines >= CFG.MAX_OUTPUT_LINES then return end
    line = tostring(line or "")
    if is_blocked(line) then
        line = "-- [CATMIO: line redacted – matched blocked pattern]"
    end
    state.output_lines = state.output_lines + 1
    output_buffer[#output_buffer + 1] = line
    print(line)
end

local function emit_blank()
    emit("")
end

local function emit_banner(title)
    emit("-- ============================================================")
    emit("--  " .. tostring(title))
    emit("-- ============================================================")
end

-- ============================================================
--  SECTION 5 – BASE64 CODEC
-- ============================================================
local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local B64_URL   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

local function make_b64_lookup(alpha)
    local t = {}
    for i = 1, #alpha do
        t[string.sub(alpha, i, i)] = i - 1
    end
    return t
end

local B64_LUT     = make_b64_lookup(B64_CHARS)
local B64_URL_LUT = make_b64_lookup(B64_URL)

local function b64_decode_inner(s, lut)
    s = string.gsub(s, "[%s=]", "")
    local out = {}
    local i = 1
    while i <= #s - 3 do
        local c0 = lut[string.sub(s, i,   i  )] or 0
        local c1 = lut[string.sub(s, i+1, i+1)] or 0
        local c2 = lut[string.sub(s, i+2, i+2)] or 0
        local c3 = lut[string.sub(s, i+3, i+3)] or 0
        local n  = c0 * 262144 + c1 * 4096 + c2 * 64 + c3
        out[#out+1] = string.char(
            math.floor(n / 65536) % 256,
            math.floor(n / 256)   % 256,
            n % 256
        )
        i = i + 4
    end
    -- handle remaining 2 or 3 chars
    local rem = #s - i + 1
    if rem == 2 then
        local c0 = lut[string.sub(s, i,   i  )] or 0
        local c1 = lut[string.sub(s, i+1, i+1)] or 0
        local n  = c0 * 4096 + c1 * 64
        out[#out+1] = string.char(math.floor(n / 65536) % 256)
    elseif rem == 3 then
        local c0 = lut[string.sub(s, i,   i  )] or 0
        local c1 = lut[string.sub(s, i+1, i+1)] or 0
        local c2 = lut[string.sub(s, i+2, i+2)] or 0
        local n  = c0 * 262144 + c1 * 4096 + c2 * 64
        out[#out+1] = string.char(
            math.floor(n / 65536) % 256,
            math.floor(n / 256)   % 256
        )
    end
    return table.concat(out)
end

local function b64_decode(s)
    local ok, result = pcall(b64_decode_inner, s, B64_LUT)
    return ok and result or nil
end

local function b64_url_decode(s)
    local ok, result = pcall(b64_decode_inner, s, B64_URL_LUT)
    return ok and result or nil
end

local function b64_encode(s)
    local out = {}
    local i   = 1
    while i <= #s - 2 do
        local b0 = string.byte(s, i)
        local b1 = string.byte(s, i+1)
        local b2 = string.byte(s, i+2)
        local n  = b0 * 65536 + b1 * 256 + b2
        out[#out+1] = string.sub(B64_CHARS, math.floor(n/262144)%64+1, math.floor(n/262144)%64+1)
                   .. string.sub(B64_CHARS, math.floor(n/4096)%64+1,   math.floor(n/4096)%64+1)
                   .. string.sub(B64_CHARS, math.floor(n/64)%64+1,     math.floor(n/64)%64+1)
                   .. string.sub(B64_CHARS, n%64+1,                    n%64+1)
        i = i + 3
    end
    local rem = #s - i + 1
    if rem == 1 then
        local b0 = string.byte(s, i)
        out[#out+1] = string.sub(B64_CHARS, math.floor(b0/4)+1,          math.floor(b0/4)+1)
                   .. string.sub(B64_CHARS, (b0 % 4)*16+1,               (b0 % 4)*16+1)
                   .. "=="
    elseif rem == 2 then
        local b0 = string.byte(s, i)
        local b1 = string.byte(s, i+1)
        local n  = b0 * 256 + b1
        out[#out+1] = string.sub(B64_CHARS, math.floor(n/1024)+1,         math.floor(n/1024)+1)
                   .. string.sub(B64_CHARS, math.floor(n/16)%64+1,        math.floor(n/16)%64+1)
                   .. string.sub(B64_CHARS, (n%16)*4+1,                   (n%16)*4+1)
                   .. "="
    end
    return table.concat(out)
end

-- ============================================================
--  SECTION 6 – MULTI-SCHEME DECODERS
-- ============================================================
local function hex_decode(s)
    s = string.gsub(s, "%s", "")
    if #s % 2 ~= 0 then return nil end
    if not string.find(s, "^[0-9A-Fa-f]+$") then return nil end
    local out = {}
    for i = 1, #s, 2 do
        out[#out+1] = string.char(tonumber(string.sub(s, i, i+1), 16))
    end
    return table.concat(out)
end

local function url_decode(s)
    local result = string.gsub(s, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    result = string.gsub(result, "%+", " ")
    return result
end

local HTML_ENTITIES = {
    ["&amp;"]  = "&",
    ["&lt;"]   = "<",
    ["&gt;"]   = ">",
    ["&quot;"] = '"',
    ["&apos;"] = "'",
    ["&nbsp;"] = " ",
}

local function html_decode(s)
    local result = string.gsub(s, "&[%a]+;", function(e)
        return HTML_ENTITIES[e] or e
    end)
    result = string.gsub(result, "&#(%d+);", function(n)
        local code = tonumber(n)
        if code and code >= 0 and code <= 127 then
            return string.char(code)
        end
        return "?"
    end)
    result = string.gsub(result, "&#x(%x+);", function(h)
        local code = tonumber(h, 16)
        if code and code >= 0 and code <= 127 then
            return string.char(code)
        end
        return "?"
    end)
    return result
end

local function rot_decode(s, n)
    n = n % 26
    local out = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        if b >= 65 and b <= 90 then
            out[#out+1] = string.char((b - 65 + n) % 26 + 65)
        elseif b >= 97 and b <= 122 then
            out[#out+1] = string.char((b - 97 + n) % 26 + 97)
        else
            out[#out+1] = string.char(b)
        end
    end
    return table.concat(out)
end

local function rot13_decode(s)
    return rot_decode(s, 13)
end

-- English bigram frequency scoring for caesar cracking
local BIGRAM_SCORES = {
    th=10, he=9, ["in"]=8, en=8, nt=7, re=7, er=7, an=7, ti=6, es=6,
    on=6, at=6, se=5, nd=5, ["or"]=5, ar=5, al=5, te=5, co=5, de=5,
}

local function score_text(s)
    local lower = string.lower(s)
    local score = 0
    for i = 1, #lower - 1 do
        local bg = string.sub(lower, i, i+1)
        score = score + (BIGRAM_SCORES[bg] or 0)
    end
    return score
end

local function caesar_crack(s)
    local best_score = -1
    local best_shift = 0
    local best_text  = s
    for shift = 1, 25 do
        local candidate = rot_decode(s, shift)
        local sc = score_text(candidate)
        if sc > best_score then
            best_score = sc
            best_shift = shift
            best_text  = candidate
        end
    end
    return best_text, best_shift
end

local function vigenere_decode(s, key)
    if not key or #key == 0 then return s end
    local key_lower = string.lower(key)
    local out       = {}
    local ki        = 1
    for i = 1, #s do
        local b = string.byte(s, i)
        if (b >= 65 and b <= 90) or (b >= 97 and b <= 122) then
            local upper  = b >= 65 and b <= 90
            local base   = upper and 65 or 97
            local kb     = string.byte(key_lower, ki) - 97
            out[#out+1]  = string.char((b - base - kb + 26) % 26 + base)
            ki = ki % #key + 1
        else
            out[#out+1] = string.char(b)
        end
    end
    return table.concat(out)
end

local function xor_byte_decode(s, key)
    key = key % 256
    local out = {}
    for i = 1, #s do
        local b  = string.byte(s, i)
        local bv = b
        local kv = key
        local acc = 0
        local bit = 1
        for _ = 1, 8 do
            local bb = bv % 2
            local kb = kv % 2
            if bb ~= kb then acc = acc + bit end
            bv = math.floor(bv / 2)
            kv = math.floor(kv / 2)
            bit = bit * 2
        end
        out[#out+1] = string.char(acc)
    end
    return table.concat(out)
end

local function xor_key_decode(s, key)
    if not key or #key == 0 then return s end
    local out = {}
    for i = 1, #s do
        local b  = string.byte(s, i)
        local kb = string.byte(key, (i - 1) % #key + 1)
        -- manual XOR
        local bv = b
        local kv = kb
        local acc = 0
        local bit = 1
        for _ = 1, 8 do
            local bb = bv % 2
            local kbb = kv % 2
            if bb ~= kbb then acc = acc + bit end
            bv = math.floor(bv / 2)
            kv = math.floor(kv / 2)
            bit = bit * 2
        end
        out[#out+1] = string.char(acc)
    end
    return table.concat(out)
end

local function bitrev_byte(b)
    local result = 0
    for _ = 1, 8 do
        result = result * 2 + b % 2
        b = math.floor(b / 2)
    end
    return result
end

local function bitrev_decode(s)
    local out = {}
    for i = 1, #s do
        out[#out+1] = string.char(bitrev_byte(string.byte(s, i)))
    end
    return table.concat(out)
end

local function byterev_decode(s)
    local out = {}
    for i = #s, 1, -1 do
        out[#out+1] = string.sub(s, i, i)
    end
    return table.concat(out)
end

local function null_strip(s)
    return (string.gsub(s, "%z", ""))
end

-- ============================================================
--  SECTION 7 – HELPER FUNCTIONS
-- ============================================================
local function is_readable(s)
    if not s or #s == 0 then return false end
    local printable = 0
    for i = 1, #s do
        local b = string.byte(s, i)
        if (b >= 32 and b <= 126) or b == 9 or b == 10 or b == 13 then
            printable = printable + 1
        end
    end
    return (printable / #s) >= 0.70
end

local function safe_literal(s)
    if not s then return "nil" end
    -- Prefer short quoted form
    local q = string.format("%q", s)
    if #q <= CFG.MAX_INLINE_STRING then
        return q
    end
    -- Use long bracket form
    local level = 0
    while string.find(s, "%]" .. string.rep("=", level) .. "%]") do
        level = level + 1
    end
    local eq = string.rep("=", level)
    return "[" .. eq .. "[" .. s .. "]" .. eq .. "]"
end

local function shannon_entropy(s)
    if not s or #s == 0 then return 0 end
    local freq = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        freq[b] = (freq[b] or 0) + 1
    end
    local n    = #s
    local entr = 0
    for _, count in pairs(freq) do
        local p = count / n
        entr = entr - p * math.log(p) / math.log(2)
    end
    return entr / 8  -- normalise to 0-1
end

local function score_obfuscation(src)
    if not src or #src == 0 then return 0 end
    local score = 0
    local len   = #src

    -- high entropy
    local entr = shannon_entropy(src)
    if entr > 0.85 then score = score + 0.25 end

    -- very long single line
    local longest = 0
    for line in string.gmatch(src .. "\n", "([^\n]*)\n") do
        if #line > longest then longest = #line end
    end
    if longest > 2000 then score = score + 0.20 end

    -- hex/base64-looking dense regions
    local hex_runs = 0
    for run in string.gmatch(src, "[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]+") do
        hex_runs = hex_runs + 1
    end
    if hex_runs > 20 then score = score + 0.10 end

    -- loadstring calls
    local ls_count = 0
    for _ in string.gmatch(src, "loadstring") do ls_count = ls_count + 1 end
    if ls_count >= 1 then score = score + 0.15 end

    -- variable name obfuscation (very short identifiers densely packed)
    local short_ids = 0
    for id in string.gmatch(src, "%f[%a_][%a_][%w_]?%f[^%w_]") do
        if #id <= 2 then short_ids = short_ids + 1 end
    end
    if short_ids > 50 then score = score + 0.15 end

    -- numeric string escapes
    local esc_count = 0
    for _ in string.gmatch(src, "\\%d%d%d") do esc_count = esc_count + 1 end
    if esc_count > 20 then score = score + 0.15 end

    return math.min(score, 1.0)
end

local function normalise_source(src)
    if not src then return "" end
    -- Strip UTF-8 BOM
    if string.sub(src, 1, 3) == "\239\187\191" then
        src = string.sub(src, 4)
    end
    -- Strip null bytes
    src = null_strip(src)
    -- Normalize line endings
    src = string.gsub(src, "\r\n", "\n")
    src = string.gsub(src, "\r",   "\n")
    return src
end

-- ============================================================
--  SECTION 8 – OBFUSCATOR FINGERPRINTS
-- ============================================================
local OBFUSCATOR_FINGERPRINTS = {
    {
        name     = "K0lrot",
        patterns = {
            "return%(function%(S,n,f,B,d,l,M,i,r,R,Z,b,t,Y,C,F,A,z,x,K,L,P,X,E%)",
        },
    },
    {
        name     = "Iron Brew",
        patterns = {
            "local%s+IronBrew",
            "IronBrew_",
            "%(function%(a0,a1,a2",
        },
    },
    {
        name     = "WeAreDevs",
        patterns = {
            "WeAreDevs",
            "_WRD_VM",
            "return%(function%(W,",
        },
    },
    {
        name     = "Luraph",
        patterns = {
            "-- Luraph Obfuscator",
            "LuraphObfuscator",
            "LURAPH_",
        },
    },
    {
        name     = "Prometheus",
        patterns = {
            "return%(%(function%(env,fenv",
            "PROMETHEUS_",
        },
    },
    {
        name     = "Lightcate v2",
        patterns = {
            "Lightcate",
            "_lc_%d+",
        },
    },
    {
        name     = "Moonsec",
        patterns = {
            "Moonsec",
            "MOONSEC",
            "MoonSec",
            "ms_strings",
        },
    },
    {
        name     = "Acrylic",
        patterns = {
            "Acrylic",
            "ACRYLIC_",
            "acrylic_vm",
        },
    },
    {
        name     = "Jelly",
        patterns = {
            "Jelly",
            "JellyObf",
            "JELLY_",
        },
    },
    {
        name     = "PSU-Crypt",
        patterns = {
            "PSU%-Crypt",
            "PSU_CRYPT",
            "psu_strings",
        },
    },
    {
        name     = "Comet",
        patterns = {
            "Comet",
            "COMET_VM",
            "comet_strings",
        },
    },
    {
        name     = "ByteObf",
        patterns = {
            "ByteObf",
            "BYTE_OBF",
            "byteobf_pool",
        },
    },
    {
        name     = "CodeLock",
        patterns = {
            "CodeLock",
            "CODELOCK_",
            "cl_decode",
        },
    },
    {
        name     = "SecureByte",
        patterns = {
            "SecureByte",
            "ByteLock",
            "SECUREBYTE_",
        },
    },
    {
        name     = "Nexus",
        patterns = {
            "NexusObf",
            "NEXUS_VM",
            "nexus_decode",
        },
    },
    {
        name     = "MicroG",
        patterns = {
            "MicroG",
            "MICROG_",
        },
    },
    {
        name     = "Villain",
        patterns = {
            "VillainObf",
            "VILLAIN_",
        },
    },
    {
        name     = "Generic-AI",
        patterns = {
            "return%(function%([%a_][%w_]+,[%a_]",
        },
    },
}

local function detect_obfuscator(src)
    if not src then return nil end
    for _, fp in ipairs(OBFUSCATOR_FINGERPRINTS) do
        for _, pat in ipairs(fp.patterns) do
            if string.find(src, pat) then
                return fp.name
            end
        end
    end
    return nil
end

-- ============================================================
--  SECTION 9 – VM BOUNDARY DETECTION
-- ============================================================
local VM_BOUNDARY_SIGS = {
    "local%s+[%a_][%w_]*%s*=%s*{%s*%d+%s*,",  -- table of numeric constants (string pool)
    "local%s+[%a_][%w_]*%s*=%s*string%.byte",
    "local%s+[%a_][%w_]*%s*=%s*loadstring%(",
    "local%s+[%a_][%w_]*%s*=%s*load%(",
    "for%s+[%a_][%w_]*%s*=%s*1%s*,#[%a_]",    -- typical VM loop
    "while%s+[%a_][%w_]*%s*<=%s*[%a_]",        -- VM dispatch while loop
    "repeat%s*local",                            -- repeat-until VM patterns
}

local function find_vm_boundary(src)
    if not src then return nil end
    local best_pos = nil
    for _, sig in ipairs(VM_BOUNDARY_SIGS) do
        local pos = string.find(src, sig)
        if pos then
            if not best_pos or pos < best_pos then
                best_pos = pos
            end
        end
    end
    return best_pos
end

-- ============================================================
--  SECTION 10 – MULTI-DECODE + XOR CRACK
-- ============================================================
local function multi_decode(s, max_passes)
    if not s or #s < CFG.MIN_DEOBF_LENGTH then return nil, nil end
    max_passes = max_passes or CFG.MAX_DEOBF_PASSES

    local schemes = {
        { name = "base64",    fn = b64_decode     },
        { name = "base64url", fn = b64_url_decode  },
        { name = "hex",       fn = hex_decode      },
        { name = "url",       fn = url_decode      },
        { name = "html",      fn = html_decode     },
        { name = "rot13",     fn = rot13_decode    },
        { name = "bitrev",    fn = bitrev_decode   },
        { name = "byterev",   fn = byterev_decode  },
        { name = "nullstrip", fn = null_strip      },
    }

    local current      = s
    local chain        = {}
    local pass         = 0

    while pass < max_passes do
        -- Stop if the current string is already human-readable
        if is_readable(current) and pass > 0 then break end
        local improved = false
        for _, scheme in ipairs(schemes) do
            local ok, decoded = pcall(scheme.fn, current)
            if ok and decoded and decoded ~= current and #decoded >= CFG.MIN_DEOBF_LENGTH then
                if is_readable(decoded) then
                    chain[#chain+1] = scheme.name
                    current  = decoded
                    improved = true
                    break
                elseif shannon_entropy(decoded) < shannon_entropy(current) - 0.05 then
                    -- Only take a non-readable result if entropy dropped meaningfully
                    chain[#chain+1] = scheme.name
                    current  = decoded
                    improved = true
                    break
                end
            end
        end
        if not improved then break end
        pass = pass + 1
    end

    if current == s then return nil, nil end
    return current, table.concat(chain, "→")
end

local function try_xor_crack(s)
    if not s or #s < CFG.MIN_DEOBF_LENGTH then return nil, nil end
    local best_score   = -1
    local best_decoded = nil
    local best_key     = nil

    for key = 1, 255 do
        local decoded = xor_byte_decode(s, key)
        if is_readable(decoded) then
            local sc = score_text(decoded)
            if sc > best_score then
                best_score   = sc
                best_decoded = decoded
                best_key     = key
            end
        end
    end

    if best_decoded then
        return best_decoded, ("xor(0x%02x)"):format(best_key)
    end
    return nil, nil
end

-- ============================================================
--  SECTION 11 – STRING POOL EXTRACTOR
-- ============================================================
local function extract_string_pool(src, pool_key)
    state.string_pool = {}
    if not src then return end

    local boundary = find_vm_boundary(src)
    local preamble = boundary and string.sub(src, 1, boundary - 1) or string.sub(src, 1, CFG.OUTER_HEADER_BYTES)

    -- Intercept sandbox will catch string table assignments
    local intercepted = {}

    local sandbox = {
        string  = string,
        table   = table,
        math    = math,
        pairs   = pairs,
        ipairs  = ipairs,
        type    = type,
        tostring= tostring,
        tonumber= tonumber,
        select  = select,
        unpack  = table.unpack or unpack,
        setmetatable = setmetatable,
        getmetatable = getmetatable,
        rawget  = rawget,
        rawset  = rawset,
        pcall   = pcall,
        xpcall  = xpcall,
        error   = error,
    }

    -- A stub to intercept "pool key" global assignment
    if pool_key then
        setmetatable(sandbox, {
            __newindex = function(t, k, v)
                rawset(t, k, v)
                if type(v) == "table" then
                    for _, item in ipairs(v) do
                        if type(item) == "string" then
                            intercepted[#intercepted+1] = item
                        end
                    end
                elseif type(v) == "string" then
                    intercepted[#intercepted+1] = v
                end
            end,
        })
    end

    -- Scan preamble for inline string literals instead (safer approach)
    for str in string.gmatch(preamble, '"([^"\\]*)"') do
        if #str >= CFG.MIN_DEOBF_LENGTH then
            intercepted[#intercepted+1] = str
        end
    end
    for str in string.gmatch(preamble, "'([^'\\]*)'") do
        if #str >= CFG.MIN_DEOBF_LENGTH then
            intercepted[#intercepted+1] = str
        end
    end
    -- Long bracket strings
    for str in string.gmatch(preamble, "%[%[(.-)%]%]") do
        if #str >= CFG.MIN_DEOBF_LENGTH then
            intercepted[#intercepted+1] = str
        end
    end

    -- Deduplicate and decode
    local seen = {}
    for _, s in ipairs(intercepted) do
        if not seen[s] then
            seen[s] = true
            local decoded, chain = multi_decode(s)
            state.string_pool[#state.string_pool+1] = {
                raw     = s,
                decoded = decoded,
                chain   = chain,
            }
        end
    end
end

-- ============================================================
--  SECTION 12 – PURE LUA BIT LIBRARY
-- ============================================================
local function bw_and(a, b)
    local result = 0
    local bit    = 1
    while a > 0 or b > 0 do
        if a % 2 == 1 and b % 2 == 1 then result = result + bit end
        a   = math.floor(a / 2)
        b   = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

local function bw_or(a, b)
    local result = 0
    local bit    = 1
    while a > 0 or b > 0 do
        if a % 2 == 1 or b % 2 == 1 then result = result + bit end
        a   = math.floor(a / 2)
        b   = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

local function bw_xor(a, b)
    local result = 0
    local bit    = 1
    while a > 0 or b > 0 do
        if a % 2 ~= b % 2 then result = result + bit end
        a   = math.floor(a / 2)
        b   = math.floor(b / 2)
        bit = bit * 2
    end
    return result
end

local MASK32 = 4294967295  -- 0xFFFFFFFF

local function bw_not(a)
    return bw_xor(a, MASK32)
end

local function bw_lshift(a, n)
    if n < 0  then return math.floor(a / (2^(-n))) end
    if n >= 32 then return 0 end
    return bw_and(a * (2^n), MASK32)
end

local function bw_rshift(a, n)
    if n < 0  then return bw_lshift(a, -n) end
    if n >= 32 then return 0 end
    return math.floor(bw_and(a, MASK32) / (2^n))
end

local function bw_rol(a, n)
    n = n % 32
    a = bw_and(a, MASK32)
    return bw_or(bw_lshift(a, n), bw_rshift(a, 32 - n))
end

local function bw_ror(a, n)
    n = n % 32
    a = bw_and(a, MASK32)
    return bw_or(bw_rshift(a, n), bw_lshift(a, 32 - n))
end

local function bw_extract(a, field, width)
    width = width or 1
    return bw_and(bw_rshift(a, field), (2^width) - 1)
end

local function bw_replace(a, v, field, width)
    width = width or 1
    local mask = bw_lshift((2^width) - 1, field)
    return bw_or(bw_and(a, bw_not(mask)), bw_lshift(bw_and(v, (2^width)-1), field))
end

local function bw_test(a, b)
    return bw_and(a, b) ~= 0
end

local function bw_countlz(a)
    if a == 0 then return 32 end
    a = bw_and(a, MASK32)
    local count = 0
    local mask  = 2147483648  -- 1 << 31
    while bw_and(a, mask) == 0 do
        count = count + 1
        mask  = math.floor(mask / 2)
    end
    return count
end

local bit_lib = {
    band    = bw_and,
    bor     = bw_or,
    bxor    = bw_xor,
    bnot    = bw_not,
    lshift  = bw_lshift,
    rshift  = bw_rshift,
    rol     = bw_rol,
    ror     = bw_ror,
    extract = bw_extract,
    replace = bw_replace,
    btest   = bw_test,
    countlz = bw_countlz,
    arshift = function(a, n)
        local sign = a >= 2147483648 and 1 or 0
        local shifted = bw_rshift(a, n)
        if sign == 1 then
            local fill = bw_lshift(MASK32, 32 - n)
            shifted = bw_or(shifted, fill)
        end
        return shifted
    end,
}

-- ============================================================
--  SECTION 13 – PROXY FACTORY
-- ============================================================
local function record_remote(rtype, name, ...)
    local args = {...}
    local arg_strs = {}
    for _, v in ipairs(args) do
        arg_strs[#arg_strs+1] = tostring(v)
    end
    local entry = {
        rtype = rtype,
        name  = name,
        args  = args,
        time  = os.clock(),
    }
    state.call_graph[#state.call_graph+1] = entry
    emit("-- [REMOTE:" .. rtype .. "] " .. tostring(name) .. "(" .. table.concat(arg_strs, ", ") .. ")")
end

local function make_proxy(class_name)
    local proxy_data = {
        _class    = class_name,
        _props    = {},
        _children = {},
        Name      = class_name,
        ClassName = class_name,
        Parent    = nil,
    }

    local function get_proxy()
        return proxy_data
    end

    local proxy = {}

    -- Record instance creation
    state.instance_creations[#state.instance_creations+1] = {
        class = class_name,
        time  = os.clock(),
    }

    local methods = {}

    methods.FindFirstChild = function(self, name, recursive)
        emit("-- [PROXY:" .. class_name .. "] FindFirstChild(" .. tostring(name) .. ")")
        for _, child in ipairs(proxy_data._children) do
            if child._props.Name == name then return child end
        end
        return nil
    end

    methods.WaitForChild = function(self, name, timeout)
        emit("-- [PROXY:" .. class_name .. "] WaitForChild(" .. tostring(name) .. ")")
        return make_proxy(name)
    end

    methods.GetChildren = function(self)
        return proxy_data._children
    end

    methods.GetDescendants = function(self)
        local desc = {}
        local function recurse(children)
            for _, child in ipairs(children) do
                desc[#desc+1] = child
                if child._props and child._props._children then
                    recurse(child._props._children)
                end
            end
        end
        recurse(proxy_data._children)
        return desc
    end

    methods.IsA = function(self, cls)
        return class_name == cls or proxy_data.ClassName == cls
    end

    methods.Destroy = function(self)
        emit("-- [PROXY:" .. class_name .. "] Destroy()")
    end

    methods.Clone = function(self)
        return make_proxy(class_name)
    end

    methods.GetFullName = function(self)
        return "game." .. class_name
    end

    methods.GetAttribute = function(self, attr)
        return proxy_data._props[attr]
    end

    methods.SetAttribute = function(self, attr, value)
        proxy_data._props[attr] = value
    end

    methods.GetPropertyChangedSignal = function(self, prop)
        return {
            Connect = function(self2, fn)
                emit("-- [PROXY:" .. class_name .. "] GetPropertyChangedSignal(" .. tostring(prop) .. "):Connect")
                return { Disconnect = function() end }
            end,
        }
    end

    -- Changed signal
    proxy_data.Changed = {
        Connect = function(self2, fn)
            emit("-- [PROXY:" .. class_name .. "] Changed:Connect")
            return { Disconnect = function() end }
        end,
    }

    -- Remote-specific
    methods.FireServer = function(self, ...)
        record_remote("FireServer", class_name, ...)
    end

    methods.InvokeServer = function(self, ...)
        record_remote("InvokeServer", class_name, ...)
        return nil
    end

    methods.FireClient = function(self, player, ...)
        record_remote("FireClient", class_name, ...)
    end

    methods.FireAllClients = function(self, ...)
        record_remote("FireAllClients", class_name, ...)
    end

    proxy_data.OnClientEvent = {
        Connect = function(self2, fn)
            emit("-- [PROXY:" .. class_name .. "] OnClientEvent:Connect")
            return { Disconnect = function() end }
        end,
        Wait = function(self2)
            return nil
        end,
    }

    proxy_data.OnServerEvent = {
        Connect = function(self2, fn)
            emit("-- [PROXY:" .. class_name .. "] OnServerEvent:Connect")
            return { Disconnect = function() end }
        end,
    }

    proxy_data.OnInvoke = nil

    -- DataStore stubs
    methods.GetAsync = function(self, key)
        emit("-- [DATASTORE:" .. class_name .. "] GetAsync(" .. tostring(key) .. ")")
        return nil
    end

    methods.SetAsync = function(self, key, value)
        emit("-- [DATASTORE:" .. class_name .. "] SetAsync(" .. tostring(key) .. ", " .. tostring(value) .. ")")
    end

    methods.UpdateAsync = function(self, key, fn)
        emit("-- [DATASTORE:" .. class_name .. "] UpdateAsync(" .. tostring(key) .. ")")
        return nil
    end

    methods.RemoveAsync = function(self, key)
        emit("-- [DATASTORE:" .. class_name .. "] RemoveAsync(" .. tostring(key) .. ")")
    end

    methods.IncrementAsync = function(self, key, delta)
        emit("-- [DATASTORE:" .. class_name .. "] IncrementAsync(" .. tostring(key) .. ")")
        return 0
    end

    -- RunService signals
    proxy_data.Heartbeat = {
        Connect = function(self2, fn)
            emit("-- [RUNSERVICE] Heartbeat:Connect")
            return { Disconnect = function() end }
        end,
        Wait = function(self2) return 1/60 end,
    }
    proxy_data.RenderStepped = {
        Connect = function(self2, fn)
            emit("-- [RUNSERVICE] RenderStepped:Connect")
            return { Disconnect = function() end }
        end,
        Wait = function(self2) return 1/60 end,
    }
    proxy_data.Stepped = {
        Connect = function(self2, fn)
            emit("-- [RUNSERVICE] Stepped:Connect")
            return { Disconnect = function() end }
        end,
        Wait = function(self2) return 1/60 end,
    }

    -- AncestryChanged
    proxy_data.AncestryChanged = {
        Connect = function(self2, fn)
            return { Disconnect = function() end }
        end,
    }

    -- ChildAdded / ChildRemoved
    proxy_data.ChildAdded = {
        Connect = function(self2, fn)
            return { Disconnect = function() end }
        end,
    }
    proxy_data.ChildRemoved = {
        Connect = function(self2, fn)
            return { Disconnect = function() end }
        end,
    }

    methods.Connect = function(self, fn)
        return { Disconnect = function() end }
    end

    methods.Wait = function(self)
        return nil
    end

    setmetatable(proxy, {
        __index = function(t, k)
            if methods[k] then return methods[k] end
            if proxy_data[k] ~= nil then return proxy_data[k] end
            if proxy_data._props[k] ~= nil then return proxy_data._props[k] end
            -- Return a child proxy for unknown keys
            local child = make_proxy(tostring(k))
            proxy_data._children[#proxy_data._children+1] = child
            return child
        end,
        __newindex = function(t, k, v)
            state.property_store[class_name .. "." .. k] = v
            proxy_data._props[k] = v
        end,
        __tostring = function(t)
            return class_name
        end,
        __call = function(t, ...)
            emit("-- [PROXY:" .. class_name .. "] called as function")
            return make_proxy(class_name)
        end,
    })

    return proxy
end

-- ============================================================
--  SECTION 14 – SINGLETON PROXIES
-- ============================================================
local game_proxy      = make_proxy("DataModel")
local workspace_proxy = make_proxy("Workspace")
local script_proxy    = make_proxy("Script")

-- Override specific game services
local service_cache = {}
local function get_service(name)
    if not service_cache[name] then
        service_cache[name] = make_proxy(name)
    end
    return service_cache[name]
end

-- game:GetService()
local game_mt = getmetatable(game_proxy)
local orig_game_index = game_mt.__index
game_mt.__index = function(t, k)
    if k == "GetService" then
        return function(self, name)
            emit("-- [GAME] GetService(" .. tostring(name) .. ")")
            return get_service(name)
        end
    end
    if k == "Players"        then return get_service("Players")        end
    if k == "Workspace"      then return workspace_proxy               end
    if k == "workspace"      then return workspace_proxy               end
    if k == "ReplicatedStorage" then return get_service("ReplicatedStorage") end
    if k == "ServerStorage"  then return get_service("ServerStorage")  end
    if k == "StarterGui"     then return get_service("StarterGui")     end
    if k == "StarterPack"    then return get_service("StarterPack")    end
    if k == "Lighting"       then return get_service("Lighting")       end
    if k == "RunService"     then return get_service("RunService")     end
    if k == "HttpService"    then return get_service("HttpService")    end
    if k == "TweenService"   then return get_service("TweenService")   end
    if k == "DataStoreService" then return get_service("DataStoreService") end
    if k == "UserInputService" then return get_service("UserInputService") end
    if k == "ContentProvider" then return get_service("ContentProvider") end
    if k == "SoundService"   then return get_service("SoundService")   end
    if k == "MarketplaceService" then return get_service("MarketplaceService") end
    if k == "PlaceId"        then return 0 end
    if k == "JobId"          then return "catmio-sandbox" end
    if k == "CreatorId"      then return 0 end
    if k == "CreatorType"    then return "User" end
    return orig_game_index(t, k)
end

-- ============================================================
--  SECTION 15 – ROBLOX TYPE CONSTRUCTORS
-- ============================================================
local function make_Vector3(x, y, z)
    x, y, z = x or 0, y or 0, z or 0
    local v = {X=x, Y=y, Z=z, x=x, y=y, z=z}
    local mt = {
        __tostring = function() return ("(%g, %g, %g)"):format(x, y, z) end,
        __add = function(a, b) return make_Vector3(a.X+b.X, a.Y+b.Y, a.Z+b.Z) end,
        __sub = function(a, b) return make_Vector3(a.X-b.X, a.Y-b.Y, a.Z-b.Z) end,
        __mul = function(a, b)
            if type(a) == "number" then return make_Vector3(a*b.X, a*b.Y, a*b.Z) end
            if type(b) == "number" then return make_Vector3(a.X*b, a.Y*b, a.Z*b) end
            return make_Vector3(a.X*b.X, a.Y*b.Y, a.Z*b.Z)
        end,
        __unm = function(a) return make_Vector3(-a.X, -a.Y, -a.Z) end,
        __eq  = function(a, b) return a.X==b.X and a.Y==b.Y and a.Z==b.Z end,
        __index = function(t, k)
            if k == "Magnitude" then return math.sqrt(x*x + y*y + z*z) end
            if k == "Unit" then
                local mag = math.sqrt(x*x + y*y + z*z)
                if mag == 0 then return make_Vector3(0,0,0) end
                return make_Vector3(x/mag, y/mag, z/mag)
            end
            if k == "Dot" then return function(self, other) return x*other.X + y*other.Y + z*other.Z end end
            if k == "Cross" then return function(self, other)
                return make_Vector3(y*other.Z - z*other.Y, z*other.X - x*other.Z, x*other.Y - y*other.X)
            end end
            if k == "Lerp" then return function(self, other, t) return make_Vector3(x+(other.X-x)*t, y+(other.Y-y)*t, z+(other.Z-z)*t) end end
            return rawget(t, k)
        end,
    }
    return setmetatable(v, mt)
end

local Vector3 = {
    new = make_Vector3,
    zero = make_Vector3(0, 0, 0),
    one  = make_Vector3(1, 1, 1),
    xAxis = make_Vector3(1, 0, 0),
    yAxis = make_Vector3(0, 1, 0),
    zAxis = make_Vector3(0, 0, 1),
    fromNormalId = function(id) return make_Vector3(0, 1, 0) end,
    fromAxis    = function(ax)  return make_Vector3(0, 1, 0) end,
}

local function make_Vector2(x, y)
    x, y = x or 0, y or 0
    local v = {X=x, Y=y, x=x, y=y}
    return setmetatable(v, {
        __tostring = function() return ("(%g, %g)"):format(x, y) end,
        __add = function(a, b) return make_Vector2(a.X+b.X, a.Y+b.Y) end,
        __sub = function(a, b) return make_Vector2(a.X-b.X, a.Y-b.Y) end,
        __mul = function(a, b)
            if type(b) == "number" then return make_Vector2(a.X*b, a.Y*b) end
            return make_Vector2(a.X*b.X, a.Y*b.Y)
        end,
        __index = function(t, k)
            if k == "Magnitude" then return math.sqrt(x*x + y*y) end
            if k == "Unit" then
                local m = math.sqrt(x*x + y*y)
                if m == 0 then return make_Vector2(0, 0) end
                return make_Vector2(x/m, y/m)
            end
            return rawget(t, k)
        end,
    })
end

local Vector2 = { new = make_Vector2, zero = make_Vector2(0,0), one = make_Vector2(1,1) }

local function make_CFrame(x, y, z, r00, r01, r02, r10, r11, r12, r20, r21, r22)
    x, y, z = x or 0, y or 0, z or 0
    r00, r01, r02 = r00 or 1, r01 or 0, r02 or 0
    r10, r11, r12 = r10 or 0, r11 or 1, r12 or 0
    r20, r21, r22 = r20 or 0, r21 or 0, r22 or 1
    local cf = {
        X=x, Y=y, Z=z, x=x, y=y, z=z,
        Position = make_Vector3(x, y, z),
    }
    return setmetatable(cf, {
        __tostring = function() return ("CFrame(%g, %g, %g)"):format(x, y, z) end,
        __mul = function(a, b)
            if type(b) == "table" and b.X and b.Y and b.Z then
                return make_Vector3(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
            end
            return make_CFrame(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
        end,
        __index = function(t, k)
            if k == "p"         then return make_Vector3(x, y, z) end
            if k == "LookVector"then return make_Vector3(-r02, -r12, -r22) end
            if k == "RightVector" then return make_Vector3(r00, r10, r20) end
            if k == "UpVector"  then return make_Vector3(r01, r11, r21) end
            if k == "Inverse"   then return function(self) return make_CFrame(-x,-y,-z) end end
            if k == "Lerp"      then return function(self, other, t) return make_CFrame(x+(other.X-x)*t, y+(other.Y-y)*t, z+(other.Z-z)*t) end end
            if k == "ToEulerAnglesXYZ" then return function(self) return 0, 0, 0 end end
            if k == "GetComponents" then return function(self) return x,y,z,r00,r01,r02,r10,r11,r12,r20,r21,r22 end end
            return rawget(t, k)
        end,
    })
end

local CFrame = {
    new           = make_CFrame,
    identity      = make_CFrame(),
    fromEulerAnglesXYZ = function(rx, ry, rz) return make_CFrame(0,0,0) end,
    fromEulerAnglesYXZ = function(rx, ry, rz) return make_CFrame(0,0,0) end,
    Angles        = function(rx, ry, rz) return make_CFrame(0,0,0) end,
    lookAt        = function(from, at, up) return make_CFrame(from.X, from.Y, from.Z) end,
    fromMatrix     = function(pos, rx, ry, rz) return make_CFrame(pos.X, pos.Y, pos.Z) end,
}

local function make_Color3(r, g, b)
    r, g, b = r or 0, g or 0, b or 0
    local c = {R=r, G=g, B=b, r=r, g=g, b=b}
    return setmetatable(c, {
        __tostring = function() return ("Color3(%g, %g, %g)"):format(r, g, b) end,
        __index = function(t, k)
            if k == "Lerp" then return function(self, other, t2) return make_Color3(r+(other.R-r)*t2, g+(other.G-g)*t2, b+(other.B-b)*t2) end end
            if k == "ToHSV" then return function(self)
                local maxc = math.max(r,g,b); local minc = math.min(r,g,b)
                return 0, maxc == 0 and 0 or 1 - minc/maxc, maxc
            end end
            return rawget(t, k)
        end,
    })
end

local Color3 = {
    new         = make_Color3,
    fromRGB     = function(r, g, b) return make_Color3(r/255, g/255, b/255) end,
    fromHSV     = function(h, s, v) return make_Color3(v, v, v) end,
    fromHex     = function(hex) hex = hex:gsub("^#", ""); return make_Color3(tonumber(hex:sub(1,2),16)/255, tonumber(hex:sub(3,4),16)/255, tonumber(hex:sub(5,6),16)/255) end,
}

local function make_UDim(scale, offset)
    local u = {Scale=scale or 0, Offset=offset or 0}
    return setmetatable(u, {__tostring = function() return ("UDim(%g, %d)"):format(u.Scale, u.Offset) end})
end

local function make_UDim2(xs, xo, ys, yo)
    local u = {
        X = make_UDim(xs, xo), Y = make_UDim(ys, yo),
        Width = make_UDim(xs, xo), Height = make_UDim(ys, yo),
    }
    return setmetatable(u, {
        __tostring = function() return ("UDim2(%g,%d,%g,%d)"):format(xs or 0, xo or 0, ys or 0, yo or 0) end,
        __add = function(a, b) return make_UDim2(a.X.Scale+b.X.Scale, a.X.Offset+b.X.Offset, a.Y.Scale+b.Y.Scale, a.Y.Offset+b.Y.Offset) end,
        __sub = function(a, b) return make_UDim2(a.X.Scale-b.X.Scale, a.X.Offset-b.X.Offset, a.Y.Scale-b.Y.Scale, a.Y.Offset-b.Y.Offset) end,
        __index = function(t, k)
            if k == "Lerp" then return function(self, other, t2) return make_UDim2(
                u.X.Scale+(other.X.Scale-u.X.Scale)*t2, u.X.Offset+(other.X.Offset-u.X.Offset)*t2,
                u.Y.Scale+(other.Y.Scale-u.Y.Scale)*t2, u.Y.Offset+(other.Y.Offset-u.Y.Offset)*t2
            ) end end
            return rawget(t, k)
        end,
    })
end

local UDim2 = {
    new        = make_UDim2,
    fromScale  = function(x, y) return make_UDim2(x, 0, y, 0) end,
    fromOffset = function(x, y) return make_UDim2(0, x, 0, y) end,
}

local UDim = { new = make_UDim }

local function make_Rect(x0, y0, x1, y1)
    if type(x0) == "table" then
        -- Two Vector2 arguments: make_Rect(min_vec2, max_vec2)
        local min_v = x0
        local max_v = y0
        x0, y0 = min_v.X, min_v.Y
        x1, y1 = max_v.X, max_v.Y
    end
    local r = {
        Min    = make_Vector2(x0 or 0, y0 or 0),
        Max    = make_Vector2(x1 or 0, y1 or 0),
        Width  = (x1 or 0) - (x0 or 0),
        Height = (y1 or 0) - (y0 or 0),
    }
    return setmetatable(r, {__tostring = function() return ("Rect(%g,%g,%g,%g)"):format(x0,y0,x1,y1) end})
end

local Rect = { new = make_Rect }

local function make_NumberRange(min, max)
    max = max or min
    local nr = {Min=min, Max=max}
    return setmetatable(nr, {__tostring = function() return ("NumberRange(%g, %g)"):format(min, max) end})
end

local NumberRange = { new = make_NumberRange }

local function make_TweenInfo(time, easing_style, easing_direction, repeat_count, reverses, delay_time)
    local ti = {
        Time            = time or 1,
        EasingStyle     = easing_style,
        EasingDirection = easing_direction,
        RepeatCount     = repeat_count or 0,
        Reverses        = reverses or false,
        DelayTime       = delay_time or 0,
    }
    return setmetatable(ti, {__tostring = function() return "TweenInfo" end})
end

local TweenInfo = { new = make_TweenInfo }

local function make_BrickColor(val)
    local bc = {Name = tostring(val), Number = 0, Color = make_Color3(0.5, 0.5, 0.5)}
    return setmetatable(bc, {__tostring = function() return tostring(val) end})
end

local BrickColor = {
    new     = make_BrickColor,
    random  = function() return make_BrickColor("Medium stone grey") end,
    White   = make_BrickColor("White"),
    Black   = make_BrickColor("Black"),
    Red     = make_BrickColor("Bright red"),
    Yellow  = make_BrickColor("Bright yellow"),
    Blue    = make_BrickColor("Bright blue"),
    Green   = make_BrickColor("Bright green"),
}

local function make_DateTime(unix)
    unix = unix or os.time()
    local dt = {UnixTimestamp = unix, UnixTimestampMillis = unix * 1000}
    return setmetatable(dt, {
        __index = function(t, k)
            if k == "FormatUniversalTime" then return function(self, fmt, tz) return tostring(unix) end end
            if k == "FormatLocalTime"     then return function(self, fmt, tz) return tostring(unix) end end
            if k == "ToIsoDate"           then return function(self) return "1970-01-01T00:00:00Z" end end
            if k == "ToUniversalTime"     then return function(self) return {Year=1970,Month=1,Day=1,Hour=0,Minute=0,Second=0,Millisecond=0} end end
            return rawget(t, k)
        end,
    })
end

local DateTime = {
    now          = function() return make_DateTime(os.time()) end,
    fromUnixTimestamp = function(unix) return make_DateTime(unix) end,
    fromUnixTimestampMillis = function(ms) return make_DateTime(math.floor(ms/1000)) end,
    fromIsoDate  = function(s) return make_DateTime(0) end,
    fromLocalTime = function(t) return make_DateTime(0) end,
    fromUniversalTime = function(t) return make_DateTime(0) end,
}

local function make_Random(seed)
    local rng_state = seed or os.time()
    local function lcg()
        rng_state = (rng_state * 1664525 + 1013904223) % 4294967296
        return rng_state
    end
    local r = {}
    r.NextNumber  = function(self, lo, hi)
        local n = lcg() / 4294967296
        if lo and hi then return lo + n * (hi - lo) end
        return n
    end
    r.NextInteger = function(self, lo, hi)
        return lo + lcg() % (hi - lo + 1)
    end
    r.NextUnitVector = function(self) return make_Vector3(0,1,0) end
    r.Clone = function(self) return make_Random(rng_state) end
    return setmetatable(r, {__tostring = function() return "Random" end})
end

local Random = { new = make_Random }

-- Enum stub
local EnumMeta = {
    __index = function(t, k)
        local sub = {}
        return setmetatable(sub, {
            __index = function(t2, k2)
                return {Name=k2, Value=0, EnumType=k}
            end,
            __tostring = function() return "Enum." .. k end,
        })
    end,
    __tostring = function() return "Enum" end,
}
local Enum = setmetatable({}, EnumMeta)

local function make_Font(family, weight, style)
    return {Family=family or "rbxasset://fonts/families/SourceSansPro.json", Weight=weight, Style=style}
end

local Font = {
    new         = make_Font,
    fromEnum    = function(e) return make_Font() end,
    fromName    = function(name, weight, style) return make_Font(name, weight, style) end,
}

local function make_NumberSequenceKeypoint(time, value, envelope)
    return {Time=time, Value=value, Envelope=envelope or 0}
end

local function make_NumberSequence(...)
    local args = {...}
    if type(args[1]) == "number" and #args == 1 then
        return {Keypoints = {make_NumberSequenceKeypoint(0, args[1]), make_NumberSequenceKeypoint(1, args[1])}}
    end
    if type(args[1]) == "number" and #args == 2 then
        return {Keypoints = {make_NumberSequenceKeypoint(0, args[1]), make_NumberSequenceKeypoint(1, args[2])}}
    end
    return {Keypoints = type(args[1]) == "table" and args[1] or args}
end

local NumberSequenceKeypoint = { new = make_NumberSequenceKeypoint }
local NumberSequence         = { new = make_NumberSequence }

local function make_ColorSequenceKeypoint(time, color)
    return {Time=time, Value=color}
end

local function make_ColorSequence(...)
    local args = {...}
    if #args == 1 and type(args[1]) == "table" and args[1].R then
        return {Keypoints = {make_ColorSequenceKeypoint(0, args[1]), make_ColorSequenceKeypoint(1, args[1])}}
    end
    return {Keypoints = type(args[1]) == "table" and args[1] or args}
end

local ColorSequenceKeypoint = { new = make_ColorSequenceKeypoint }
local ColorSequence         = { new = make_ColorSequence }

local function make_PhysicalProperties(density, friction, elasticity, frictionWeight, elasticityWeight)
    return {Density=density or 0.7, Friction=friction or 0.3, Elasticity=elasticity or 0.5, FrictionWeight=frictionWeight or 1, ElasticityWeight=elasticityWeight or 1}
end

local PhysicalProperties = { new = make_PhysicalProperties }

local function make_Ray(origin, direction)
    return {Origin=origin or make_Vector3(), Direction=direction or make_Vector3()}
end

local Ray = { new = make_Ray }

local function make_Axes(...)
    return {Top=false, Bottom=false, Left=false, Right=false, Front=false, Back=false}
end

local Axes = { new = make_Axes }

local function make_Faces(...)
    return {Top=false, Bottom=false, Left=false, Right=false, Front=false, Back=false}
end

local Faces = { new = make_Faces }

-- ============================================================
--  SECTION 16 – EXECUTOR STUBS
-- ============================================================
local executor_stubs = {}

executor_stubs.identifyexecutor  = function() return "CatMio", "1.0.0" end
executor_stubs.getexecutorname   = function() return "CatMio" end
executor_stubs.newcclosure       = function(f) return f end
executor_stubs.iscclosure        = function(f) return false end
executor_stubs.checkcaller       = function() return false end

executor_stubs.hookfunction      = function(orig, hook)
    emit("-- [EXEC] hookfunction called")
    return orig
end

executor_stubs.hookmetamethod    = function(obj, name, hook)
    emit("-- [EXEC] hookmetamethod(" .. tostring(name) .. ")")
    local mt = getmetatable(obj)
    if mt and mt[name] then
        local orig = mt[name]
        mt[name] = hook
        return orig
    end
    return function() end
end

executor_stubs.getgenv = function()
    return _G
end

executor_stubs.getrenv = function()
    return _G
end

executor_stubs.getsenv = function(scr)
    return {}
end

executor_stubs.getfenv = function(fn)
    if fn == 0 then return _G end
    if type(fn) == "function" then return _G end
    return _G
end

executor_stubs.setfenv = function(fn, env)
    -- no-op in sandbox
end

executor_stubs.getreg = function()
    return debug and debug.getregistry and debug.getregistry() or {}
end

executor_stubs.getgc = function(include_tables)
    emit("-- [EXEC] getgc() – returning stub list")
    return state.gc_functions
end

executor_stubs.getupvalues = function(fn)
    local upvals = {}
    if type(fn) ~= "function" then return upvals end
    local i = 1
    while true do
        local ok, name, val = pcall(debug.getupvalue, fn, i)
        if not ok or not name then break end
        upvals[i] = val
        i = i + 1
        if i > CFG.MAX_UPVALUES_PER_FUNCTION then break end
    end
    return upvals
end

executor_stubs.getupvalue = function(fn, idx)
    if type(fn) ~= "function" then return nil end
    local ok, name, val = pcall(debug.getupvalue, fn, idx)
    return ok and val or nil
end

executor_stubs.setupvalue = function(fn, idx, val)
    if type(fn) ~= "function" then return end
    pcall(debug.setupvalue, fn, idx, val)
end

executor_stubs.getconstants = function(fn)
    emit("-- [EXEC] getconstants() – stub")
    return {}
end

executor_stubs.getconstant = function(fn, idx)
    return nil
end

executor_stubs.setconstant = function(fn, idx, val)
    emit("-- [EXEC] setconstant(" .. tostring(idx) .. ")")
end

executor_stubs.getprotos = function(fn)
    return {}
end

executor_stubs.getproto = function(fn, idx, activated)
    return nil
end

executor_stubs.getscriptclosure = function(scr)
    return function() end
end

executor_stubs.decompile = function(scr)
    emit("-- [EXEC] decompile() – stub")
    return "-- decompile stub"
end

executor_stubs.getrawmetatable = function(obj)
    return getmetatable(obj)
end

executor_stubs.setrawmetatable = function(obj, mt)
    -- no-op in sandbox
end

executor_stubs.setreadonly = function(tbl, ro)
    -- no-op in sandbox
end

executor_stubs.isreadonly = function(tbl)
    return false
end

executor_stubs.mousemoveabs = function(x, y)
    emit("-- [EXEC] mousemoveabs(" .. tostring(x) .. "," .. tostring(y) .. ")")
end

executor_stubs.mousemoverel = function(dx, dy)
    emit("-- [EXEC] mousemoverel(" .. tostring(dx) .. "," .. tostring(dy) .. ")")
end

executor_stubs.keypress = function(keycode)
    emit("-- [EXEC] keypress(" .. tostring(keycode) .. ")")
end

executor_stubs.keyrelease = function(keycode)
    emit("-- [EXEC] keyrelease(" .. tostring(keycode) .. ")")
end

executor_stubs.toclipboard = function(text)
    emit("-- [EXEC] toclipboard(" .. tostring(text) .. ")")
end

executor_stubs.setclipboard = executor_stubs.toclipboard

executor_stubs.getclipboard = function()
    return ""
end

executor_stubs.consoleclear = function()
    emit("-- [EXEC] consoleclear()")
end

executor_stubs.consoleprint = function(...)
    local args = {...}
    local parts = {}
    for _, v in ipairs(args) do parts[#parts+1] = tostring(v) end
    emit("-- [CONSOLE] " .. table.concat(parts, "\t"))
end

executor_stubs.request = function(options)
    emit("-- [HTTP] request(" .. tostring(options and options.Url or "?") .. ")")
    return { StatusCode=200, Body="", Headers={}, Success=true }
end

executor_stubs.httpget = function(url, sync, headers)
    emit("-- [HTTP] httpget(" .. tostring(url) .. ")")
    return ""
end

executor_stubs.httppost = function(url, data, content_type, compress, headers)
    emit("-- [HTTP] httppost(" .. tostring(url) .. ")")
    return ""
end

executor_stubs.http_request = executor_stubs.request

executor_stubs.queue_on_teleport = function(src)
    emit("-- [EXEC] queue_on_teleport()")
    state.script_loads[#state.script_loads+1] = {source=string.sub(src or "", 1, CFG.MAX_SCRIPT_LOAD_SNIPPET), kind="queue_on_teleport"}
end

-- Drawing stub
executor_stubs.Drawing = setmetatable({}, {
    __index = function(t, k)
        return function(...) return make_proxy("Drawing." .. k) end
    end,
    __call  = function(t, class)
        return make_proxy("Drawing." .. tostring(class))
    end,
})
executor_stubs.Drawing.new = function(class)
    return make_proxy("Drawing." .. tostring(class))
end
executor_stubs.Drawing.Fonts = {UI=0, System=1, Plex=2, Monospace=3}

-- WebSocket stub
executor_stubs.WebSocket = {
    connect = function(url)
        emit("-- [WEBSOCKET] connect(" .. tostring(url) .. ")")
        local ws = {}
        ws.Send = function(self, msg) emit("-- [WS:SEND] " .. tostring(msg)) end
        ws.Close = function(self) emit("-- [WS:CLOSE]") end
        ws.OnMessage = {Connect = function(self, fn) return {Disconnect=function()end} end}
        ws.OnClose   = {Connect = function(self, fn) return {Disconnect=function()end} end}
        return ws
    end,
}

-- crypt stub
local function fnv1a_hash(s)
    local hash = 2166136261
    for i = 1, #s do
        hash = bw_xor(hash, string.byte(s, i))
        hash = bw_and(hash * 16777619, MASK32)
    end
    return hash
end

executor_stubs.crypt = {
    base64encode  = b64_encode,
    base64decode  = b64_decode,
    base64_encode = b64_encode,
    base64_decode = b64_decode,
    encrypt       = function(data, key, iv) return data end,
    decrypt       = function(data, key, iv) return data end,
    hash          = function(data, algo)
        local h = fnv1a_hash(tostring(data))
        return string.format("%08x", h)
    end,
    generatekey   = function() return string.rep("a", 32) end,
    generatebytes = function(n) return string.rep("\0", n or 16) end,
    random        = function(n) return string.rep("\0", n or 16) end,
}

executor_stubs.base64encode = b64_encode
executor_stubs.base64decode = b64_decode

executor_stubs.bit   = bit_lib
executor_stubs.bit32 = {
    band   = bw_and,
    bor    = bw_or,
    bxor   = bw_xor,
    bnot   = bw_not,
    lshift = bw_lshift,
    rshift = bw_rshift,
    arshift = bit_lib.arshift,
    btest  = bw_test,
    extract = bw_extract,
    replace = bw_replace,
    countlz = bw_countlz,
}

-- ============================================================
--  SECTION 17 – TASK LIBRARY
-- ============================================================
local unpack_fn = table.unpack or unpack

local task_lib = {
    spawn = function(fn, ...)
        local args = {...}
        state.deferred_hooks[#state.deferred_hooks+1] = {kind="spawn", fn=fn}
        local ok, err = pcall(fn, unpack_fn(args))
        if not ok then
            emit("-- [TASK:spawn] error: " .. tostring(err))
        end
    end,
    defer = function(fn, ...)
        local args = {...}
        state.deferred_hooks[#state.deferred_hooks+1] = {kind="defer", fn=fn}
        local ok, err = pcall(fn, unpack_fn(args))
        if not ok then
            emit("-- [TASK:defer] error: " .. tostring(err))
        end
    end,
    delay = function(secs, fn, ...)
        local args = {...}
        state.deferred_hooks[#state.deferred_hooks+1] = {kind="delay", secs=secs, fn=fn}
        emit("-- [TASK:delay] " .. tostring(secs) .. "s deferred call registered")
    end,
    wait = function(n)
        return n or 0
    end,
    cancel = function(thread)
        emit("-- [TASK:cancel]")
    end,
}

-- ============================================================
--  SECTION 18 – CRYPT LIBRARY
-- ============================================================
local crypt_lib = {
    base64encode  = b64_encode,
    base64decode  = b64_decode,
    encrypt       = function(data, key, iv)
        emit("-- [CRYPT] encrypt called")
        return data
    end,
    decrypt       = function(data, key, iv)
        emit("-- [CRYPT] decrypt called")
        return data
    end,
    hash          = function(data, algo)
        local h = fnv1a_hash(tostring(data))
        return string.format("%08x", h)
    end,
    generatekey   = function()
        return string.rep("catmio", 5)
    end,
    generatebytes = function(n)
        return string.rep("\0", n or 16)
    end,
}

-- ============================================================
--  SECTION 19 – ENVIRONMENT BUILDER
-- ============================================================
local function build_env()
    local env = {}

    -- Standard globals
    env.print          = function(...) local args={...}; local p={}; for _,v in ipairs(args) do p[#p+1]=tostring(v) end; emit("-- [PRINT] "..table.concat(p,"\t")) end
    env.warn           = function(...) local args={...}; local p={}; for _,v in ipairs(args) do p[#p+1]=tostring(v) end; emit("-- [WARN] "..table.concat(p,"\t")) end
    env.error          = function(msg, level) error(tostring(msg), (level or 1)+1) end
    env.assert         = assert
    env.type           = type
    env.tostring       = tostring
    env.tonumber       = tonumber
    env.pairs          = pairs
    env.ipairs         = ipairs
    env.next           = next
    env.select         = select
    env.rawget         = rawget
    env.rawset         = rawset
    env.rawequal       = rawequal
    env.rawlen         = rawlen
    env.setmetatable   = setmetatable
    env.getmetatable   = getmetatable
    env.unpack         = table.unpack or unpack
    env.pcall          = pcall
    env.xpcall         = xpcall
    env.require        = function(mod)
        emit("-- [REQUIRE] " .. tostring(mod))
        state.script_loads[#state.script_loads+1] = {source=tostring(mod), kind="require"}
        return make_proxy(tostring(mod))
    end

    env.loadstring = function(src, chunkname)
        state.script_loads[#state.script_loads+1] = {
            source = string.sub(tostring(src), 1, CFG.MAX_SCRIPT_LOAD_SNIPPET),
            kind   = "loadstring",
        }
        emit("-- [LOADSTRING] chunk loaded: " .. string.sub(tostring(src), 1, 60) .. "…")
        local chunk, err = load_chunk(src, chunkname, env)
        if not chunk then
            emit("-- [LOADSTRING] compile error: " .. tostring(err))
        end
        return chunk, err
    end

    env.load = function(src, chunkname, mode, load_env)
        if type(src) == "string" then
            state.script_loads[#state.script_loads+1] = {
                source = string.sub(src, 1, CFG.MAX_SCRIPT_LOAD_SNIPPET),
                kind   = "load",
            }
            emit("-- [LOAD] chunk: " .. string.sub(src, 1, 60))
        end
        return load_chunk(type(src) == "string" and src or "", chunkname, load_env or env)
    end

    env.collectgarbage = function(opt) return 0 end
    env.dofile         = function(f) emit("-- [DOFILE] " .. tostring(f)); return nil end

    -- Standard libraries
    env.math     = math
    env.string   = string
    env.table    = table
    env.coroutine = coroutine

    -- Limited os
    env.os = {
        clock  = os.clock,
        time   = os.time,
        date   = function(fmt, t) return os.date and os.date(fmt, t) or "" end,
        difftime = function(a, b) return a - b end,
    }

    -- utf8
    env.utf8 = utf8 or {
        char      = function(...) return "" end,
        len       = function(s) return #s end,
        offset    = function(s, n, i) return i or 1 end,
        codepoint = function(s, i, j) return string.byte(s, i or 1) end,
        codes     = function(s)
            local i = 0
            return function()
                i = i + 1
                if i > #s then return nil end
                return i, string.byte(s, i)
            end
        end,
        charpattern = "[\0-\x7F\xC2-\xFD][\x80-\xBF]*",
    }

    -- io stub
    env.io = {
        write = function(...) local args={...}; for _,v in ipairs(args) do emit("-- [IO:write] "..tostring(v)) end end,
        read  = function() return nil end,
    }

    -- Roblox type constructors
    env.Vector3              = Vector3
    env.Vector2              = Vector2
    env.CFrame               = CFrame
    env.Color3               = Color3
    env.UDim2                = UDim2
    env.UDim                 = UDim
    env.Rect                 = Rect
    env.NumberRange          = NumberRange
    env.TweenInfo            = TweenInfo
    env.BrickColor           = BrickColor
    env.DateTime             = DateTime
    env.Random               = Random
    env.Enum                 = Enum
    env.Font                 = Font
    env.NumberSequence       = NumberSequence
    env.NumberSequenceKeypoint = NumberSequenceKeypoint
    env.ColorSequence        = ColorSequence
    env.ColorSequenceKeypoint = ColorSequenceKeypoint
    env.PhysicalProperties   = PhysicalProperties
    env.Ray                  = Ray
    env.Axes                 = Axes
    env.Faces                = Faces

    -- Instance factory
    env.Instance = {
        new = function(class, parent)
            emit("-- [INSTANCE] Instance.new(" .. tostring(class) .. ")")
            local proxy = make_proxy(tostring(class))
            if parent then
                -- record parent relationship
            end
            return proxy
        end,
        fromExisting = function(obj)
            return obj
        end,
    }

    -- Game singletons
    env.game      = game_proxy
    env.Game      = game_proxy
    env.workspace = workspace_proxy
    env.Workspace = workspace_proxy
    env.script    = script_proxy
    env.plugin    = make_proxy("Plugin")

    -- Shared table
    env.shared    = {}
    env._G        = env

    -- Roblox globals
    env.tick         = function() return os.clock() end
    env.time         = function() return os.clock() end
    env.elapsedTime  = function() return os.clock() end
    env.wait         = function(n) return n or 0 end
    env.spawn        = task_lib.spawn
    env.delay        = task_lib.delay
    env.task         = task_lib
    env.crypt        = crypt_lib

    -- Bit libraries
    env.bit    = bit_lib
    env.bit32  = executor_stubs.bit32

    -- Executor stubs
    for k, v in pairs(executor_stubs) do
        env[k] = v
    end

    -- String interpolation helper (Roblox uses this)
    env.tostring = tostring
    env.typeof   = function(v)
        local t = type(v)
        if t == "table" then
            local mt = getmetatable(v)
            if mt and mt.__type then return mt.__type end
            local cls = rawget(v, "ClassName")
            if cls then return cls end
        end
        return t
    end

    -- Additional Roblox globals
    env.printidentity = function(desc)
        emit("-- [PRINTIDENTITY] " .. tostring(desc or ""))
    end

    env.DebuggerManager = make_proxy("DebuggerManager")
    env.settings        = function() return make_proxy("GlobalSettings") end
    env.UserSettings    = function() return make_proxy("UserSettings") end

    -- Ensure _ENV is self-referential
    env._ENV = env

    return env
end

-- ============================================================
--  SECTION 20 – DUMP FUNCTIONS
-- ============================================================
local function dump_string_refs()
    if not CFG.DUMP_DECODED_STRINGS then return end
    if #state.string_refs == 0 then return end
    emit_blank()
    emit_banner("DECODED STRING REFERENCES")
    for i, entry in ipairs(state.string_refs) do
        if i > 200 then emit("-- … (truncated)"); break end
        local line = ("-- [STR #%d] scheme=%s  raw=%s"):format(
            i,
            tostring(entry.scheme),
            safe_literal(string.sub(tostring(entry.raw), 1, 80))
        )
        emit(line)
        if entry.decoded then
            emit(("--           decoded=%s"):format(safe_literal(string.sub(entry.decoded, 1, 160))))
        end
    end
end

local function dump_generic_string_pool()
    if #state.string_pool == 0 then return end
    emit_blank()
    emit_banner("EXTRACTED STRING POOL (PREAMBLE)")
    for i, entry in ipairs(state.string_pool) do
        if i > 300 then emit("-- … (truncated)"); break end
        local line = ("-- [POOL #%d] %s"):format(i, safe_literal(string.sub(entry.raw, 1, 100)))
        emit(line)
        if entry.decoded then
            emit(("--            → [%s] %s"):format(tostring(entry.chain), safe_literal(string.sub(entry.decoded, 1, 160))))
        end
    end
end

local function dump_remote_summary()
    if not CFG.DUMP_REMOTE_SUMMARY then return end
    if #state.call_graph == 0 then return end
    emit_blank()
    emit_banner("REMOTE CALL SUMMARY")
    local counts = {}
    for _, entry in ipairs(state.call_graph) do
        local key = entry.rtype .. ":" .. entry.name
        counts[key] = (counts[key] or 0) + 1
    end
    for key, count in pairs(counts) do
        emit(("-- [REMOTE] %-40s  × %d"):format(key, count))
    end
    emit_blank()
    emit("-- Full call graph:")
    for i, entry in ipairs(state.call_graph) do
        if i > 100 then emit("-- … (truncated)"); break end
        local arg_strs = {}
        for _, v in ipairs(entry.args) do
            arg_strs[#arg_strs+1] = safe_literal(tostring(v):sub(1, 40))
        end
        emit(("--   [%.4fs] %s  %s(%s)"):format(
            entry.time, entry.rtype, entry.name, table.concat(arg_strs, ", ")))
    end
end

local function dump_instance_creations()
    if not CFG.DUMP_INSTANCE_CREATIONS then return end
    if #state.instance_creations == 0 then return end
    emit_blank()
    emit_banner("INSTANCE CREATIONS")
    local counts = {}
    for _, entry in ipairs(state.instance_creations) do
        counts[entry.class] = (counts[entry.class] or 0) + 1
    end
    for class, count in pairs(counts) do
        emit(("-- [INSTANCE] %-40s  × %d"):format(class, count))
    end
end

local function dump_script_loads()
    if not CFG.DUMP_SCRIPT_LOADS then return end
    if #state.script_loads == 0 then return end
    emit_blank()
    emit_banner("SCRIPT LOADS / REQUIRES")
    for i, entry in ipairs(state.script_loads) do
        if i > 50 then emit("-- … (truncated)"); break end
        emit(("-- [%s] %s"):format(
            string.upper(entry.kind),
            safe_literal(string.sub(entry.source or "", 1, CFG.MAX_SCRIPT_LOAD_SNIPPET))
        ))
    end
end

local function dump_deferred_hooks()
    if #state.deferred_hooks == 0 then return end
    emit_blank()
    emit_banner("DEFERRED / HOOKED CALLS")
    local counts = {}
    for _, hook in ipairs(state.deferred_hooks) do
        counts[hook.kind] = (counts[hook.kind] or 0) + 1
    end
    for kind, count in pairs(counts) do
        emit(("-- [HOOK] task.%-10s  × %d"):format(kind, count))
    end
end

local function dump_constants()
    if not CFG.CONSTANT_COLLECTION then return end
    if #state.constants_collected == 0 then return end
    emit_blank()
    emit_banner("COLLECTED CONSTANTS")
    for i, c in ipairs(state.constants_collected) do
        if i > 100 then emit("-- … (truncated)"); break end
        emit(("-- [CONST] %s"):format(safe_literal(tostring(c):sub(1, 120))))
    end
end

-- ============================================================
--  SECTION 21 – MAIN RUNNER
-- ============================================================
local function catmio_run(source)
    output_buffer = {}

    -- Normalise
    source = normalise_source(source)
    if not source or #source == 0 then
        emit("-- [CATMIO] empty source, nothing to analyse")
        return table.concat(output_buffer, "\n")
    end

    -- Detect obfuscator
    state.obfuscator_name  = detect_obfuscator(source)
    state.obfuscation_score = score_obfuscation(source)

    -- Header banner
    emit_banner("CatMio v1.0.0 – Roblox Script Env-Logger & Deobfuscator")
    emit("-- Source length   : " .. #source .. " bytes")
    emit("-- Obfusc. score   : " .. string.format("%.2f", state.obfuscation_score)
        .. (state.obfuscation_score >= CFG.OBFUSCATION_THRESHOLD and " (OBFUSCATED)" or " (likely plain)"))
    emit("-- Fingerprint     : " .. (state.obfuscator_name or "unknown"))
    emit("-- Entropy         : " .. string.format("%.4f", shannon_entropy(source)))
    emit("-- VM boundary pos : " .. tostring(find_vm_boundary(source)))
    emit_blank()

    local is_obfuscated = state.obfuscation_score >= CFG.OBFUSCATION_THRESHOLD or state.obfuscator_name ~= nil

    -- Extract string pool from preamble if obfuscated
    if is_obfuscated then
        emit("-- [CATMIO] Running string pool extraction…")
        extract_string_pool(source)
        emit("-- [CATMIO] String pool entries: " .. #state.string_pool)
        emit_blank()
    end

    -- Scan source for inline encoded strings and try to decode them
    if CFG.DUMP_DECODED_STRINGS then
        for str in string.gmatch(source, '"([^"\\]{4,})"') do
            local decoded, chain = multi_decode(str)
            if not decoded then decoded, chain = try_xor_crack(str) end
            if decoded and is_readable(decoded) then
                state.string_refs[#state.string_refs+1] = {
                    raw     = str,
                    decoded = decoded,
                    scheme  = chain,
                }
                if CFG.CONSTANT_COLLECTION then
                    state.constants_collected[#state.constants_collected+1] = decoded
                end
            end
        end
        for str in string.gmatch(source, "'([^'\\]{4,})'") do
            local decoded, chain = multi_decode(str)
            if not decoded then decoded, chain = try_xor_crack(str) end
            if decoded and is_readable(decoded) then
                state.string_refs[#state.string_refs+1] = {
                    raw     = str,
                    decoded = decoded,
                    scheme  = chain,
                }
            end
        end
    end

    -- Build sandbox environment
    local env = build_env()

    -- Instruction limit hook
    local instruction_count = 0
    local limit_hit = false

    local function instruction_hook()
        instruction_count = instruction_count + 1
        if instruction_count > CFG.INSTRUCTION_LIMIT then
            limit_hit = true
            error("CatMio: instruction limit reached (" .. CFG.INSTRUCTION_LIMIT .. ")", 2)
        end
    end

    -- Load the source chunk
    local chunk, load_err = load_chunk(source, "@catmio_sandbox", env)

    if not chunk then
        emit("-- [CATMIO] Compile error: " .. tostring(load_err))
        emit("-- [CATMIO] Attempting partial analysis without execution…")
    else
        -- Execute with instruction cap
        local exec_ok, exec_err
        if debug and debug.sethook then
            debug.sethook(instruction_hook, "", 1000)
        end

        exec_ok, exec_err = pcall(chunk)

        if debug and debug.sethook then
            debug.sethook()
        end

        if not exec_ok then
            if limit_hit then
                emit("-- [CATMIO] Execution halted: instruction limit (" .. CFG.INSTRUCTION_LIMIT .. ") reached")
            else
                emit("-- [CATMIO] Runtime error: " .. tostring(exec_err))
            end
        else
            emit("-- [CATMIO] Execution completed normally")
        end
        emit("-- [CATMIO] Instructions executed (approx): " .. instruction_count)
    end

    emit_blank()

    -- Dump all collected data
    dump_string_refs()
    dump_generic_string_pool()
    dump_remote_summary()
    dump_instance_creations()
    dump_script_loads()
    dump_deferred_hooks()
    dump_constants()

    -- Summary
    emit_blank()
    emit_banner("CATMIO ANALYSIS SUMMARY")
    emit("-- Obfuscator      : " .. (state.obfuscator_name or "not detected"))
    emit("-- Obfusc. score   : " .. string.format("%.2f / 1.00", state.obfuscation_score))
    emit("-- Decoded strings : " .. #state.string_refs)
    emit("-- Pool entries    : " .. #state.string_pool)
    emit("-- Remote calls    : " .. #state.call_graph)
    emit("-- Instances       : " .. #state.instance_creations)
    emit("-- Script loads    : " .. #state.script_loads)
    emit("-- Deferred hooks  : " .. #state.deferred_hooks)
    emit("-- Output lines    : " .. state.output_lines)
    emit("-- ============================================================")

    return table.concat(output_buffer, "\n")
end

-- ============================================================
--  SECTION 22 – PUBLIC API
-- ============================================================
local CatMio = {}

function CatMio.run(source)
    reset_state()
    return catmio_run(source)
end

function CatMio.decode(s)
    local decoded, chain = multi_decode(s)
    if not decoded then decoded, chain = try_xor_crack(s) end
    return decoded, chain
end

function CatMio.detect(src)
    return detect_obfuscator(src)
end

function CatMio.score(src)
    return score_obfuscation(src)
end

-- Codec
CatMio.b64_decode    = b64_decode
CatMio.b64_url_decode = b64_url_decode
CatMio.b64_encode    = b64_encode
CatMio.hex_decode    = hex_decode
CatMio.url_decode    = url_decode
CatMio.html_decode   = html_decode

-- Ciphers
CatMio.rot13         = rot13_decode
CatMio.rot           = rot_decode
CatMio.caesar_crack  = caesar_crack
CatMio.vigenere_decode = vigenere_decode

-- XOR / bit transforms
CatMio.xor_byte      = xor_byte_decode
CatMio.xor_key       = xor_key_decode
CatMio.bitrev        = bitrev_decode
CatMio.byterev       = byterev_decode
CatMio.null_strip    = null_strip

-- Misc helpers
CatMio.is_readable   = is_readable
CatMio.safe_literal  = safe_literal
CatMio.entropy       = shannon_entropy
CatMio.normalise     = normalise_source

-- Expose config
CatMio.CFG           = CFG

return CatMio
