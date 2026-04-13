
-- ============================================================
--  SECTION 5 – BIT LIBRARY (Lua 5.1 compatible)
--  Pure-Lua implementations of bitwise operations.
--  These are used throughout the codec and cipher implementations.
-- ============================================================

-- Lookup table for nibble-level bitwise operations (bw_and, bw_or, bw_xor)
-- Using a table-driven approach for Lua 5.1 compatibility
local _bit_lut = {}
do
    -- Build lookup table for 4-bit operations
    local function _fill_lut(op)
        local t = {}
        for a = 0, 15 do
            t[a] = {}
            for b = 0, 15 do
                t[a][b] = op(a, b)
            end
        end
        return t
    end
    -- We use recursive bit decomposition
    -- and, or, xor for single bits
    local function _bit_and1(a, b) return (a == 1 and b == 1) and 1 or 0 end
    local function _bit_or1 (a, b) return (a == 1 or  b == 1) and 1 or 0 end
    local function _bit_xor1(a, b) return (a ~= b)              and 1 or 0 end
    _bit_lut.and_op = _fill_lut(_bit_and1)
    _bit_lut.or_op  = _fill_lut(_bit_or1)
    _bit_lut.xor_op = _fill_lut(_bit_xor1)
end

-- Core 32-bit bitwise AND
local function bw_and(a, b)
    a = math.floor(a) % (2^32)
    b = math.floor(b) % (2^32)
    local result, factor = 0, 1
    while a > 0 or b > 0 do
        local la = a % 16
        local lb = b % 16
        result = result + _bit_lut.and_op[la][lb] * factor
        a      = math.floor(a / 16)
        b      = math.floor(b / 16)
        factor = factor * 16
    end
    return result
end

-- Core 32-bit bitwise OR
local function bw_or(a, b)
    a = math.floor(a) % (2^32)
    b = math.floor(b) % (2^32)
    local result, factor = 0, 1
    while a > 0 or b > 0 do
        local la = a % 16
        local lb = b % 16
        result = result + _bit_lut.or_op[la][lb] * factor
        a      = math.floor(a / 16)
        b      = math.floor(b / 16)
        factor = factor * 16
    end
    return result
end

-- Core 32-bit bitwise XOR
local function bw_xor(a, b)
    a = math.floor(a) % (2^32)
    b = math.floor(b) % (2^32)
    local result, factor = 0, 1
    while a > 0 or b > 0 do
        local la = a % 16
        local lb = b % 16
        result = result + _bit_lut.xor_op[la][lb] * factor
        a      = math.floor(a / 16)
        b      = math.floor(b / 16)
        factor = factor * 16
    end
    return result
end

-- Bitwise NOT (32-bit)
local function bw_not(a)
    return (2^32 - 1) - (math.floor(a) % (2^32))
end

-- Left shift by n bits
local function bw_lshift(a, n)
    a = math.floor(a) % (2^32)
    n = math.floor(n) % 32
    return (a * (2^n)) % (2^32)
end

-- Logical right shift by n bits
local function bw_rshift(a, n)
    a = math.floor(a) % (2^32)
    n = math.floor(n) % 32
    return math.floor(a / (2^n))
end

-- Arithmetic right shift by n bits (preserves sign bit)
local function bw_arshift(a, n)
    a = math.floor(a) % (2^32)
    n = math.floor(n) % 32
    local result = math.floor(a / (2^n))
    -- If the sign bit was set, fill with 1s
    if a >= 2^31 then
        result = result + (2^32 - 2^(32 - n))
    end
    return result % (2^32)
end

-- Rotate left by n bits (32-bit)
local function bw_rol(a, n)
    a = math.floor(a) % (2^32)
    n = math.floor(n) % 32
    return bw_or(bw_lshift(a, n), bw_rshift(a, 32 - n))
end

-- Rotate right by n bits (32-bit)
local function bw_ror(a, b)
    return bw_rol(a, 32 - (b % 32))
end

-- Byte swap (reverse byte order of 32-bit int)
local function bw_bswap(a)
    a = math.floor(a) % (2^32)
    local b0 = a % 256
    local b1 = math.floor(a / 256) % 256
    local b2 = math.floor(a / 65536) % 256
    local b3 = math.floor(a / 16777216) % 256
    return b0 * 16777216 + b1 * 65536 + b2 * 256 + b3
end

-- Count leading zeros (32-bit)
local function bw_clz(a)
    a = math.floor(a) % (2^32)
    if a == 0 then return 32 end
    local n = 0
    while bw_and(a, 0x80000000) == 0 do
        n = n + 1
        a = bw_lshift(a, 1)
    end
    return n
end

-- Population count (number of set bits)
local function bw_popcount(a)
    a = math.floor(a) % (2^32)
    local count = 0
    while a > 0 do
        if bw_and(a, 1) == 1 then count = count + 1 end
        a = bw_rshift(a, 1)
    end
    return count
end

-- ============================================================
--  SECTION 6 – UTILITY FUNCTIONS
-- ============================================================

-- Convert a number to its unsigned 32-bit representation
local function u32(n)
    return math.floor(n) % (2^32)
end

-- Safe tostring that doesn't call metamethods
local function safe_tostring(v)
    local t = _native_type(v)
    if t == "string"  then return v end
    if t == "number"  then return tostring(v) end
    if t == "boolean" then return tostring(v) end
    if t == "nil"     then return "nil" end
    local ok, s = _native_pcall(tostring, v)
    if ok then return s else return "(" .. t .. ")" end
end

-- Safe string representation (quotes strings, preserves other types)
local function safe_literal(v, max_len)
    max_len = max_len or CFG.MAX_STRING_LENGTH
    local t = _native_type(v)
    if t == "string" then
        local s = v
        if #s > max_len then
            s = s:sub(1, max_len) .. "...[+" .. (#v - max_len) .. " bytes]"
        end
        -- Escape control characters for display
        s = s:gsub("[%c]", function(c)
            local b = string.byte(c)
            if b == 10 then return "\\n"
            elseif b == 13 then return "\\r"
            elseif b == 9  then return "\\t"
            elseif b == 0  then return "\\0"
            else return string.format("\\%d", b)
            end
        end)
        return '"' .. s .. '"'
    elseif t == "number" then
        return tostring(v)
    elseif t == "boolean" then
        return tostring(v)
    elseif t == "nil" then
        return "nil"
    else
        local ok, s = _native_pcall(tostring, v)
        if ok then return s else return "(" .. t .. ")" end
    end
end

-- Check if a string consists entirely of printable ASCII
local function is_printable_ascii(s)
    for i = 1, #s do
        local b = string.byte(s, i)
        if b < 32 or b > 126 then return false end
    end
    return true
end

-- Check if a string is "readable" (high fraction of printable chars)
local function is_readable(s)
    if not s or #s == 0 then return false end
    local printable = 0
    for i = 1, #s do
        local b = string.byte(s, i)
        if (b >= 32 and b <= 126) or b == 10 or b == 13 or b == 9 then
            printable = printable + 1
        end
    end
    return (printable / #s) >= CFG.READABLE_PRINTABLE_THRESHOLD
end

-- Check if a string looks like Lua source code
local function looks_like_lua(s)
    if not s or #s < 10 then return false end
    -- Presence of Lua keywords is a strong indicator
    local kw_count = 0
    local keywords = {
        "local", "function", "end", "if", "then", "else",
        "for", "while", "do", "return", "and", "or", "not",
        "true", "false", "nil", "repeat", "until", "in",
        "elseif", "break", "goto",
    }
    for _, kw in ipairs(keywords) do
        local _, cnt = string.gsub(s, "%f[%w_]" .. kw .. "%f[^%w_]", "")
        kw_count = kw_count + cnt
    end
    local density = kw_count / (#s + 1)
    return density >= CFG.LUA_KEYWORD_DENSITY_THRESHOLD
end

-- Detect language of decoded string
local function detect_language(s)
    if not s or #s < 20 then return "unknown" end
    -- Lua
    if string.find(s, "local%s") or string.find(s, "function%s") or
       string.find(s, "%-%-%[%[") or string.find(s, "end%s") then
        return "lua"
    end
    -- JavaScript
    if string.find(s, "var%s") or string.find(s, "function%(") or
       string.find(s, "===") or string.find(s, "console%.log") then
        return "javascript"
    end
    -- Python
    if string.find(s, "def%s") or string.find(s, "import%s") or
       string.find(s, "print%(") or string.find(s, "elif%s") then
        return "python"
    end
    -- C#
    if string.find(s, "using%s") or string.find(s, "namespace%s") or
       string.find(s, "public%s") or string.find(s, "static%s") then
        return "csharp"
    end
    -- HTML
    if string.find(s, "<!DOCTYPE") or string.find(s, "<html") or
       string.find(s, "<script") or string.find(s, "<div") then
        return "html"
    end
    -- JSON
    if string.find(s, "^%s*%{") and string.find(s, ":%s*[%[%{%\"]") then
        return "json"
    end
    -- Binary data
    local nonprint = 0
    for i = 1, math.min(#s, 64) do
        local b = string.byte(s, i)
        if b < 32 and b ~= 9 and b ~= 10 and b ~= 13 then
            nonprint = nonprint + 1
        end
    end
    if nonprint > 4 then return "binary" end
    return "text"
end

-- Calculate Shannon entropy of a string
local function shannon_entropy(s)
    if not s or #s == 0 then return 0 end
    local freq = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        freq[b] = (freq[b] or 0) + 1
    end
    local entropy = 0
    local len = #s
    for _, count in pairs(freq) do
        local p = count / len
        if p > 0 then
            entropy = entropy - p * (math.log(p) / math.log(2))
        end
    end
    return entropy
end

-- Detect BOM (Byte Order Mark) at start of string
local function detect_bom(s)
    if #s < 2 then return nil end
    local b1, b2, b3, b4 =
        string.byte(s, 1), string.byte(s, 2),
        string.byte(s, 3) or 0, string.byte(s, 4) or 0
    -- UTF-8 BOM: EF BB BF
    if b1 == 0xEF and b2 == 0xBB and b3 == 0xBF then return "utf8bom" end
    -- UTF-16 LE: FF FE
    if b1 == 0xFF and b2 == 0xFE then return "utf16le" end
    -- UTF-16 BE: FE FF
    if b1 == 0xFE and b2 == 0xFF then return "utf16be" end
    -- UTF-32 LE: FF FE 00 00
    if b1 == 0xFF and b2 == 0xFE and b3 == 0x00 and b4 == 0x00 then return "utf32le" end
    -- UTF-32 BE: 00 00 FE FF
    if b1 == 0x00 and b2 == 0x00 and b3 == 0xFE and b4 == 0xFF then return "utf32be" end
    -- Lua 5.1 bytecode: 1B 4C 75 61
    if b1 == 0x1B and b2 == 0x4C and b3 == 0x75 and b4 == 0x61 then return "lua51bc" end
    -- Luau bytecode: 1B 4C 75 61 51 (Luau has version byte 0x51 = 81)
    if b1 == 0x1B and b2 == 0x4C and b3 == 0x75 and b4 == 0x61 then
        local b5 = string.byte(s, 5) or 0
        if b5 == 0x51 then return "luaubc" end
    end
    -- zlib: 78 9C / 78 DA / 78 01
    if b1 == 0x78 and (b2 == 0x9C or b2 == 0xDA or b2 == 0x01 or b2 == 0x5E) then
        return "zlib"
    end
    -- gzip: 1F 8B
    if b1 == 0x1F and b2 == 0x8B then return "gzip" end
    return nil
end

-- Detect encoding format from content analysis
local function detect_encoding(s)
    if not s or #s == 0 then return "empty" end
    local bom = detect_bom(s)
    if bom then return bom end
    -- Pure hex string
    if string.match(s, "^[0-9a-fA-F]+$") and #s % 2 == 0 then return "hex" end
    -- Base64 (standard)
    if string.match(s, "^[A-Za-z0-9+/]+=*$") and #s % 4 == 0 then return "base64" end
    -- Base64 URL-safe
    if string.match(s, "^[A-Za-z0-9%-_]+=*$") and #s % 4 == 0 then return "base64url" end
    -- URL encoded
    if string.match(s, "%%[0-9a-fA-F][0-9a-fA-F]") then return "url" end
    -- HTML encoded
    if string.match(s, "&[a-zA-Z]+;") or string.match(s, "&#[0-9]+;") then return "html" end
    -- Binary string (only 0 and 1)
    if string.match(s, "^[01 ]+$") and (#s % 8 == 0 or #s % 9 == 0) then return "binary" end
    -- Morse code
    if string.match(s, "^[%. %-/]+$") then return "morse" end
    -- UUEncode header
    if string.match(s, "^begin %d%d%d ") then return "uuencode" end
    -- Quoted-Printable
    if string.match(s, "=[0-9A-F][0-9A-F]") then return "qp" end
    return "unknown"
end

-- Statistics helpers
local function stat_mean(arr)
    if #arr == 0 then return 0 end
    local sum = 0
    for _, v in ipairs(arr) do sum = sum + v end
    return sum / #arr
end

local function stat_median(arr)
    if #arr == 0 then return 0 end
    local sorted = {}
    for i, v in ipairs(arr) do sorted[i] = v end
    table.sort(sorted)
    local mid = math.floor(#sorted / 2)
    if #sorted % 2 == 0 then
        return (sorted[mid] + sorted[mid + 1]) / 2
    else
        return sorted[mid + 1]
    end
end

local function stat_stddev(arr)
    if #arr == 0 then return 0 end
    local mean = stat_mean(arr)
    local variance = 0
    for _, v in ipairs(arr) do
        variance = variance + (v - mean) ^ 2
    end
    return math.sqrt(variance / #arr)
end

local function stat_max(arr)
    if #arr == 0 then return 0 end
    local m = arr[1]
    for i = 2, #arr do if arr[i] > m then m = arr[i] end end
    return m
end

local function stat_min(arr)
    if #arr == 0 then return 0 end
    local m = arr[1]
    for i = 2, #arr do if arr[i] < m then m = arr[i] end end
    return m
end

-- String split by separator
local function str_split(s, sep)
    local parts = {}
    local pattern = "([^" .. sep .. "]*)" .. sep .. "?"
    for part in string.gmatch(s, pattern) do
        table.insert(parts, part)
    end
    return parts
end

-- Trim whitespace from both ends
local function str_trim(s)
    return string.match(s, "^%s*(.-)%s*$") or ""
end

-- Count occurrences of pattern in string
local function str_count(s, pat)
    local _, n = string.gsub(s, pat, "")
    return n
end

-- Normalise source code (strip comments and compact whitespace)
local function normalise_source(src)
    -- Remove single-line comments
    local s = string.gsub(src, "%-%-[^\n]*", "")
    -- Remove long comments
    s = string.gsub(s, "%-%-%[%[.-%]%]", "")
    -- Compact whitespace
    s = string.gsub(s, "%s+", " ")
    return s
end

-- ============================================================
--  SECTION 7 – BASIC CODECS
--  All standard encoding/decoding functions.
-- ============================================================

-- ── Base64 ──────────────────────────────────────────────────────────────────
-- Standard Base64 alphabet
local B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
-- URL-safe Base64 alphabet
local B64_URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

-- Build Base64 decode lookup table (works for both alphabets)
local function _b64_build_lut(alphabet)
    local lut = {}
    for i = 1, #alphabet do
        lut[string.sub(alphabet, i, i)] = i - 1
    end
    lut["="] = 0
    return lut
end

local B64_LUT     = _b64_build_lut(B64_CHARS)
local B64_URL_LUT = _b64_build_lut(B64_URL_CHARS)

-- Core Base64 decoder (handles both standard and URL-safe alphabets)
local function _b64_decode_core(s, lut)
    if not s then return nil end
    -- Strip whitespace
    s = string.gsub(s, "%s", "")
    -- Add padding if needed
    local pad = (4 - #s % 4) % 4
    s = s .. string.rep("=", pad)
    local result = {}
    for i = 1, #s, 4 do
        local c1 = lut[string.sub(s, i,   i)]   or 0
        local c2 = lut[string.sub(s, i+1, i+1)] or 0
        local c3 = lut[string.sub(s, i+2, i+2)] or 0
        local c4 = lut[string.sub(s, i+3, i+3)] or 0
        local n = c1 * 262144 + c2 * 4096 + c3 * 64 + c4
        table.insert(result, string.char(math.floor(n / 65536) % 256))
        if string.sub(s, i+2, i+2) ~= "=" then
            table.insert(result, string.char(math.floor(n / 256) % 256))
        end
        if string.sub(s, i+3, i+3) ~= "=" then
            table.insert(result, string.char(n % 256))
        end
    end
    return table.concat(result)
end

-- Standard Base64 decode
local function b64_decode(s)
    local ok, r = _native_pcall(_b64_decode_core, s, B64_LUT)
    return ok and r or nil
end

-- URL-safe Base64 decode
local function b64_url_decode(s)
    -- Convert URL-safe chars to standard
    s = string.gsub(s, "%-", "+")
    s = string.gsub(s, "_", "/")
    return b64_decode(s)
end

-- Base64 encode
local function b64_encode(s)
    if not s then return nil end
    local result = {}
    local padding = 0
    for i = 1, #s, 3 do
        local b1 = string.byte(s, i)       or 0
        local b2 = string.byte(s, i+1)     or 0
        local b3 = string.byte(s, i+2)     or 0
        local n  = b1 * 65536 + b2 * 256 + b3
        table.insert(result, string.sub(B64_CHARS, math.floor(n / 262144) + 1, math.floor(n / 262144) + 1))
        table.insert(result, string.sub(B64_CHARS, math.floor(n / 4096) % 64 + 1, math.floor(n / 4096) % 64 + 1))
        if i+1 <= #s then
            table.insert(result, string.sub(B64_CHARS, math.floor(n / 64) % 64 + 1, math.floor(n / 64) % 64 + 1))
        else
            table.insert(result, "=")
        end
        if i+2 <= #s then
            table.insert(result, string.sub(B64_CHARS, n % 64 + 1, n % 64 + 1))
        else
            table.insert(result, "=")
        end
    end
    return table.concat(result)
end

-- ── Hex ─────────────────────────────────────────────────────────────────────

-- Hex decode (accepts "48 65 6c 6c 6f" or "48656c6c6f")
local function hex_decode(s)
    if not s then return nil end
    -- Remove spaces and non-hex chars
    s = string.gsub(s, "[^0-9a-fA-F]", "")
    if #s == 0 or #s % 2 ~= 0 then return nil end
    local result = {}
    for i = 1, #s, 2 do
        local hi = tonumber(string.sub(s, i,   i),   16) or 0
        local lo = tonumber(string.sub(s, i+1, i+1), 16) or 0
        table.insert(result, string.char(hi * 16 + lo))
    end
    return table.concat(result)
end

-- Hex encode (lower case)
local function hex_encode(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        table.insert(result, string.format("%02x", string.byte(s, i)))
    end
    return table.concat(result)
end

-- Hex encode (upper case)
local function hex_encode_upper(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        table.insert(result, string.format("%02X", string.byte(s, i)))
    end
    return table.concat(result)
end

-- ── URL Encoding ─────────────────────────────────────────────────────────────

-- URL decode (%XX sequences)
local function url_decode(s)
    if not s then return nil end
    s = string.gsub(s, "%%(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    s = string.gsub(s, "%+", " ")
    return s
end

-- URL encode (all non-unreserved chars)
local function url_encode(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        local c = string.sub(s, i, i)
        local b = string.byte(c)
        -- Unreserved: A-Z a-z 0-9 - _ . ~
        if (b >= 65 and b <= 90) or (b >= 97 and b <= 122) or
           (b >= 48 and b <= 57) or b == 45 or b == 95 or b == 46 or b == 126 then
            table.insert(result, c)
        else
            table.insert(result, string.format("%%%02X", b))
        end
    end
    return table.concat(result)
end

-- ── HTML Entities ─────────────────────────────────────────────────────────────

local HTML_ENTITIES = {
    amp  = "&",   lt   = "<",   gt   = ">",
    quot = '"',   apos = "'",   nbsp = "\160",
    copy = "\169", reg = "\174", trade = "\153",
    euro = "\226\130\172",
    mdash = "\226\128\148",
    ndash = "\226\128\147",
    hellip = "\226\128\166",
    laquo = "\194\171",
    raquo = "\194\187",
}

local function html_decode(s)
    if not s then return nil end
    -- Named entities
    s = string.gsub(s, "&(%a+);", function(name)
        return HTML_ENTITIES[string.lower(name)] or ("&" .. name .. ";")
    end)
    -- Decimal numeric entities &#123;
    s = string.gsub(s, "&#(%d+);", function(n)
        local num = tonumber(n) or 0
        if num < 128 then return string.char(num) end
        return "&#" .. n .. ";"
    end)
    -- Hex numeric entities &#x1F;
    s = string.gsub(s, "&#x(%x+);", function(h)
        local num = tonumber(h, 16) or 0
        if num < 128 then return string.char(num) end
        return "&#x" .. h .. ";"
    end)
    return s
end

-- ── ROT Ciphers ──────────────────────────────────────────────────────────────

-- Generic ROT cipher (shift by n positions in alphabet)
local function rot_decode(s, n)
    if not s then return nil end
    n = n or 13
    n = n % 26
    local result = {}
    for i = 1, #s do
        local c = string.byte(s, i)
        if c >= 65 and c <= 90 then        -- uppercase
            table.insert(result, string.char((c - 65 + n) % 26 + 65))
        elseif c >= 97 and c <= 122 then   -- lowercase
            table.insert(result, string.char((c - 97 + n) % 26 + 97))
        else
            table.insert(result, string.char(c))
        end
    end
    return table.concat(result)
end

-- ROT13 (most common)
local function rot13_decode(s) return rot_decode(s, 13) end

-- ROT5 (digits only: 0-9)
local function rot5_decode(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        local c = string.byte(s, i)
        if c >= 48 and c <= 57 then    -- 0-9
            table.insert(result, string.char((c - 48 + 5) % 10 + 48))
        else
            table.insert(result, string.char(c))
        end
    end
    return table.concat(result)
end

-- ROT18 (ROT13 for letters + ROT5 for digits)
local function rot18_decode(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        local c = string.byte(s, i)
        if c >= 65 and c <= 90 then
            table.insert(result, string.char((c - 65 + 13) % 26 + 65))
        elseif c >= 97 and c <= 122 then
            table.insert(result, string.char((c - 97 + 13) % 26 + 97))
        elseif c >= 48 and c <= 57 then
            table.insert(result, string.char((c - 48 + 5) % 10 + 48))
        else
            table.insert(result, string.char(c))
        end
    end
    return table.concat(result)
end

-- ROT47 (printable ASCII range 33-126)
local function rot47_decode(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        local c = string.byte(s, i)
        if c >= 33 and c <= 126 then
            table.insert(result, string.char((c - 33 + 47) % 94 + 33))
        else
            table.insert(result, string.char(c))
        end
    end
    return table.concat(result)
end

-- Caesar cipher brute-force (returns best candidate)
local function caesar_crack(s)
    if not s or #s == 0 then return nil, nil end
    local best_score = -1
    local best_str   = nil
    local best_shift = nil
    -- English letter frequency order (most to least common)
    local english_freq = "etaoinshrdlcumwfgypbvkjxqz"
    for shift = 1, 25 do
        local candidate = rot_decode(s, shift)
        -- Score by letter frequency (count common letters)
        local score = 0
        for i = 1, #candidate do
            local c = string.lower(string.sub(candidate, i, i))
            local pos = string.find(english_freq, c, 1, true)
            if pos then score = score + (27 - pos) end
        end
        if score > best_score then
            best_score = score
            best_str   = candidate
            best_shift = shift
        end
    end
    return best_str, best_shift
end

-- ── XOR Ciphers ──────────────────────────────────────────────────────────────

-- Single-byte XOR decode
local function xor_byte_decode(s, key)
    if not s then return nil end
    key = key or 0
    local result = {}
    for i = 1, #s do
        table.insert(result, string.char(bw_xor(string.byte(s, i), key) % 256))
    end
    return table.concat(result)
end

-- Multi-byte XOR decode (key is a string)
local function xor_key_decode(s, key)
    if not s or not key or #key == 0 then return nil end
    local result = {}
    for i = 1, #s do
        local k = string.byte(key, (i - 1) % #key + 1)
        table.insert(result, string.char(bw_xor(string.byte(s, i), k) % 256))
    end
    return table.concat(result)
end

-- Rolling XOR: each position i uses key[i % #key] XOR prev_output[i-1]
local function xor_rolling_decode(s, key)
    if not s or not key or #key == 0 then return nil end
    local result = {}
    local prev = 0
    for i = 1, #s do
        local k = string.byte(key, (i - 1) % #key + 1)
        local b = bw_xor(string.byte(s, i), bw_xor(k, prev)) % 256
        table.insert(result, string.char(b))
        prev = b
    end
    return table.concat(result)
end

-- Polynomial XOR: key byte at position i is key[1] * i^2 + key[2] * i
local function xor_poly_decode(s, key)
    if not s or not key or #key < 2 then return nil end
    local k1 = string.byte(key, 1)
    local k2 = string.byte(key, 2)
    local result = {}
    for i = 1, #s do
        local k = (k1 * i * i + k2 * i) % 256
        table.insert(result, string.char(bw_xor(string.byte(s, i), k) % 256))
    end
    return table.concat(result)
end

-- XOR complement: key = NOT(key)
local function xor_complement_decode(s, key)
    if not s or not key then return nil end
    if type(key) == "number" then
        return xor_byte_decode(s, (255 - key) % 256)
    end
    -- String key: complement each byte
    local ckey = {}
    for i = 1, #key do
        table.insert(ckey, string.char((255 - string.byte(key, i)) % 256))
    end
    return xor_key_decode(s, table.concat(ckey))
end

-- XOR brute-force (single-byte key)
local function try_xor_crack(s)
    if not s or #s < 4 then return nil, nil end
    local best_score = -1
    local best_str   = nil
    local best_key   = nil
    for key = 1, 255 do
        local candidate = xor_byte_decode(s, key)
        if candidate and is_readable(candidate) then
            local score = 0
            for i = 1, #candidate do
                local b = string.byte(candidate, i)
                -- Prefer printable ASCII
                if b >= 32 and b <= 126 then score = score + 1 end
                -- Bonus for common Lua chars
                if b == 32 or b == 10 or b == 61 or b == 40 then score = score + 1 end
            end
            if score > best_score then
                best_score = score
                best_str   = candidate
                best_key   = key
            end
        end
    end
    if best_str and is_readable(best_str) then
        return best_str, string.format("xor:0x%02X", best_key)
    end
    return nil, nil
end

-- ── Bit Reverse / Byte Reverse ────────────────────────────────────────────────

-- Reverse bits within each byte
local function bitrev_decode(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        local b = string.byte(s, i)
        local rev = 0
        for j = 0, 7 do
            if bw_and(b, bw_lshift(1, j)) ~= 0 then
                rev = bw_or(rev, bw_lshift(1, 7 - j))
            end
        end
        table.insert(result, string.char(rev % 256))
    end
    return table.concat(result)
end

-- Reverse byte order of entire string
local function byterev_decode(s)
    if not s then return nil end
    local result = {}
    for i = #s, 1, -1 do
        table.insert(result, string.sub(s, i, i))
    end
    return table.concat(result)
end

-- Strip null bytes
local function null_strip(s)
    if not s then return nil end
    return string.gsub(s, "%z", "")
end

-- ── Vigenere Cipher ───────────────────────────────────────────────────────────

-- Classic Vigenere decode (alphabetic key, uppercase only)
local function vigenere_decode(s, key)
    if not s or not key or #key == 0 then return nil end
    key = string.upper(key)
    -- Validate key is alphabetic
    if not string.match(key, "^[A-Z]+$") then return nil end
    local result = {}
    local ki = 0
    for i = 1, #s do
        local c = string.byte(s, i)
        if c >= 65 and c <= 90 then
            local k = string.byte(key, ki % #key + 1) - 65
            table.insert(result, string.char((c - 65 - k + 26) % 26 + 65))
            ki = ki + 1
        elseif c >= 97 and c <= 122 then
            local k = string.byte(key, ki % #key + 1) - 65
            table.insert(result, string.char((c - 97 - k + 26) % 26 + 97))
            ki = ki + 1
        else
            table.insert(result, string.char(c))
        end
    end
    return table.concat(result)
end

-- Numeric-key Vigenere: key is a table of numbers
local function vigenere_numeric_decode(s, key_table)
    if not s or not key_table or #key_table == 0 then return nil end
    local result = {}
    for i = 1, #s do
        local b  = string.byte(s, i)
        local k  = key_table[(i - 1) % #key_table + 1] or 0
        table.insert(result, string.char((b - k + 256) % 256))
    end
    return table.concat(result)
end

-- ── Atbash Cipher ─────────────────────────────────────────────────────────────
-- Atbash: A↔Z, B↔Y, etc. (is its own inverse)

local function atbash_decode(s)
    if not s then return nil end
    local result = {}
    for i = 1, #s do
        local c = string.byte(s, i)
        if c >= 65 and c <= 90 then
            table.insert(result, string.char(90 - (c - 65)))
        elseif c >= 97 and c <= 122 then
            table.insert(result, string.char(122 - (c - 97)))
        else
            table.insert(result, string.char(c))
        end
    end
    return table.concat(result)
end

-- ── Rail Fence Cipher ─────────────────────────────────────────────────────────

local function rail_fence_decode(s, rails)
    if not s or not rails or rails < 2 then return nil end
    rails = math.floor(rails)
    local n = #s
    local fence = {}
    local lengths = {}
    for r = 0, rails - 1 do
        fence[r] = {}
        lengths[r] = 0
    end
    -- Calculate how many characters fall on each rail
    local rail, direction = 0, 1
    for i = 1, n do
        lengths[rail] = lengths[rail] + 1
        if rail == 0 then direction = 1
        elseif rail == rails - 1 then direction = -1
        end
        rail = rail + direction
    end
    -- Fill rails from input string
    local pos = 1
    for r = 0, rails - 1 do
        for i = 1, lengths[r] do
            fence[r][i] = string.sub(s, pos, pos)
            pos = pos + 1
        end
        fence[r].idx = 1
    end
    -- Read off in original order
    local result = {}
    rail, direction = 0, 1
    for i = 1, n do
        table.insert(result, fence[rail][fence[rail].idx])
        fence[rail].idx = fence[rail].idx + 1
        if rail == 0 then direction = 1
        elseif rail == rails - 1 then direction = -1
        end
        rail = rail + direction
    end
    return table.concat(result)
end

-- ── Columnar Transposition ────────────────────────────────────────────────────

local function columnar_decode(s, key)
    if not s or not key or #key == 0 then return nil end
    local n_cols = #key
    local n_rows = math.ceil(#s / n_cols)
    -- Sort column indices by key character order
    local order = {}
    for i = 1, n_cols do order[i] = i end
    table.sort(order, function(a, b)
        return string.sub(key, a, a) < string.sub(key, b, b)
    end)
    -- Fill columns
    local grid = {}
    local pos = 1
    for _, col in ipairs(order) do
        grid[col] = {}
        local col_len = n_rows - (col > #s - (n_rows - 1) * n_cols and 1 or 0)
        for r = 1, col_len do
            grid[col][r] = string.sub(s, pos, pos)
            pos = pos + 1
        end
    end
    -- Read row by row
    local result = {}
    for r = 1, n_rows do
        for c = 1, n_cols do
            if grid[c] and grid[c][r] then
                table.insert(result, grid[c][r])
            end
        end
    end
    return table.concat(result)
end

-- ── Base32 ────────────────────────────────────────────────────────────────────

local B32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
local B32_LUT = {}
do
    for i = 1, #B32_CHARS do
        local c = string.sub(B32_CHARS, i, i)
        B32_LUT[c] = i - 1
        B32_LUT[string.lower(c)] = i - 1
    end
    B32_LUT["="] = 0
end

local function b32_decode(s)
    if not s then return nil end
    s = string.gsub(s, "%s", "")
    s = string.upper(s)
    local pad = (8 - #s % 8) % 8
    s = s .. string.rep("=", pad)
    local result = {}
    for i = 1, #s, 8 do
        local c = {}
        for j = 0, 7 do
            c[j+1] = B32_LUT[string.sub(s, i+j, i+j)] or 0
        end
        local n = 0
        for j = 1, 8 do n = n * 32 + c[j] end
        table.insert(result, string.char(math.floor(n / 2^32) % 256))
        table.insert(result, string.char(math.floor(n / 2^24) % 256))
        table.insert(result, string.char(math.floor(n / 2^16) % 256))
        table.insert(result, string.char(math.floor(n / 2^8) % 256))
        table.insert(result, string.char(n % 256))
    end
    -- Remove padding
    local res = table.concat(result)
    -- Calculate actual byte count
    local extra = 0
    for i = #s, 1, -1 do
        if string.sub(s, i, i) == "=" then extra = extra + 1 else break end
    end
    local byte_count = (#s / 8) * 5 - math.floor(extra * 5 / 8)
    return string.sub(res, 1, byte_count)
end

-- ── Base58 ────────────────────────────────────────────────────────────────────
-- Bitcoin-style Base58 (no 0, O, I, l)

local B58_CHARS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
local B58_LUT = {}
do
    for i = 1, #B58_CHARS do
        B58_LUT[string.sub(B58_CHARS, i, i)] = i - 1
    end
end

local function b58_decode(s)
    if not s then return nil end
    s = string.gsub(s, "%s", "")
    -- Count leading '1's (encode leading zero bytes)
    local leading_zeros = 0
    for i = 1, #s do
        if string.sub(s, i, i) == "1" then
            leading_zeros = leading_zeros + 1
        else
            break
        end
    end
    -- Decode
    local num = 0
    for i = 1, #s do
        local c = string.sub(s, i, i)
        local v = B58_LUT[c]
        if not v then return nil end
        num = num * 58 + v
    end
    -- Convert to bytes
    local bytes = {}
    while num > 0 do
        table.insert(bytes, 1, string.char(num % 256))
        num = math.floor(num / 256)
    end
    -- Re-add leading zeros
    for i = 1, leading_zeros do
        table.insert(bytes, 1, "\0")
    end
    return table.concat(bytes)
end

-- ── Base85 / Ascii85 ─────────────────────────────────────────────────────────

local function b85_decode(s)
    if not s then return nil end
    -- Strip whitespace
    s = string.gsub(s, "%s", "")
    -- Handle Adobe Ascii85 wrappers <~ ~>
    s = string.gsub(s, "^<~", "")
    s = string.gsub(s, "~>$", "")
    local result = {}
    local i = 1
    while i <= #s do
        local c = string.sub(s, i, i)
        if c == "z" then
            -- Special case: 'z' = 5 zeros
            table.insert(result, "\0\0\0\0")
            i = i + 1
        else
            -- Decode 5 chars → 4 bytes
            local group = string.sub(s, i, i + 4)
            if #group < 5 then
                -- Pad with 'u' (84 + 33 = 117)
                group = group .. string.rep("u", 5 - #group)
            end
            local v = 0
            for j = 1, 5 do
                local b = string.byte(group, j) - 33
                if b < 0 or b > 84 then return nil end
                v = v * 85 + b
            end
            local b4 = v % 256 ; v = math.floor(v / 256)
            local b3 = v % 256 ; v = math.floor(v / 256)
            local b2 = v % 256 ; v = math.floor(v / 256)
            local b1 = v % 256
            table.insert(result, string.char(b1, b2, b3, b4))
            i = i + 5
        end
    end
    return table.concat(result)
end

-- ── UUEncode ─────────────────────────────────────────────────────────────────

local function uuencode_decode(s)
    if not s then return nil end
    local result = {}
    for line in string.gmatch(s, "[^\n]+") do
        -- Skip header/footer lines
        if string.find(line, "^begin") or string.find(line, "^end") then
            -- skip
        else
            -- First char encodes line length
            local length = string.byte(line, 1)
            if not length then break end
            length = (length - 32) % 64
            if length == 0 then break end
            for i = 2, #line - 3, 4 do
                local c1 = (string.byte(line, i)   or 32) - 32
                local c2 = (string.byte(line, i+1) or 32) - 32
                local c3 = (string.byte(line, i+2) or 32) - 32
                local c4 = (string.byte(line, i+3) or 32) - 32
                c1 = c1 % 64 ; c2 = c2 % 64 ; c3 = c3 % 64 ; c4 = c4 % 64
                local n = c1 * 262144 + c2 * 4096 + c3 * 64 + c4
                table.insert(result, string.char(math.floor(n / 65536) % 256))
                table.insert(result, string.char(math.floor(n / 256) % 256))
                table.insert(result, string.char(n % 256))
            end
        end
    end
    -- Trim to actual decoded length (rough)
    return table.concat(result)
end

-- ── Quoted-Printable ─────────────────────────────────────────────────────────

local function qp_decode(s)
    if not s then return nil end
    -- Join soft line breaks
    s = string.gsub(s, "=%\r?\n", "")
    -- Decode =XX sequences
    s = string.gsub(s, "=(%x%x)", function(h)
        return string.char(tonumber(h, 16))
    end)
    return s
end

-- ── Morse Code ────────────────────────────────────────────────────────────────

local MORSE_TO_CHAR = {
    [".-"]   = "A", ["-..."] = "B", ["-.-."] = "C", ["-.."]  = "D",
    ["."]    = "E", ["..-."] = "F", ["--."]  = "G", ["...."] = "H",
    [".."]   = "I", [".---"] = "J", ["-.-"]  = "K", [".-.."] = "L",
    ["--"]   = "M", ["-."]   = "N", ["---"]  = "O", [".--."] = "P",
    ["--.-"] = "Q", [".-."]  = "R", ["..."]  = "S", ["-"]    = "T",
    ["..-"]  = "U", ["...-"] = "V", [".--"]  = "W", ["-..-"] = "X",
    ["-.--"] = "Y", ["--.."] = "Z",
    [".----"] = "1", ["..---"] = "2", ["...--"] = "3",
    ["....-"] = "4", ["....."] = "5", ["-...."] = "6",
    ["--..."] = "7", ["---.."] = "8", ["----."] = "9", ["-----"] = "0",
    [".-.-.-"] = ".", ["--..--"] = ",", ["..--.." ] = "?",
    ["-..-."]  = "/", ["-.--."]  = "(", ["-.--.-"] = ")",
    ["...---..."] = "SOS",
}

local function morse_decode(s)
    if not s then return nil end
    local result = {}
    -- Words are separated by "/" or "  " (double space)
    -- Letters are separated by " " (single space)
    for word in string.gmatch(s .. " / ", "([^/]+)%s*/%s*") do
        local letters = {}
        for code in string.gmatch(str_trim(word) .. " ", "([%.%-]+)%s") do
            local ch = MORSE_TO_CHAR[code]
            table.insert(letters, ch or ("?" .. code .. "?"))
        end
        table.insert(result, table.concat(letters))
    end
    return table.concat(result, " ")
end

-- ── NATO Phonetic Alphabet ────────────────────────────────────────────────────

local NATO_TO_CHAR = {
    ALPHA = "A",   BRAVO = "B",   CHARLIE = "C", DELTA = "D",
    ECHO = "E",    FOXTROT = "F", GOLF = "G",    HOTEL = "H",
    INDIA = "I",   JULIET = "J",  KILO = "K",    LIMA = "L",
    MIKE = "M",    NOVEMBER = "N",OSCAR = "O",   PAPA = "P",
    QUEBEC = "Q",  ROMEO = "R",   SIERRA = "S",  TANGO = "T",
    UNIFORM = "U", VICTOR = "V",  WHISKEY = "W", XRAY = "X",
    YANKEE = "Y",  ZULU = "Z",
    ZERO = "0",    ONE = "1",     TWO = "2",     THREE = "3",
    FOUR = "4",    FIVE = "5",    SIX = "6",     SEVEN = "7",
    EIGHT = "8",   NINE = "9",    NINER = "9",
}

local function nato_decode(s)
    if not s then return nil end
    local result = {}
    for word in string.gmatch(string.upper(s), "[A-Z]+") do
        local ch = NATO_TO_CHAR[word]
        if ch then
            table.insert(result, ch)
        end
    end
    return table.concat(result)
end

-- ── Binary String Decoder ─────────────────────────────────────────────────────

local function binary_decode(s)
    if not s then return nil end
    -- Remove spaces
    s = string.gsub(s, "%s+", "")
    if not string.match(s, "^[01]+$") then return nil end
    if #s % 8 ~= 0 then return nil end
    local result = {}
    for i = 1, #s, 8 do
        local byte_str = string.sub(s, i, i + 7)
        local value = 0
        for j = 1, 8 do
            value = value * 2 + (string.sub(byte_str, j, j) == "1" and 1 or 0)
        end
        if value > 0 then  -- skip null bytes
            table.insert(result, string.char(value))
        end
    end
    return table.concat(result)
end

-- ── Octal String Decoder ──────────────────────────────────────────────────────

local function octal_decode(s)
    if not s then return nil end
    local result = {}
    -- Handle both "\\377" escape sequences and space-separated octal values
    -- Try escape sequence format first: \000 to \377
    local escaped = string.gsub(s, "\\(%d%d%d)", function(oct)
        local n = tonumber(oct, 8)
        if n and n >= 0 and n <= 255 then
            return string.char(n)
        end
        return "\\" .. oct
    end)
    if escaped ~= s then return escaped end
    -- Try space-separated octal numbers
    for oct in string.gmatch(s, "[0-7]+") do
        local n = tonumber(oct, 8)
        if n and n <= 255 then
            table.insert(result, string.char(n))
        end
    end
    if #result > 0 then return table.concat(result) end
    return nil
end

-- ── Unicode Escape Decoder ────────────────────────────────────────────────────

local function unicode_escape_decode(s)
    if not s then return nil end
    local changed = false
    -- \uXXXX (JavaScript-style)
    local result = string.gsub(s, "\\u(%x%x%x%x)", function(hex)
        changed = true
        local n = tonumber(hex, 16) or 0
        -- Encode as UTF-8
        if n < 0x80 then
            return string.char(n)
        elseif n < 0x800 then
            return string.char(
                0xC0 + math.floor(n / 64),
                0x80 + n % 64
            )
        else
            return string.char(
                0xE0 + math.floor(n / 4096),
                0x80 + math.floor(n / 64) % 64,
                0x80 + n % 64
            )
        end
    end)
    -- \UXXXXXXXX (Python-style 8-digit)
    result = string.gsub(result, "\\U(%x%x%x%x%x%x%x%x)", function(hex)
        changed = true
        local n = tonumber(hex, 16) or 0
        if n < 0x80 then
            return string.char(n)
        elseif n < 0x800 then
            return string.char(0xC0 + math.floor(n/64), 0x80 + n%64)
        elseif n < 0x10000 then
            return string.char(0xE0 + math.floor(n/4096), 0x80 + math.floor(n/64)%64, 0x80 + n%64)
        else
            return string.char(
                0xF0 + math.floor(n/262144),
                0x80 + math.floor(n/4096)%64,
                0x80 + math.floor(n/64)%64,
                0x80 + n%64
            )
        end
    end)
    -- \xXX hex escapes
    result = string.gsub(result, "\\x(%x%x)", function(hex)
        changed = true
        return string.char(tonumber(hex, 16) or 0)
    end)
    if not changed then return nil end
    return result
end

-- ── CRC32 ────────────────────────────────────────────────────────────────────
-- Standard CRC-32 (IEEE 802.3 polynomial: 0xEDB88320)

local CRC32_TABLE = {}
do
    for i = 0, 255 do
        local crc = i
        for _ = 1, 8 do
            if bw_and(crc, 1) == 1 then
                crc = bw_xor(bw_rshift(crc, 1), 0xEDB88320)
            else
                crc = bw_rshift(crc, 1)
            end
        end
        CRC32_TABLE[i] = crc
    end
end

local function crc32(s)
    if not s then return 0 end
    local crc = 0xFFFFFFFF
    for i = 1, #s do
        local b = string.byte(s, i)
        local idx = bw_and(bw_xor(crc, b), 0xFF)
        crc = bw_xor(bw_rshift(crc, 8), CRC32_TABLE[idx])
    end
    return bw_xor(crc, 0xFFFFFFFF)
end

-- ── Adler-32 ─────────────────────────────────────────────────────────────────

local function adler32(s)
    if not s then return 0 end
    local MOD_ADLER = 65521
    local a, b = 1, 0
    for i = 1, #s do
        a = (a + string.byte(s, i)) % MOD_ADLER
        b = (b + a) % MOD_ADLER
    end
    return b * 65536 + a
end

-- ── Fletcher-16 ──────────────────────────────────────────────────────────────

local function fletcher16(s)
    if not s then return 0 end
    local sum1, sum2 = 0, 0
    for i = 1, #s do
        sum1 = (sum1 + string.byte(s, i)) % 255
        sum2 = (sum2 + sum1) % 255
    end
    return sum2 * 256 + sum1
end

-- ── FNV-1a Hash ──────────────────────────────────────────────────────────────

local FNV_PRIME  = 16777619
local FNV_OFFSET = 2166136261

local function fnv1a_hash(s)
    if not s then return 0 end
    local hash = FNV_OFFSET
    for i = 1, #s do
        hash = bw_xor(hash, string.byte(s, i))
        -- Multiply by FNV prime (modular)
        hash = (hash * FNV_PRIME) % (2^32)
    end
    return hash
end

-- ── MD5 stub ─────────────────────────────────────────────────────────────────
-- Full MD5 implementation
local function md5(s)
    if not s then return nil end
    -- MD5 initialization values
    local A0 = 0x67452301
    local B0 = 0xefcdab89
    local C0 = 0x98badcfe
    local D0 = 0x10325476
    -- Pre-processing: adding padding bits
    local msg_len = #s
    local bit_len = msg_len * 8
    s = s .. "\128"  -- append bit '1' (0x80 byte)
    while #s % 64 ~= 56 do s = s .. "\0" end
    -- Append original length in bits as 64-bit LE
    local lo = bit_len % (2^32)
    local hi = math.floor(bit_len / (2^32))
    s = s .. string.char(
        lo % 256, math.floor(lo/256) % 256,
        math.floor(lo/65536) % 256, math.floor(lo/16777216) % 256,
        hi % 256, math.floor(hi/256) % 256,
        math.floor(hi/65536) % 256, math.floor(hi/16777216) % 256
    )
    -- Per-round shift amounts
    local R = {
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    }
    -- Pre-computed table of K constants
    local K = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    }
    local A, B, C, D = A0, B0, C0, D0
    -- Process each 512-bit (64-byte) chunk
    for chunk_start = 1, #s, 64 do
        local M = {}
        for i = 0, 15 do
            local p = chunk_start + i * 4
            M[i] = string.byte(s, p) +
                   string.byte(s, p+1) * 256 +
                   string.byte(s, p+2) * 65536 +
                   string.byte(s, p+3) * 16777216
        end
        local a, b, c, d = A, B, C, D
        for i = 0, 63 do
            local F, g
            if i < 16 then
                F = bw_or(bw_and(b, c), bw_and(bw_not(b), d))
                g = i
            elseif i < 32 then
                F = bw_or(bw_and(d, b), bw_and(bw_not(d), c))
                g = (5 * i + 1) % 16
            elseif i < 48 then
                F = bw_xor(bw_xor(b, c), d)
                g = (3 * i + 5) % 16
            else
                F = bw_xor(c, bw_or(b, bw_not(d)))
                g = (7 * i) % 16
            end
            F = u32(F + a + K[i+1] + M[g])
            a = d
            d = c
            c = b
            b = u32(b + bw_rol(F, R[i+1]))
        end
        A = u32(A + a)
        B = u32(B + b)
        C = u32(C + c)
        D = u32(D + d)
    end
    -- Output as hex string
    local function le32_hex(n)
        return string.format("%02x%02x%02x%02x",
            n % 256, math.floor(n/256) % 256,
            math.floor(n/65536) % 256, math.floor(n/16777216) % 256)
    end
    return le32_hex(A) .. le32_hex(B) .. le32_hex(C) .. le32_hex(D)
end

-- ── SHA-1 stub ────────────────────────────────────────────────────────────────
-- Simplified SHA-1 implementation

local function sha1(s)
    if not s then return nil end
    -- Initial hash values
    local H = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 }
    -- Pre-processing
    local msg_len = #s
    local bit_len = msg_len * 8
    s = s .. "\128"
    while #s % 64 ~= 56 do s = s .. "\0" end
    local hi = math.floor(bit_len / (2^32))
    local lo = bit_len % (2^32)
    s = s .. string.char(
        math.floor(hi / 16777216) % 256, math.floor(hi / 65536) % 256,
        math.floor(hi / 256) % 256, hi % 256,
        math.floor(lo / 16777216) % 256, math.floor(lo / 65536) % 256,
        math.floor(lo / 256) % 256, lo % 256
    )
    for chunk_start = 1, #s, 64 do
        local W = {}
        for t = 0, 15 do
            local p = chunk_start + t * 4
            W[t] = string.byte(s,p)*16777216 + string.byte(s,p+1)*65536 +
                   string.byte(s,p+2)*256     + string.byte(s,p+3)
        end
        for t = 16, 79 do
            W[t] = bw_rol(bw_xor(bw_xor(bw_xor(W[t-3], W[t-8]), W[t-14]), W[t-16]), 1)
        end
        local a, b, c, d, e = H[1], H[2], H[3], H[4], H[5]
        for t = 0, 79 do
            local f, k
            if t < 20 then
                f = bw_or(bw_and(b,c), bw_and(bw_not(b),d))
                k = 0x5A827999
            elseif t < 40 then
                f = bw_xor(bw_xor(b,c),d)
                k = 0x6ED9EBA1
            elseif t < 60 then
                f = bw_or(bw_or(bw_and(b,c), bw_and(b,d)), bw_and(c,d))
                k = 0x8F1BBCDC
            else
                f = bw_xor(bw_xor(b,c),d)
                k = 0xCA62C1D6
            end
            local temp = u32(bw_rol(a,5) + f + e + k + W[t])
            e = d ; d = c ; c = bw_rol(b,30) ; b = a ; a = temp
        end
        H[1] = u32(H[1]+a); H[2] = u32(H[2]+b); H[3] = u32(H[3]+c)
        H[4] = u32(H[4]+d); H[5] = u32(H[5]+e)
    end
    return string.format("%08x%08x%08x%08x%08x", H[1], H[2], H[3], H[4], H[5])
end

-- SHA-256 stub (returns a plausible-looking hash based on FNV)
local function sha256(s)
    if not s then return nil end
    -- This is a simplified stub; not cryptographically secure
    local h = fnv1a_hash(s)
    local h2 = fnv1a_hash(s .. "\xff")
    local h3 = fnv1a_hash(s .. "\x00")
    local h4 = fnv1a_hash("\x01" .. s)
    local h5 = fnv1a_hash(s .. "\x02")
    local h6 = fnv1a_hash(s .. "\x03")
    local h7 = fnv1a_hash(s .. "\x04")
    local h8 = fnv1a_hash("\x05" .. s)
    return string.format("%08x%08x%08x%08x%08x%08x%08x%08x",
        h, h2, h3, h4, h5, h6, h7, h8)
end

-- ── RC4 Stream Cipher ─────────────────────────────────────────────────────────
-- Full RC4 implementation (decrypt == encrypt due to symmetric nature)

local function rc4_decode(s, key)
    if not s or not key or #key == 0 then return nil end
    -- Key scheduling algorithm (KSA)
    local S = {}
    for i = 0, 255 do S[i] = i end
    local j = 0
    for i = 0, 255 do
        j = (j + S[i] + string.byte(key, i % #key + 1)) % 256
        S[i], S[j] = S[j], S[i]
    end
    -- Pseudo-random generation algorithm (PRGA) + XOR
    local result = {}
    local ii, jj = 0, 0
    for k = 1, #s do
        ii = (ii + 1) % 256
        jj = (jj + S[ii]) % 256
        S[ii], S[jj] = S[jj], S[ii]
        local keystroke = S[(S[ii] + S[jj]) % 256]
        table.insert(result, string.char(bw_xor(string.byte(s, k), keystroke)))
    end
    return table.concat(result)
end

-- ── XTEA Block Cipher ─────────────────────────────────────────────────────────
-- XTEA: eXtended TEA, 64-bit block, 128-bit key, 64 rounds

local function xtea_decode(data, key_table)
    if not data or not key_table then return nil end
    if #data % 8 ~= 0 then
        -- Pad with zeros
        data = data .. string.rep("\0", 8 - #data % 8)
    end
    if #key_table < 4 then
        while #key_table < 4 do table.insert(key_table, 0) end
    end
    local k = {
        key_table[1] or 0, key_table[2] or 0,
        key_table[3] or 0, key_table[4] or 0,
    }
    local DELTA = 0x9E3779B9
    local MASK  = 0xFFFFFFFF
    local result = {}
    for i = 1, #data, 8 do
        local b0, b1, b2, b3 = string.byte(data, i, i+3)
        local b4, b5, b6, b7 = string.byte(data, i+4, i+7)
        b0 = b0 or 0 ; b1 = b1 or 0 ; b2 = b2 or 0 ; b3 = b3 or 0
        b4 = b4 or 0 ; b5 = b5 or 0 ; b6 = b6 or 0 ; b7 = b7 or 0
        local v0 = b0*16777216 + b1*65536 + b2*256 + b3
        local v1 = b4*16777216 + b5*65536 + b6*256 + b7
        -- 64 rounds of XTEA decryption
        local sum = u32(DELTA * 32)
        for _ = 1, 32 do
            v1 = u32(v1 - (bw_xor(bw_xor(bw_lshift(v0,4), bw_rshift(v0,5)) + v0,
                                    sum + k[bw_and(bw_rshift(sum, 11), 3) + 1])))
            sum = u32(sum - DELTA)
            v0 = u32(v0 - (bw_xor(bw_xor(bw_lshift(v1,4), bw_rshift(v1,5)) + v1,
                                    sum + k[bw_and(sum, 3) + 1])))
        end
        table.insert(result, string.char(
            math.floor(v0 / 16777216) % 256, math.floor(v0 / 65536) % 256,
            math.floor(v0 / 256) % 256,      v0 % 256,
            math.floor(v1 / 16777216) % 256, math.floor(v1 / 65536) % 256,
            math.floor(v1 / 256) % 256,      v1 % 256
        ))
    end
    return table.concat(result)
end

-- ── zlib Header Stripper (stub) ───────────────────────────────────────────────
-- Strips the 2-byte zlib header to get raw DEFLATE data.
-- Full decompression is not implemented in pure Lua here.

local function zlib_strip_header(s)
    if not s or #s < 2 then return nil end
    local b1, b2 = string.byte(s, 1), string.byte(s, 2)
    -- CMF = b1, FLG = b2; zlib requires (CMF*256+FLG) % 31 == 0
    if (b1 * 256 + b2) % 31 == 0 then
        return string.sub(s, 3), "zlib"
    end
    return nil
end

-- LZ77 decompressor stub (returns nil – full implementation omitted)
local function lz77_decode(s)
    -- A full LZ77/LZW decompressor requires a significant amount of code.
    -- This stub detects common LZ77 magic bytes and returns nil to signal
    -- that decompression was attempted but not successful.
    if not s then return nil end
    -- Detect gzip magic: 1F 8B
    if string.byte(s, 1) == 0x1F and string.byte(s, 2) == 0x8B then
        return nil  -- gzip detected, cannot decompress in pure Lua
    end
    return nil
end

-- Deflate stub
local function deflate_decode(s)
    return nil  -- Not implemented; requires native extension or FFI
end

