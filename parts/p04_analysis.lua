
-- ============================================================
--  SECTION 9 – VM BOUNDARY SIGNATURES
--  Patterns that identify VM dispatch loops and bytecode regions.
--  These are used to detect whether the script is VM-obfuscated
--  (as opposed to just textually obfuscated).
-- ============================================================
local VM_BOUNDARY_SIGS = {
    -- Dispatch loop patterns: characteristic while/for + indexing combos
    { name = "dispatch_while_infinite",  pattern = r"while true do.*end",         desc = "Infinite dispatch loop" },
    { name = "dispatch_for_ip",          pattern = r"for%s+ip%s*=",               desc = "Instruction pointer for-loop" },
    { name = "dispatch_opcode_index",    pattern = r"opcodes%[ip%]",              desc = "Opcode table indexing" },
    { name = "dispatch_instruction_arr", pattern = r"instructions%[%d+%]",        desc = "Instruction array access" },
    { name = "dispatch_pc_var",          pattern = r"local%s+pc%s*=%s*1",         desc = "Program counter local var" },
    { name = "dispatch_ip_inc",          pattern = r"ip%s*=%s*ip%s*%+%s*1",      desc = "Instruction pointer increment" },
    { name = "dispatch_big_if_chain",    pattern = r"if%s+op%s*==%s*%d+",        desc = "Large if-chain dispatch" },
    { name = "dispatch_op_table",        pattern = r"opcode_handlers%[op%]",      desc = "Opcode handler table" },
    { name = "dispatch_func_table",      pattern = r"vm_ops%[op%]%()",            desc = "VM ops function dispatch" },
    { name = "vm_stack_push",            pattern = r"stack%[sp%]%s*=",            desc = "VM stack push" },
    { name = "vm_stack_pop",             pattern = r"stack%[sp%s*%-%s*1%]",       desc = "VM stack pop" },
    { name = "vm_register_file",         pattern = r"regs%[%a+%]",               desc = "VM register file" },
    { name = "vm_constant_pool",         pattern = r"constants%[%d+%]",           desc = "VM constant pool access" },
    { name = "vm_proto_table",           pattern = r"protos%[%d+%]",             desc = "VM proto table" },
    { name = "vm_upval_table",           pattern = r"upvals%[%d+%]",             desc = "VM upvalue table" },
    { name = "vm_closure_create",        pattern = r"setmetatable%({},",          desc = "VM closure creation via mt" },
    { name = "vm_env_wrap",              pattern = r"setfenv%(func,",             desc = "VM environment wrapping" },
    { name = "vm_bytecode_string",       pattern = r'\\27Lua',                    desc = "Embedded Lua bytecode" },
    { name = "vm_luau_bytecode",         pattern = r"\\27LuaQ",                  desc = "Embedded Luau bytecode" },
    { name = "vm_large_string_pool",     pattern = r"= {%s*\"%x+\"",             desc = "Large hex-encoded string pool" },
    { name = "vm_bit_operations",        pattern = r"bit%.band%b()",             desc = "Bit library in dispatch" },
    { name = "vm_select_vararg",         pattern = r"select%(#,{%s*}%s*%)",      desc = "Select vararg pattern" },
    { name = "vm_long_string_lit",       pattern = r'".{300,}"',                  desc = "Very long string literal" },
    { name = "vm_string_byte_seq",       pattern = r"string%.byte.*string%.char", desc = "byte/char transform sequence" },
    { name = "vm_number_arithmetic",     pattern = r"%d+%s*%+%s*%d+%s*%*%s*%d+", desc = "Complex numeric arithmetic" },
    { name = "vm_getfenv_0",             pattern = r"getfenv%(0%)",               desc = "getfenv(0) global access" },
    { name = "vm_rawget_env",            pattern = r"rawget%(env,",               desc = "rawget on environment" },
    { name = "vm_debug_getinfo",         pattern = r"debug%.getinfo",             desc = "Debug getinfo in dispatch" },
    { name = "vm_loadstring_b64",        pattern = r"loadstring%(.*b64",          desc = "loadstring with base64" },
    { name = "vm_xor_decode",            pattern = r"bxor%b()",                  desc = "XOR in decode loop" },
    { name = "vm_table_concat_loop",     pattern = r"for.*table%.insert.*char",  desc = "Table-concat char loop" },
    { name = "vm_math_floor_index",      pattern = r"math%.floor%(.*/%s*%d+",    desc = "Math.floor indexing (VM opcode extract)" },
    { name = "vm_tonumber_base",         pattern = r"tonumber%([^,]+,%s*%d+%)",  desc = "tonumber with base (number decoding)" },
    { name = "vm_pcall_chunk",           pattern = r"pcall%(chunk,",             desc = "pcall chunk execution" },
    { name = "vm_env_sandbox",           pattern = r"setmetatable%(env,",        desc = "Environment sandboxing" },
    { name = "vm_hash_check",            pattern = r"== 0x%x%x%x%x%x%x%x%x",   desc = "Hash integrity check" },
    { name = "vm_anti_tamper",           pattern = r"anti_tamper",               desc = "Explicit anti-tamper label" },
    { name = "vm_wrap_env",              pattern = r"setfenv%(1,",               desc = "setfenv(1,...) environment wrap" },
    { name = "vm_coroutine_wrap",        pattern = r"coroutine%.wrap%(function", desc = "Coroutine-based VM execution" },
    { name = "vm_repeat_loop",           pattern = r"repeat.*until.*true",       desc = "Repeat-until true loop (obf pattern)" },
    { name = "vm_goto_dispatch",         pattern = r"goto%s+dispatch",           desc = "Goto-based dispatch (Lua 5.2+)" },
    { name = "vm_jmp_table",             pattern = r"jmp_table%[",              desc = "Jump table for opcode dispatch" },
    { name = "vm_obf_string_table",      pattern = r'local%s+t%s*=%s*{"',       desc = "Obfuscated string table init" },
    { name = "vm_base64_embedded",       pattern = r'"[A-Za-z0-9+/]{64,}={0,2}"', desc = "Large base64 string literal" },
    { name = "vm_hex_string_embedded",   pattern = r'"[0-9a-fA-F]{64,}"',       desc = "Large hex string literal" },
    { name = "vm_number_array",          pattern = r"= {%s*%d+,%s*%d+,%s*%d+", desc = "Large number array (const pool)" },
    { name = "vm_function_wrap",         pattern = r"%(function%(%.%.%.%)",      desc = "IIFE with vararg (VM wrapper)" },
    { name = "vm_iife_call",             pattern = r"%(function%(%).*end%)%(%)$", desc = "Immediately invoked function" },
    { name = "vm_string_rep",            pattern = r"string%.rep%(%S+,",         desc = "string.rep for padding" },
    { name = "vm_rawset_global",         pattern = r"rawset%(_G,",              desc = "rawset on _G (global injection)" },
}

-- ============================================================
--  SECTION 10 – OBFUSCATOR DETECTION
--  Matches the source against OBFUSCATOR_FINGERPRINTS and
--  VM_BOUNDARY_SIGS to identify the obfuscator used.
-- ============================================================

-- How many patterns from an entry must match to flag it?
local FINGERPRINT_MIN_MATCH = 2

local function detect_obfuscator(src)
    if not src or #src == 0 then return nil, 0 end
    -- Try each fingerprint entry
    local best_name  = nil
    local best_score = 0
    for _, entry in ipairs(OBFUSCATOR_FINGERPRINTS) do
        local score = 0
        for _, pat in ipairs(entry.patterns) do
            local ok, found = _native_pcall(string.find, src, pat)
            if ok and found then
                score = score + 1
            end
        end
        if score >= FINGERPRINT_MIN_MATCH and score > best_score then
            best_score = score
            best_name  = entry.name
        end
    end
    -- Count VM boundary signatures
    local vm_sig_count = 0
    for _, sig in ipairs(VM_BOUNDARY_SIGS) do
        local ok, found = _native_pcall(string.find, src, sig.pattern)
        if ok and found then vm_sig_count = vm_sig_count + 1 end
    end
    return best_name, best_score, vm_sig_count
end

-- ============================================================
--  SECTION 11 – OBFUSCATION SCORING
--  Computes a normalised 0–1 score indicating how obfuscated the
--  source is, using 30+ independent metrics.
-- ============================================================

-- Individual metric functions (each returns a 0–1 sub-score)

-- Metric: Shannon entropy (higher = more random = more obfuscated)
local function metric_entropy(src)
    local e = shannon_entropy(src)
    -- Typical Lua: ~4.5 bits; highly obfuscated: ~6+ bits
    return math.min(1, math.max(0, (e - 3.5) / 3.0))
end

-- Metric: Non-ASCII character density
local function metric_nonascii(src)
    local count = 0
    for i = 1, #src do
        if string.byte(src, i) > 127 then count = count + 1 end
    end
    return math.min(1, count / math.max(1, #src) * 10)
end

-- Metric: Null byte density
local function metric_nullbytes(src)
    local count = 0
    for i = 1, #src do
        if string.byte(src, i) == 0 then count = count + 1 end
    end
    return math.min(1, count / math.max(1, #src) * 20)
end

-- Metric: Escape sequence density (\xXX, \ddd patterns)
local function metric_escapes(src)
    local _, n1 = string.gsub(src, "\\x%x%x", "")
    local _, n2 = string.gsub(src, "\\%d%d%d", "")
    local n = n1 + n2
    return math.min(1, n / math.max(1, #src / 10))
end

-- Metric: Average line length (long lines = obfuscated)
local function metric_line_length(src)
    local lines = {}
    for line in string.gmatch(src, "([^\n]*)") do
        table.insert(lines, #line)
    end
    if #lines == 0 then return 0 end
    local avg = stat_mean(lines)
    -- Normal Lua: avg ~40 chars; obfuscated: can be 1000+
    return math.min(1, math.max(0, (avg - 40) / 960))
end

-- Metric: Max single line length
local function metric_max_line(src)
    local max_len = 0
    for line in string.gmatch(src, "([^\n]*)") do
        if #line > max_len then max_len = #line end
    end
    return math.min(1, max_len / 10000)
end

-- Metric: Identifier name length distribution (short names = obfuscated)
local function metric_ident_length(src)
    local total_len, count = 0, 0
    for ident in string.gmatch(src, "[%a_][%w_]*") do
        total_len = total_len + #ident
        count = count + 1
    end
    if count == 0 then return 0 end
    local avg = total_len / count
    -- Normal code: avg 8+ chars; obfuscated: avg 1-2 chars
    return math.min(1, math.max(0, (4 - avg) / 3))
end

-- Metric: String literal density (high density = likely obfuscated data)
local function metric_string_density(src)
    local _, string_chars = string.gsub(src, '"[^"]*"', function(s) return s end)
    local _, n_strings = string.gsub(src, '"[^"]*"', "")
    return math.min(1, n_strings / math.max(1, #src / 100))
end

-- Metric: Numeric literal density
local function metric_numeric_density(src)
    local _, n = string.gsub(src, "%d+", "")
    return math.min(1, n / math.max(1, #src / 20))
end

-- Metric: Compression ratio estimate (lower = already compressed/encrypted)
local function metric_compression(src)
    -- Estimate by counting repeated 4-grams
    local grams = {}
    local total, unique = 0, 0
    for i = 1, #src - 3 do
        local g = string.sub(src, i, i + 3)
        total = total + 1
        if not grams[g] then
            grams[g] = true
            unique = unique + 1
        end
    end
    if total == 0 then return 0 end
    -- Low ratio of unique/total = lots of repetition = not compressed
    -- High ratio = random-looking = possibly compressed/encrypted
    local uniqueness = unique / total
    return math.min(1, math.max(0, (uniqueness - 0.5) / 0.5))
end

-- Metric: Comment density (low = obfuscated)
local function metric_comment_density(src)
    local _, n_single = string.gsub(src, "%-%-[^\n]*", "")
    local _, n_long   = string.gsub(src, "%-%-%[%[.-%]%]", "")
    local total = n_single + n_long
    -- Normal code has >5% comment lines
    local comment_frac = total * 30 / math.max(1, #src)
    return math.min(1, math.max(0, 1 - comment_frac * 5))
end

-- Metric: Keyword frequency (low keyword density = obfuscated)
local LUA_KEYWORDS = {
    "and", "break", "do", "else", "elseif", "end", "false",
    "for", "function", "goto", "if", "in", "local", "nil",
    "not", "or", "repeat", "return", "then", "true", "until", "while"
}
local function metric_keyword_density(src)
    local count = 0
    for _, kw in ipairs(LUA_KEYWORDS) do
        local _, n = string.gsub(src, "%f[%w_]" .. kw .. "%f[^%w_]", "")
        count = count + n
    end
    -- Normal code: ~5% keywords; obfuscated: ~1% or less
    local density = count / math.max(1, #src / 5)
    return math.min(1, math.max(0, 1 - density * 3))
end

-- Metric: loadstring / load usage
local function metric_loadstring(src)
    local _, n = string.gsub(src, "loadstring%s*%(", "")
    local _, n2 = string.gsub(src, "[^%w]load%s*%(", "")
    return math.min(1, (n + n2) / 5)
end

-- Metric: getfenv / setfenv usage
local function metric_fenv(src)
    local _, n1 = string.gsub(src, "getfenv%s*%(", "")
    local _, n2 = string.gsub(src, "setfenv%s*%(", "")
    return math.min(1, (n1 + n2) / 5)
end

-- Metric: string.byte / string.char density
local function metric_bytechr(src)
    local _, n1 = string.gsub(src, "string%.byte", "")
    local _, n2 = string.gsub(src, "string%.char", "")
    local _, n3 = string.gsub(src, "string%.byte", "")
    return math.min(1, (n1 + n2) / math.max(1, #src / 200))
end

-- Metric: Table constructor density (many anonymous tables = data encoding)
local function metric_table_density(src)
    local _, n = string.gsub(src, "{", "")
    return math.min(1, n / math.max(1, #src / 50))
end

-- Metric: Nesting depth (deeply nested = obfuscated)
local function metric_nesting(src)
    local max_depth, depth = 0, 0
    for i = 1, #src do
        local c = string.sub(src, i, i)
        if c == "(" or c == "{" or c == "[" then
            depth = depth + 1
            if depth > max_depth then max_depth = depth end
        elseif c == ")" or c == "}" or c == "]" then
            depth = math.max(0, depth - 1)
        end
    end
    return math.min(1, max_depth / 50)
end

-- Metric: getfenv(0) or rawget(_G presence
local function metric_env_probe(src)
    local _, n1 = string.gsub(src, "getfenv%(0%)", "")
    local _, n2 = string.gsub(src, "rawget%(_G,", "")
    local _, n3 = string.gsub(src, "rawget%(env,", "")
    return math.min(1, (n1 + n2 + n3) / 3)
end

-- Metric: rawget / rawset usage (bypassing metamethods)
local function metric_rawaccess(src)
    local _, n1 = string.gsub(src, "rawget%s*%(", "")
    local _, n2 = string.gsub(src, "rawset%s*%(", "")
    return math.min(1, (n1 + n2) / 10)
end

-- Metric: debug library usage
local function metric_debug_lib(src)
    local _, n = string.gsub(src, "debug%.", "")
    return math.min(1, n / 5)
end

-- Metric: Metamethod count (__index, __newindex, __call, etc.)
local function metric_metamethods(src)
    local metamethods = {
        "__index", "__newindex", "__call", "__len",
        "__eq", "__lt", "__le", "__concat", "__unm",
        "__add", "__sub", "__mul", "__div", "__mod",
        "__pow", "__tostring", "__metatable", "__gc",
    }
    local count = 0
    for _, mm in ipairs(metamethods) do
        local _, n = string.gsub(src, mm, "")
        count = count + n
    end
    return math.min(1, count / 10)
end

-- Metric: pcall / xpcall usage (error suppression)
local function metric_pcall(src)
    local _, n1 = string.gsub(src, "[^%w]pcall%s*%(", "")
    local _, n2 = string.gsub(src, "xpcall%s*%(", "")
    return math.min(1, (n1 + n2) / 20)
end

-- Metric: Presence of long hex/base64 literals
local function metric_encoded_strings(src)
    local count = 0
    -- Look for strings of 64+ hex chars
    for _ in string.gmatch(src, '"[0-9a-fA-F]{64,}"') do count = count + 1 end
    -- Look for base64 strings
    for _ in string.gmatch(src, '"[A-Za-z0-9+/]{64,}={0,2}"') do count = count + 1 end
    return math.min(1, count / 3)
end

-- Metric: Operator density (lots of operators = complex expressions)
local function metric_operator_density(src)
    local _, n1 = string.gsub(src, "%+", "")
    local _, n2 = string.gsub(src, "%-", "")
    local _, n3 = string.gsub(src, "%*", "")
    local _, n4 = string.gsub(src, "/", "")
    local _, n5 = string.gsub(src, "%%", "")
    local total = n1 + n2 + n3 + n4 + n5
    return math.min(1, total / math.max(1, #src / 20))
end

-- Metric: goto usage (rare in normal code)
local function metric_goto(src)
    local _, n = string.gsub(src, "%f[%w_]goto%f[^%w_]", "")
    return math.min(1, n / 5)
end

-- Metric: require density (high require = modular, low = self-contained/obf)
local function metric_require(src)
    local _, n = string.gsub(src, "[^%w]require%s*%(", "")
    -- Very few requires in obfuscated code (it's self-contained)
    -- Moderate requires in normal code
    if n == 0 then return 0.3 end  -- no requires = slightly suspicious
    return 0
end

-- Metric: Bytecode magic bytes presence
local function metric_bytecode(src)
    if string.find(src, "\027Lua", 1, true) then return 1.0 end
    if string.find(src, "\027LuaQ", 1, true) then return 1.0 end
    return 0
end

-- Metric: VM boundary signature count
local function metric_vm_sigs(src)
    local count = 0
    for _, sig in ipairs(VM_BOUNDARY_SIGS) do
        local ok, found = _native_pcall(string.find, src, sig.pattern)
        if ok and found then count = count + 1 end
    end
    return math.min(1, count / 10)
end

-- Metric: math.floor/ceil density (used in VM instruction decode)
local function metric_math_ops(src)
    local _, n1 = string.gsub(src, "math%.floor%s*%(", "")
    local _, n2 = string.gsub(src, "math%.ceil%s*%(", "")
    local _, n3 = string.gsub(src, "math%.fmod%s*%(", "")
    return math.min(1, (n1 + n2 + n3) / math.max(1, #src / 1000))
end

-- Metric: whitespace pattern (single-line scripts)
local function metric_whitespace(src)
    local _, newlines = string.gsub(src, "\n", "")
    if newlines == 0 then return 1.0 end  -- single-line = minified
    local avg_line = #src / (newlines + 1)
    return math.min(1, math.max(0, (avg_line - 80) / 920))
end

-- Weights for each metric (must sum to 1.0)
local SCORE_METRICS = {
    { fn = metric_entropy,          weight = 0.10, name = "entropy"          },
    { fn = metric_nonascii,         weight = 0.04, name = "non_ascii"        },
    { fn = metric_nullbytes,        weight = 0.03, name = "null_bytes"       },
    { fn = metric_escapes,          weight = 0.03, name = "escape_sequences" },
    { fn = metric_line_length,      weight = 0.05, name = "line_length"      },
    { fn = metric_max_line,         weight = 0.04, name = "max_line"         },
    { fn = metric_ident_length,     weight = 0.07, name = "ident_length"     },
    { fn = metric_string_density,   weight = 0.03, name = "string_density"   },
    { fn = metric_numeric_density,  weight = 0.02, name = "numeric_density"  },
    { fn = metric_compression,      weight = 0.05, name = "compression"      },
    { fn = metric_comment_density,  weight = 0.04, name = "comment_density"  },
    { fn = metric_keyword_density,  weight = 0.07, name = "keyword_density"  },
    { fn = metric_loadstring,       weight = 0.04, name = "loadstring"       },
    { fn = metric_fenv,             weight = 0.03, name = "fenv_usage"       },
    { fn = metric_bytechr,          weight = 0.03, name = "byte_char"        },
    { fn = metric_table_density,    weight = 0.02, name = "table_density"    },
    { fn = metric_nesting,          weight = 0.03, name = "nesting_depth"    },
    { fn = metric_env_probe,        weight = 0.02, name = "env_probe"        },
    { fn = metric_rawaccess,        weight = 0.02, name = "raw_access"       },
    { fn = metric_debug_lib,        weight = 0.02, name = "debug_lib"        },
    { fn = metric_metamethods,      weight = 0.02, name = "metamethods"      },
    { fn = metric_pcall,            weight = 0.02, name = "pcall_density"    },
    { fn = metric_encoded_strings,  weight = 0.04, name = "encoded_strings"  },
    { fn = metric_operator_density, weight = 0.02, name = "operator_density" },
    { fn = metric_goto,             weight = 0.01, name = "goto_usage"       },
    { fn = metric_require,          weight = 0.01, name = "require_density"  },
    { fn = metric_bytecode,         weight = 0.04, name = "bytecode_marker"  },
    { fn = metric_vm_sigs,          weight = 0.05, name = "vm_signatures"    },
    { fn = metric_math_ops,         weight = 0.02, name = "math_ops"         },
    { fn = metric_whitespace,       weight = 0.04, name = "whitespace"       },
}

-- Compute weighted obfuscation score
local function score_obfuscation(src)
    if not src or #src == 0 then return 0, {} end
    local total_score = 0
    local details = {}
    for _, m in ipairs(SCORE_METRICS) do
        local ok, sub = _native_pcall(m.fn, src)
        if ok and type(sub) == "number" then
            sub = math.max(0, math.min(1, sub))
        else
            sub = 0
        end
        total_score = total_score + sub * m.weight
        details[m.name] = sub
    end
    return math.min(1, total_score), details
end

-- ============================================================
--  SECTION 12 – STRING POOL EXTRACTOR
--  Extracts the obfuscator's string pool from the source header.
-- ============================================================

-- Common string pool patterns:
--   local t = {"str1", "str2", ...}
--   local pool = {...}

local function extract_string_pool(src)
    local pool = {}
    -- Pattern 1: local var = {"...", "...", ...}  (common in IronBrew)
    for block in string.gmatch(src, "{([^{}]*)}" ) do
        local found_strings = false
        for s in string.gmatch(block, '"([^"]*)"') do
            if #s >= CFG.MIN_DEOBF_LENGTH then
                table.insert(pool, s)
                found_strings = true
            end
        end
        if found_strings and #pool > 50 then break end
    end
    -- Pattern 2: string.char(...) sequences
    for char_seq in string.gmatch(src, "string%.char%(([%d,]+)%)") do
        local chars = {}
        for n in string.gmatch(char_seq, "%d+") do
            local num = tonumber(n)
            if num and num >= 1 and num <= 255 then
                table.insert(chars, string.char(num))
            end
        end
        if #chars > 0 then
            table.insert(pool, table.concat(chars))
        end
    end
    -- Pattern 3: Hex-encoded strings
    for hex_s in string.gmatch(src, '"([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)"') do
        local decoded = hex_decode(hex_s)
        if decoded and is_readable(decoded) then
            table.insert(pool, decoded)
        elseif #hex_s >= 8 then
            table.insert(pool, "[hex:" .. #hex_s .. "]" .. string.sub(hex_s, 1, 32))
        end
    end
    -- Pattern 4: Base64 strings
    for b64_s in string.gmatch(src, '"([A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/][A-Za-z0-9+/=]+)"') do
        if #b64_s >= 12 and #b64_s % 4 == 0 then
            local decoded = b64_decode(b64_s)
            if decoded and is_readable(decoded) then
                table.insert(pool, decoded)
            end
        end
    end
    -- Remove duplicates
    local seen = {}
    local unique = {}
    for _, s in ipairs(pool) do
        if not seen[s] then
            seen[s] = true
            table.insert(unique, s)
        end
    end
    return unique
end

-- ============================================================
--  SECTION 13 – MULTI-PASS DECODER ENGINE
--  Attempts every known decoder in sequence and picks the
--  best readable result. Chains up to MAX_DECODE_PASSES passes.
-- ============================================================

-- Registry of all available decoders
-- Each entry: { name, fn(s) → decoded|nil }
local DECODERS = {
    -- Encoding-based
    { name = "base64",           fn = b64_decode          },
    { name = "base64url",        fn = b64_url_decode      },
    { name = "hex",              fn = hex_decode          },
    { name = "url",              fn = url_decode          },
    { name = "html",             fn = html_decode         },
    { name = "base32",           fn = b32_decode          },
    { name = "base58",           fn = b58_decode          },
    { name = "base85",           fn = b85_decode          },
    { name = "uuencode",         fn = uuencode_decode     },
    { name = "quoted-printable", fn = qp_decode           },
    -- Cipher-based
    { name = "rot13",            fn = rot13_decode        },
    { name = "rot47",            fn = rot47_decode        },
    { name = "rot18",            fn = rot18_decode        },
    { name = "rot5",             fn = rot5_decode         },
    { name = "atbash",           fn = atbash_decode       },
    -- Structural
    { name = "bitrev",           fn = bitrev_decode       },
    { name = "byterev",          fn = byterev_decode      },
    { name = "null_strip",       fn = null_strip          },
    -- Escape/encoding transforms
    { name = "unicode_escape",   fn = unicode_escape_decode },
    { name = "octal",            fn = octal_decode        },
    { name = "binary",           fn = binary_decode       },
    -- Protocol
    { name = "morse",            fn = morse_decode        },
    { name = "nato",             fn = nato_decode         },
    -- Compression stubs
    { name = "zlib_strip",       fn = zlib_strip_header   },
}

-- Score a decoded result's quality (higher = better)
local function score_decode_result(decoded, original)
    if not decoded then return -1 end
    if #decoded == 0 then return -2 end
    if decoded == original then return -3 end  -- no change

    local score = 0
    -- Readability
    if is_readable(decoded) then score = score + 100 end
    -- Lua code
    if looks_like_lua(decoded) then score = score + 200 end
    -- Length is reasonable
    if #decoded >= CFG.MIN_DEOBF_LENGTH then score = score + 10 end
    -- Lower entropy (more structured)
    local e = shannon_entropy(decoded)
    score = score + math.max(0, (5 - e) * 20)
    -- Shorter than original = likely decompressed
    if #decoded < #original then score = score + 5 end
    -- Has printable chars
    local printable = 0
    for i = 1, math.min(64, #decoded) do
        local b = string.byte(decoded, i)
        if b >= 32 and b <= 126 then printable = printable + 1 end
    end
    score = score + printable * 2
    return score
end

-- Single-pass decode: try every decoder and return best result
local function try_all_decoders(s, exclude)
    if not s or #s < CFG.MIN_DEOBF_LENGTH then return nil, nil end
    exclude = exclude or {}
    local best_score  = 0
    local best_result = nil
    local best_name   = nil
    for _, dec in ipairs(DECODERS) do
        if not exclude[dec.name] then
            local ok, result = _native_pcall(dec.fn, s)
            if ok and result and type(result) == "string" then
                local sc = score_decode_result(result, s)
                if sc > best_score then
                    best_score  = sc
                    best_result = result
                    best_name   = dec.name
                end
            end
        end
    end
    -- Also try XOR brute-force
    if not exclude["xor_crack"] then
        local ok, xored, xname = _native_pcall(try_xor_crack, s)
        if ok and xored then
            local sc = score_decode_result(xored, s)
            if sc > best_score then
                best_score  = sc
                best_result = xored
                best_name   = xname or "xor_crack"
            end
        end
    end
    if best_score > 0 then
        return best_result, best_name
    end
    return nil, nil
end

-- Multi-pass decode: repeatedly apply decoders until readable or max passes
local function multi_decode(s)
    if not s or #s < CFG.MIN_DEOBF_LENGTH then return nil, {} end
    local chain   = {}
    local current = s
    local used    = {}
    for pass = 1, CFG.MAX_DEOBF_PASSES do
        local decoded, name = try_all_decoders(current, used)
        if decoded and decoded ~= current then
            table.insert(chain, name)
            used[name] = true  -- Don't re-use same decoder in next pass
            current = decoded
            if is_readable(current) then
                return current, chain
            end
        else
            -- Try RC4 with common keys
            local common_rc4_keys = {
                "key", "secret", "password", "1234", "0000",
                "roblox", "admin", "hack", "cheat",
            }
            local found_rc4 = false
            for _, k in ipairs(common_rc4_keys) do
                local dec_ok, dec = _native_pcall(rc4_decode, current, k)
                if dec_ok and dec and is_readable(dec) then
                    table.insert(chain, "rc4:" .. k)
                    current = dec
                    found_rc4 = true
                    break
                end
            end
            if not found_rc4 then break end
        end
    end
    if current ~= s and is_readable(current) then
        return current, chain
    end
    return nil, chain
end

-- Decode with entropy guidance (only attempts if high entropy)
local function entropy_guided_decode(s)
    if not s then return nil, nil end
    local e = shannon_entropy(s)
    if e < CFG.LOW_ENTROPY_THRESHOLD then
        -- Already low entropy = probably plaintext
        return s, {"plaintext"}
    end
    if e >= CFG.HIGH_ENTROPY_THRESHOLD then
        -- High entropy = likely encoded/encrypted
        return multi_decode(s)
    end
    -- Medium entropy: try simple transforms first
    local result, name = try_all_decoders(s, {xor_crack = true})
    if result and result ~= s then
        return result, {name}
    end
    return multi_decode(s)
end

-- ============================================================
--  SECTION 14 – STRING ANALYSIS
--  Analyses individual strings for suspicious patterns.
-- ============================================================

-- Patterns for suspicious string content
local SUSPICIOUS_PATTERNS = {
    -- Network-related
    { name = "discord_webhook",    pattern = "discord%.com/api/webhooks/",       risk = 30 },
    { name = "http_url",           pattern = "https?://[%w%.%-]+/",              risk = 10 },
    { name = "ip_address",         pattern = "%d+%.%d+%.%d+%.%d+",              risk = 10 },
    { name = "pastebin",           pattern = "pastebin%.com/raw",                risk = 15 },
    { name = "raw_github",         pattern = "raw%.githubusercontent%.com",      risk = 10 },
    -- Authentication
    { name = "token",              pattern = "token%s*=",                        risk = 20 },
    { name = "cookie",             pattern = "%.ROBLOSECURITY",                  risk = 35 },
    { name = "bearer",             pattern = "Bearer%s+",                        risk = 20 },
    { name = "api_key",            pattern = "api[_%-]key",                      risk = 15 },
    -- Executor / environment probing
    { name = "getfenv_probe",      pattern = "getfenv%(0%)",                     risk = 10 },
    { name = "debug_probe",        pattern = "debug%.getinfo",                   risk = 10 },
    { name = "rawget_G",           pattern = "rawget%(_G,",                      risk = 8  },
    -- Dangerous functions
    { name = "loadstring_call",    pattern = "loadstring%s*%(\"",                risk = 20 },
    { name = "queue_teleport",     pattern = "queue_on_teleport",                risk = 25 },
    { name = "hookfunction",       pattern = "hookfunction%s*(",                 risk = 20 },
    { name = "hookmetamethod",     pattern = "hookmetamethod%s*(",               risk = 20 },
    { name = "getrawmetatable",    pattern = "getrawmetatable%s*(",              risk = 10 },
    -- Keylogging
    { name = "keydown",            pattern = "UserInputService.*KeyDown",        risk = 15 },
    { name = "input_began",        pattern = "InputBegan.*KeyCode",              risk = 10 },
    -- Roblox-specific risks
    { name = "remote_fire",        pattern = "FireServer%s*(",                   risk = 5  },
    { name = "remote_invoke",      pattern = "InvokeServer%s*(",                 risk = 5  },
    { name = "http_request",       pattern = "HttpService.*RequestAsync",        risk = 15 },
    { name = "execute_script",     pattern = "ExecuteScript%s*(",               risk = 20 },
    -- Data exfiltration
    { name = "send_data",          pattern = "PostAsync.*{",                     risk = 20 },
    { name = "getplayer_info",     pattern = "GetPlayerByUserId",               risk = 5  },
    { name = "player_userid",      pattern = "LocalPlayer.UserId",              risk = 10 },
    -- Anti-debug
    { name = "detect_hook",        pattern = "newcclosure",                     risk = 10 },
    { name = "is_closure",         pattern = "islclosure",                      risk = 5  },
    { name = "compare_instances",  pattern = "compareinstances",                risk = 5  },
}

-- Analyse a single string for suspicious patterns
local function analyse_string(s)
    if not s then return {}, 0 end
    local flags = {}
    local risk  = 0
    for _, sp in ipairs(SUSPICIOUS_PATTERNS) do
        if string.find(s, sp.pattern) then
            table.insert(flags, sp.name)
            risk = risk + sp.risk
        end
    end
    return flags, math.min(100, risk)
end

-- Cluster strings by encoding type
local function classify_string(s)
    if not s or #s == 0 then return "empty" end
    local enc = detect_encoding(s)
    if enc ~= "unknown" then return enc end
    local e = shannon_entropy(s)
    if e >= 6.5 then return "encrypted" end
    if e >= 5.0 then return "high_entropy" end
    if is_readable(s) then return "readable" end
    return "binary"
end

-- Detect URLs in a string
local function find_urls(s)
    if not s then return {} end
    local urls = {}
    for url in string.gmatch(s, "https?://[%w%.%-/%%?=&#_~:@!$&'()*+,;]+") do
        table.insert(urls, url)
    end
    for url in string.gmatch(s, "wss?://[%w%.%-/%%?=&#_~:@!$&'()*+,;]+") do
        table.insert(urls, url)
    end
    return urls
end

-- Detect IP addresses in a string
local function find_ips(s)
    if not s then return {} end
    local ips = {}
    for ip in string.gmatch(s, "(%d+%.%d+%.%d+%.%d+)") do
        -- Validate ranges
        local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if a and b and c and d and
           a <= 255 and b <= 255 and c <= 255 and d <= 255 then
            table.insert(ips, ip)
        end
    end
    return ips
end

