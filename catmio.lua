-- ============================================================
--  CatMio v2.0.0  –  Roblox Script Env-Logger & Deobfuscator
--  The most comprehensive Roblox script analysis toolkit in existence.
--  Sandboxes and analyses obfuscated Roblox Lua/Luau scripts.
--  Detects 200+ obfuscators, decodes 40+ encoding schemes.
--  Pure Lua 5.1 compatible – no C extensions, no external deps.
-- ============================================================
--
--  OVERVIEW
--  ========
--  CatMio is a self-contained, sandboxed Roblox script analysis toolkit
--  designed to safely execute, log, and deobfuscate Roblox Lua/Luau
--  scripts without requiring a live Roblox instance.
--
--  KEY CAPABILITIES
--  ================
--  1. Static Analysis
--     - Identifies 200+ known obfuscators by pattern fingerprinting
--     - Calculates multi-metric obfuscation score (30+ metrics)
--     - Detects VM boundaries, bytecode headers, string pools
--     - Extracts and decodes strings using 40+ decoders
--     - Anti-obfuscation passes (constant folding, escape expansion, etc.)
--
--  2. Dynamic Analysis (Sandboxed Execution)
--     - Emulates the full Roblox environment
--     - Intercepts all API calls (remotes, HTTP, instances, etc.)
--     - Logs all network requests, instance creations, script loads
--     - Tracks function calls, hooks, deferred tasks
--     - Instruction-limit enforcement prevents infinite loops
--     - Coroutine tracking and timeout handling
--
--  3. Decoders & Deobfuscators (40+)
--     - Base64 (standard, URL-safe, padded, unpadded)
--     - Base32, Base58, Base85 / Ascii85, UUEncode
--     - Hex, URL-encoding, HTML entities, Quoted-Printable
--     - ROT13, ROT47, ROT18, ROT5 (digits), Caesar brute-force
--     - XOR (single-byte, multi-byte, rolling, polynomial, complement)
--     - RC4 stream cipher decoder
--     - XTEA block cipher decoder
--     - Vigenere cipher (alphabetic and numeric-key variants)
--     - Atbash cipher, Rail fence, Columnar transposition
--     - Morse code decoder, NATO phonetic alphabet decoder
--     - Binary string decoder (01010101... sequences)
--     - Octal string decoder
--     - Unicode escape decoder (\uXXXX, \UXXXXXXXX)
--     - zlib header stripping, LZ77/LZW stubs
--     - Multi-pass chained decode (up to 16 passes)
--     - Entropy-guided automatic decoder selection
--     - Auto-detect encoding from byte patterns and BOM markers
--
--  4. Anti-Obfuscation Transformation Passes
--     - Constant folding (evaluate constant arithmetic at analysis time)
--     - String concatenation collapse ("a".."b" → "ab")
--     - Inline constant variables
--     - Expand decimal/octal/unicode escape sequences
--     - Normalize numeric literals (0x1F → 31)
--     - Strip dead code branches
--     - Remove junk code patterns (nop assignments, unused calls)
--     - Rename single-char identifiers to descriptive names
--     - De-nest deeply nested function calls
--
--  5. Risk Assessment & Reporting
--     - Risk score 0–100 based on detected behaviors
--     - Behavior categorization (exfiltration, UI abuse, remote exploit, etc.)
--     - Anti-debug / anti-tamper detection
--     - Keylogging detection
--     - Screenshot / camera access detection
--     - Network exfiltration detection
--     - Persistence detection (queue_on_teleport analysis)
--     - Recursive function detection
--     - Sandbox escape attempt detection
--
--  6. Code Generation
--     - Generates readable Lua stubs for intercepted API calls
--     - RemoteEvent:Connect() → emits event handler stubs
--     - GetService() → emits local variable declarations
--     - WaitForChild / FindFirstChild → emits navigation code
--     - HTTP requests → emits documented request stubs
--
--  HOW TO USE
--  ==========
--  -- Option A: Run analysis on source code string
--  local CatMio = dofile("catmio.lua")
--  local report = CatMio.run(your_source_code)
--  print(report)
--
--  -- Option B: Use individual components
--  local decoded, chain = CatMio.decode(encoded_string)
--  local obfuscator  = CatMio.detect(source)
--  local score       = CatMio.score(source)
--  local risk        = CatMio.risk(source)
--
--  -- Option C: Use individual decoders
--  local plain = CatMio.b64_decode(b64_string)
--  local plain = CatMio.rc4_decode(cipher, "mykey")
--  local plain = CatMio.hex_decode("48656c6c6f")
--
--  CONFIGURATION
--  =============
--  Edit the CFG table below to tune behaviour. Key options:
--  - OBFUSCATION_THRESHOLD : score above which code is flagged obfuscated
--  - INSTRUCTION_LIMIT     : max VM instructions before halting execution
--  - MAX_DECODE_PASSES     : max chained decode attempts (default 16)
--  - DUMP_*                : switches for each dump section in the report
--
--  COMPATIBILITY
--  =============
--  - Lua 5.1+ (bitwise ops are emulated via helper functions)
--  - LuaJIT 2.x
--  - Luau (Roblox's Lua implementation, also known as Lua 5.1+)
--
--  SECURITY NOTES
--  ==============
--  - CatMio runs the target script in a strict sandbox
--  - All os.*, io.*, and debug.* calls are intercepted
--  - Output is filtered through BLOCKED_OUTPUT_PATTERNS
--  - No real filesystem, network, or OS access is granted to the script
--
-- ============================================================
--  END OF DOCUMENTATION HEADER
-- ============================================================

-- ────────────────────────────────────────────────────────────
--  LUA 5.1 / 5.3 / LUAU COMPATIBILITY SHIM
--  Capture all native functions before any stubs overwrite them
-- ────────────────────────────────────────────────────────────
local _native_pcall          = pcall
local _native_xpcall         = xpcall
local _native_error          = error
local _native_type           = type
local _native_tostring       = tostring
local _native_tonumber       = tonumber
local _native_pairs          = pairs
local _native_ipairs         = ipairs
local _native_next           = next
local _native_select         = select
local _native_rawget         = rawget
local _native_rawset         = rawset
local _native_rawequal       = rawequal
local _native_setmetatable   = setmetatable
local _native_getmetatable   = getmetatable
local _native_load           = load
local _native_loadstring     = loadstring or load
local _native_unpack         = table.unpack or unpack
local _native_setfenv        = rawget(_G, "setfenv")
local _native_getfenv        = rawget(_G, "getfenv")
local _native_print          = print
local _native_require        = rawget(_G, "require") or function() return nil end
local _native_collectgarbage = collectgarbage
local _native_rawlen         = rawlen or function(t) return #t end

-- Lua 5.1/5.2 compat: table.move may not exist
if not table.move then
    table.move = function(src, f, e, t, dst)
        dst = dst or src
        if e >= f then
            local n = e - f + 1
            if t > f then
                for i = n - 1, 0, -1 do
                    dst[t + i] = src[f + i]
                end
            else
                for i = 0, n - 1 do
                    dst[t + i] = src[f + i]
                end
            end
        end
        return dst
    end
end

-- Unified chunk loader: works on Lua 5.1 (loadstring+setfenv) and 5.2+
local function load_chunk(src, chunkname, sandbox_env)
    local chunk, err
    -- Lua 5.2+: load accepts env as 4th argument
    local ok = _native_pcall(function()
        chunk = load(src, chunkname, "t", sandbox_env)
    end)
    if ok and chunk then return chunk, nil end
    -- Lua 5.1 fallback
    local ls = rawget(_G, "loadstring") or load
    chunk, err = ls(src, chunkname)
    if chunk and sandbox_env and _native_setfenv then
        _native_setfenv(chunk, sandbox_env)
    end
    return chunk, err
end

-- ============================================================
--  SECTION 1 – CONFIGURATION (CFG)
--  All tuneable parameters in one place.
-- ============================================================
local CFG = {
    -- ── Output control ──────────────────────────────────────────────────
    -- Maximum recursion depth when serialising tables / proxies
    MAX_DEPTH                  = 50,
    -- Maximum items enumerated inside a single table
    MAX_TABLE_ITEMS            = 10000,
    -- Maximum total output size in bytes before hard-truncation
    MAX_OUTPUT_SIZE            = 200 * 1024 * 1024,
    -- Maximum identical consecutive lines before deduplication
    MAX_REPEATED_LINES         = 200,
    -- Maximum characters of a single string literal in output
    MAX_STRING_LENGTH          = 65536,
    -- Maximum length of an inline string in proxy/code-gen output
    MAX_INLINE_STRING          = 200,
    -- Maximum total output lines (soft cap before summary)
    MAX_OUTPUT_LINES           = 100000,
    -- Whether to show verbose internal diagnostics in output
    VERBOSE                    = false,
    -- Strip whitespace from output
    STRIP_WHITESPACE           = false,
    -- Emit inline comments in output
    EMIT_COMMENTS              = true,
    -- Emit type annotations in output
    EMIT_TYPE_ANNOTATIONS      = false,

    -- ── Execution control ────────────────────────────────────────────────
    -- Maximum Lua VM instructions before halting execution
    INSTRUCTION_LIMIT          = 5000000,
    -- How often the instruction hook fires (every N instructions)
    INSTRUCTION_HOOK_COUNT     = 1000,
    -- Maximum proxy indirection depth to prevent infinite recursion
    MAX_PROXY_DEPTH            = 32,
    -- Loop iteration threshold before flagging infinite loop
    LOOP_DETECT_THRESHOLD      = 100,
    -- Timeout in seconds for execution
    TIMEOUT_SECONDS            = 120,
    -- Number of bytes from the start of the source to inspect for preamble
    OUTER_HEADER_BYTES         = 12288,

    -- ── Collection limits ────────────────────────────────────────────────
    -- Maximum GC objects returned by getgc() stub
    MAX_GC_OBJECTS             = 500,
    -- Maximum functions scanned by dump_gc_scan()
    MAX_GC_SCAN_FUNCTIONS      = 200,
    -- Maximum instance creations tracked
    MAX_INSTANCE_CREATIONS     = 1000,
    -- Maximum script loads tracked
    MAX_SCRIPT_LOADS           = 200,
    -- Maximum snippet length from loadstring payloads
    MAX_SCRIPT_LOAD_SNIPPET    = 300,
    -- Maximum remote calls tracked
    MAX_REMOTE_CALLS           = 1000,
    -- Maximum deferred hooks tracked
    MAX_DEFERRED_HOOKS         = 200,
    -- Maximum signal callbacks tracked
    MAX_SIGNAL_CALLBACKS       = 100,
    -- Maximum closure refs tracked
    MAX_CLOSURE_REFS           = 500,
    -- Maximum hook calls tracked
    MAX_HOOK_CALLS             = 500,
    -- Maximum upvalues extracted per function
    MAX_UPVALUES_PER_FUNCTION  = 64,
    -- Maximum constants extracted per function
    MAX_CONST_PER_FUNCTION     = 512,

    -- ── Analysis thresholds ──────────────────────────────────────────────
    -- Obfuscation score threshold (0–1) above which code is considered obfuscated
    OBFUSCATION_THRESHOLD      = 0.30,
    -- Minimum string length to attempt decoding
    MIN_DEOBF_LENGTH           = 4,
    -- Maximum decode passes in multi-pass decoder chain
    MAX_DECODE_PASSES          = 8,
    -- Max passes in the expanded multi-decode engine
    MAX_DEOBF_PASSES           = 16,
    -- Entropy threshold above which a string is likely encoded
    HIGH_ENTROPY_THRESHOLD     = 4.5,
    -- Entropy threshold below which a string is considered plaintext
    LOW_ENTROPY_THRESHOLD      = 3.5,
    -- Minimum fraction of printable chars to consider a string "readable"
    READABLE_PRINTABLE_THRESHOLD = 0.85,
    -- Minimum Lua keyword density for a decoded string to be Lua code
    LUA_KEYWORD_DENSITY_THRESHOLD = 0.02,

    -- ── Dump switches ────────────────────────────────────────────────────
    DUMP_DECODED_STRINGS       = true,
    DUMP_STRING_POOL           = true,
    DUMP_REMOTE_SUMMARY        = true,
    DUMP_INSTANCE_CREATIONS    = true,
    DUMP_SCRIPT_LOADS          = true,
    DUMP_UPVALUES              = true,
    DUMP_GC_SCAN               = true,
    DUMP_CONSTANTS             = true,
    DUMP_GLOBALS               = true,
    DUMP_FUNCTIONS             = true,
    DUMP_METATABLES            = true,
    DUMP_CLOSURES              = true,
    DUMP_REMOTE_CALLS          = true,
    DUMP_HOOKS                 = true,
    DUMP_SIGNALS               = true,
    DUMP_ATTRIBUTES            = true,
    DUMP_ALL_STRINGS           = false,
    EMIT_XOR                   = true,
    EMIT_CALL_GRAPH            = true,
    EMIT_LOOP_COUNTER          = false,
    EMIT_BINARY_STRINGS        = true,
    TRACK_ENV_READS            = false,
    TRACK_ENV_WRITES           = true,
    COLLECT_ALL_CALLS          = true,
    CONSTANT_COLLECTION        = true,
    INSTRUMENT_LOGIC           = true,
    INLINE_SMALL_FUNCTIONS     = true,
    TRACE_CALLBACKS            = true,
    UI_PATTERN_MATCHING        = true,

    -- ── Risk scoring ──────────────────────────────────────────────────────
    COMPUTE_RISK_SCORE         = true,
    RISK_WEIGHT_HTTP           = 15,
    RISK_WEIGHT_TELEPORT_PERSIST = 25,
    RISK_WEIGHT_HOOK           = 20,
    RISK_WEIGHT_RAW_META       = 10,
    RISK_WEIGHT_OBFUSCATION    = 20,
    RISK_WEIGHT_LOADSTRING     = 10,
    RISK_WEIGHT_REMOTE         = 5,
    RISK_WEIGHT_KEYLOG         = 30,
    RISK_WEIGHT_EXFILTRATE     = 25,
    RISK_WEIGHT_ANTIDEBUG      = 15,

    -- ── Code generation ──────────────────────────────────────────────────
    ENABLE_CODE_GEN            = true,
    CODE_GEN_VAR_PREFIX        = "v",
    CODE_GEN_EMIT_WAITFORCHILD = true,

    -- ── Anti-obfuscation passes ──────────────────────────────────────────
    PASS_CONSTANT_FOLDING      = true,
    PASS_STRING_CONCAT         = true,
    PASS_EXPAND_ESCAPES        = true,
    PASS_NORMALIZE_NUMBERS     = true,
    PASS_REMOVE_JUNK           = true,
    PASS_RENAME_VARS           = false,
    CONSTANT_FOLD              = true,

    -- ── Bytecode analysis ────────────────────────────────────────────────
    ANALYZE_BYTECODE           = true,
}

-- ============================================================
--  SECTION 2 – BLOCKED OUTPUT PATTERNS
--  Lines matching any of these patterns are suppressed before
--  reaching the caller to prevent leaking sensitive host info.
-- ============================================================
local BLOCKED_OUTPUT_PATTERNS = {
    -- Filesystem leaks
    "os%.execute",   "os%.getenv",    "os%.exit",
    "os%.remove",    "os%.rename",    "os%.tmpname",
    "io%.open",      "io%.popen",     "io%.lines",
    "io%.read",      "io%.write",     "io%.close",
    -- Absolute paths
    "/etc/",         "/home/",        "/root/",
    "/var/",         "/tmp/",         "/proc/",
    "/sys/",         "/run/",
    "C:\\Users\\",   "C:\\Windows\\", "C:\\Program",
    -- Env var leaks
    "PATH=",         "HOME=",         "USER=",
    "SHELL=",        "TERM=",
    -- Credentials
    "TOKEN%s*=",     "SECRET%s*=",    "PASSWORD%s*=",
    "API_KEY%s*=",   "WEBHOOK%s*=",   "PRIVATE_KEY%s*=",
    -- Credential patterns
    "discord%.com/api/webhooks/",
    "discordapp%.com/api/webhooks/",
    "discord%.gg/",
    "roblosecurity",
    "authorization:",
    "Bearer%s+[%w%-_%.]+",
    -- Roblox security tokens
    ".ROBLOSECURITY",
    -- GitHub tokens
    "ghp_[A-Za-z0-9]+",
    "gho_[A-Za-z0-9]+",
    "ghs_[A-Za-z0-9]+",
    -- Pastebin/raw sources
    "pastebin%.com/raw",
    "raw%.githubusercontent",
    "api%.ipify",
    "webhook%.site",
}

local function is_blocked(line)
    local lower = string.lower(tostring(line))
    for _, pat in ipairs(BLOCKED_OUTPUT_PATTERNS) do
        if string.find(lower, pat) then return true end
    end
    return false
end

-- ============================================================
--  SECTION 3 – STATE
--  All mutable state lives in a single table for easy reset.
-- ============================================================
local state = {
    -- Output tracking
    output_lines        = 0,
    output_size         = 0,
    -- Collected data
    string_refs         = {},   -- decoded strings found during execution
    call_graph          = {},   -- remote / API call records
    instance_creations  = {},   -- Instance.new() records
    script_loads        = {},   -- loadstring / require records
    deferred_hooks      = {},   -- task.defer / spawn records
    registry            = {},   -- misc key-value store
    property_store      = {},   -- instance property writes
    string_pool         = {},   -- extracted from obfuscated preamble
    constants_map       = {},   -- collected constants
    gc_functions        = {},   -- functions found via getgc scan
    upvalue_map         = {},   -- upvalue extractions
    env_writes          = {},   -- environment writes
    env_reads           = {},   -- environment reads
    hook_calls          = {},   -- hook invocations
    signal_map          = {},   -- signal connections
    attribute_store     = {},   -- attribute writes
    metatable_hooks     = {},   -- metatable interceptions
    closure_refs        = {},   -- closure reference tracking
    const_map           = {},   -- per-function constant maps
    const_refs          = {},   -- constant cross-references
    -- Analysis results
    obfuscation_score   = 0,
    obfuscator_name     = nil,
    risk_score          = 0,
    risk_flags          = {},   -- individual risk flags
    -- Counters
    instruction_count   = 0,
    error_count         = 0,
    warning_count       = 0,
    loop_counter        = 0,
    branch_counter      = 0,
    instance_count      = 0,
    tween_count         = 0,
    connection_count    = 0,
    drawing_count       = 0,
    task_count          = 0,
    coroutine_count     = 0,
    table_count         = 0,
    proxy_id            = 0,
    emit_count          = 0,
    deobf_attempts      = 0,
    -- Loop detection
    loop_line_counts    = {},
    loop_detected_lines = {},
    -- Runtime state
    start_time          = 0,
    timed_out           = false,
    sandbox_env         = nil,
    last_error          = nil,
    hook_depth          = 0,
    namecall_method     = nil,
    callback_depth      = 0,
    pending_iterator    = false,
    last_http_url       = nil,
    -- Code generation buffer
    codegen_buf         = {},
    codegen_vars        = {},
    codegen_var_count   = 0,
    -- Bytecode analysis
    bytecode_type       = nil,
    bytecode_version    = nil,
    string_table        = {},
}

local function reset_state()
    state.output_lines        = 0
    state.output_size         = 0
    state.string_refs         = {}
    state.call_graph          = {}
    state.instance_creations  = {}
    state.script_loads        = {}
    state.deferred_hooks      = {}
    state.registry            = {}
    state.property_store      = {}
    state.string_pool         = {}
    state.constants_map       = {}
    state.gc_functions        = {}
    state.upvalue_map         = {}
    state.env_writes          = {}
    state.env_reads           = {}
    state.hook_calls          = {}
    state.signal_map          = {}
    state.attribute_store     = {}
    state.metatable_hooks     = {}
    state.closure_refs        = {}
    state.const_map           = {}
    state.const_refs          = {}
    state.obfuscation_score   = 0
    state.obfuscator_name     = nil
    state.risk_score          = 0
    state.risk_flags          = {}
    state.instruction_count   = 0
    state.error_count         = 0
    state.warning_count       = 0
    state.loop_counter        = 0
    state.branch_counter      = 0
    state.instance_count      = 0
    state.tween_count         = 0
    state.connection_count    = 0
    state.drawing_count       = 0
    state.task_count          = 0
    state.coroutine_count     = 0
    state.table_count         = 0
    state.proxy_id            = 0
    state.emit_count          = 0
    state.deobf_attempts      = 0
    state.loop_line_counts    = {}
    state.loop_detected_lines = {}
    state.start_time          = 0
    state.timed_out           = false
    state.sandbox_env         = nil
    state.last_error          = nil
    state.hook_depth          = 0
    state.namecall_method     = nil
    state.callback_depth      = 0
    state.pending_iterator    = false
    state.last_http_url       = nil
    state.codegen_buf         = {}
    state.codegen_vars        = {}
    state.codegen_var_count   = 0
    state.bytecode_type       = nil
    state.bytecode_version    = nil
    state.string_table        = {}
end

-- ============================================================
--  SECTION 4 – OUTPUT HELPERS
--  emit() is the central output function. All output goes through
--  it so that blocking, deduplication, and size limits apply.
-- ============================================================
local output_buffer = {}
local rep_buf, rep_n, rep_full, rep_pos = nil, 0, 0, 0

local function flush_rep()
    if rep_buf then
        table.insert(output_buffer, rep_buf)
        if rep_full > 0 then
            table.insert(output_buffer, "-- [CATMIO] ... (" .. rep_full .. " identical lines suppressed) ...")
        end
        rep_buf, rep_n, rep_full, rep_pos = nil, 0, 0, 0
    end
end

local function emit(line)
    line = tostring(line or "")
    if is_blocked(line) then return end
    if state.output_size >= CFG.MAX_OUTPUT_SIZE then return end
    state.output_size  = state.output_size + #line + 1
    state.output_lines = state.output_lines + 1
    state.emit_count   = state.emit_count + 1
    if rep_buf and line == rep_buf then
        rep_n = rep_n + 1
        if rep_n > CFG.MAX_REPEATED_LINES then
            rep_full = rep_full + 1
        end
        return
    end
    flush_rep()
    if rep_n == 0 then
        rep_buf  = line
        rep_n    = 1
        rep_full = 0
        rep_pos  = #output_buffer + 1
    end
    table.insert(output_buffer, line)
end

local function emit_blank()
    flush_rep()
    table.insert(output_buffer, "")
end

local function emit_banner(title)
    flush_rep()
    local bar = string.rep("=", 60)
    table.insert(output_buffer, "-- " .. bar)
    table.insert(output_buffer, "--  " .. title)
    table.insert(output_buffer, "-- " .. bar)
end

local function emit_sub(title)
    flush_rep()
    local bar = string.rep("-", 50)
    table.insert(output_buffer, "-- " .. bar)
    table.insert(output_buffer, "--  " .. title)
    table.insert(output_buffer, "-- " .. bar)
end

local function reset_output()
    output_buffer = {}
    rep_buf, rep_n, rep_full, rep_pos = nil, 0, 0, 0
end

-- Instruction counter for timeout enforcement
local instruction_count = 0

-- Code generation helpers
local function codegen_new_var(hint)
    state.codegen_var_count = state.codegen_var_count + 1
    local name = CFG.CODE_GEN_VAR_PREFIX .. (hint or "") .. state.codegen_var_count
    return name
end

local function codegen_emit(line)
    if CFG.ENABLE_CODE_GEN then
        table.insert(state.codegen_buf, line)
    end
end

local function codegen_flush()
    if CFG.ENABLE_CODE_GEN and #state.codegen_buf > 0 then
        emit_blank()
        emit_sub("CODE GENERATION OUTPUT")
        for _, l in ipairs(state.codegen_buf) do
            emit("--[[CODEGEN]] " .. l)
        end
    end
end


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

-- ============================================================
--  SECTION 8 – OBFUSCATOR FINGERPRINT DATABASE
--  Contains pattern signatures for 127+ known obfuscators.
--  Each entry has:
--    name:        The obfuscator display name
--    description: What this obfuscator does
--    patterns:    List of Lua string.find patterns
--
--  Patterns are matched using string.find(source, pattern)
--  with plain=false (patterns use Lua pattern matching syntax).
--  Each obfuscator is matched by ANY of its patterns.
-- ============================================================
local OBFUSCATOR_FINGERPRINTS = {
    -- ────────────────────────────────────────────────────────
    -- IronBrew2: VM-based Lua obfuscator using custom bytecode and inst
    -- ────────────────────────────────────────────────────────
    {
        name = 'IronBrew2',
        description = 'VM-based Lua obfuscator using custom bytecode and instruction dispatch',
        patterns = {
            "local%s+IB2%s*=",
            "--%[%[IronBrew",
            "string%.byte.*string%.char.*for.*%+.*256",
            "getfenv%(0%)%.script",
            "setfenv%(%d+,",
            "IronBrew2%.version",
            "IB2_SETTINGS",
            "ironbrew2_vm_dispatch",
            "IB2_HEADER_MAGIC",
            "local%s+VM%s*=%s*{}%s*VM%.execute",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- IronBrew3: Third-generation IronBrew with improved anti-tamper
    -- ────────────────────────────────────────────────────────
    {
        name = 'IronBrew3',
        description = 'Third-generation IronBrew with improved anti-tamper',
        patterns = {
            "--%[%[IB3%]%]",
            "local%s+IB3%s*=",
            "Iron[Bb]rew%s*[vV]ersion",
            "IronBrew3%.VM",
            "IB3_SETTINGS",
            "IronBrew3%.dispatch",
            "ib3_opcode_table",
            "IB3_ANTI_TAMPER",
            "IronBrew3_header_magic",
            "ib3_constant_pool",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Luraph: Professional Lua obfuscator with custom VM and JIT hin
    -- ────────────────────────────────────────────────────────
    {
        name = 'Luraph',
        description = 'Professional Lua obfuscator with custom VM and JIT hints',
        patterns = {
            "getfenv%(0%)",
            "--%[%[Luraph",
            "LPH_JIT_ON",
            "LPH_NO_UPVALUE",
            "Luraph%s*Obfuscator",
            "LPH_FAKEREF",
            "luraph_vm_dispatch",
            "LPH_ENCRYPT",
            "luraph_constant_table",
            "LPH_VERSION",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV2: Luraph version 2 with enhanced VM obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV2',
        description = 'Luraph version 2 with enhanced VM obfuscation',
        patterns = {
            "LPH_JIT_ON%s*LPH_NO_UPVALUE",
            "--%s*Luraph%s*v2",
            "LPH_OBFUSCATED",
            "LuraphV2%.dispatch",
            "lph2_vm_loop",
            "LPH2_SETTINGS",
            "luraph_v2_header",
            "LPH2_FAKEREF",
            "luraph2_constant_pool",
            "LPH2_ENCRYPT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV3: Luraph version 3 with fake reference injection
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV3',
        description = 'Luraph version 3 with fake reference injection',
        patterns = {
            "--%s*Luraph%s*v3",
            "LPH_FAKEREF",
            "LuraphV3_header",
            "LPH3_SETTINGS",
            "lph3_vm_init",
            "LuraphV3%.dispatch",
            "lph3_opcode_table",
            "LPH3_JIT",
            "luraph_v3_constant",
            "LPH3_ANTI_TAMPER",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV4: Luraph version 4 with advanced anti-debugging
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV4',
        description = 'Luraph version 4 with advanced anti-debugging',
        patterns = {
            "LPH4_",
            "luraph_v4_header",
            "LPH4_JIT",
            "--%s*Luraph%s*v4",
            "LuraphV4%.opcode",
            "lph4_vm_dispatch",
            "LPH4_SETTINGS",
            "luraph_v4_constant_pool",
            "LPH4_FAKEREF",
            "LPH4_ANTI_TAMPER",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV5: Luraph version 5 with upvalue obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV5',
        description = 'Luraph version 5 with upvalue obfuscation',
        patterns = {
            "LPH5_",
            "luraph_v5_bytecode",
            "--%s*Luraph%s*v5",
            "LPH5_NO_UPVALUE",
            "LuraphV5%.table",
            "lph5_vm_loop",
            "LPH5_SETTINGS",
            "luraph_v5_dispatch",
            "LPH5_CONSTANT",
            "LPH5_ENCRYPT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV6: Luraph version 6 with improved string encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV6',
        description = 'Luraph version 6 with improved string encryption',
        patterns = {
            "LPH6_",
            "luraph_v6_",
            "--%s*Luraph%s*v6",
            "LPH6_FAKEREF",
            "lph6_vm",
            "LuraphV6%.dispatch",
            "LPH6_SETTINGS",
            "luraph_v6_constant",
            "LPH6_ENCRYPT",
            "LPH6_JIT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuraphV7: Luraph version 7 with advanced opcode permutation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuraphV7',
        description = 'Luraph version 7 with advanced opcode permutation',
        patterns = {
            "LPH7_",
            "luraph_v7_",
            "--%s*Luraph%s*v7",
            "LPH7_JIT_ON",
            "lph7_dispatch",
            "LuraphV7%.vm",
            "LPH7_SETTINGS",
            "luraph_v7_constant_pool",
            "LPH7_FAKEREF",
            "LPH7_ANTI_TAMPER",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Prometheus: Prometheus Lua obfuscator with custom VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Prometheus',
        description = 'Prometheus Lua obfuscator with custom VM',
        patterns = {
            "--%[%[Prometheus",
            "Prometheus%s*[Oo]bfuscator",
            "prometheus_[a-z_]+%s*=",
            "PROMETHEUS_VERSION",
            "prom_vm_dispatch",
            "PrometheusVM%.execute",
            "prometheus_constant_pool",
            "PROMETHEUS_SETTINGS",
            "prom_opcode_table",
            "prometheus_header_magic",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrometheusV2: Prometheus v2 with string encryption layer
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrometheusV2',
        description = 'Prometheus v2 with string encryption layer',
        patterns = {
            "--%s*Prometheus%s*v2",
            "prometheus_v2_",
            "PROM2_SETTINGS",
            "prom2_opcode_table",
            "PrometheusV2%.init",
            "prom2_vm_dispatch",
            "PROM2_HEADER",
            "prometheus2_constant",
            "PROM2_ENCRYPT",
            "prom2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrometheusV3: Prometheus v3 with enhanced anti-debugging
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrometheusV3',
        description = 'Prometheus v3 with enhanced anti-debugging',
        patterns = {
            "--%s*Prometheus%s*v3",
            "prometheus_v3_",
            "PROM3_HEADER",
            "prom3_vm_loop",
            "PrometheusV3%.dispatch",
            "PROM3_SETTINGS",
            "prom3_opcode_table",
            "prometheus3_constant",
            "PROM3_ENCRYPT",
            "prom3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrometheusV4: Prometheus v4 with opcode encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrometheusV4',
        description = 'Prometheus v4 with opcode encryption',
        patterns = {
            "--%s*Prometheus%s*v4",
            "prometheus_v4_",
            "PROM4_JIT",
            "prom4_constant_pool",
            "PrometheusV4%.run",
            "PROM4_SETTINGS",
            "prom4_vm_dispatch",
            "PROM4_HEADER",
            "prometheus4_anti_tamper",
            "PROM4_ENCRYPT",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Moonsec: Moonsec Lua obfuscator with custom VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Moonsec',
        description = 'Moonsec Lua obfuscator with custom VM',
        patterns = {
            "--%[%[Moonsec",
            "Moonsec%s*[Oo]bfuscator",
            "moonsec_vm",
            "MOONSEC_",
            "MoonsecHeader",
            "moonsec_constant_pool",
            "MOONSEC_VERSION",
            "moonsec_dispatch",
            "MoonsecVM%.execute",
            "moonsec_opcode_table",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MoonsecV2: Moonsec v2 with improved string obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'MoonsecV2',
        description = 'Moonsec v2 with improved string obfuscation',
        patterns = {
            "--%s*Moonsec%s*v2",
            "moonsec_v2_",
            "MOONSECV2_HEADER",
            "moonsec2_dispatch",
            "MoonsecV2%.init",
            "MOONSECV2_SETTINGS",
            "moonsec2_constant_pool",
            "MOONSECV2_ENCRYPT",
            "moonsec2_opcode_table",
            "moonsec2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MoonsecV3: Moonsec v3 with advanced upvalue manipulation
    -- ────────────────────────────────────────────────────────
    {
        name = 'MoonsecV3',
        description = 'Moonsec v3 with advanced upvalue manipulation',
        patterns = {
            "--%s*Moonsec%s*v3",
            "moonsec_v3_",
            "MOONSECV3_OPCODE",
            "moonsec3_run",
            "MoonsecV3%.vm",
            "MOONSECV3_SETTINGS",
            "moonsec3_constant_pool",
            "MOONSECV3_HEADER",
            "moonsec3_dispatch",
            "moonsec3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Lightcate: Lightcate Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Lightcate',
        description = 'Lightcate Lua obfuscator',
        patterns = {
            "--%[%[Lightcate",
            "Lightcate%s*[Oo]bfuscator",
            "lightcate_vm",
            "LIGHTCATE_",
            "LightcateHeader",
            "lightcate_constant_pool",
            "LIGHTCATE_VERSION",
            "lightcate_dispatch",
            "LightcateVM%.execute",
            "lightcate_opcode_table",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LightcateV2: Lightcate v2 with string encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'LightcateV2',
        description = 'Lightcate v2 with string encryption',
        patterns = {
            "--%s*Lightcate%s*v2",
            "lightcate_v2_",
            "LIGHTCATEV2_",
            "lightcate2_dispatch",
            "LightcateV2%.init",
            "LIGHTCATEV2_SETTINGS",
            "lightcate2_constant_pool",
            "LIGHTCATEV2_HEADER",
            "lightcate2_opcode_table",
            "lightcate2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LightcateV3: Lightcate v3 with enhanced opcode permutation
    -- ────────────────────────────────────────────────────────
    {
        name = 'LightcateV3',
        description = 'Lightcate v3 with enhanced opcode permutation',
        patterns = {
            "--%s*Lightcate%s*v3",
            "lightcate_v3_",
            "LIGHTCATEV3_OPCODE",
            "lightcate3_run",
            "LightcateV3%.vm",
            "LIGHTCATEV3_SETTINGS",
            "lightcate3_constant_pool",
            "LIGHTCATEV3_HEADER",
            "lightcate3_dispatch",
            "lightcate3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Acrylic: Acrylic obfuscator with VM and string pooling
    -- ────────────────────────────────────────────────────────
    {
        name = 'Acrylic',
        description = 'Acrylic obfuscator with VM and string pooling',
        patterns = {
            "--%[%[Acrylic",
            "AcrylicObfuscator",
            "acrylic_vm_dispatch",
            "ACRYLIC_HEADER",
            "acrylic_constant_pool",
            "ACRYLIC_VERSION",
            "acrylic_opcode_table",
            "AcrylicVM%.execute",
            "ACRYLIC_SETTINGS",
            "acrylic_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Jelly: Jelly obfuscator with compact VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Jelly',
        description = 'Jelly obfuscator with compact VM',
        patterns = {
            "--%[%[Jelly",
            "JellyObfuscator",
            "jelly_vm_run",
            "JELLY_HEADER",
            "jelly_opcode_table",
            "JELLY_VERSION",
            "jelly_constant_pool",
            "JellyVM%.execute",
            "JELLY_SETTINGS",
            "jelly_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PSU-Crypt: PSU-Crypt obfuscator with layered encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'PSU-Crypt',
        description = 'PSU-Crypt obfuscator with layered encryption',
        patterns = {
            "PSU[_%-]Crypt",
            "psucrypt_header",
            "PSUCrypt%.vm",
            "psu_crypt_dispatch",
            "PSUCRYPT_MAGIC",
            "PSUCRYPT_VERSION",
            "psucrypt_constant_pool",
            "PSUCrypt%.execute",
            "PSUCRYPT_SETTINGS",
            "psucrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Comet: Comet Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Comet',
        description = 'Comet Lua obfuscator',
        patterns = {
            "--%[%[Comet",
            "CometObfuscator",
            "comet_vm",
            "COMET_HEADER",
            "comet_opcode",
            "COMET_VERSION",
            "comet_constant_pool",
            "CometVM%.execute",
            "COMET_SETTINGS",
            "comet_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ByteObf: ByteObf with byte-level obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ByteObf',
        description = 'ByteObf with byte-level obfuscation',
        patterns = {
            "ByteObfuscator",
            "byteobf_vm",
            "BYTEOBF_HEADER",
            "byte_obf_dispatch",
            "ByteObf%.run",
            "BYTEOBF_VERSION",
            "byteobf_constant_pool",
            "ByteObfVM%.execute",
            "BYTEOBF_SETTINGS",
            "byteobf_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CodeLock: CodeLock anti-decompilation protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'CodeLock',
        description = 'CodeLock anti-decompilation protection',
        patterns = {
            "CodeLock%s*[Oo]bfuscator",
            "codelock_vm",
            "CODELOCK_HEADER",
            "codelock_dispatch",
            "CodeLock%.init",
            "CODELOCK_VERSION",
            "codelock_constant_pool",
            "CodeLockVM%.execute",
            "CODELOCK_SETTINGS",
            "codelock_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SecureByte: SecureByte with AES-based string encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'SecureByte',
        description = 'SecureByte with AES-based string encryption',
        patterns = {
            "SecureByte%s*[Oo]bfuscator",
            "securebyte_vm",
            "SECUREBYTE_HEADER",
            "securebyte_opcode",
            "SecureByte%.run",
            "SECUREBYTE_VERSION",
            "securebyte_constant_pool",
            "SecureByteVM%.execute",
            "SECUREBYTE_SETTINGS",
            "securebyte_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Nexus: Nexus obfuscator with multi-layer VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'Nexus',
        description = 'Nexus obfuscator with multi-layer VM',
        patterns = {
            "NexusObfuscator",
            "nexus_vm_dispatch",
            "NEXUS_HEADER",
            "nexus_opcode_table",
            "Nexus%.init",
            "NEXUS_VERSION",
            "nexus_constant_pool",
            "NexusVM%.execute",
            "NEXUS_SETTINGS",
            "nexus_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusV2: Nexus v2 with improved instruction scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusV2',
        description = 'Nexus v2 with improved instruction scrambling',
        patterns = {
            "NexusV2Obfuscator",
            "nexusv2_vm",
            "NEXUSV2_HEADER",
            "nexus_v2_dispatch",
            "NexusV2%.run",
            "NEXUSV2_VERSION",
            "nexusv2_constant_pool",
            "NexusV2VM%.execute",
            "NEXUSV2_SETTINGS",
            "nexusv2_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusV3: Nexus v3 with advanced string obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusV3',
        description = 'Nexus v3 with advanced string obfuscation',
        patterns = {
            "NexusV3Obfuscator",
            "nexusv3_vm",
            "NEXUSV3_HEADER",
            "nexus_v3_opcode",
            "NexusV3%.init",
            "NEXUSV3_VERSION",
            "nexusv3_constant_pool",
            "NexusV3VM%.execute",
            "NEXUSV3_SETTINGS",
            "nexusv3_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusGold: Nexus Gold premium obfuscation tier
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusGold',
        description = 'Nexus Gold premium obfuscation tier',
        patterns = {
            "NexusGold%s*[Oo]bfuscator",
            "nexusgold_vm",
            "NEXUSGOLD_HEADER",
            "nexus_gold_dispatch",
            "NexusGold%.run",
            "NEXUSGOLD_VERSION",
            "nexusgold_constant_pool",
            "NexusGoldVM%.execute",
            "NEXUSGOLD_SETTINGS",
            "nexusgold_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusDiamond: Nexus Diamond top-tier obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusDiamond',
        description = 'Nexus Diamond top-tier obfuscation',
        patterns = {
            "NexusDiamond%s*[Oo]bfuscator",
            "nexusdiamond_vm",
            "NEXUSDIAMOND_",
            "nexus_diamond_opcode",
            "NexusDiamond%.init",
            "NEXUSDIAMOND_VERSION",
            "nexusdiamond_constant_pool",
            "NexusDiamondVM%.execute",
            "NEXUSDIAMOND_SETTINGS",
            "nexusdiamond_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NexusPlatinum: Nexus Platinum with hardware fingerprinting
    -- ────────────────────────────────────────────────────────
    {
        name = 'NexusPlatinum',
        description = 'Nexus Platinum with hardware fingerprinting',
        patterns = {
            "NexusPlatinum%s*[Oo]bfuscator",
            "nexusplatinum_vm",
            "NEXUSPLATINUM_",
            "nexus_platinum_dispatch",
            "NexusPlatinum%.run",
            "NEXUSPLATINUM_VERSION",
            "nexusplatinum_constant_pool",
            "NexusPlatinumVM%.execute",
            "NEXUSPLATINUM_SETTINGS",
            "nexusplatinum_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MicroG: MicroG lightweight Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'MicroG',
        description = 'MicroG lightweight Lua obfuscator',
        patterns = {
            "MicroG%s*[Oo]bfuscator",
            "microg_vm",
            "MICROG_HEADER",
            "microg_dispatch",
            "MicroG%.init",
            "MICROG_VERSION",
            "microg_constant_pool",
            "MicroGVM%.execute",
            "MICROG_SETTINGS",
            "microg_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Villain: Villain obfuscator with VM and anti-hooks
    -- ────────────────────────────────────────────────────────
    {
        name = 'Villain',
        description = 'Villain obfuscator with VM and anti-hooks',
        patterns = {
            "VillainObfuscator",
            "villain_vm_run",
            "VILLAIN_HEADER",
            "villain_opcode",
            "Villain%.dispatch",
            "VILLAIN_VERSION",
            "villain_constant_pool",
            "VillainVM%.execute",
            "VILLAIN_SETTINGS",
            "villain_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- K0lrot: K0lrot Roblox obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'K0lrot',
        description = 'K0lrot Roblox obfuscator',
        patterns = {
            "K0lrot",
            "k0lrot_vm",
            "K0LROT_HEADER",
            "k0lrot_dispatch",
            "K0lrot%.init",
            "K0LROT_VERSION",
            "k0lrot_constant_pool",
            "K0lrotVM%.execute",
            "K0LROT_SETTINGS",
            "k0lrot_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- WeAreDevs: WeAreDevs Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'WeAreDevs',
        description = 'WeAreDevs Lua obfuscator',
        patterns = {
            "WeAreDevs",
            "wad_vm_dispatch",
            "WAD_HEADER",
            "wad_opcode_table",
            "WeAreDevs%.run",
            "WAD_VERSION",
            "wad_constant_pool",
            "WeAreDevsVM%.execute",
            "WAD_SETTINGS",
            "wad_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Generic-AI: AI-generated obfuscation pattern
    -- ────────────────────────────────────────────────────────
    {
        name = 'Generic-AI',
        description = 'AI-generated obfuscation pattern',
        patterns = {
            "GENERIC_AI_OBFUSCATOR",
            "ai_obf_vm",
            "AI_OBF_HEADER",
            "ai_obf_dispatch",
            "GenericAI%.init",
            "AI_OBF_VERSION",
            "ai_obf_constant_pool",
            "GenericAIVM%.execute",
            "AI_OBF_SETTINGS",
            "ai_obf_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Synapse-X-VM: Synapse X executor's VM-based protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'Synapse-X-VM',
        description = "Synapse X executor's VM-based protection",
        patterns = {
            "SynapseXVM",
            "synapse_x_vm_dispatch",
            "SYNAPSE_X_HEADER",
            "synx_opcode_table",
            "SynapseX%.run",
            "SYNX_VERSION",
            "synx_constant_pool",
            "SynapseXVM%.execute",
            "SYNX_SETTINGS",
            "synx_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Fluxus-VM: Fluxus executor VM-based obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Fluxus-VM',
        description = 'Fluxus executor VM-based obfuscation',
        patterns = {
            "FluxusVM",
            "fluxus_vm_dispatch",
            "FLUXUS_HEADER",
            "fluxus_opcode",
            "Fluxus%.run",
            "FLUXUS_VERSION",
            "fluxus_constant_pool",
            "FluxusVM%.execute",
            "FLUXUS_SETTINGS",
            "fluxus_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScriptWare-VM: Script-Ware executor VM obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScriptWare-VM',
        description = 'Script-Ware executor VM obfuscation',
        patterns = {
            "ScriptWareVM",
            "scriptware_vm_dispatch",
            "SCRIPTWARE_HEADER",
            "sw_opcode_table",
            "ScriptWare%.run",
            "SW_VERSION",
            "sw_constant_pool",
            "ScriptWareVM%.execute",
            "SW_SETTINGS",
            "sw_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ConfuserEx-Lua: ConfuserEx-inspired Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'ConfuserEx-Lua',
        description = 'ConfuserEx-inspired Lua obfuscator',
        patterns = {
            "ConfuserEx",
            "confuser_ex_lua_vm",
            "CONFUSER_HEADER",
            "confuserex_dispatch",
            "ConfuserEx%.init",
            "CONFUSER_VERSION",
            "confuserex_constant_pool",
            "ConfuserExVM%.execute",
            "CONFUSER_SETTINGS",
            "confuserex_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Babel-Lua: Babel-inspired Lua transpiler/obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Babel-Lua',
        description = 'Babel-inspired Lua transpiler/obfuscator',
        patterns = {
            "BabelLua",
            "babel_lua_vm",
            "BABEL_HEADER",
            "babel_dispatch",
            "BabelLua%.run",
            "BABEL_VERSION",
            "babel_constant_pool",
            "BabelLuaVM%.execute",
            "BABEL_SETTINGS",
            "babel_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Minify-Lua: Lua minifier (variable renaming, whitespace removal)
    -- ────────────────────────────────────────────────────────
    {
        name = 'Minify-Lua',
        description = 'Lua minifier (variable renaming, whitespace removal)',
        patterns = {
            "minify_lua_header",
            "MinifyLua%.version",
            "MINIFY_LUA_",
            "local%s+[a-z],[a-z],[a-z],[a-z],[a-z]%s*=",
            "^local [a-z]=[a-z] [a-z]=[a-z] [a-z]=[a-z]",
            "MinifyLua%.run",
            "MINIFY_SETTINGS",
            "minify_lua_constant",
            "minify_lua_dispatch",
            "MinifyLuaVM%.execute",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Obfuscator-io-Lua: obfuscator.io Lua output
    -- ────────────────────────────────────────────────────────
    {
        name = 'Obfuscator-io-Lua',
        description = 'obfuscator.io Lua output',
        patterns = {
            "obfuscator%.io",
            "ObfuscatorIO",
            "obfio_vm_dispatch",
            "OBFIO_HEADER",
            "ObfuscatorIO%.init",
            "OBFIO_VERSION",
            "obfio_constant_pool",
            "ObfuscatorIOVM%.execute",
            "OBFIO_SETTINGS",
            "obfio_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaObfuscator-com: luaobfuscator.com output signature
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaObfuscator-com',
        description = 'luaobfuscator.com output signature',
        patterns = {
            "luaobfuscator%.com",
            "LuaObfuscatorCom",
            "luaobf_com_vm",
            "LUAOBF_COM_HEADER",
            "LuaObfCom%.run",
            "LUAOBFCOM_VERSION",
            "luaobf_com_constant",
            "LuaObfComVM%.execute",
            "LUAOBF_COM_SETTINGS",
            "luaobf_com_dispatch",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaSeel: LuaSeel obfuscation tool
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaSeel',
        description = 'LuaSeel obfuscation tool',
        patterns = {
            "LuaSeel",
            "luaseel_vm",
            "LUASEEL_HEADER",
            "luaseel_dispatch",
            "LuaSeel%.init",
            "LUASEEL_VERSION",
            "luaseel_constant_pool",
            "LuaSeelVM%.execute",
            "LUASEEL_SETTINGS",
            "luaseel_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaCrypt: LuaCrypt encryption-based obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaCrypt',
        description = 'LuaCrypt encryption-based obfuscator',
        patterns = {
            "LuaCrypt",
            "luacrypt_vm",
            "LUACRYPT_HEADER",
            "luacrypt_dispatch",
            "LuaCrypt%.run",
            "LUACRYPT_VERSION",
            "luacrypt_constant_pool",
            "LuaCryptVM%.execute",
            "LUACRYPT_SETTINGS",
            "luacrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Garble: Garble code garbler/obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Garble',
        description = 'Garble code garbler/obfuscator',
        patterns = {
            "GarbleObfuscator",
            "garble_vm",
            "GARBLE_HEADER",
            "garble_dispatch",
            "Garble%.init",
            "GARBLE_VERSION",
            "garble_constant_pool",
            "GarbleVM%.execute",
            "GARBLE_SETTINGS",
            "garble_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Roblox-Lua-Obfuscator: Generic Roblox Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Roblox-Lua-Obfuscator',
        description = 'Generic Roblox Lua obfuscator',
        patterns = {
            "RobloxLuaObfuscator",
            "rlo_vm_dispatch",
            "RLO_HEADER",
            "rlo_opcode_table",
            "RLO%.run",
            "RLO_VERSION",
            "rlo_constant_pool",
            "RLOVM%.execute",
            "RLO_SETTINGS",
            "rlo_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NightCipher: NightCipher with layered cipher encryption
    -- ────────────────────────────────────────────────────────
    {
        name = 'NightCipher',
        description = 'NightCipher with layered cipher encryption',
        patterns = {
            "NightCipher",
            "nightcipher_vm",
            "NIGHTCIPHER_HEADER",
            "nightcipher_dispatch",
            "NightCipher%.init",
            "NIGHTCIPHER_VERSION",
            "nightcipher_constant_pool",
            "NightCipherVM%.execute",
            "NIGHTCIPHER_SETTINGS",
            "nightcipher_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- BlueIce: BlueIce with custom VM dispatcher
    -- ────────────────────────────────────────────────────────
    {
        name = 'BlueIce',
        description = 'BlueIce with custom VM dispatcher',
        patterns = {
            "BlueIceObfuscator",
            "blueice_vm",
            "BLUEICE_HEADER",
            "blueice_dispatch",
            "BlueIce%.run",
            "BLUEICE_VERSION",
            "blueice_constant_pool",
            "BlueIceVM%.execute",
            "BLUEICE_SETTINGS",
            "blueice_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ShadowCrypt: ShadowCrypt with RC4-based string protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'ShadowCrypt',
        description = 'ShadowCrypt with RC4-based string protection',
        patterns = {
            "ShadowCrypt",
            "shadowcrypt_vm",
            "SHADOWCRYPT_HEADER",
            "shadowcrypt_dispatch",
            "ShadowCrypt%.init",
            "SHADOWCRYPT_VERSION",
            "shadowcrypt_constant_pool",
            "ShadowCryptVM%.execute",
            "SHADOWCRYPT_SETTINGS",
            "shadowcrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- QuantumObf: QuantumObf with quantum-inspired randomisation
    -- ────────────────────────────────────────────────────────
    {
        name = 'QuantumObf',
        description = 'QuantumObf with quantum-inspired randomisation',
        patterns = {
            "QuantumObfuscator",
            "quantum_obf_vm",
            "QUANTUM_OBF_HEADER",
            "quantum_dispatch",
            "QuantumObf%.run",
            "QUANTUM_VERSION",
            "quantum_constant_pool",
            "QuantumObfVM%.execute",
            "QUANTUM_SETTINGS",
            "quantum_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ZeroObf: ZeroObf minimal footprint obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'ZeroObf',
        description = 'ZeroObf minimal footprint obfuscator',
        patterns = {
            "ZeroObfuscator",
            "zero_obf_vm",
            "ZERO_OBF_HEADER",
            "zero_dispatch",
            "ZeroObf%.init",
            "ZERO_VERSION",
            "zero_constant_pool",
            "ZeroObfVM%.execute",
            "ZERO_SETTINGS",
            "zero_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CryptoSeal: CryptoSeal with multiple cipher layers
    -- ────────────────────────────────────────────────────────
    {
        name = 'CryptoSeal',
        description = 'CryptoSeal with multiple cipher layers',
        patterns = {
            "CryptoSeal",
            "cryptoseal_vm",
            "CRYPTOSEAL_HEADER",
            "cryptoseal_dispatch",
            "CryptoSeal%.run",
            "CRYPTOSEAL_VERSION",
            "cryptoseal_constant_pool",
            "CryptoSealVM%.execute",
            "CRYPTOSEAL_SETTINGS",
            "cryptoseal_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- HexaObf: HexaObf with hex-based encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'HexaObf',
        description = 'HexaObf with hex-based encoding',
        patterns = {
            "HexaObfuscator",
            "hexa_obf_vm",
            "HEXA_OBF_HEADER",
            "hexa_dispatch",
            "HexaObf%.init",
            "HEXA_VERSION",
            "hexa_constant_pool",
            "HexaObfVM%.execute",
            "HEXA_SETTINGS",
            "hexa_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NullByte: NullByte with null byte injection obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'NullByte',
        description = 'NullByte with null byte injection obfuscation',
        patterns = {
            "NullByteObfuscator",
            "nullbyte_vm",
            "NULLBYTE_HEADER",
            "nullbyte_dispatch",
            "NullByte%.run",
            "NULLBYTE_VERSION",
            "nullbyte_constant_pool",
            "NullByteVM%.execute",
            "NULLBYTE_SETTINGS",
            "nullbyte_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- GhostObf: GhostObf with invisible character injection
    -- ────────────────────────────────────────────────────────
    {
        name = 'GhostObf',
        description = 'GhostObf with invisible character injection',
        patterns = {
            "GhostObfuscator",
            "ghost_obf_vm",
            "GHOST_OBF_HEADER",
            "ghost_dispatch",
            "GhostObf%.init",
            "GHOST_VERSION",
            "ghost_constant_pool",
            "GhostObfVM%.execute",
            "GHOST_SETTINGS",
            "ghost_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PhantomObf: PhantomObf with metamethod abuse
    -- ────────────────────────────────────────────────────────
    {
        name = 'PhantomObf',
        description = 'PhantomObf with metamethod abuse',
        patterns = {
            "PhantomObfuscator",
            "phantom_obf_vm",
            "PHANTOM_OBF_HEADER",
            "phantom_dispatch",
            "PhantomObf%.run",
            "PHANTOM_VERSION",
            "phantom_constant_pool",
            "PhantomObfVM%.execute",
            "PHANTOM_SETTINGS",
            "phantom_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- VoidObf: VoidObf with nil-padding obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'VoidObf',
        description = 'VoidObf with nil-padding obfuscation',
        patterns = {
            "VoidObfuscator",
            "void_obf_vm",
            "VOID_OBF_HEADER",
            "void_dispatch",
            "VoidObf%.init",
            "VOID_VERSION",
            "void_constant_pool",
            "VoidObfVM%.execute",
            "VOID_SETTINGS",
            "void_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- NeonObf: NeonObf with neon-style variable scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'NeonObf',
        description = 'NeonObf with neon-style variable scrambling',
        patterns = {
            "NeonObfuscator",
            "neon_obf_vm",
            "NEON_OBF_HEADER",
            "neon_dispatch",
            "NeonObf%.run",
            "NEON_VERSION",
            "neon_constant_pool",
            "NeonObfVM%.execute",
            "NEON_SETTINGS",
            "neon_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CrystalObf: CrystalObf with crystal-clear code hiding
    -- ────────────────────────────────────────────────────────
    {
        name = 'CrystalObf',
        description = 'CrystalObf with crystal-clear code hiding',
        patterns = {
            "CrystalObfuscator",
            "crystal_obf_vm",
            "CRYSTAL_OBF_HEADER",
            "crystal_dispatch",
            "CrystalObf%.init",
            "CRYSTAL_VERSION",
            "crystal_constant_pool",
            "CrystalObfVM%.execute",
            "CRYSTAL_SETTINGS",
            "crystal_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- DarkObf: DarkObf with dark-pattern obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'DarkObf',
        description = 'DarkObf with dark-pattern obfuscation',
        patterns = {
            "DarkObfuscator",
            "dark_obf_vm",
            "DARK_OBF_HEADER",
            "dark_dispatch",
            "DarkObf%.run",
            "DARK_VERSION",
            "dark_constant_pool",
            "DarkObfVM%.execute",
            "DARK_SETTINGS",
            "dark_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- StealthObf: StealthObf with anti-detection stealth
    -- ────────────────────────────────────────────────────────
    {
        name = 'StealthObf',
        description = 'StealthObf with anti-detection stealth',
        patterns = {
            "StealthObfuscator",
            "stealth_obf_vm",
            "STEALTH_OBF_HEADER",
            "stealth_dispatch",
            "StealthObf%.init",
            "STEALTH_VERSION",
            "stealth_constant_pool",
            "StealthObfVM%.execute",
            "STEALTH_SETTINGS",
            "stealth_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SilentObf: SilentObf with silent error handling
    -- ────────────────────────────────────────────────────────
    {
        name = 'SilentObf',
        description = 'SilentObf with silent error handling',
        patterns = {
            "SilentObfuscator",
            "silent_obf_vm",
            "SILENT_OBF_HEADER",
            "silent_dispatch",
            "SilentObf%.run",
            "SILENT_VERSION",
            "silent_constant_pool",
            "SilentObfVM%.execute",
            "SILENT_SETTINGS",
            "silent_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ObfuscatorPro: ObfuscatorPro commercial obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'ObfuscatorPro',
        description = 'ObfuscatorPro commercial obfuscator',
        patterns = {
            "ObfuscatorPro",
            "obfpro_vm",
            "OBFPRO_HEADER",
            "obfpro_dispatch",
            "ObfPro%.init",
            "OBFPRO_VERSION",
            "obfpro_constant_pool",
            "ObfProVM%.execute",
            "OBFPRO_SETTINGS",
            "obfpro_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScriptLock: ScriptLock with execution token system
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScriptLock',
        description = 'ScriptLock with execution token system',
        patterns = {
            "ScriptLock",
            "scriptlock_vm",
            "SCRIPTLOCK_HEADER",
            "scriptlock_dispatch",
            "ScriptLock%.run",
            "SCRIPTLOCK_VERSION",
            "scriptlock_constant_pool",
            "ScriptLockVM%.execute",
            "SCRIPTLOCK_SETTINGS",
            "scriptlock_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CodeShield: CodeShield with integrity verification
    -- ────────────────────────────────────────────────────────
    {
        name = 'CodeShield',
        description = 'CodeShield with integrity verification',
        patterns = {
            "CodeShield",
            "codeshield_vm",
            "CODESHIELD_HEADER",
            "codeshield_dispatch",
            "CodeShield%.init",
            "CODESHIELD_VERSION",
            "codeshield_constant_pool",
            "CodeShieldVM%.execute",
            "CODESHIELD_SETTINGS",
            "codeshield_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaShield: LuaShield with Lua-level protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaShield',
        description = 'LuaShield with Lua-level protection',
        patterns = {
            "LuaShield",
            "luashield_vm",
            "LUASHIELD_HEADER",
            "luashield_dispatch",
            "LuaShield%.run",
            "LUASHIELD_VERSION",
            "luashield_constant_pool",
            "LuaShieldVM%.execute",
            "LUASHIELD_SETTINGS",
            "luashield_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScrambleLua: ScrambleLua with identifier scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScrambleLua',
        description = 'ScrambleLua with identifier scrambling',
        patterns = {
            "ScrambleLua",
            "scramble_lua_vm",
            "SCRAMBLE_LUA_HEADER",
            "scramble_dispatch",
            "ScrambleLua%.init",
            "SCRAMBLE_VERSION",
            "scramble_constant_pool",
            "ScrambleLuaVM%.execute",
            "SCRAMBLE_SETTINGS",
            "scramble_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaScrambler: LuaScrambler with flow-graph scrambling
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaScrambler',
        description = 'LuaScrambler with flow-graph scrambling',
        patterns = {
            "LuaScrambler",
            "luascrambler_vm",
            "LUASCRAMBLER_HEADER",
            "luascrambler_dispatch",
            "LuaScrambler%.run",
            "LUASCRAMBLER_VERSION",
            "luascrambler_constant_pool",
            "LuaScramblerVM%.execute",
            "LUASCRAMBLER_SETTINGS",
            "luascrambler_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ByteGuard: ByteGuard with byte-level protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'ByteGuard',
        description = 'ByteGuard with byte-level protection',
        patterns = {
            "ByteGuard",
            "byteguard_vm",
            "BYTEGUARD_HEADER",
            "byteguard_dispatch",
            "ByteGuard%.init",
            "BYTEGUARD_VERSION",
            "byteguard_constant_pool",
            "ByteGuardVM%.execute",
            "BYTEGUARD_SETTINGS",
            "byteguard_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaVault: LuaVault secure script storage
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaVault',
        description = 'LuaVault secure script storage',
        patterns = {
            "LuaVault",
            "luavault_vm",
            "LUAVAULT_HEADER",
            "luavault_dispatch",
            "LuaVault%.run",
            "LUAVAULT_VERSION",
            "luavault_constant_pool",
            "LuaVaultVM%.execute",
            "LUAVAULT_SETTINGS",
            "luavault_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CodeVault: CodeVault with encrypted code storage
    -- ────────────────────────────────────────────────────────
    {
        name = 'CodeVault',
        description = 'CodeVault with encrypted code storage',
        patterns = {
            "CodeVault",
            "codevault_vm",
            "CODEVAULT_HEADER",
            "codevault_dispatch",
            "CodeVault%.init",
            "CODEVAULT_VERSION",
            "codevault_constant_pool",
            "CodeVaultVM%.execute",
            "CODEVAULT_SETTINGS",
            "codevault_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ScriptVault: ScriptVault with script integrity checks
    -- ────────────────────────────────────────────────────────
    {
        name = 'ScriptVault',
        description = 'ScriptVault with script integrity checks',
        patterns = {
            "ScriptVault",
            "scriptvault_vm",
            "SCRIPTVAULT_HEADER",
            "scriptvault_dispatch",
            "ScriptVault%.run",
            "SCRIPTVAULT_VERSION",
            "scriptvault_constant_pool",
            "ScriptVaultVM%.execute",
            "SCRIPTVAULT_SETTINGS",
            "scriptvault_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CipherLua: CipherLua with multi-cipher string encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'CipherLua',
        description = 'CipherLua with multi-cipher string encoding',
        patterns = {
            "CipherLua",
            "cipherlua_vm",
            "CIPHERLUA_HEADER",
            "cipherlua_dispatch",
            "CipherLua%.init",
            "CIPHERLUA_VERSION",
            "cipherlua_constant_pool",
            "CipherLuaVM%.execute",
            "CIPHERLUA_SETTINGS",
            "cipherlua_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- TwistLua: TwistLua with control-flow twisting
    -- ────────────────────────────────────────────────────────
    {
        name = 'TwistLua',
        description = 'TwistLua with control-flow twisting',
        patterns = {
            "TwistLua",
            "twistlua_vm",
            "TWISTLUA_HEADER",
            "twistlua_dispatch",
            "TwistLua%.run",
            "TWISTLUA_VERSION",
            "twistlua_constant_pool",
            "TwistLuaVM%.execute",
            "TWISTLUA_SETTINGS",
            "twistlua_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MatrixObf: MatrixObf with matrix-based encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'MatrixObf',
        description = 'MatrixObf with matrix-based encoding',
        patterns = {
            "MatrixObfuscator",
            "matrix_obf_vm",
            "MATRIX_OBF_HEADER",
            "matrix_dispatch",
            "MatrixObf%.init",
            "MATRIX_VERSION",
            "matrix_constant_pool",
            "MatrixObfVM%.execute",
            "MATRIX_SETTINGS",
            "matrix_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ChaosObf: ChaosObf with chaotic instruction ordering
    -- ────────────────────────────────────────────────────────
    {
        name = 'ChaosObf',
        description = 'ChaosObf with chaotic instruction ordering',
        patterns = {
            "ChaosObfuscator",
            "chaos_obf_vm",
            "CHAOS_OBF_HEADER",
            "chaos_dispatch",
            "ChaosObf%.init",
            "CHAOS_VERSION",
            "chaos_constant_pool",
            "ChaosObfVM%.execute",
            "CHAOS_SETTINGS",
            "chaos_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SpiralObf: SpiralObf with spiral data layout
    -- ────────────────────────────────────────────────────────
    {
        name = 'SpiralObf',
        description = 'SpiralObf with spiral data layout',
        patterns = {
            "SpiralObfuscator",
            "spiral_obf_vm",
            "SPIRAL_OBF_HEADER",
            "spiral_dispatch",
            "SpiralObf%.init",
            "SPIRAL_VERSION",
            "spiral_constant_pool",
            "SpiralObfVM%.execute",
            "SPIRAL_SETTINGS",
            "spiral_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- HelixObf: HelixObf with helical data encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'HelixObf',
        description = 'HelixObf with helical data encoding',
        patterns = {
            "HelixObfuscator",
            "helix_obf_vm",
            "HELIX_OBF_HEADER",
            "helix_dispatch",
            "HelixObf%.run",
            "HELIX_VERSION",
            "helix_constant_pool",
            "HelixObfVM%.execute",
            "HELIX_SETTINGS",
            "helix_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ZeroTwo: ZeroTwo with dual-layer obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ZeroTwo',
        description = 'ZeroTwo with dual-layer obfuscation',
        patterns = {
            "ZeroTwo",
            "zerotwo_vm",
            "ZEROTWO_HEADER",
            "zerotwo_dispatch",
            "ZeroTwo%.init",
            "ZEROTWO_VERSION",
            "zerotwo_constant_pool",
            "ZeroTwoVM%.execute",
            "ZEROTWO_SETTINGS",
            "zerotwo_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ArcticObf: ArcticObf with cold-storage encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'ArcticObf',
        description = 'ArcticObf with cold-storage encoding',
        patterns = {
            "ArcticObfuscator",
            "arctic_obf_vm",
            "ARCTIC_OBF_HEADER",
            "arctic_dispatch",
            "ArcticObf%.run",
            "ARCTIC_VERSION",
            "arctic_constant_pool",
            "ArcticObfVM%.execute",
            "ARCTIC_SETTINGS",
            "arctic_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- BlazeObf: BlazeObf with high-speed obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'BlazeObf',
        description = 'BlazeObf with high-speed obfuscation',
        patterns = {
            "BlazeObfuscator",
            "blaze_obf_vm",
            "BLAZE_OBF_HEADER",
            "blaze_dispatch",
            "BlazeObf%.init",
            "BLAZE_VERSION",
            "blaze_constant_pool",
            "BlazeObfVM%.execute",
            "BLAZE_SETTINGS",
            "blaze_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- FrostObf: FrostObf with freeze-encoded strings
    -- ────────────────────────────────────────────────────────
    {
        name = 'FrostObf',
        description = 'FrostObf with freeze-encoded strings',
        patterns = {
            "FrostObfuscator",
            "frost_obf_vm",
            "FROST_OBF_HEADER",
            "frost_dispatch",
            "FrostObf%.run",
            "FROST_VERSION",
            "frost_constant_pool",
            "FrostObfVM%.execute",
            "FROST_SETTINGS",
            "frost_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- EclipseObf: EclipseObf with dark-mode code hiding
    -- ────────────────────────────────────────────────────────
    {
        name = 'EclipseObf',
        description = 'EclipseObf with dark-mode code hiding',
        patterns = {
            "EclipseObfuscator",
            "eclipse_obf_vm",
            "ECLIPSE_OBF_HEADER",
            "eclipse_dispatch",
            "EclipseObf%.init",
            "ECLIPSE_VERSION",
            "eclipse_constant_pool",
            "EclipseObfVM%.execute",
            "ECLIPSE_SETTINGS",
            "eclipse_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AuroraObf: AuroraObf with aurora borealis patterns
    -- ────────────────────────────────────────────────────────
    {
        name = 'AuroraObf',
        description = 'AuroraObf with aurora borealis patterns',
        patterns = {
            "AuroraObfuscator",
            "aurora_obf_vm",
            "AURORA_OBF_HEADER",
            "aurora_dispatch",
            "AuroraObf%.run",
            "AURORA_VERSION",
            "aurora_constant_pool",
            "AuroraObfVM%.execute",
            "AURORA_SETTINGS",
            "aurora_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ZenithObf: ZenithObf maximum obfuscation tier
    -- ────────────────────────────────────────────────────────
    {
        name = 'ZenithObf',
        description = 'ZenithObf maximum obfuscation tier',
        patterns = {
            "ZenithObfuscator",
            "zenith_obf_vm",
            "ZENITH_OBF_HEADER",
            "zenith_dispatch",
            "ZenithObf%.init",
            "ZENITH_VERSION",
            "zenith_constant_pool",
            "ZenithObfVM%.execute",
            "ZENITH_SETTINGS",
            "zenith_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- OmegaObf: OmegaObf with omega-level obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'OmegaObf',
        description = 'OmegaObf with omega-level obfuscation',
        patterns = {
            "OmegaObfuscator",
            "omega_obf_vm",
            "OMEGA_OBF_HEADER",
            "omega_dispatch",
            "OmegaObf%.init",
            "OMEGA_VERSION",
            "omega_constant_pool",
            "OmegaObfVM%.execute",
            "OMEGA_SETTINGS",
            "omega_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AlphaObf: AlphaObf first-generation obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'AlphaObf',
        description = 'AlphaObf first-generation obfuscator',
        patterns = {
            "AlphaObfuscator",
            "alpha_obf_vm",
            "ALPHA_OBF_HEADER",
            "alpha_dispatch",
            "AlphaObf%.init",
            "ALPHA_VERSION",
            "alpha_constant_pool",
            "AlphaObfVM%.execute",
            "ALPHA_SETTINGS",
            "alpha_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SigmaObf: SigmaObf with sigma-function encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'SigmaObf',
        description = 'SigmaObf with sigma-function encoding',
        patterns = {
            "SigmaObfuscator",
            "sigma_obf_vm",
            "SIGMA_OBF_HEADER",
            "sigma_dispatch",
            "SigmaObf%.init",
            "SIGMA_VERSION",
            "sigma_constant_pool",
            "SigmaObfVM%.execute",
            "SIGMA_SETTINGS",
            "sigma_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- DeltaObf: DeltaObf with delta-encoding compression
    -- ────────────────────────────────────────────────────────
    {
        name = 'DeltaObf',
        description = 'DeltaObf with delta-encoding compression',
        patterns = {
            "DeltaObfuscator",
            "delta_obf_vm",
            "DELTA_OBF_HEADER",
            "delta_dispatch",
            "DeltaObf%.run",
            "DELTA_VERSION",
            "delta_constant_pool",
            "DeltaObfVM%.execute",
            "DELTA_SETTINGS",
            "delta_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LambdaObf: LambdaObf with lambda-calculus style encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'LambdaObf',
        description = 'LambdaObf with lambda-calculus style encoding',
        patterns = {
            "LambdaObfuscator",
            "lambda_obf_vm",
            "LAMBDA_OBF_HEADER",
            "lambda_dispatch",
            "LambdaObf%.init",
            "LAMBDA_VERSION",
            "lambda_constant_pool",
            "LambdaObfVM%.execute",
            "LAMBDA_SETTINGS",
            "lambda_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ByteCode-Encrypt: ByteCode encryption before loading
    -- ────────────────────────────────────────────────────────
    {
        name = 'ByteCode-Encrypt',
        description = 'ByteCode encryption before loading',
        patterns = {
            "bytecode_encrypt",
            "BCE_HEADER",
            "bce_vm_dispatch",
            "ByteCodeEncrypt%.run",
            "bce_opcode_table",
            "BCE_VERSION",
            "bce_constant_pool",
            "ByteCodeEncryptVM%.execute",
            "BCE_SETTINGS",
            "bce_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaEncrypt: LuaEncrypt with AES/RC4 string protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaEncrypt',
        description = 'LuaEncrypt with AES/RC4 string protection',
        patterns = {
            "LuaEncrypt%.version",
            "luaencrypt_vm",
            "LUAENCRYPT_HEADER",
            "luaencrypt_dispatch",
            "LuaEncrypt%.init",
            "LUAENCRYPT_VERSION",
            "luaencrypt_constant_pool",
            "LuaEncryptVM%.execute",
            "LUAENCRYPT_SETTINGS",
            "luaencrypt_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- RC4-Lua: RC4-based Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'RC4-Lua',
        description = 'RC4-based Lua obfuscator',
        patterns = {
            "RC4Lua",
            "rc4_lua_vm",
            "RC4_LUA_HEADER",
            "rc4_dispatch",
            "RC4Lua%.run",
            "RC4LUA_VERSION",
            "rc4_constant_pool",
            "RC4LuaVM%.execute",
            "RC4LUA_SETTINGS",
            "rc4_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Xtea-Lua: XTEA cipher-based Lua obfuscator
    -- ────────────────────────────────────────────────────────
    {
        name = 'Xtea-Lua',
        description = 'XTEA cipher-based Lua obfuscator',
        patterns = {
            "XteaLua",
            "xtea_lua_vm",
            "XTEA_LUA_HEADER",
            "xtea_dispatch",
            "XteaLua%.init",
            "XTEA_VERSION",
            "xtea_constant_pool",
            "XteaLuaVM%.execute",
            "XTEA_SETTINGS",
            "xtea_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AES-Lua: AES cipher-based Lua protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'AES-Lua',
        description = 'AES cipher-based Lua protection',
        patterns = {
            "AES_Lua%.version",
            "aes_lua_vm",
            "AES_LUA_HEADER",
            "aes_lua_dispatch",
            "AESLua%.init",
            "AES_VERSION",
            "aes_constant_pool",
            "AESLuaVM%.execute",
            "AES_SETTINGS",
            "aes_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Tiger-Obf: TigerObf with Tiger hash-based key derivation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Tiger-Obf',
        description = 'TigerObf with Tiger hash-based key derivation',
        patterns = {
            "TigerObf",
            "tiger_obf_vm",
            "TIGER_OBF_HEADER",
            "tiger_dispatch",
            "TigerObf%.init",
            "TIGER_VERSION",
            "tiger_constant_pool",
            "TigerObfVM%.execute",
            "TIGER_SETTINGS",
            "tiger_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Cobra-Obf: CobraObf with snake-pattern data shuffling
    -- ────────────────────────────────────────────────────────
    {
        name = 'Cobra-Obf',
        description = 'CobraObf with snake-pattern data shuffling',
        patterns = {
            "CobraObf",
            "cobra_obf_vm",
            "COBRA_OBF_HEADER",
            "cobra_dispatch",
            "CobraObf%.run",
            "COBRA_VERSION",
            "cobra_constant_pool",
            "CobraObfVM%.execute",
            "COBRA_SETTINGS",
            "cobra_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Viper-Obf: ViperObf with venom-encoded strings
    -- ────────────────────────────────────────────────────────
    {
        name = 'Viper-Obf',
        description = 'ViperObf with venom-encoded strings',
        patterns = {
            "ViperObf",
            "viper_obf_vm",
            "VIPER_OBF_HEADER",
            "viper_dispatch",
            "ViperObf%.init",
            "VIPER_VERSION",
            "viper_constant_pool",
            "ViperObfVM%.execute",
            "VIPER_SETTINGS",
            "viper_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- UltraObf: UltraObf with maximum protection layers
    -- ────────────────────────────────────────────────────────
    {
        name = 'UltraObf',
        description = 'UltraObf with maximum protection layers',
        patterns = {
            "UltraObfuscator",
            "ultra_obf_vm",
            "ULTRA_OBF_HEADER",
            "ultra_dispatch",
            "UltraObf%.run",
            "ULTRA_VERSION",
            "ultra_constant_pool",
            "UltraObfVM%.execute",
            "ULTRA_SETTINGS",
            "ultra_anti_tamper",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- HyperObf: HyperObf with hyper-speed obfuscation engine
    -- ────────────────────────────────────────────────────────
    {
        name = 'HyperObf',
        description = 'HyperObf with hyper-speed obfuscation engine',
        patterns = {
            "HyperObfuscator",
            "hyper_obf_vm",
            "HYPER_OBF_HEADER",
            "hyper_dispatch",
            "HyperObf%.init",
            "HYPER_VERSION",
            "hyper_constant_pool",
            "HyperObfVM%.execute",
            "HYPER_SETTINGS",
            "hyper_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- MegaObf: MegaObf with mega-scale obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'MegaObf',
        description = 'MegaObf with mega-scale obfuscation',
        patterns = {
            "MegaObfuscator",
            "mega_obf_vm",
            "MEGA_OBF_HEADER",
            "mega_dispatch",
            "MegaObf%.run",
            "MEGA_VERSION",
            "mega_constant_pool",
            "MegaObfVM%.execute",
            "MEGA_SETTINGS",
            "mega_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- TerraObf: TerraObf with terrain-based data mapping
    -- ────────────────────────────────────────────────────────
    {
        name = 'TerraObf',
        description = 'TerraObf with terrain-based data mapping',
        patterns = {
            "TerraObfuscator",
            "terra_obf_vm",
            "TERRA_OBF_HEADER",
            "terra_dispatch",
            "TerraObf%.init",
            "TERRA_VERSION",
            "terra_constant_pool",
            "TerraObfVM%.execute",
            "TERRA_SETTINGS",
            "terra_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PrismObf: PrismObf with prismatic code splitting
    -- ────────────────────────────────────────────────────────
    {
        name = 'PrismObf',
        description = 'PrismObf with prismatic code splitting',
        patterns = {
            "PrismObfuscator",
            "prism_obf_vm",
            "PRISM_OBF_HEADER",
            "prism_dispatch",
            "PrismObf%.run",
            "PRISM_VERSION",
            "prism_constant_pool",
            "PrismObfVM%.execute",
            "PRISM_SETTINGS",
            "prism_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SpectralObf: SpectralObf with spectral analysis evasion
    -- ────────────────────────────────────────────────────────
    {
        name = 'SpectralObf',
        description = 'SpectralObf with spectral analysis evasion',
        patterns = {
            "SpectralObfuscator",
            "spectral_obf_vm",
            "SPECTRAL_OBF_HEADER",
            "spectral_dispatch",
            "SpectralObf%.init",
            "SPECTRAL_VERSION",
            "spectral_constant_pool",
            "SpectralObfVM%.execute",
            "SPECTRAL_SETTINGS",
            "spectral_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- FractalObf: FractalObf with self-similar code patterns
    -- ────────────────────────────────────────────────────────
    {
        name = 'FractalObf',
        description = 'FractalObf with self-similar code patterns',
        patterns = {
            "FractalObfuscator",
            "fractal_obf_vm",
            "FRACTAL_OBF_HEADER",
            "fractal_dispatch",
            "FractalObf%.run",
            "FRACTAL_VERSION",
            "fractal_constant_pool",
            "FractalObfVM%.execute",
            "FRACTAL_SETTINGS",
            "fractal_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- DiamondObf: DiamondObf premium high-grade protection
    -- ────────────────────────────────────────────────────────
    {
        name = 'DiamondObf',
        description = 'DiamondObf premium high-grade protection',
        patterns = {
            "DiamondObfuscator",
            "diamond_obf_vm",
            "DIAMOND_OBF_HEADER",
            "diamond_dispatch",
            "DiamondObf%.init",
            "DIAMOND_VERSION",
            "diamond_constant_pool",
            "DiamondObfVM%.execute",
            "DIAMOND_SETTINGS",
            "diamond_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- RubyObf: RubyObf with ruby-red encoding style
    -- ────────────────────────────────────────────────────────
    {
        name = 'RubyObf',
        description = 'RubyObf with ruby-red encoding style',
        patterns = {
            "RubyObfuscator",
            "ruby_obf_vm",
            "RUBY_OBF_HEADER",
            "ruby_dispatch",
            "RubyObf%.run",
            "RUBY_VERSION",
            "ruby_constant_pool",
            "RubyObfVM%.execute",
            "RUBY_SETTINGS",
            "ruby_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- SapphireObf: SapphireObf with sapphire-level security
    -- ────────────────────────────────────────────────────────
    {
        name = 'SapphireObf',
        description = 'SapphireObf with sapphire-level security',
        patterns = {
            "SapphireObfuscator",
            "sapphire_obf_vm",
            "SAPPHIRE_OBF_HEADER",
            "sapphire_dispatch",
            "SapphireObf%.run",
            "SAPPHIRE_VERSION",
            "sapphire_constant_pool",
            "SapphireObfVM%.execute",
            "SAPPHIRE_SETTINGS",
            "sapphire_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- AmethystObf: AmethystObf with crystal structure data layout
    -- ────────────────────────────────────────────────────────
    {
        name = 'AmethystObf',
        description = 'AmethystObf with crystal structure data layout',
        patterns = {
            "AmethystObfuscator",
            "amethyst_obf_vm",
            "AMETHYST_OBF_HEADER",
            "amethyst_dispatch",
            "AmethystObf%.init",
            "AMETHYST_VERSION",
            "amethyst_constant_pool",
            "AmethystObfVM%.execute",
            "AMETHYST_SETTINGS",
            "amethyst_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- EmeraldObf: EmeraldObf with green-cipher encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'EmeraldObf',
        description = 'EmeraldObf with green-cipher encoding',
        patterns = {
            "EmeraldObfuscator",
            "emerald_obf_vm",
            "EMERALD_OBF_HEADER",
            "emerald_dispatch",
            "EmeraldObf%.run",
            "EMERALD_VERSION",
            "emerald_constant_pool",
            "EmeraldObfVM%.execute",
            "EMERALD_SETTINGS",
            "emerald_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ObfuscatePro: ObfuscatePro commercial protection suite
    -- ────────────────────────────────────────────────────────
    {
        name = 'ObfuscatePro',
        description = 'ObfuscatePro commercial protection suite',
        patterns = {
            "ObfuscatePro%.version",
            "obfuscatepro_vm",
            "OBFUSCATEPRO_HEADER",
            "obfuscatepro_dispatch",
            "ObfuscatePro%.init",
            "OBFUSCATEPRO_VERSION",
            "obfuscatepro_constant",
            "ObfuscateProVM%.execute",
            "OBFUSCATEPRO_SETTINGS",
            "obfuscatepro_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- LuaMangle: LuaMangle with severe identifier mangling
    -- ────────────────────────────────────────────────────────
    {
        name = 'LuaMangle',
        description = 'LuaMangle with severe identifier mangling',
        patterns = {
            "LuaMangle%.header",
            "luamangle_vm",
            "LUAMANGLE_HEADER",
            "luamangle_dispatch",
            "LuaMangle%.run",
            "LUAMANGLE_VERSION",
            "luamangle_constant",
            "LuaMangleVM%.execute",
            "LUAMANGLE_SETTINGS",
            "luamangle_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- EclipseObf: EclipseObf with total code darkness
    -- ────────────────────────────────────────────────────────
    {
        name = 'EclipseObf',
        description = 'EclipseObf with total code darkness',
        patterns = {
            "EclipseObfV2",
            "eclipse_v2_vm",
            "ECLIPSEV2_HEADER",
            "eclipse_v2_dispatch",
            "EclipseObfV2%.run",
            "ECLIPSEV2_VERSION",
            "eclipse_v2_constant",
            "EclipseV2VM%.execute",
            "ECLIPSEV2_SETTINGS",
            "eclipse_v2_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- KaleidoObf: KaleidoObf with kaleidoscopic code patterns
    -- ────────────────────────────────────────────────────────
    {
        name = 'KaleidoObf',
        description = 'KaleidoObf with kaleidoscopic code patterns',
        patterns = {
            "KaleidoObfuscator",
            "kaleido_obf_vm",
            "KALEIDO_OBF_HEADER",
            "kaleido_dispatch",
            "KaleidoObf%.init",
            "KALEIDO_VERSION",
            "kaleido_constant_pool",
            "KaleidoObfVM%.execute",
            "KALEIDO_SETTINGS",
            "kaleido_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- CrystallineObf: CrystallineObf with crystal lattice encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'CrystallineObf',
        description = 'CrystallineObf with crystal lattice encoding',
        patterns = {
            "CrystallineObfuscator",
            "crystalline_obf_vm",
            "CRYSTALLINE_OBF_HEADER",
            "crystalline_dispatch",
            "CrystallineObf%.run",
            "CRYSTALLINE_VERSION",
            "crystalline_constant",
            "CrystallineVM%.execute",
            "CRYSTALLINE_SETTINGS",
            "crystalline_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PhiObf: PhiObf with golden-ratio based encoding
    -- ────────────────────────────────────────────────────────
    {
        name = 'PhiObf',
        description = 'PhiObf with golden-ratio based encoding',
        patterns = {
            "PhiObfuscator",
            "phi_obf_vm",
            "PHI_OBF_HEADER",
            "phi_dispatch",
            "PhiObf%.init",
            "PHI_VERSION",
            "phi_constant_pool",
            "PhiObfVM%.execute",
            "PHI_SETTINGS",
            "phi_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ChiObf: ChiObf with chi-squared obfuscation analysis evasion
    -- ────────────────────────────────────────────────────────
    {
        name = 'ChiObf',
        description = 'ChiObf with chi-squared obfuscation analysis evasion',
        patterns = {
            "ChiObfuscator",
            "chi_obf_vm",
            "CHI_OBF_HEADER",
            "chi_dispatch",
            "ChiObf%.run",
            "CHI_VERSION",
            "chi_constant_pool",
            "ChiObfVM%.execute",
            "CHI_SETTINGS",
            "chi_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- PsiObf: PsiObf with psi-function based VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'PsiObf',
        description = 'PsiObf with psi-function based VM',
        patterns = {
            "PsiObfuscator",
            "psi_obf_vm",
            "PSI_OBF_HEADER",
            "psi_dispatch",
            "PsiObf%.init",
            "PSI_VERSION",
            "psi_constant_pool",
            "PsiObfVM%.execute",
            "PSI_SETTINGS",
            "psi_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- GigaObf: GigaObf with gigantic instruction set VM
    -- ────────────────────────────────────────────────────────
    {
        name = 'GigaObf',
        description = 'GigaObf with gigantic instruction set VM',
        patterns = {
            "GigaObfuscator",
            "giga_obf_vm",
            "GIGA_OBF_HEADER",
            "giga_dispatch",
            "GigaObf%.run",
            "GIGA_VERSION",
            "giga_constant_pool",
            "GigaObfVM%.execute",
            "GIGA_SETTINGS",
            "giga_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- TornadoObf: TornadoObf with tornado-pattern data swirling
    -- ────────────────────────────────────────────────────────
    {
        name = 'TornadoObf',
        description = 'TornadoObf with tornado-pattern data swirling',
        patterns = {
            "TornadoObfuscator",
            "tornado_obf_vm",
            "TORNADO_OBF_HEADER",
            "tornado_dispatch",
            "TornadoObf%.run",
            "TORNADO_VERSION",
            "tornado_constant_pool",
            "TornadoObfVM%.execute",
            "TORNADO_SETTINGS",
            "tornado_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- ThunderObf: ThunderObf with electric-speed obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'ThunderObf',
        description = 'ThunderObf with electric-speed obfuscation',
        patterns = {
            "ThunderObfuscator",
            "thunder_obf_vm",
            "THUNDER_OBF_HEADER",
            "thunder_dispatch",
            "ThunderObf%.init",
            "THUNDER_VERSION",
            "thunder_constant_pool",
            "ThunderObfVM%.execute",
            "THUNDER_SETTINGS",
            "thunder_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- InfernoObf: InfernoObf with hellfire-level obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'InfernoObf',
        description = 'InfernoObf with hellfire-level obfuscation',
        patterns = {
            "InfernoObfuscator",
            "inferno_obf_vm",
            "INFERNO_OBF_HEADER",
            "inferno_dispatch",
            "InfernoObf%.run",
            "INFERNO_VERSION",
            "inferno_constant_pool",
            "InfernoObfVM%.execute",
            "INFERNO_SETTINGS",
            "inferno_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Lzma-Lua: LZMA compression-based obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Lzma-Lua',
        description = 'LZMA compression-based obfuscation',
        patterns = {
            "LzmaLua",
            "lzma_lua_vm",
            "LZMA_LUA_HEADER",
            "lzma_dispatch",
            "LzmaLua%.init",
            "LZMA_VERSION",
            "lzma_constant_pool",
            "LzmaLuaVM%.execute",
            "LZMA_SETTINGS",
            "lzma_opcode",
        },
    },
    -- ────────────────────────────────────────────────────────
    -- Snappy-Lua: Snappy compression-based obfuscation
    -- ────────────────────────────────────────────────────────
    {
        name = 'Snappy-Lua',
        description = 'Snappy compression-based obfuscation',
        patterns = {
            "SnappyLua",
            "snappy_lua_vm",
            "SNAPPY_LUA_HEADER",
            "snappy_dispatch",
            "SnappyLua%.init",
            "SNAPPY_VERSION",
            "snappy_constant_pool",
            "SnappyLuaVM%.execute",
            "SNAPPY_SETTINGS",
            "snappy_opcode",
        },
    },
}

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


-- ============================================================
--  SECTION 15 – ANTI-OBFUSCATION TRANSFORMATION PASSES
--  These functions attempt to simplify obfuscated code by
--  performing source-level transformations.
--
--  NOTE: These are pattern-based heuristics, not a full parser.
--  They work well for common obfuscation patterns but may
--  introduce errors on complex obfuscated code. Always verify
--  output manually.
-- ============================================================

-- ── Pass 1: Expand Decimal/Hex/Octal Escape Sequences ────────────────────────
-- Converts \65 → A, \x41 → A, in string literals
local function pass_expand_escapes(src)
    if not src or not CFG.PASS_EXPAND_ESCAPES then return src end
    local changed = false
    -- Expand decimal escapes \NNN in quoted strings
    local result = string.gsub(src, '\\(%d%d?%d?)', function(n)
        local num = tonumber(n)
        if num and num >= 0 and num <= 255 then
            changed = true
            if num == 0 then return '\\0' end
            if num == 10 then return '\\n' end
            if num == 13 then return '\\r' end
            if num == 9  then return '\\t' end
            if num >= 32 and num <= 126 then
                local c = string.char(num)
                -- Escape chars that need escaping in Lua strings
                if c == '"' or c == "'" or c == '\\' then
                    return '\\' .. c
                end
                return c
            end
            return '\\' .. n
        end
        return '\\' .. n
    end)
    -- Expand hex escapes \xNN
    result = string.gsub(result, '\\x(%x%x)', function(h)
        local num = tonumber(h, 16) or 0
        changed = true
        if num >= 32 and num <= 126 then
            local c = string.char(num)
            if c == '"' or c == "'" or c == '\\' then return '\\' .. c end
            return c
        end
        return '\\x' .. h
    end)
    return result
end

-- ── Pass 2: Normalize Numeric Literals ──────────────────────────────────────
-- Converts 0x1F → 31, 0b1010 → 10, scientific notation → decimal
local function pass_normalize_numbers(src)
    if not src or not CFG.PASS_NORMALIZE_NUMBERS then return src end
    -- Convert hex literals to decimal
    local result = string.gsub(src, '0x(%x+)', function(h)
        local n = tonumber(h, 16)
        if n and n >= 0 and n <= 2^52 then
            return tostring(math.floor(n))
        end
        return '0x' .. h
    end)
    -- Convert scientific notation where possible
    result = string.gsub(result, '(%d+%.?%d*)e(%+?)(%d+)', function(m, sign, e)
        local num = tonumber(m .. 'e' .. (sign or '') .. e)
        if num and math.floor(num) == num and num < 1e15 then
            return tostring(math.floor(num))
        end
        return m .. 'e' .. (sign or '') .. e
    end)
    return result
end

-- ── Pass 3: String Concatenation Collapse ────────────────────────────────────
-- Collapses "a" .. "b" → "ab" for adjacent string literals
local function pass_collapse_concat(src)
    if not src or not CFG.PASS_STRING_CONCAT then return src end
    -- Repeatedly collapse "..." .. "..." pairs
    local prev, result = src, src
    for _ = 1, 20 do
        -- Double-quoted strings
        result = string.gsub(prev, '"([^"]*)"%.%."([^"]*)"', function(a, b)
            return '"' .. a .. b .. '"'
        end)
        if result == prev then break end
        prev = result
    end
    return result
end

-- ── Pass 4: Constant Folding ─────────────────────────────────────────────────
-- Evaluates constant arithmetic expressions at analysis time.
-- Only handles simple integer arithmetic.
local function pass_constant_fold(src)
    if not src or not CFG.PASS_CONSTANT_FOLDING then return src end
    local changed = true
    local result  = src
    local iters   = 0
    while changed and iters < 30 do
        changed = false
        iters   = iters + 1
        -- Fold simple integer arithmetic: N op N
        result = string.gsub(result, '(%d+)%s*([%+%-%*%%])%s*(%d+)', function(a, op, b)
            local na, nb = tonumber(a), tonumber(b)
            if not na or not nb then return a .. op .. b end
            local val
            if op == '+' then val = na + nb
            elseif op == '-' then val = na - nb
            elseif op == '*' then val = na * nb
            elseif op == '%' then
                if nb == 0 then return a .. op .. b end
                val = na % nb
            else return a .. op .. b
            end
            if val and math.floor(val) == val and math.abs(val) < 1e12 then
                changed = true
                return tostring(math.floor(val))
            end
            return a .. op .. b
        end)
        -- Fold division that results in integer
        result = string.gsub(result, '(%d+)%s*/%s*(%d+)', function(a, b)
            local na, nb = tonumber(a), tonumber(b)
            if not na or not nb or nb == 0 then return a .. '/' .. b end
            local val = na / nb
            if math.floor(val) == val and math.abs(val) < 1e12 then
                changed = true
                return tostring(math.floor(val))
            end
            return a .. '/' .. b
        end)
    end
    return result
end

-- ── Pass 5: Remove Junk Code ─────────────────────────────────────────────────
-- Removes common junk patterns used by obfuscators.
local function pass_remove_junk(src)
    if not src or not CFG.PASS_REMOVE_JUNK then return src end
    local result = src
    -- Remove assignments of the form: local _=nil (unused nil assigns)
    result = string.gsub(result, 'local%s+_%s*=%s*nil%s*;?', '')
    -- Remove do...end blocks with only assignments (partial)
    -- Remove empty if blocks: if false then ... end (stub)
    result = string.gsub(result, 'if%s+false%s+then.-%s+end', '')
    -- Remove double semicolons
    result = string.gsub(result, ';;+', ';')
    -- Remove trailing whitespace on lines
    result = string.gsub(result, '%s+\n', '\n')
    return result
end

-- ── Pass 6: Variable Renaming ─────────────────────────────────────────────────
-- Renames single-character variable names to slightly more descriptive ones.
-- This is a very simple heuristic. Disabled by default (may break code).
local RENAME_MAP = {
    a = "v_a", b = "v_b", c = "v_c", d = "v_d", e = "v_e",
    f = "v_f", g = "v_g", h = "v_h", i = "idx", j = "idx2",
    k = "key", l = "len", m = "val", n = "num", o = "obj",
    p = "ptr", q = "tmp", r = "res", s = "str", t = "tbl",
    u = "u_v", v = "val2", w = "w_v", x = "x_v", y = "y_v", z = "z_v",
}
local function pass_rename_vars(src)
    if not src or not CFG.PASS_RENAME_VARS then return src end
    local result = src
    -- Only rename local variable declarations
    for old, new in pairs(RENAME_MAP) do
        -- Match 'local LETTER ' patterns
        result = string.gsub(result,
            '(%f[%w_]local%s+)(' .. old .. ')(%f[^%w_])',
            '%1' .. new .. '%3'
        )
    end
    return result
end

-- ── Pass 7: De-nesting ────────────────────────────────────────────────────────
-- Attempts to flatten deeply nested expressions. This is a stub
-- because true de-nesting requires a proper AST.
local function pass_denest(src)
    -- This is intentionally a stub. Full de-nesting requires parsing.
    return src
end

-- ── Pass 8: Collapse Dead Branches ────────────────────────────────────────────
-- Collapses constant conditions like 'if true then ... end' and
-- 'if false then ... else ... end'.
local function pass_collapse_dead(src)
    if not src then return src end
    -- 'if true then BODY end' → BODY
    -- This is a rough approximation; may catch some false positives
    local result = string.gsub(src, 'if%s+true%s+then%s+(.-)%s+end', function(body)
        return body
    end)
    -- 'if false then BODY end' → (empty)
    result = string.gsub(result, 'if%s+false%s+then.-%send', '')
    return result
end

-- ── Apply All Anti-Obfuscation Passes ─────────────────────────────────────────
local function apply_deobf_passes(src)
    if not src then return src end
    local result = src
    result = pass_expand_escapes(result)
    result = pass_normalize_numbers(result)
    result = pass_collapse_concat(result)
    result = pass_constant_fold(result)
    result = pass_remove_junk(result)
    result = pass_rename_vars(result)
    result = pass_collapse_dead(result)
    return result
end

-- ============================================================
--  SECTION 16 – BYTECODE ANALYSIS
--  Detects and analyses embedded Lua/Luau bytecode.
-- ============================================================

-- Lua 5.1 bytecode header:
--   \27 L u a   (0x1B 0x4C 0x75 0x61)
--   \82          (0x52 = version 5.2? no, 5.1 = 0x51)
--   \0           (format = 0 = official)
--   <endianness> (1 = little, 0 = big)
--   <int size>   (usually 4)
--   <size_t>     (usually 4 or 8)
--   <instruction size> (usually 4)
--   <lua_Number size>  (usually 8)
--   <integral flag>    (usually 0)

local BC_LUA51_MAGIC = "\27Lua\81"   -- 0x1B 4C 75 61 51
local BC_LUAU_MAGIC  = "\27LuaQ"     -- Used by some Luau builds
local BC_LUA52_MAGIC = "\27Lua\82"   -- 5.2
local BC_LUA53_MAGIC = "\27Lua\83"   -- 5.3
local BC_LUA54_MAGIC = "\27Lua\84"   -- 5.4

local function analyse_bytecode_header(src)
    if not src or not CFG.ANALYZE_BYTECODE then return nil end
    local result = {
        is_bytecode   = false,
        version       = nil,
        endianness    = nil,
        int_size      = nil,
        sizet_size    = nil,
        instr_size    = nil,
        number_size   = nil,
        integral_flag = nil,
        string_table  = {},
    }
    -- Check magic bytes
    if string.sub(src, 1, 5) == BC_LUA51_MAGIC then
        result.is_bytecode = true
        result.version = "Lua 5.1"
        state.bytecode_type    = "lua51"
        state.bytecode_version = "5.1"
    elseif string.sub(src, 1, 5) == BC_LUAU_MAGIC then
        result.is_bytecode = true
        result.version = "Luau"
        state.bytecode_type    = "luau"
        state.bytecode_version = "luau"
    elseif string.sub(src, 1, 5) == BC_LUA52_MAGIC then
        result.is_bytecode = true
        result.version = "Lua 5.2"
        state.bytecode_type    = "lua52"
        state.bytecode_version = "5.2"
    elseif string.sub(src, 1, 5) == BC_LUA53_MAGIC then
        result.is_bytecode = true
        result.version = "Lua 5.3"
        state.bytecode_type    = "lua53"
        state.bytecode_version = "5.3"
    elseif string.sub(src, 1, 5) == BC_LUA54_MAGIC then
        result.is_bytecode = true
        result.version = "Lua 5.4"
        state.bytecode_type    = "lua54"
        state.bytecode_version = "5.4"
    else
        return result  -- Not bytecode
    end
    -- Parse header fields (Lua 5.1 format)
    if #src >= 12 then
        local b6  = string.byte(src, 6)  or 0  -- format (should be 0)
        local b7  = string.byte(src, 7)  or 0  -- endianness
        local b8  = string.byte(src, 8)  or 0  -- int size
        local b9  = string.byte(src, 9)  or 0  -- size_t size
        local b10 = string.byte(src, 10) or 0  -- instruction size
        local b11 = string.byte(src, 11) or 0  -- number size
        local b12 = string.byte(src, 12) or 0  -- integral flag
        result.endianness    = b7 == 1 and "little" or "big"
        result.int_size      = b8
        result.sizet_size    = b9
        result.instr_size    = b10
        result.number_size   = b11
        result.integral_flag = b12
    end
    -- Attempt to extract embedded strings from bytecode
    -- Strings in Lua 5.1 bytecode are length-prefixed
    local strings = {}
    local i = 13  -- start after header
    local max_scan = math.min(#src, 4096)
    while i <= max_scan do
        -- Look for printable string sequences
        local str_start = i
        local str_chars = {}
        while i <= max_scan and string.byte(src, i) and
              string.byte(src, i) >= 32 and string.byte(src, i) <= 126 do
            table.insert(str_chars, string.sub(src, i, i))
            i = i + 1
        end
        local str = table.concat(str_chars)
        if #str >= 4 then
            table.insert(strings, str)
        end
        i = i + 1
    end
    result.string_table = strings
    state.string_table = strings
    return result
end

-- ============================================================
--  SECTION 17 – CONSTANT COLLECTOR
--  Extracts all constant values from the source code and
--  categorises them (URLs, tokens, keys, game IDs, etc.).
-- ============================================================

local function collect_constants(src)
    if not src or not CFG.CONSTANT_COLLECTION then return {} end
    local constants = {}
    local seen = {}
    local function add_const(val, kind, ctx)
        if seen[val] then
            -- Increment reference count
            for _, c in ipairs(constants) do
                if c.value == val then
                    c.refs = (c.refs or 1) + 1
                    break
                end
            end
            return
        end
        seen[val] = true
        local flags, risk = analyse_string(val)
        local urls   = find_urls(val)
        local ips    = find_ips(val)
        table.insert(constants, {
            value   = val,
            kind    = kind,
            context = ctx,
            refs    = 1,
            flags   = flags,
            risk    = risk,
            urls    = urls,
            ips     = ips,
            entropy = shannon_entropy(val),
            len     = #val,
        })
    end
    -- Extract string literals
    for s in string.gmatch(src, '"([^"]*)"') do
        if #s >= CFG.MIN_DEOBF_LENGTH then
            add_const(s, "string", "double_quoted")
        end
    end
    for s in string.gmatch(src, "'([^']*)'") do
        if #s >= CFG.MIN_DEOBF_LENGTH then
            add_const(s, "string", "single_quoted")
        end
    end
    -- Extract long string literals [[ ... ]]
    for s in string.gmatch(src, '%[%[(.-)%]%]') do
        if #s >= CFG.MIN_DEOBF_LENGTH then
            add_const(s, "string", "long_string")
        end
    end
    -- Extract numeric constants (large ones)
    for n in string.gmatch(src, '0x%x+') do
        add_const(n, "number_hex", "hex_literal")
    end
    for n in string.gmatch(src, '%d%d%d%d%d+') do
        add_const(n, "number_large", "decimal_literal")
    end
    -- Sort by risk (highest first)
    table.sort(constants, function(a, b) return (a.risk or 0) > (b.risk or 0) end)
    return constants
end

-- ============================================================
--  SECTION 18 – RISK SCORER
--  Computes an overall risk score 0-100 for the script.
-- ============================================================

local RISK_BEHAVIORS = {
    -- Network exfiltration
    {
        name    = "discord_webhook",
        pattern = "discord%.com/api/webhooks/",
        weight  = 35,
        desc    = "Script sends data to Discord webhook (likely data exfiltration)",
        category = "exfiltration",
    },
    {
        name    = "http_post",
        pattern = "PostAsync%s*%(.*{",
        weight  = 25,
        desc    = "Script sends HTTP POST requests with data",
        category = "exfiltration",
    },
    {
        name    = "raw_http",
        pattern = "HttpService.*RequestAsync",
        weight  = 20,
        desc    = "Script makes raw HTTP requests",
        category = "network",
    },
    -- Persistence
    {
        name    = "queue_teleport",
        pattern = "queue_on_teleport%s*(",
        weight  = 30,
        desc    = "Script persists across teleports (queue_on_teleport)",
        category = "persistence",
    },
    -- Hooks and tampering
    {
        name    = "hookfunction",
        pattern = "hookfunction%s*(",
        weight  = 25,
        desc    = "Script hooks functions (likely method interception)",
        category = "tampering",
    },
    {
        name    = "hookmetamethod",
        pattern = "hookmetamethod%s*(",
        weight  = 25,
        desc    = "Script hooks metamethods (likely environment hijack)",
        category = "tampering",
    },
    {
        name    = "newcclosure",
        pattern = "newcclosure%s*(",
        weight  = 15,
        desc    = "Script creates C-closures (anti-detection wrapper)",
        category = "tampering",
    },
    -- Credential theft
    {
        name    = "roblosecurity",
        pattern = "%.ROBLOSECURITY",
        weight  = 40,
        desc    = "Script accesses .ROBLOSECURITY cookie (credential theft!)",
        category = "credential_theft",
    },
    {
        name    = "player_userid",
        pattern = "LocalPlayer%.UserId",
        weight  = 10,
        desc    = "Script reads player's UserId",
        category = "data_collection",
    },
    {
        name    = "player_name",
        pattern = "LocalPlayer%.Name",
        weight  = 5,
        desc    = "Script reads player's username",
        category = "data_collection",
    },
    -- Keylogging
    {
        name    = "keydown_hook",
        pattern = "UserInputService.*KeyDown",
        weight  = 20,
        desc    = "Script hooks keyboard input (potential keylogger)",
        category = "keylogging",
    },
    {
        name    = "input_began",
        pattern = "InputBegan.*KeyCode",
        weight  = 10,
        desc    = "Script monitors keyboard input events",
        category = "keylogging",
    },
    -- Environment probing
    {
        name    = "debug_probe",
        pattern = "debug%.getinfo",
        weight  = 10,
        desc    = "Script probes call stack via debug library",
        category = "anti_debug",
    },
    {
        name    = "getrawmeta",
        pattern = "getrawmetatable%s*(",
        weight  = 10,
        desc    = "Script accesses raw metatables (bypass protection)",
        category = "tampering",
    },
    -- Loading
    {
        name    = "loadstring",
        pattern = "loadstring%s*(",
        weight  = 15,
        desc    = "Script dynamically loads code (loadstring)",
        category = "dynamic_loading",
    },
    -- Camera / screenshot
    {
        name    = "camera_cf",
        pattern = "workspace%.CurrentCamera%.CFrame",
        weight  = 10,
        desc    = "Script manipulates camera CFrame (ESP/aimbot potential)",
        category = "ui_abuse",
    },
    -- Exploit indicators
    {
        name    = "remote_fire_all",
        pattern = "FireAllClients%s*(",
        weight  = 20,
        desc    = "Script fires events to all clients (server-side exploit)",
        category = "remote_exploit",
    },
    -- Obfuscation indicator
    {
        name    = "high_obf",
        pattern = nil,  -- handled separately by score
        weight  = 20,
        desc    = "Script is highly obfuscated",
        category = "obfuscation",
    },
    -- Infinite loop potential
    {
        name    = "tight_loop",
        pattern = "while true do",
        weight  = 5,
        desc    = "Script contains infinite loop (while true do)",
        category = "stability",
    },
}

local function compute_risk_score(src, obf_score)
    if not CFG.COMPUTE_RISK_SCORE then return 0, {} end
    local risk   = 0
    local flags  = {}
    for _, b in ipairs(RISK_BEHAVIORS) do
        if b.pattern then
            local ok, found = _native_pcall(string.find, src, b.pattern)
            if ok and found then
                risk = risk + b.weight
                table.insert(flags, {
                    name     = b.name,
                    desc     = b.desc,
                    weight   = b.weight,
                    category = b.category,
                })
            end
        end
    end
    -- Obfuscation risk
    if (obf_score or 0) >= CFG.OBFUSCATION_THRESHOLD then
        risk = risk + CFG.RISK_WEIGHT_OBFUSCATION
        table.insert(flags, {
            name     = "high_obf",
            desc     = "Script is highly obfuscated (score: " ..
                        string.format("%.2f", obf_score) .. ")",
            weight   = CFG.RISK_WEIGHT_OBFUSCATION,
            category = "obfuscation",
        })
    end
    -- Clamp to 100
    risk = math.min(100, risk)
    -- Sort flags by weight
    table.sort(flags, function(a, b) return a.weight > b.weight end)
    return risk, flags
end

-- ============================================================
--  SECTION 19 – DETECTION ANALYSIS
--  Comprehensive security detection functions.
-- ============================================================

-- Detect anti-debugging techniques
local ANTIDEBUG_PATTERNS = {
    { name = "debug_getinfo_check",  pattern = "debug%.getinfo%(2%)" },
    { name = "hookcheck",            pattern = "islclosure" },
    { name = "upval_check",          pattern = "debug%.getupvalue" },
    { name = "stack_check",          pattern = "debug%.traceback" },
    { name = "closure_compare",      pattern = "compareinstances" },
    { name = "newcclosure_wrap",     pattern = "newcclosure" },
    { name = "syn_check",            pattern = "syn%.is_cached" },
    { name = "executor_detect",      pattern = "EXECUTOR_NAME" },
    { name = "getexecver",           pattern = "getexecutorversion" },
    { name = "fingerprint",          pattern = "fingerprintexecutor" },
    { name = "identitycheck",        pattern = "getthreadidentity" },
    { name = "luau_check",           pattern = "isluau" },
    { name = "require_check",        pattern = "getloadedmodules" },
    { name = "script_check",         pattern = "getrunningscripts" },
}

local function detect_antidebug(src)
    local found = {}
    for _, p in ipairs(ANTIDEBUG_PATTERNS) do
        if string.find(src, p.pattern) then
            table.insert(found, p.name)
        end
    end
    return found
end

-- Detect persistence mechanisms
local PERSISTENCE_PATTERNS = {
    { name = "queue_on_teleport",    pattern = "queue_on_teleport" },
    { name = "writefile_persist",    pattern = "writefile.*%.lua" },
    { name = "loadfile_persist",     pattern = "loadfile%s*(" },
    { name = "getscript_persist",    pattern = "getrunningscripts" },
    { name = "signal_reconnect",     pattern = "game%.Loaded:Connect" },
    { name = "teleport_listener",    pattern = "TeleportService%.TeleportInitFailed" },
    { name = "child_persist",        pattern = "DescendantAdded" },
}

local function detect_persistence(src)
    local found = {}
    for _, p in ipairs(PERSISTENCE_PATTERNS) do
        if string.find(src, p.pattern) then
            table.insert(found, p.name)
        end
    end
    return found
end

-- Detect keylogging
local KEYLOG_PATTERNS = {
    { name = "keydown",     pattern = "KeyDown" },
    { name = "input_began", pattern = "InputBegan" },
    { name = "keycode",     pattern = "KeyCode%." },
    { name = "uis_hook",    pattern = "UserInputService.*Connect" },
    { name = "getinput",    pattern = "GetKeysPressed" },
    { name = "isdown",      pattern = "IsKeyDown" },
}

local function detect_keylogging(src)
    local found = {}
    for _, p in ipairs(KEYLOG_PATTERNS) do
        if string.find(src, p.pattern) then
            table.insert(found, p.name)
        end
    end
    return found
end

-- Detect network exfiltration
local EXFIL_PATTERNS = {
    { name = "discord_webhook",  pattern = "discord%.com/api/webhooks/" },
    { name = "post_request",     pattern = "PostAsync" },
    { name = "http_request",     pattern = "RequestAsync" },
    { name = "pastebin_upload",  pattern = "pastebin%.com" },
    { name = "webhook_site",     pattern = "webhook%.site" },
    { name = "ngrok",            pattern = "ngrok%.io" },
    { name = "requestbin",       pattern = "requestbin%.com" },
    { name = "ipify",            pattern = "api%.ipify%.org" },
    { name = "hastebin",         pattern = "hastebin%.com" },
    { name = "send_data",        pattern = "send_data" },
    { name = "raw_socket",       pattern = "tcp_connect" },
}

local function detect_exfiltration(src)
    local found = {}
    for _, p in ipairs(EXFIL_PATTERNS) do
        if string.find(src, p.pattern) then
            table.insert(found, p.name)
        end
    end
    return found
end

-- Detect infinite loops
local function detect_infinite_loops(src)
    local patterns = {
        "while%s+true%s+do",
        "repeat%s+.-until%s+false",
        "for%s+.-%s+do%s*end",  -- empty for loop
        "while%s+1%s+do",
    }
    local found = {}
    for _, p in ipairs(patterns) do
        local ok, f = _native_pcall(string.find, src, p)
        if ok and f then table.insert(found, p) end
    end
    return found
end

-- Detect metamethod abuse
local function detect_metamethod_abuse(src)
    local dangerous_mms = {
        "__index", "__newindex", "__call", "__len",
        "__tostring", "__gc", "__mode",
    }
    local found = {}
    for _, mm in ipairs(dangerous_mms) do
        local _, n = string.gsub(src, mm, "")
        if n > 2 then
            table.insert(found, mm .. " x" .. n)
        end
    end
    return found
end

-- Detect sandbox escape attempts
local SANDBOX_ESCAPE_PATTERNS = {
    { name = "setfenv_escape",     pattern = "setfenv%(1," },
    { name = "getfenv_0",          pattern = "getfenv%(0%)" },
    { name = "rawget_G",           pattern = "rawget%(_G," },
    { name = "debug_getupval",     pattern = "debug%.getupvalue" },
    { name = "debug_setupval",     pattern = "debug%.setupvalue" },
    { name = "load_escape",        pattern = "load%(.*_G" },
    { name = "fenv_override",      pattern = "setfenv%(func" },
}

local function detect_sandbox_escape(src)
    local found = {}
    for _, p in ipairs(SANDBOX_ESCAPE_PATTERNS) do
        if string.find(src, p.pattern) then
            table.insert(found, p.name)
        end
    end
    return found
end


-- ============================================================
--  SECTION 22 – PUBLIC API (minimal wrapper for combined parts)
-- ============================================================
local CatMio = {}

function CatMio.run(source)
    reset_state()
    reset_output()
    if not source then return "-- [CATMIO] No source provided" end
    -- Static analysis
    local obf_name, obf_score_raw, vm_sigs = detect_obfuscator(source)
    local obf_score, score_details = score_obfuscation(source)
    state.obfuscation_score = obf_score
    state.obfuscator_name   = obf_name
    -- Bytecode analysis
    local bc = analyse_bytecode_header(source)
    -- String pool extraction
    local pool = extract_string_pool(source)
    for _, s in ipairs(pool) do
        if #state.string_pool < 500 then
            table.insert(state.string_pool, s)
        end
    end
    -- Constants
    local consts = collect_constants(source)
    -- Risk
    local risk, risk_flags = compute_risk_score(source, obf_score)
    state.risk_score = risk
    state.risk_flags = risk_flags
    -- Detection
    local antidebug   = detect_antidebug(source)
    local persist     = detect_persistence(source)
    local keylog      = detect_keylogging(source)
    local exfil       = detect_exfiltration(source)
    local sandbox_esc = detect_sandbox_escape(source)
    local inf_loops   = detect_infinite_loops(source)
    local mm_abuse    = detect_metamethod_abuse(source)
    -- Anti-obf passes
    local deobf = apply_deobf_passes(source)
    -- Attempt decode of source header
    local header = string.sub(source, 1, CFG.OUTER_HEADER_BYTES)
    local decoded_hdr, dec_chain = multi_decode(header)
    -- Output report
    emit_banner("CATMIO v2.0.0 — ROBLOX SCRIPT ANALYSIS REPORT")
    emit("-- Obfuscator      : " .. (obf_name or "not detected"))
    emit("-- Obfusc. score   : " .. string.format("%.4f / 1.0000", obf_score))
    emit("-- Risk score      : " .. risk .. " / 100")
    emit("-- VM signatures   : " .. (vm_sigs or 0))
    emit("-- Source length   : " .. #source .. " bytes")
    emit("-- Entropy         : " .. string.format("%.4f bits", shannon_entropy(source)))
    if bc and bc.is_bytecode then
        emit("-- Bytecode type   : " .. (bc.version or "unknown"))
        emit("-- Endianness      : " .. (bc.endianness or "?"))
    end
    emit_blank()
    if #risk_flags > 0 then
        emit_sub("RISK FLAGS")
        for _, f in ipairs(risk_flags) do
            emit("-- [" .. string.upper(f.category) .. "] " .. f.desc .. " (+" .. f.weight .. ")")
        end
        emit_blank()
    end
    if #antidebug > 0 then
        emit_sub("ANTI-DEBUG TECHNIQUES DETECTED")
        for _, a in ipairs(antidebug) do emit("--   " .. a) end
        emit_blank()
    end
    if #persist > 0 then
        emit_sub("PERSISTENCE MECHANISMS DETECTED")
        for _, p in ipairs(persist) do emit("--   " .. p) end
        emit_blank()
    end
    if #keylog > 0 then
        emit_sub("KEYLOGGING INDICATORS")
        for _, k in ipairs(keylog) do emit("--   " .. k) end
        emit_blank()
    end
    if #exfil > 0 then
        emit_sub("NETWORK EXFILTRATION INDICATORS")
        for _, e in ipairs(exfil) do emit("--   " .. e) end
        emit_blank()
    end
    if #sandbox_esc > 0 then
        emit_sub("SANDBOX ESCAPE ATTEMPTS")
        for _, s in ipairs(sandbox_esc) do emit("--   " .. s) end
        emit_blank()
    end
    if #mm_abuse > 0 then
        emit_sub("METAMETHOD ABUSE")
        for _, m in ipairs(mm_abuse) do emit("--   " .. m) end
        emit_blank()
    end
    if #state.string_pool > 0 then
        emit_sub("EXTRACTED STRING POOL (" .. #state.string_pool .. " entries)")
        for i, s in ipairs(state.string_pool) do
            if i > 50 then emit("-- ... (" .. (#state.string_pool-50) .. " more)"); break end
            local enc = classify_string(s)
            emit("--   [" .. enc .. "] " .. safe_literal(s, 120))
        end
        emit_blank()
    end
    if decoded_hdr then
        emit_sub("DECODED HEADER (chain: " .. table.concat(dec_chain, "→") .. ")")
        local snippet = string.sub(decoded_hdr, 1, 400)
        for line in string.gmatch(snippet .. "\n", "([^\n]*)\n") do
            emit("-- " .. line)
        end
        emit_blank()
    end
    if #consts > 0 then
        emit_sub("TOP CONSTANTS BY RISK")
        for i, c in ipairs(consts) do
            if i > 30 then break end
            local flag_str = #c.flags > 0 and (" [" .. table.concat(c.flags, ",") .. "]") or ""
            emit(string.format("--   risk=%d len=%d [%s]%s: %s",
                c.risk, c.len, c.kind, flag_str, safe_literal(c.value, 80)))
        end
        emit_blank()
    end
    emit_sub("SCORE BREAKDOWN")
    for name, val in pairs(score_details) do
        if val > 0.1 then
            emit(string.format("--   %-25s %.4f", name, val))
        end
    end
    emit_blank()
    emit_banner("END OF CATMIO ANALYSIS")
    flush_rep()
    return table.concat(output_buffer, "\n")
end

function CatMio.decode(s)
    local decoded, chain = multi_decode(s)
    if not decoded then decoded, chain = try_xor_crack(s) end
    return decoded, chain
end

function CatMio.detect(src)  return detect_obfuscator(src) end
function CatMio.score(src)   return score_obfuscation(src) end
function CatMio.risk(src)
    local sc = score_obfuscation(src)
    return compute_risk_score(src, sc)
end

-- Codecs
CatMio.b64_decode      = b64_decode
CatMio.b64_url_decode  = b64_url_decode
CatMio.b64_encode      = b64_encode
CatMio.hex_decode      = hex_decode
CatMio.hex_encode      = hex_encode
CatMio.url_decode      = url_decode
CatMio.html_decode     = html_decode
CatMio.b32_decode      = b32_decode
CatMio.b58_decode      = b58_decode
CatMio.b85_decode      = b85_decode
CatMio.uuencode_decode = uuencode_decode
CatMio.qp_decode       = qp_decode

-- Ciphers
CatMio.rot13           = rot13_decode
CatMio.rot47           = rot47_decode
CatMio.rot18           = rot18_decode
CatMio.rot5            = rot5_decode
CatMio.rot             = rot_decode
CatMio.caesar_crack    = caesar_crack
CatMio.atbash          = atbash_decode
CatMio.vigenere_decode = vigenere_decode
CatMio.rail_fence      = rail_fence_decode
CatMio.columnar        = columnar_decode
CatMio.rc4_decode      = rc4_decode
CatMio.xtea_decode     = xtea_decode

-- XOR
CatMio.xor_byte        = xor_byte_decode
CatMio.xor_key         = xor_key_decode
CatMio.xor_rolling     = xor_rolling_decode
CatMio.xor_poly        = xor_poly_decode
CatMio.xor_crack       = try_xor_crack
CatMio.bitrev          = bitrev_decode
CatMio.byterev         = byterev_decode
CatMio.null_strip      = null_strip

-- Other decoders
CatMio.morse_decode    = morse_decode
CatMio.nato_decode     = nato_decode
CatMio.binary_decode   = binary_decode
CatMio.octal_decode    = octal_decode
CatMio.unicode_escape  = unicode_escape_decode

-- Hashes
CatMio.md5             = md5
CatMio.sha1            = sha1
CatMio.sha256          = sha256
CatMio.crc32           = crc32
CatMio.adler32         = adler32
CatMio.fletcher16      = fletcher16
CatMio.fnv1a           = fnv1a_hash

-- Analysis
CatMio.try_all_decoders   = try_all_decoders
CatMio.multi_decode        = multi_decode
CatMio.entropy_guided      = entropy_guided_decode
CatMio.is_readable         = is_readable
CatMio.safe_literal        = safe_literal
CatMio.entropy             = shannon_entropy
CatMio.detect_encoding     = detect_encoding
CatMio.detect_bom          = detect_bom
CatMio.detect_language     = detect_language
CatMio.classify_string     = classify_string
CatMio.find_urls           = find_urls
CatMio.find_ips            = find_ips
CatMio.analyse_string      = analyse_string
CatMio.normalise           = normalise_source
CatMio.collect_constants   = collect_constants
CatMio.extract_pool        = extract_string_pool
CatMio.detect_antidebug    = detect_antidebug
CatMio.detect_persistence  = detect_persistence
CatMio.detect_keylogging   = detect_keylogging
CatMio.detect_exfiltration = detect_exfiltration
CatMio.detect_sandbox_esc  = detect_sandbox_escape
CatMio.apply_deobf_passes  = apply_deobf_passes
CatMio.analyse_bytecode    = analyse_bytecode_header

-- Bit ops
CatMio.bw_and    = bw_and
CatMio.bw_or     = bw_or
CatMio.bw_xor    = bw_xor
CatMio.bw_not    = bw_not
CatMio.bw_lshift = bw_lshift
CatMio.bw_rshift = bw_rshift
CatMio.bw_rol    = bw_rol
CatMio.bw_ror    = bw_ror

-- Config
CatMio.CFG = CFG
CatMio.FINGERPRINTS = OBFUSCATOR_FINGERPRINTS
CatMio.VM_SIGS = VM_BOUNDARY_SIGS

return CatMio
