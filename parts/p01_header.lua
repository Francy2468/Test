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

