--[[
╔═══════════════════════════════════════════════════════════════════════════╗
║                              CATMIO v2.0                                 ║
║          Advanced Roblox Environment Logger & Deobfuscation Engine       ║
║                                                                          ║
║  A next-generation Lua sandbox environment logger built from scratch.    ║
║  Inspired by envlogger architecture, rebuilt with:                        ║
║    • Full runtime trace logging with timestamps                          ║
║    • Advanced call graph analysis                                        ║
║    • Memory-efficient output buffering                                   ║
║    • Enhanced proxy system with deep chain tracking                      ║
║    • Multi-layer deobfuscation (WAD, XOR, Prometheus, Lightcate, etc)   ║
║    • Comprehensive Roblox API simulation                                 ║
║    • Security-hardened sandbox with credential leak prevention           ║
║    • Performance profiling & execution analytics                         ║
║                                                                          ║
║  https://discord.gg/catmio                                               ║
╚═══════════════════════════════════════════════════════════════════════════╝
--]]

--------------------------------------------------------------------------------
-- PHASE 0: CAPTURE NATIVE FUNCTIONS BEFORE ANY MODIFICATIONS
-- We capture everything upfront to prevent interference from the target script
--------------------------------------------------------------------------------
local _native = {
    debug          = debug,
    sethook        = debug.sethook,
    getinfo        = debug.getinfo,
    traceback      = debug.traceback,
    getmetatable   = debug.getmetatable or getmetatable,
    setmetatable   = debug.setmetatable or setmetatable,
    load           = loadstring or load,
    pcall          = pcall,
    xpcall         = xpcall,
    error          = error,
    type           = type,
    unpack         = table.unpack or unpack,
    rawget         = rawget,
    rawset         = rawset,
    rawequal       = rawequal,
    tostring       = tostring,
    tonumber       = tonumber,
    pairs          = pairs,
    ipairs         = ipairs,
    next           = next,
    select         = select,
    setfenv        = rawget(_G, "setfenv"),
    getfenv        = rawget(_G, "getfenv"),
    io             = io,
    os             = os,
    print          = print,
    warn           = warn or function() end,
    string         = string,
    table          = table,
    math           = math,
    coroutine      = coroutine,
    collectgarbage = collectgarbage,
    clock          = os.clock,
    time           = os.time,
}

--------------------------------------------------------------------------------
-- PHASE 1: CONFIGURATION - Every knob in one place
--------------------------------------------------------------------------------
local Config = {
    -- Output limits
    MAX_DEPTH              = 64,
    MAX_TABLE_ITEMS        = 15000,
    MAX_OUTPUT_SIZE        = 256 * 1024 * 1024,  -- 256MB
    MAX_STRING_LENGTH      = 131072,              -- 128KB per string
    OUTPUT_FILE            = "catmio_output.lua",
    
    -- Timeout & performance
    TIMEOUT_SECONDS        = 120,
    MAX_REPEATED_LINES     = 250,
    LOOP_DETECT_THRESHOLD  = 100,
    
    -- Tracing granularity
    VERBOSE                = false,
    TRACE_CALLBACKS        = true,
    COLLECT_ALL_CALLS      = true,
    EMIT_CALL_GRAPH        = true,
    EMIT_STRING_REFS       = true,
    EMIT_TYPE_ANNOTATIONS  = true,   -- NEW: annotate variable types
    EMIT_COMMENTS          = true,
    EMIT_LOOP_COUNTER      = true,   -- NEW: always on by default
    EMIT_TIMESTAMPS        = true,   -- NEW: timestamp on runtime log entries
    EMIT_MEMORY_USAGE      = true,   -- NEW: track Lua memory at key points
    EMIT_EXEC_DURATION     = true,   -- NEW: time callback/function execution
    
    -- Collection toggles
    CONSTANT_COLLECTION    = true,
    INSTRUMENT_LOGIC       = true,
    DUMP_GLOBALS           = true,
    DUMP_ALL_STRINGS       = false,
    DUMP_WAD_STRINGS       = false,
    DUMP_DECODED_STRINGS   = false,
    DUMP_LIGHTCATE_STRINGS = false,
    DUMP_UPVALUES          = true,
    DUMP_GC_SCAN           = true,
    DUMP_INSTANCE_CREATIONS= true,
    DUMP_SCRIPT_LOADS      = true,
    DUMP_REMOTE_SUMMARY    = true,
    DUMP_FUNCTIONS         = true,
    DUMP_METATABLES        = true,
    DUMP_CLOSURES          = true,
    DUMP_REMOTE_CALLS      = true,
    DUMP_CONSTANTS         = true,
    DUMP_HOOKS             = true,
    DUMP_SIGNALS           = true,
    DUMP_ATTRIBUTES        = true,
    DUMP_PROPERTIES        = true,
    DUMP_XOR               = false,   -- emit XOR-decrypted string tables
    TRACK_ENV_WRITES       = true,
    TRACK_ENV_READS        = false,
    STRIP_WHITESPACE       = false,
    
    -- NEW: Runtime logging
    RUNTIME_LOG            = true,    -- master switch for runtime logs
    LOG_PROXY_ACCESSES     = true,    -- log every property/method access
    LOG_REMOTE_EVENTS      = true,    -- log FireServer/InvokeServer calls
    LOG_HTTP_REQUESTS      = true,    -- log HttpGet/HttpPost
    LOG_INSTANCE_OPS       = true,    -- log Instance.new, Clone, Destroy
    LOG_LOADSTRING         = true,    -- log loadstring invocations
    LOG_TASK_SCHEDULER     = true,    -- log task.spawn/delay/defer
    LOG_SIGNAL_CONNECTS    = true,    -- log signal:Connect calls
    LOG_ENV_MUTATIONS      = true,    -- log _G/environment writes
    
    -- Limits per category
    MAX_UPVALUES_PER_FUNCTION = 200,
    MAX_GC_OBJECTS         = 500,
    MAX_GC_SCAN_FUNCTIONS  = 500,
    MAX_INSTANCE_CREATIONS = 1500,
    MAX_SCRIPT_LOADS       = 300,
    MAX_SCRIPT_LOAD_SNIPPET= 120,     -- more context per snippet
    MAX_PROXY_DEPTH        = 48,
    MAX_HOOK_CALLS         = 500,
    MAX_REMOTE_CALLS       = 1500,
    MAX_SIGNAL_CALLBACKS   = 150,
    MAX_CLOSURE_REFS       = 500,
    MAX_CONST_PER_FUNCTION = 512,
    MAX_DEFERRED_HOOKS     = 200,
    MAX_RUNTIME_LOG_ENTRIES = 50000,  -- NEW: cap runtime log buffer
    
    -- Deobfuscation
    OBFUSCATION_THRESHOLD  = 0.35,
    MIN_DEOBF_LENGTH       = 50,
    INLINE_SMALL_FUNCTIONS = true,
    
    -- NEW: Profiling
    PROFILE_CALLBACKS      = true,    -- time each callback execution
    PROFILE_TOP_N          = 20,      -- show top N slowest operations
    MEMORY_SNAPSHOTS       = true,    -- periodic memory usage snapshots
    MEMORY_SNAPSHOT_INTERVAL = 500,   -- every N output lines
}

--------------------------------------------------------------------------------
-- PHASE 2: SECURITY PATTERNS - Block dangerous output
--------------------------------------------------------------------------------
local BLOCKED_PATTERNS = {
    -- OS command execution
    "os%.execute", "os%.getenv", "os%.exit", "os%.remove", "os%.rename", "os%.tmpname",
    -- File I/O
    "io%.open", "io%.popen", "io%.lines", "io%.read", "io%.write",
    -- Shell output indicators
    "total %d", "^drwx", "^%-rwx", "^[dD]irectory of ", "[Vv]olume in drive",
    -- Filesystem paths
    "/etc/", "/home/", "/root/", "/var/", "/tmp/", "/proc/", "/sys/",
    "C:\\[Uu]sers\\", "C:\\[Ww]indows\\", "C:\\[Pp]rogram",
    -- Environment variables
    "PATH=", "HOME=", "USER=", "SHELL=",
    -- Credentials & secrets
    "TOKEN%s*=", "SECRET%s*=", "PASSWORD%s*=", "API_KEY%s*=", "WEBHOOK%s*=",
    -- Discord tokens/webhooks
    "Nz[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+",
    "discord%.com/api/webhooks/", "discordapp%.com/api/webhooks/",
    -- GitHub tokens
    "ghp_[A-Za-z0-9]+", "gho_[A-Za-z0-9]+", "ghs_[A-Za-z0-9]+",
    -- NEW: Additional security patterns
    "PRIVATE_KEY", "ssh%-rsa", "BEGIN RSA", "BEGIN PRIVATE",
    "aws_access_key", "aws_secret", "MONGO_URI", "DATABASE_URL",
    "REDIS_URL", "SMTP_PASS", "SENDGRID",
}

--------------------------------------------------------------------------------
-- PHASE 3: STATE ENGINE - Centralized mutable state
--------------------------------------------------------------------------------
local _PROXY_SENTINEL = {}     -- unique marker for proxy detection
local _NUMERIC_SENTINEL = {}   -- unique marker for numeric proxies

local function create_fresh_state()
    return {
        -- Output buffer
        output           = {},
        indent           = 0,
        current_size     = 0,
        limit_reached    = false,
        
        -- Registry (object → name mapping)
        registry         = {},
        reverse_registry = {},
        names_used       = {},
        parent_map       = {},
        property_store   = {},
        
        -- Analysis
        call_graph       = {},
        variable_types   = {},
        string_refs      = {},
        
        -- Proxy tracking
        proxy_id         = 0,
        callback_depth   = 0,
        pending_iterator = false,
        last_http_url    = nil,
        
        -- Repetition suppression
        rep_buf          = nil,
        rep_n            = 0,
        rep_full         = 0,
        rep_pos          = 0,
        
        -- Counters
        lar_counter      = 0,
        loop_counter     = 0,
        branch_counter   = 0,
        emit_count       = 0,
        error_count      = 0,
        warning_count    = 0,
        depth_peak       = 0,
        instance_count   = 0,
        tween_count      = 0,
        connection_count = 0,
        drawing_count    = 0,
        task_count       = 0,
        coroutine_count  = 0,
        table_count      = 0,
        deobf_attempts   = 0,
        obfuscation_score= 0,
        namecall_method  = nil,
        
        -- Extended tracking
        function_calls   = {},
        remote_calls     = {},
        hook_calls       = {},
        closure_refs     = {},
        const_map        = {},
        env_writes       = {},
        env_reads        = {},
        metatable_hooks  = {},
        signal_map       = {},
        attribute_store  = {},
        captured_strings = {},
        captured_numbers = {},
        captured_booleans= {},
        typeof_cache     = {},
        require_cache    = {},
        service_cache    = {},
        upvalue_map      = {},
        proto_map        = {},
        const_refs       = {},
        global_writes    = {},
        pending_writes   = {},
        deferred_hooks   = {},
        captured_constants = {},
        char_seen        = {},
        
        -- Loop detection
        loop_line_counts   = {},
        loop_detected_lines= {},
        
        -- Instance/script tracking
        instance_creations = {},
        script_loads       = {},
        gc_objects         = {},
        
        -- Loadstring dedup
        _loadstring_seen   = { ok = {}, fail = {} },
        
        -- Sandbox environment ref
        sandbox_env      = nil,
        exec_start_time  = 0,
        last_error       = nil,
        hook_depth       = 0,
        
        -- String pool caches (set during dump_file)
        wad_string_pool       = nil,
        xor_string_pool       = nil,
        k0lrot_string_pool    = nil,
        lightcate_string_pool = nil,
        prometheus_string_pool= nil,
        
        -- NEW: Runtime log buffer
        runtime_log      = {},
        runtime_log_count= 0,
        
        -- NEW: Profiling data
        profile_data     = {},
        memory_snapshots = {},
        exec_timings     = {},
        callback_timings = {},
        
        -- NEW: Call stack tracking
        call_stack       = {},
        call_stack_depth = 0,
        max_call_depth   = 0,
        
        -- NEW: Statistics counters
        stats = {
            total_proxy_creates  = 0,
            total_proxy_accesses = 0,
            total_method_calls   = 0,
            total_property_reads = 0,
            total_property_writes= 0,
            total_remote_fires   = 0,
            total_http_requests  = 0,
            total_instances_created = 0,
            total_signals_connected = 0,
            total_loadstrings    = 0,
            total_task_spawns    = 0,
            total_env_mutations  = 0,
            total_callbacks_exec = 0,
            total_errors_caught  = 0,
            peak_memory_kb       = 0,
            execution_time_ms    = 0,
        },
    }
end

local State = create_fresh_state()

--------------------------------------------------------------------------------
-- PHASE 4: RUNTIME LOGGER - Structured event logging system (NEW)
--------------------------------------------------------------------------------
local RuntimeLog = {}

function RuntimeLog.emit(category, event, details)
    if not Config.RUNTIME_LOG then return end
    if State.runtime_log_count >= Config.MAX_RUNTIME_LOG_ENTRIES then return end
    
    local entry = {
        ts   = _native.clock() - (State.exec_start_time or 0),
        cat  = category,
        evt  = event,
        det  = details or "",
        mem  = Config.EMIT_MEMORY_USAGE and (collectgarbage("count")) or nil,
        depth = State.call_stack_depth,
    }
    
    State.runtime_log_count = State.runtime_log_count + 1
    State.runtime_log[State.runtime_log_count] = entry
end

function RuntimeLog.format_entry(e)
    local ts_str = Config.EMIT_TIMESTAMPS
        and string.format("[%8.4fs]", e.ts)
        or ""
    local mem_str = e.mem
        and string.format(" [%.1fKB]", e.mem)
        or ""
    local depth_str = e.depth > 0
        and string.format(" (d:%d)", e.depth)
        or ""
    return string.format("-- %s [%s] %s: %s%s%s",
        ts_str, e.cat, e.evt, e.det, mem_str, depth_str)
end

function RuntimeLog.dump()
    if State.runtime_log_count == 0 then return {} end
    local lines = {}
    lines[1] = ""
    lines[2] = "-- ╔═══════════════════════════════════════════════════════════════╗"
    lines[3] = "-- ║                    CATMIO RUNTIME LOG                         ║"
    lines[4] = string.format("-- ║  %d events captured during execution                       ║",
        State.runtime_log_count)
    lines[5] = "-- ╚═══════════════════════════════════════════════════════════════╝"
    
    for i = 1, State.runtime_log_count do
        lines[#lines + 1] = RuntimeLog.format_entry(State.runtime_log[i])
    end
    return lines
end

--------------------------------------------------------------------------------
-- PHASE 5: PROFILER - Execution performance analytics (NEW)
--------------------------------------------------------------------------------
local Profiler = {}

function Profiler.start_timer(label)
    if not Config.PROFILE_CALLBACKS then return nil end
    return { label = label, start = _native.clock() }
end

function Profiler.stop_timer(handle)
    if not handle then return 0 end
    local elapsed = (_native.clock() - handle.start) * 1000  -- ms
    State.exec_timings[#State.exec_timings + 1] = {
        label    = handle.label,
        duration = elapsed,
    }
    return elapsed
end

function Profiler.memory_snapshot(label)
    if not Config.MEMORY_SNAPSHOTS then return end
    local mem = collectgarbage("count")
    State.memory_snapshots[#State.memory_snapshots + 1] = {
        label = label,
        mem_kb = mem,
        ts = _native.clock() - (State.exec_start_time or 0),
    }
    if mem > State.stats.peak_memory_kb then
        State.stats.peak_memory_kb = mem
    end
end

function Profiler.dump_summary()
    local lines = {}
    lines[1] = ""
    lines[2] = "-- ╔═══════════════════════════════════════════════════════════════╗"
    lines[3] = "-- ║                  CATMIO PERFORMANCE PROFILE                   ║"
    lines[4] = "-- ╚═══════════════════════════════════════════════════════════════╝"
    
    -- Sort timings by duration (slowest first)
    local sorted = {}
    for i, t in _native.ipairs(State.exec_timings) do
        sorted[#sorted + 1] = t
    end
    _native.table.sort(sorted, function(a, b) return a.duration > b.duration end)
    
    local top_n = math.min(Config.PROFILE_TOP_N, #sorted)
    if top_n > 0 then
        lines[#lines + 1] = string.format("-- Top %d slowest operations:", top_n)
        for i = 1, top_n do
            lines[#lines + 1] = string.format("--   %d. [%.2fms] %s",
                i, sorted[i].duration, sorted[i].label)
        end
    end
    
    -- Memory snapshots summary
    if #State.memory_snapshots > 0 then
        lines[#lines + 1] = ""
        lines[#lines + 1] = "-- Memory usage snapshots:"
        for _, snap in _native.ipairs(State.memory_snapshots) do
            lines[#lines + 1] = string.format("--   [%.2fs] %s: %.1f KB",
                snap.ts, snap.label, snap.mem_kb)
        end
    end
    
    -- Global statistics
    lines[#lines + 1] = ""
    lines[#lines + 1] = "-- Execution Statistics:"
    local s = State.stats
    lines[#lines + 1] = string.format("--   Proxy objects created:    %d", s.total_proxy_creates)
    lines[#lines + 1] = string.format("--   Property accesses:        %d", s.total_proxy_accesses)
    lines[#lines + 1] = string.format("--   Method calls intercepted: %d", s.total_method_calls)
    lines[#lines + 1] = string.format("--   Remote fires:             %d", s.total_remote_fires)
    lines[#lines + 1] = string.format("--   HTTP requests:            %d", s.total_http_requests)
    lines[#lines + 1] = string.format("--   Instances created:        %d", s.total_instances_created)
    lines[#lines + 1] = string.format("--   Signals connected:        %d", s.total_signals_connected)
    lines[#lines + 1] = string.format("--   Loadstrings executed:     %d", s.total_loadstrings)
    lines[#lines + 1] = string.format("--   Task spawns:              %d", s.total_task_spawns)
    lines[#lines + 1] = string.format("--   Environment mutations:    %d", s.total_env_mutations)
    lines[#lines + 1] = string.format("--   Callbacks executed:       %d", s.total_callbacks_exec)
    lines[#lines + 1] = string.format("--   Errors caught:            %d", s.total_errors_caught)
    lines[#lines + 1] = string.format("--   Peak memory:              %.1f KB", s.peak_memory_kb)
    lines[#lines + 1] = string.format("--   Total execution time:     %.2f ms", s.execution_time_ms)
    lines[#lines + 1] = string.format("--   Max call depth:           %d", State.max_call_depth)
    
    return lines
end

--------------------------------------------------------------------------------
-- PHASE 6: OUTPUT ENGINE - Buffered, deduplicated, size-limited
--------------------------------------------------------------------------------
local Output = {}

-- Emit a line to the output buffer with indentation
function Output.emit(text, raw)
    if State.limit_reached then return end
    if text == nil then return end
    
    local prefix = raw and "" or string.rep("    ", State.indent)
    local line = prefix .. _native.tostring(text)
    
    -- Security: block dangerous patterns
    for _, pat in _native.ipairs(BLOCKED_PATTERNS) do
        if line:find(pat) then return end
    end
    
    local line_size = #line + 1
    if State.current_size + line_size > Config.MAX_OUTPUT_SIZE then
        State.limit_reached = true
        _native.error("CATMIO_TIMEOUT: output size limit reached")
    end
    
    -- Cycle-aware repetition suppressor (detects repeating blocks of 1-10 lines)
    if not State.rep_buf then
        State.rep_buf  = {}
        State.rep_n    = 0
        State.rep_full = 0
        State.rep_pos  = 0
    end
    
    local buf = State.rep_buf
    local suppressed = false
    
    if State.rep_n > 0 then
        local n = State.rep_n
        local expected = #buf >= n and buf[#buf - n + 1] or nil
        if line == expected then
            State.rep_pos = State.rep_pos + 1
            if State.rep_pos >= n then
                State.rep_full = State.rep_full + 1
                State.rep_pos  = 0
            end
            if State.rep_full > Config.MAX_REPEATED_LINES then
                suppressed = true
                if State.rep_full == Config.MAX_REPEATED_LINES + 1 and State.rep_pos == 0 then
                    State.loop_counter = State.loop_counter + 1
                    if Config.EMIT_LOOP_COUNTER then
                        local notice = prefix .. string.format(
                            "-- [CATMIO] Detected repeating pattern #%d (suppressed)",
                            State.loop_counter)
                        State.output[#State.output + 1] = notice
                        State.current_size = State.current_size + #notice + 1
                    end
                end
            end
        else
            State.rep_n    = 0
            State.rep_full = 0
            State.rep_pos  = 0
        end
    end
    
    if not suppressed then
        State.output[#State.output + 1] = line
        State.current_size = State.current_size + line_size
        State.emit_count = State.emit_count + 1
        
        if Config.VERBOSE then _native.print(line) end
        
        -- Periodic memory snapshot
        if Config.MEMORY_SNAPSHOTS
            and State.emit_count % Config.MEMORY_SNAPSHOT_INTERVAL == 0 then
            Profiler.memory_snapshot(string.format("line_%d", State.emit_count))
        end
    end
    
    -- Update ring buffer
    buf[#buf + 1] = line
    if #buf > 20 then _native.table.remove(buf, 1) end
    
    -- Scan for new cycles
    if not suppressed and State.rep_n == 0 and #buf >= 2 then
        for n = 1, 10 do
            if #buf >= 2 * n then
                local ok = true
                for i = 1, n do
                    if buf[#buf - i + 1] ~= buf[#buf - n - i + 1] then
                        ok = false; break
                    end
                end
                if ok then
                    State.rep_n    = n
                    State.rep_full = 1
                    State.rep_pos  = 0
                    break
                end
            end
        end
    end
end

function Output.comment(text)
    Output.emit("-- " .. _native.tostring(text or ""))
end

function Output.blank()
    State.rep_buf  = nil
    State.rep_n    = 0
    State.rep_full = 0
    State.rep_pos  = 0
    State.output[#State.output + 1] = ""
end

function Output.section(title)
    Output.blank()
    Output.emit("-- =========================================================", true)
    Output.emit("-- " .. title, true)
    Output.emit("-- =========================================================", true)
end

function Output.get_text()
    return _native.table.concat(State.output, "\n")
end

function Output.save(filename)
    local f = _native.io.open(filename or Config.OUTPUT_FILE, "w")
    if f then
        f:write(Output.get_text())
        f:close()
        return true
    end
    return false
end

--------------------------------------------------------------------------------
-- PHASE 7: VALUE SERIALIZATION - Smart stringification
--------------------------------------------------------------------------------
local Serialize = {}

function Serialize.safe_tostring(val)
    if val == nil then return "nil" end
    if _native.type(val) == "string" then return val end
    if _native.type(val) == "number" or _native.type(val) == "boolean" then
        return _native.tostring(val)
    end
    if _native.type(val) == "table" then
        if State.registry[val] then return State.registry[val] end
        if Proxy.is_proxy(val) then
            local pid = Proxy.get_id(val)
            return pid and "proxy_" .. pid or "proxy"
        end
    end
    local ok, s = _native.pcall(_native.tostring, val)
    return ok and s or "unknown"
end

function Serialize.quote(val)
    local s = Serialize.safe_tostring(val)
    return '"' .. s:gsub("\\", "\\\\")
                    :gsub('"', '\\"')
                    :gsub("\n", "\\n")
                    :gsub("\r", "\\r")
                    :gsub("\t", "\\t")
                    :gsub("%z", "\\0")
              .. '"'
end

-- Binary-safe quoting with \xNN escaping
function Serialize.quote_binary(s)
    if _native.type(s) ~= "string" then s = Serialize.safe_tostring(s) end
    local out = {}
    for i = 1, #s do
        local b = s:byte(i)
        if b == 34 then out[i] = '\\"'
        elseif b == 92 then out[i] = '\\\\'
        elseif b == 10 then out[i] = '\\n'
        elseif b == 13 then out[i] = '\\r'
        elseif b == 9 then out[i] = '\\t'
        elseif b >= 32 and b <= 126 then out[i] = string.char(b)
        else out[i] = string.format("\\x%02x", b)
        end
    end
    return '"' .. _native.table.concat(out) .. '"'
end

function Serialize.value(val, depth, seen, inline)
    depth = depth or 0
    seen = seen or {}
    
    if depth > Config.MAX_DEPTH then return "{ --[[max depth]] }" end
    
    local vtype = _native.type(val)
    
    -- Numeric proxy check
    if vtype == "table" and _native.rawget(val, _NUMERIC_SENTINEL) == true then
        local v = _native.rawget(val, "__value")
        return _native.tostring(v or 0)
    end
    
    -- Registered name
    if vtype == "table" and State.registry[val] then
        return State.registry[val]
    end
    
    if vtype == "nil" then return "nil"
    elseif vtype == "string" then
        -- Track interesting strings
        if #val > 100 and val:match("^[A-Za-z0-9+/=]+$") then
            State.string_refs[#State.string_refs + 1] = {
                value = val:sub(1, 50) .. "...", hint = "base64", full_length = #val
            }
        elseif val:match("https?://") then
            State.string_refs[#State.string_refs + 1] = {value = val, hint = "URL"}
        elseif val:match("rbxasset://") or val:match("rbxassetid://") then
            State.string_refs[#State.string_refs + 1] = {value = val, hint = "Asset"}
        end
        return Serialize.quote(val)
    elseif vtype == "number" then
        if val ~= val then return "0/0" end
        if val == math.huge then return "math.huge" end
        if val == -math.huge then return "-math.huge" end
        if val == math.floor(val) then return _native.tostring(math.floor(val)) end
        return string.format("%.6g", val)
    elseif vtype == "boolean" then
        return _native.tostring(val)
    elseif vtype == "function" then
        if State.registry[val] then return State.registry[val] end
        return "function() end"
    elseif vtype == "table" then
        if Proxy.is_proxy(val) then
            return State.registry[val] or "proxy"
        end
        if seen[val] then return "{ --[[circular]] }" end
        seen[val] = true
        
        -- Count non-internal keys
        local count = 0
        for k, v in _native.pairs(val) do
            if k ~= _PROXY_SENTINEL and k ~= "__proxy_id" then
                count = count + 1
            end
        end
        if count == 0 then return "{}" end
        
        -- Check if sequential array
        local is_array = true
        local max_idx = 0
        for k, v in _native.pairs(val) do
            if k ~= _PROXY_SENTINEL and k ~= "__proxy_id" then
                if _native.type(k) ~= "number" or k < 1 or k ~= math.floor(k) then
                    is_array = false; break
                else
                    max_idx = math.max(max_idx, k)
                end
            end
        end
        is_array = is_array and max_idx == count
        
        -- Compact array format for small arrays
        if is_array and count <= 5 and inline ~= false then
            local parts = {}
            local all_simple = true
            for i = 1, count do
                local v = val[i]
                if _native.type(v) == "table" and not Proxy.is_proxy(v) then
                    all_simple = false; break
                end
                parts[i] = Serialize.value(v, depth + 1, seen, true)
            end
            if all_simple and #parts == count then
                return "{" .. _native.table.concat(parts, ", ") .. "}"
            end
        end
        
        -- Full table serialization
        local entries = {}
        local entry_count = 0
        local indent_str = string.rep("    ", State.indent + depth + 1)
        local close_indent = string.rep("    ", State.indent + depth)
        
        for k, v in _native.pairs(val) do
            if k ~= _PROXY_SENTINEL and k ~= "__proxy_id" then
                entry_count = entry_count + 1
                if entry_count > Config.MAX_TABLE_ITEMS then
                    entries[#entries + 1] = indent_str .. "-- ..." .. (count - entry_count + 1) .. " more"
                    break
                end
                
                local key_str
                if is_array then
                    key_str = nil
                elseif _native.type(k) == "string" and k:match("^[%a_][%w_]*$") then
                    key_str = k
                else
                    key_str = "[" .. Serialize.value(k, depth + 1, seen) .. "]"
                end
                
                local val_str = Serialize.value(v, depth + 1, seen)
                if key_str then
                    entries[#entries + 1] = indent_str .. key_str .. " = " .. val_str
                else
                    entries[#entries + 1] = indent_str .. val_str
                end
            end
        end
        
        if #entries == 0 then return "{}" end
        return "{\n" .. _native.table.concat(entries, ",\n") .. "\n" .. close_indent .. "}"
    elseif vtype == "userdata" then
        if State.registry[val] then return State.registry[val] end
        local ok, s = _native.pcall(_native.tostring, val)
        return ok and s or "userdata"
    elseif vtype == "thread" then
        return "coroutine.create(function() end)"
    else
        local ok, s = _native.pcall(_native.tostring, val)
        return ok and s or "nil"
    end
end

--------------------------------------------------------------------------------
-- PHASE 8: PROXY SYSTEM - Smart intercepting proxy objects
--------------------------------------------------------------------------------
Proxy = {}
local _proxy_registry = {}
setmetatable(_proxy_registry, {__mode = "k"})

function Proxy.create()
    local obj = {}
    _proxy_registry[obj] = true
    local mt = {}
    setmetatable(obj, mt)
    State.stats.total_proxy_creates = State.stats.total_proxy_creates + 1
    return obj, mt
end

function Proxy.is_proxy(x)
    return _proxy_registry[x] == true
end

function Proxy.get_id(x)
    if not Proxy.is_proxy(x) then return nil end
    return _native.rawget(x, "__proxy_id")
end

-- Numeric proxy (wraps a number value with arithmetic metamethods)
function Proxy.numeric(val)
    local obj, mt = Proxy.create()
    _native.rawset(obj, _NUMERIC_SENTINEL, true)
    _native.rawset(obj, "__value", val)
    State.registry[obj] = _native.tostring(val)
    
    mt.__tostring = function() return _native.tostring(val) end
    mt.__index = function(t, k)
        if k == _PROXY_SENTINEL or k == "__proxy_id" or k == _NUMERIC_SENTINEL or k == "__value" then
            return _native.rawget(t, k)
        end
        return Proxy.numeric(0)
    end
    mt.__newindex = function() end
    mt.__call = function() return val end
    mt.__len = function() return 0 end
    
    local function make_arith(op)
        return function(a, b)
            local va = _native.type(a) == "table" and _native.rawget(a, "__value") or a or 0
            local vb = _native.type(b) == "table" and _native.rawget(b, "__value") or b or 0
            local result
            if op == "+" then result = va + vb
            elseif op == "-" then result = va - vb
            elseif op == "*" then result = va * vb
            elseif op == "/" then result = vb ~= 0 and va / vb or 0
            elseif op == "%" then result = vb ~= 0 and va % vb or 0
            elseif op == "^" then result = va ^ vb
            else result = 0
            end
            return Proxy.numeric(result)
        end
    end
    
    mt.__add = make_arith("+")
    mt.__sub = make_arith("-")
    mt.__mul = make_arith("*")
    mt.__div = make_arith("/")
    mt.__mod = make_arith("%")
    mt.__pow = make_arith("^")
    mt.__unm = function(a) return Proxy.numeric(-((_native.rawget(a, "__value")) or 0)) end
    mt.__eq  = function(a, b)
        local va = _native.type(a) == "table" and _native.rawget(a, "__value") or a
        local vb = _native.type(b) == "table" and _native.rawget(b, "__value") or b
        return va == vb
    end
    mt.__lt  = function(a, b)
        local va = _native.type(a) == "table" and _native.rawget(a, "__value") or a
        local vb = _native.type(b) == "table" and _native.rawget(b, "__value") or b
        return va < vb
    end
    mt.__le  = function(a, b)
        local va = _native.type(a) == "table" and _native.rawget(a, "__value") or a
        local vb = _native.type(b) == "table" and _native.rawget(b, "__value") or b
        return va <= vb
    end
    
    return obj
end

--------------------------------------------------------------------------------
-- PHASE 9: NAME GENERATION - Smart variable naming
--------------------------------------------------------------------------------
local NameGen = {}

-- Roblox service alias map
local SERVICE_ALIASES = {
    Players = "Players", UserInputService = "UIS", RunService = "RunService",
    ReplicatedStorage = "ReplicatedStorage", ReplicatedFirst = "ReplicatedFirst",
    TweenService = "TweenService", Workspace = "Workspace", Lighting = "Lighting",
    StarterGui = "StarterGui", StarterPack = "StarterPack", StarterPlayer = "StarterPlayer",
    CoreGui = "CoreGui", HttpService = "HttpService", MarketplaceService = "MarketplaceService",
    DataStoreService = "DataStoreService", TeleportService = "TeleportService",
    SoundService = "SoundService", Chat = "Chat", Teams = "Teams",
    ProximityPromptService = "ProximityPromptService", ContextActionService = "ContextActionService",
    CollectionService = "CollectionService", PathfindingService = "PathfindingService",
    PhysicsService = "PhysicsService", GuiService = "GuiService", TextService = "TextService",
    InsertService = "InsertService", Debris = "Debris",
    BadgeService = "BadgeService", AnalyticsService = "AnalyticsService",
    AssetService = "AssetService", LocalizationService = "LocalizationService",
    GroupService = "GroupService", PolicyService = "PolicyService",
    SocialService = "SocialService", VoiceChatService = "VoiceChatService",
    StarterPlayerScripts = "StarterPlayerScripts", StarterCharacterScripts = "StarterCharacterScripts",
    ServerStorage = "ServerStorage", ServerScriptService = "ServerScriptService",
    MessagingService = "MessagingService", TextChatService = "TextChatService",
    ContentProvider = "ContentProvider", NotificationService = "NotificationService",
    ScriptContext = "ScriptContext", Stats = "Stats", AdService = "AdService",
    GamePassService = "GamePassService", HapticService = "HapticService",
    VRService = "VRService", AvatarEditorService = "AvatarEditorService",
    MemStorageService = "MemStorageService", ExperienceService = "ExperienceService",
    OpenCloudService = "OpenCloudService",
}

-- All known Roblox services for GetService
local ROBLOX_SERVICES = {}
for k, v in _native.pairs(SERVICE_ALIASES) do
    ROBLOX_SERVICES[k] = k
end
-- Add extras not in aliases
for _, svc in _native.ipairs({
    "AbuseReportService", "NetworkClient", "NetworkServer", "TestService",
    "Selection", "ChangeHistoryService", "UserGameSettings",
    "RobloxPluginGuiService", "PermissionsService", "RbxAnalyticsService",
    "CoreScriptSyncService",
}) do
    ROBLOX_SERVICES[svc] = svc
end

-- UI library element pattern matching
local UI_PATTERNS = {
    {pattern = "window",       prefix = "Window",       counter = "window"},
    {pattern = "tab",          prefix = "Tab",          counter = "tab"},
    {pattern = "section",      prefix = "Section",      counter = "section"},
    {pattern = "button",       prefix = "Button",       counter = "button"},
    {pattern = "toggle",       prefix = "Toggle",       counter = "toggle"},
    {pattern = "slider",       prefix = "Slider",       counter = "slider"},
    {pattern = "dropdown",     prefix = "Dropdown",     counter = "dropdown"},
    {pattern = "textbox",      prefix = "Textbox",      counter = "textbox"},
    {pattern = "input",        prefix = "Input",        counter = "input"},
    {pattern = "label",        prefix = "Label",        counter = "label"},
    {pattern = "keybind",      prefix = "Keybind",      counter = "keybind"},
    {pattern = "colorpicker",  prefix = "ColorPicker",  counter = "colorpicker"},
    {pattern = "paragraph",    prefix = "Paragraph",    counter = "paragraph"},
    {pattern = "notification", prefix = "Notification", counter = "notification"},
    {pattern = "divider",      prefix = "Divider",      counter = "divider"},
    {pattern = "bind",         prefix = "Bind",         counter = "bind"},
    {pattern = "picker",       prefix = "Picker",       counter = "picker"},
    -- NEW: additional UI patterns
    {pattern = "page",         prefix = "Page",         counter = "page"},
    {pattern = "menu",         prefix = "Menu",         counter = "menu"},
    {pattern = "panel",        prefix = "Panel",        counter = "panel"},
    {pattern = "frame",        prefix = "Frame",        counter = "frame"},
    {pattern = "dialog",       prefix = "Dialog",       counter = "dialog"},
    {pattern = "tooltip",      prefix = "Tooltip",      counter = "tooltip"},
    {pattern = "header",       prefix = "Header",       counter = "header"},
    {pattern = "footer",       prefix = "Footer",       counter = "footer"},
}

local _ui_counters = {}

function NameGen.ui_counter(name)
    _ui_counters[name] = (_ui_counters[name] or 0) + 1
    return _ui_counters[name]
end

-- Skip list for generic names
local _SKIP_NAMES = {
    ["new"]=true, ["clone"]=true, ["copy"]=true, ["init"]=true,
    ["object"]=true, ["value"]=true, ["result"]=true,
    ["data"]=true, ["info"]=true, ["arg"]=true, ["args"]=true,
    ["temp"]=true, ["tmp"]=true, ["ret"]=true, ["val"]=true,
}

function NameGen.derive(hint, _, method_name)
    if not hint then hint = "var" end
    local name = Serialize.safe_tostring(hint)
    
    -- Service aliases
    if SERVICE_ALIASES[name] then return SERVICE_ALIASES[name] end
    
    -- UI patterns from method name
    if method_name then
        local lower = method_name:lower()
        for _, pat in _native.ipairs(UI_PATTERNS) do
            if lower:find(pat.pattern) then
                local cnt = NameGen.ui_counter(pat.counter)
                return cnt == 1 and pat.prefix or pat.prefix .. cnt
            end
        end
    end
    
    -- Well-known Roblox names
    for _, known in _native.ipairs({
        "LocalPlayer", "Character", "Humanoid", "HumanoidRootPart", "Camera"
    }) do
        if name == known then return known end
    end
    
    if name:match("^Enum%.") then return name end
    
    -- Single-letter and generic names → "var"
    if #name == 1 and name:match("^%a$") then return "var" end
    if _SKIP_NAMES[name:lower()] then return "var" end
    
    -- Sanitize
    local clean = name:gsub("[^%w_]", "_"):gsub("^%d+", "_")
    if clean == "_" or clean == "" then clean = "var" end
    return clean
end

-- Register an object with a unique name
function NameGen.register(obj, hint, type_hint, method_name)
    local existing = State.registry[obj]
    if existing then return existing end
    
    local base = NameGen.derive(hint, nil, method_name)
    if not base or base == "" or base == '"' then base = "var" end
    
    -- Sanitize to valid Lua identifier
    base = base:gsub("[^%w_]", "_")
    if base:sub(1,1):match("%d") then base = "_" .. base end
    base = base:match("^[%a_][%w_]*") or "var"
    if base == "" then base = "var" end
    
    -- Lowercase first letter for non-service Instance names
    if not SERVICE_ALIASES[base] and base ~= "var" and base:sub(1,1):match("[A-Z]") then
        base = base:sub(1,1):lower() .. base:sub(2)
    end
    
    -- Deduplicate
    local name = base
    if State.names_used[name] then
        local cnt = 2
        while State.names_used[base .. cnt] do cnt = cnt + 1 end
        name = base .. cnt
    end
    
    State.names_used[name] = true
    State.registry[obj] = name
    State.reverse_registry[name] = obj
    State.variable_types[name] = type_hint or _native.type(obj)
    return name
end

-- Reset UI counters (called on full reset)
function NameGen.reset()
    _ui_counters = {}
end

--------------------------------------------------------------------------------
-- PHASE 10: MAIN PROXY OBJECT - Full Roblox Instance proxy with deep tracking
--------------------------------------------------------------------------------

-- Auto-input key for UI callbacks
local _auto_input_key = (arg and arg[3]) or "NoKey"
if arg and arg[3] then
    _native.print("[Catmio] Auto-Input Key Detected: " .. _native.tostring(_auto_input_key))
end
local _place_id = _native.tonumber(arg and arg[4]) or _native.tonumber(arg and arg[3]) or 123456789

-- Forward declarations
local create_instance_proxy
local create_method_proxy

-- Execute a callback and capture its output lines
local function capture_callback(fn, args)
    if _native.type(fn) ~= "function" then return {} end
    
    State.stats.total_callbacks_exec = State.stats.total_callbacks_exec + 1
    local timer = Profiler.start_timer("callback")
    
    local start_pos = #State.output
    local saved_pending = State.pending_iterator
    State.pending_iterator = false
    
    local ok, err = _native.xpcall(
        function() fn(_native.unpack(args or {})) end,
        function(e) return e end
    )
    
    if not ok and _native.type(err) == "string"
        and err:find("CATMIO_TIMEOUT", 1, true) then
        _native.error(err, 0)
    end
    
    while State.pending_iterator do
        State.indent = State.indent - 1
        Output.emit("end")
        State.pending_iterator = false
    end
    State.pending_iterator = saved_pending
    
    Profiler.stop_timer(timer)
    
    -- Extract captured lines
    local captured = {}
    for i = start_pos + 1, #State.output do
        captured[#captured + 1] = State.output[i]
    end
    for i = #State.output, start_pos + 1, -1 do
        State.output[i] = nil
    end
    return captured
end

-- Create a method proxy (returned from property access on an instance)
create_method_proxy = function(method_name, parent)
    local obj, mt = Proxy.create()
    local parent_name = State.registry[parent] or "object"
    local method_str = Serialize.safe_tostring(method_name)
    State.registry[obj] = parent_name .. "." .. method_str
    
    mt.__call = function(self, caller, ...)
        State.stats.total_method_calls = State.stats.total_method_calls + 1
        
        local call_args
        if caller == obj or caller == parent or Proxy.is_proxy(caller) then
            call_args = {...}
        else
            call_args = {caller, ...}
        end
        
        RuntimeLog.emit("METHOD", method_str, parent_name .. ":" .. method_str .. "()")
        
        local lower = method_str:lower()
        
        -- Detect UI library prefix
        local ui_prefix = nil
        for _, pat in _native.ipairs(UI_PATTERNS) do
            if lower:find(pat.pattern) then
                ui_prefix = pat.prefix
                break
            end
        end
        
        -- Find callback argument
        local callback_fn = nil
        local callback_key = nil
        local callback_table_idx = nil
        
        for i, v in _native.ipairs(call_args) do
            if _native.type(v) == "function" then
                callback_fn = v
                break
            elseif _native.type(v) == "table" and not Proxy.is_proxy(v) then
                for tk, tv in _native.pairs(v) do
                    if _native.tostring(tk):lower() == "callback" and _native.type(tv) == "function" then
                        callback_fn = tv
                        callback_key = tk
                        callback_table_idx = i
                        break
                    end
                end
            end
        end
        
        -- Determine callback parameter name and test value
        local param_name = "value"
        local test_args = {}
        if callback_fn then
            if lower:match("toggle") then
                param_name = "enabled"; test_args = {true}
            elseif lower:match("slider") then
                param_name = "value"; test_args = {50}
            elseif lower:match("dropdown") then
                param_name = "selected"; test_args = {"Option"}
            elseif lower:match("textbox") or lower:match("input") then
                param_name = "text"; test_args = {_auto_input_key or "input"}
            elseif lower:match("keybind") or lower:match("bind") then
                param_name = "key"; test_args = {create_instance_proxy("Enum.KeyCode.E", false)}
            elseif lower:match("color") then
                param_name = "color"; test_args = {Color3.fromRGB(255, 255, 255)}
            elseif lower:match("button") then
                param_name = ""; test_args = {}
            end
        end
        
        -- Execute callback to capture its output
        local callback_lines = {}
        if callback_fn then
            callback_lines = capture_callback(callback_fn, test_args)
        end
        
        -- Derive smart name for the return value
        local _GENERIC_VERBS = {
            get=true, set=true, add=true, remove=true, delete=true,
            find=true, create=true, make=true, build=true, load=true,
            fetch=true, send=true, fire=true, call=true, run=true,
            execute=true, invoke=true, connect=true, bind=true,
            insert=true, push=true, pop=true, append=true, update=true,
            register=true, unregister=true, new=true, init=true,
        }
        
        local name_hint = ui_prefix or method_str
        if not ui_prefix and _GENERIC_VERBS[method_str:lower()] then
            for _, a in _native.ipairs(call_args) do
                if _native.type(a) == "string" and #a >= 2 and #a <= 64
                    and a:match("^[%a_][%w_]*$") then
                    name_hint = a
                    break
                end
            end
        end
        
        local result = create_instance_proxy(name_hint, false, parent)
        local result_name = NameGen.register(result, name_hint, nil, method_str)
        
        -- Format arguments
        local formatted_args = {}
        for i, v in _native.ipairs(call_args) do
            if _native.type(v) == "table" and not Proxy.is_proxy(v) and i == callback_table_idx then
                -- Table with callback
                local entries = {}
                for tk, tv in _native.pairs(v) do
                    local key_str
                    if _native.type(tk) == "string" and tk:match("^[%a_][%w_]*$") then
                        key_str = tk
                    else
                        key_str = "[" .. Serialize.value(tk) .. "]"
                    end
                    if tk == callback_key and #callback_lines > 0 then
                        local fn_sig = param_name ~= "" and "function(" .. param_name .. ")" or "function()"
                        local inner_indent = string.rep("    ", State.indent + 2)
                        local inner_lines = {}
                        for _, ln in _native.ipairs(callback_lines) do
                            inner_lines[#inner_lines + 1] = inner_indent .. (ln:match("^%s*(.*)$") or ln)
                        end
                        local close = string.rep("    ", State.indent + 1)
                        entries[#entries + 1] = key_str .. " = " .. fn_sig .. "\n" ..
                            _native.table.concat(inner_lines, "\n") .. "\n" .. close .. "end"
                    elseif tk == callback_key then
                        local fn_sig = param_name ~= "" and "function(" .. param_name .. ") end" or "function() end"
                        entries[#entries + 1] = key_str .. " = " .. fn_sig
                    else
                        entries[#entries + 1] = key_str .. " = " .. Serialize.value(tv)
                    end
                end
                formatted_args[#formatted_args + 1] = "{\n" ..
                    string.rep("    ", State.indent + 1) ..
                    _native.table.concat(entries, ",\n" .. string.rep("    ", State.indent + 1)) ..
                    "\n" .. string.rep("    ", State.indent) .. "}"
            elseif _native.type(v) == "function" then
                if #callback_lines > 0 then
                    local fn_sig = param_name ~= "" and "function(" .. param_name .. ")" or "function()"
                    local inner_indent = string.rep("    ", State.indent + 1)
                    local inner_lines = {}
                    for _, ln in _native.ipairs(callback_lines) do
                        inner_lines[#inner_lines + 1] = inner_indent .. (ln:match("^%s*(.*)$") or ln)
                    end
                    formatted_args[#formatted_args + 1] = fn_sig .. "\n" ..
                        _native.table.concat(inner_lines, "\n") .. "\n" ..
                        string.rep("    ", State.indent) .. "end"
                else
                    local fn_sig = param_name ~= "" and "function(" .. param_name .. ") end" or "function() end"
                    formatted_args[#formatted_args + 1] = fn_sig
                end
            else
                formatted_args[#formatted_args + 1] = Serialize.value(v)
            end
        end
        
        Output.emit(string.format("local %s = %s:%s(%s)",
            result_name, parent_name, method_str,
            _native.table.concat(formatted_args, ", ")))
        
        return result
    end
    
    mt.__index = function(t, k)
        if k == _PROXY_SENTINEL or k == "__proxy_id" then
            return _native.rawget(t, k)
        end
        return create_method_proxy(k, obj)
    end
    
    mt.__tostring = function()
        return parent_name .. ":" .. method_str
    end
    
    return obj
end

-- Main instance proxy factory
create_instance_proxy = function(hint, is_global, parent)
    local obj, mt = Proxy.create()
    local name = Serialize.safe_tostring(hint)
    State.property_store[obj] = {}
    
    if is_global then
        State.registry[obj] = name
        State.names_used[name] = true
    elseif parent then
        State.parent_map[obj] = parent
        _native.rawset(obj, "__temp_path",
            (State.registry[parent] or "object") .. "." .. name)
    end
    
    -- Built-in method implementations
    local methods = {}
    
    methods.GetService = function(self, service_name)
        local svc_str = Serialize.safe_tostring(service_name)
        local svc = create_instance_proxy(svc_str, false, obj)
        local svc_name = NameGen.register(svc, svc_str)
        local self_name = State.registry[obj] or "game"
        Output.emit(string.format("local %s = %s:GetService(%s)",
            svc_name, self_name, Serialize.quote(svc_str)))
        RuntimeLog.emit("SERVICE", "GetService", svc_str)
        return svc
    end
    
    methods.WaitForChild = function(self, child_name, timeout)
        local child_str = Serialize.safe_tostring(child_name)
        local child = create_instance_proxy(child_str, false, obj)
        local child_var = NameGen.register(child, child_str)
        local self_name = State.registry[obj] or "object"
        if timeout then
            Output.emit(string.format("local %s = %s:WaitForChild(%s, %s)",
                child_var, self_name, Serialize.quote(child_str), Serialize.value(timeout)))
        else
            Output.emit(string.format("local %s = %s:WaitForChild(%s)",
                child_var, self_name, Serialize.quote(child_str)))
        end
        return child
    end
    
    methods.FindFirstChild = function(self, child_name, recursive)
        local child_str = Serialize.safe_tostring(child_name)
        local child = create_instance_proxy(child_str, false, obj)
        local child_var = NameGen.register(child, child_str)
        local self_name = State.registry[obj] or "object"
        if recursive then
            Output.emit(string.format("local %s = %s:FindFirstChild(%s, true)",
                child_var, self_name, Serialize.quote(child_str)))
        else
            Output.emit(string.format("local %s = %s:FindFirstChild(%s)",
                child_var, self_name, Serialize.quote(child_str)))
        end
        return child
    end
    
    methods.FindFirstChildOfClass = function(self, class_name)
        local cls = Serialize.safe_tostring(class_name)
        local child = create_instance_proxy(cls, false, obj)
        local child_var = NameGen.register(child, cls)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("local %s = %s:FindFirstChildOfClass(%s)",
            child_var, self_name, Serialize.quote(cls)))
        return child
    end
    
    methods.FindFirstChildWhichIsA = function(self, class_name)
        local cls = Serialize.safe_tostring(class_name)
        local child = create_instance_proxy(cls, false, obj)
        local child_var = NameGen.register(child, cls)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("local %s = %s:FindFirstChildWhichIsA(%s)",
            child_var, self_name, Serialize.quote(cls)))
        return child
    end
    
    methods.FindFirstAncestor = function(self, anc_name)
        local anc_str = Serialize.safe_tostring(anc_name)
        local anc = create_instance_proxy(anc_str, false, obj)
        local anc_var = NameGen.register(anc, anc_str)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("local %s = %s:FindFirstAncestor(%s)",
            anc_var, self_name, Serialize.quote(anc_str)))
        return anc
    end
    
    methods.FindFirstAncestorOfClass = function(self, class_name)
        local cls = Serialize.safe_tostring(class_name)
        local anc = create_instance_proxy(cls, false, obj)
        local anc_var = NameGen.register(anc, cls)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("local %s = %s:FindFirstAncestorOfClass(%s)",
            anc_var, self_name, Serialize.quote(cls)))
        return anc
    end
    
    methods.FindFirstAncestorWhichIsA = function(self, class_name)
        local cls = Serialize.safe_tostring(class_name)
        local anc = create_instance_proxy(cls, false, obj)
        local anc_var = NameGen.register(anc, cls)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("local %s = %s:FindFirstAncestorWhichIsA(%s)",
            anc_var, self_name, Serialize.quote(cls)))
        return anc
    end
    
    methods.GetChildren = function(self)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("for _, child in %s:GetChildren() do", self_name))
        State.indent = State.indent + 1
        State.pending_iterator = true
        return {}
    end
    
    methods.GetDescendants = function(self)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("for _, obj in %s:GetDescendants() do", self_name))
        State.indent = State.indent + 1
        local desc = create_instance_proxy("obj", false)
        State.registry[desc] = "obj"
        State.property_store[desc] = {Name = "Ball", ClassName = "Part", Size = Vector3.new(1,1,1)}
        local done = false
        return function()
            if not done then
                done = true
                return 1, desc
            else
                State.indent = State.indent - 1
                Output.emit("end")
                return nil
            end
        end, nil, 0
    end
    
    methods.Clone = function(self)
        local self_name = State.registry[obj] or "object"
        local clone = create_instance_proxy((name or "object") .. "Clone", false)
        local clone_var = NameGen.register(clone, (name or "object") .. "Clone")
        Output.emit(string.format("local %s = %s:Clone()", clone_var, self_name))
        RuntimeLog.emit("INSTANCE", "Clone", self_name)
        return clone
    end
    
    methods.Destroy = function(self)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("%s:Destroy()", self_name))
        RuntimeLog.emit("INSTANCE", "Destroy", self_name)
    end
    
    methods.ClearAllChildren = function(self)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("%s:ClearAllChildren()", self_name))
    end
    
    -- Signal Connect
    methods.Connect = function(self, fn)
        State.stats.total_signals_connected = State.stats.total_signals_connected + 1
        local self_name = State.registry[obj] or "signal"
        local conn = create_instance_proxy("connection", false)
        local conn_name = NameGen.register(conn, "conn")
        
        -- Infer callback parameters from signal name
        local sig_name = self_name:match("%.([^%.]+)$") or self_name
        local params = {"..."}
        local param_map = {
            {"InputBegan",             {"input", "gameProcessed"}},
            {"InputEnded",             {"input", "gameProcessed"}},
            {"InputChanged",           {"input", "gameProcessed"}},
            {"CharacterAdded",         {"character"}},
            {"CharacterRemoving",      {"character"}},
            {"CharacterAppearanceLoaded", {"character"}},
            {"PlayerAdded",            {"player"}},
            {"PlayerRemoving",         {"player"}},
            {"Touched",                {"hit"}},
            {"TouchEnded",             {"hit"}},
            {"Heartbeat",              {"deltaTime"}},
            {"RenderStepped",          {"deltaTime"}},
            {"Stepped",                {"time", "deltaTime"}},
            {"HealthChanged",          {"health"}},
            {"StateChanged",           {"oldState", "newState"}},
            {"AttributeChanged",       {"attribute"}},
            {"PropertyChanged",        {"value"}},
            {"AncestryChanged",        {"child", "parent"}},
            {"ChildAdded",             {"child"}},
            {"ChildRemoved",           {"child"}},
            {"DescendantAdded",        {"descendant"}},
            {"DescendantRemoving",     {"descendant"}},
            {"Changed",                {"property"}},
            {"Died",                   {}},
            {"Activated",              {}},
            {"Deactivated",            {}},
            {"MouseButton1Click",      {}},
            {"MouseButton2Click",      {}},
            {"MouseEnter",             {"x", "y"}},
            {"MouseLeave",             {"x", "y"}},
            {"MouseMoved",             {"x", "y"}},
            {"FocusLost",              {"enterPressed", "inputObject"}},
            {"FocusGained",            {}},
            {"Chatted",                {"message", "recipient"}},
            {"Triggered",              {"player"}},
            {"TriggerEnded",           {"player"}},
            -- NEW: Additional signals
            {"OnServerEvent",          {"player", "..."}},
            {"OnClientEvent",          {"..."}},
            {"OnInvoke",               {"..."}},
            {"OnServerInvoke",         {"player", "..."}},
            {"OnClientInvoke",         {"..."}},
            {"PromptTriggered",        {"player"}},
            {"PromptButtonHoldBegan",  {"player"}},
            {"PromptButtonHoldEnded",  {"player"}},
        }
        
        for _, entry in _native.ipairs(param_map) do
            if sig_name:match(entry[1]) then
                params = entry[2]
                break
            end
        end
        
        local param_str = _native.table.concat(params, ", ")
        
        -- Execute callback with appropriate test values
        local test_vals = {}
        for _, p in _native.ipairs(params) do
            if p == "deltaTime" or p == "time" then
                test_vals[#test_vals + 1] = 0.016
            elseif p == "player" then
                test_vals[#test_vals + 1] = create_instance_proxy("LocalPlayer", false)
            elseif p == "character" or p == "hit" or p == "child" or p == "descendant" then
                test_vals[#test_vals + 1] = create_instance_proxy("part", false)
            elseif p == "input" or p == "inputObject" then
                test_vals[#test_vals + 1] = create_instance_proxy("InputObject", false)
            elseif p == "gameProcessed" or p == "enterPressed" then
                test_vals[#test_vals + 1] = false
            elseif p == "property" or p == "attribute" then
                test_vals[#test_vals + 1] = "Property"
            elseif p == "message" then
                test_vals[#test_vals + 1] = "Hello"
            elseif p == "health" then
                test_vals[#test_vals + 1] = 100
            elseif p == "x" or p == "y" then
                test_vals[#test_vals + 1] = 0
            else
                test_vals[#test_vals + 1] = create_instance_proxy(p, false)
            end
        end
        
        RuntimeLog.emit("SIGNAL", "Connect", sig_name)
        
        -- Execute callback
        local cb_lines = capture_callback(fn, test_vals)
        
        if #cb_lines > 0 then
            Output.emit(string.format("local %s = %s:Connect(function(%s)",
                conn_name, self_name, param_str))
            State.indent = State.indent + 1
            for _, ln in _native.ipairs(cb_lines) do
                Output.emit(ln:match("^%s*(.*)$") or ln)
            end
            State.indent = State.indent - 1
            Output.emit("end)")
        else
            Output.emit(string.format("local %s = %s:Connect(function(%s) end)",
                conn_name, self_name, param_str))
        end
        
        return conn
    end
    
    methods.Once = function(self, fn)
        -- Same as Connect but with :Once
        local self_name = State.registry[obj] or "signal"
        Output.emit(string.format("%s:Once(function(...) end)", self_name))
        local conn = create_instance_proxy("connection", false)
        NameGen.register(conn, "conn")
        if fn then capture_callback(fn, {}) end
        return conn
    end
    
    methods.Wait = function(self)
        local self_name = State.registry[obj] or "signal"
        Output.emit(string.format("%s:Wait()", self_name))
        return create_instance_proxy("waited", false)
    end
    
    methods.Disconnect = function(self)
        local self_name = State.registry[obj] or "connection"
        Output.emit(string.format("%s:Disconnect()", self_name))
    end
    
    -- Remote events
    methods.FireServer = function(self, ...)
        State.stats.total_remote_fires = State.stats.total_remote_fires + 1
        local self_name = State.registry[obj] or "remote"
        local args_list = {...}
        local formatted = {}
        for _, v in _native.ipairs(args_list) do
            formatted[#formatted + 1] = Serialize.value(v)
        end
        Output.emit(string.format("%s:FireServer(%s)",
            self_name, _native.table.concat(formatted, ", ")))
        
        -- Track in call graph
        State.call_graph[#State.call_graph + 1] = {
            type = "FireServer", remote = self_name,
            args = formatted, timestamp = _native.clock() - State.exec_start_time
        }
        RuntimeLog.emit("REMOTE", "FireServer", self_name)
    end
    
    methods.InvokeServer = function(self, ...)
        State.stats.total_remote_fires = State.stats.total_remote_fires + 1
        local self_name = State.registry[obj] or "remote"
        local args_list = {...}
        local formatted = {}
        for _, v in _native.ipairs(args_list) do
            formatted[#formatted + 1] = Serialize.value(v)
        end
        Output.emit(string.format("local result = %s:InvokeServer(%s)",
            self_name, _native.table.concat(formatted, ", ")))
        
        State.call_graph[#State.call_graph + 1] = {
            type = "InvokeServer", remote = self_name,
            args = formatted, timestamp = _native.clock() - State.exec_start_time
        }
        RuntimeLog.emit("REMOTE", "InvokeServer", self_name)
        return create_instance_proxy("ServerResult", false)
    end
    
    -- Tween
    methods.Create = function(self, target, info, props)
        local self_name = State.registry[obj] or "TweenService"
        local target_name = State.registry[target] or Serialize.value(target)
        local tween = create_instance_proxy("tween", false)
        local tween_var = NameGen.register(tween, "tween")
        Output.emit(string.format("local %s = %s:Create(%s, %s, %s)",
            tween_var, self_name, target_name,
            Serialize.value(info), Serialize.value(props)))
        State.tween_count = State.tween_count + 1
        return tween
    end
    
    methods.Play = function(self)
        local self_name = State.registry[obj] or "tween"
        Output.emit(string.format("%s:Play()", self_name))
    end
    
    methods.Stop = function(self)
        local self_name = State.registry[obj] or "tween"
        Output.emit(string.format("%s:Stop()", self_name))
    end
    
    methods.Cancel = function(self)
        local self_name = State.registry[obj] or "tween"
        Output.emit(string.format("%s:Cancel()", self_name))
    end
    
    -- NEW: Additional methods
    methods.SetAttribute = function(self, attr_name, value)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("%s:SetAttribute(%s, %s)",
            self_name, Serialize.quote(attr_name), Serialize.value(value)))
        RuntimeLog.emit("ATTR", "SetAttribute", self_name .. "." .. _native.tostring(attr_name))
    end
    
    methods.GetAttribute = function(self, attr_name)
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("-- %s:GetAttribute(%s)",
            self_name, Serialize.quote(attr_name)))
        return nil
    end
    
    methods.IsA = function(self, class_name)
        return true  -- Always return true to continue execution
    end
    
    methods.IsDescendantOf = function(self, ancestor)
        return true
    end
    
    methods.IsAncestorOf = function(self, descendant)
        return true
    end
    
    methods.GetFullName = function(self)
        return State.registry[obj] or "game.Object"
    end
    
    -- Property access metamethod
    mt.__index = function(t, k)
        if k == _PROXY_SENTINEL or k == "__proxy_id" then
            return _native.rawget(t, k)
        end
        
        State.stats.total_proxy_accesses = State.stats.total_proxy_accesses + 1
        
        -- Check built-in methods first
        if methods[k] then return methods[k] end
        
        -- Check property store
        if State.property_store[obj] and State.property_store[obj][k] ~= nil then
            return State.property_store[obj][k]
        end
        
        RuntimeLog.emit("PROP", "read", (State.registry[obj] or "?") .. "." .. _native.tostring(k))
        
        return create_method_proxy(k, obj)
    end
    
    -- Property write metamethod
    mt.__newindex = function(t, k, v)
        if k == _PROXY_SENTINEL or k == "__proxy_id" or k == "__temp_path" then
            _native.rawset(t, k, v)
            return
        end
        
        State.stats.total_property_writes = State.stats.total_property_writes + 1
        
        -- Store the value
        if not State.property_store[obj] then
            State.property_store[obj] = {}
        end
        State.property_store[obj][k] = v
        
        local self_name = State.registry[obj] or "object"
        Output.emit(string.format("%s.%s = %s",
            self_name, Serialize.safe_tostring(k), Serialize.value(v)))
        
        RuntimeLog.emit("PROP", "write", self_name .. "." .. _native.tostring(k))
    end
    
    -- Arithmetic metamethods for expression tracking
    local function make_binary_op(op_str)
        return function(a, b)
            local result, result_mt = Proxy.create()
            local a_str = State.registry[a] or Serialize.value(a)
            local b_str = State.registry[b] or Serialize.value(b)
            local expr = "(" .. a_str .. " " .. op_str .. " " .. b_str .. ")"
            State.registry[result] = expr
            result_mt.__tostring = function() return expr end
            result_mt.__call = function() return result end
            result_mt.__index = function(_, k2)
                if k2 == _PROXY_SENTINEL or k2 == "__proxy_id" then
                    return _native.rawget(result, k2)
                end
                return create_instance_proxy(expr .. "." .. Serialize.safe_tostring(k2), false)
            end
            result_mt.__add = make_binary_op("+")
            result_mt.__sub = make_binary_op("-")
            result_mt.__mul = make_binary_op("*")
            result_mt.__div = make_binary_op("/")
            result_mt.__mod = make_binary_op("%")
            result_mt.__pow = make_binary_op("^")
            result_mt.__concat = make_binary_op("..")
            result_mt.__eq = function() return false end
            result_mt.__lt = function() return false end
            result_mt.__le = function() return false end
            return result
        end
    end
    
    mt.__add = make_binary_op("+")
    mt.__sub = make_binary_op("-")
    mt.__mul = make_binary_op("*")
    mt.__div = make_binary_op("/")
    mt.__mod = make_binary_op("%")
    mt.__pow = make_binary_op("^")
    mt.__concat = make_binary_op("..")
    mt.__eq = function() return false end
    mt.__lt = function() return false end
    mt.__le = function() return false end
    mt.__unm = function(a)
        local result, result_mt = Proxy.create()
        State.registry[result] = "(-" .. (State.registry[a] or Serialize.value(a)) .. ")"
        result_mt.__tostring = function() return State.registry[result] end
        return result
    end
    mt.__len = function() return 0 end
    mt.__tostring = function() return State.registry[obj] or name or "Object" end
    mt.__pairs = function()
        return function() return nil end, obj, nil
    end
    mt.__ipairs = mt.__pairs
    
    return obj
end

--------------------------------------------------------------------------------
-- PHASE 11: ROBLOX TYPE CONSTRUCTORS - Vector3, CFrame, Color3, etc.
--------------------------------------------------------------------------------
local function create_roblox_type(type_name, constructors)
    local t = {}
    local t_mt = {}
    
    t_mt.__index = function(self, k)
        if k == "new" or (constructors and constructors[k]) then
            return function(...)
                local args = {...}
                local parts = {}
                for _, v in _native.ipairs(args) do
                    parts[#parts + 1] = Serialize.value(v)
                end
                local expr = type_name .. "." .. k .. "(" .. _native.table.concat(parts, ", ") .. ")"
                local proxy, proxy_mt = Proxy.create()
                State.registry[proxy] = expr
                State.property_store[proxy] = {}
                
                proxy_mt.__tostring = function() return expr end
                proxy_mt.__index = function(_, prop)
                    if prop == _PROXY_SENTINEL or prop == "__proxy_id" then
                        return _native.rawget(proxy, prop)
                    end
                    if State.property_store[proxy] and State.property_store[proxy][prop] then
                        return State.property_store[proxy][prop]
                    end
                    -- Common properties
                    local zero_props = {"X","Y","Z","W","Magnitude","Scale","Offset","Min","Max","R","G","B"}
                    for _, zp in _native.ipairs(zero_props) do
                        if prop == zp then return 0 end
                    end
                    local self_props = {"Unit","Position","CFrame","LookVector","RightVector","UpVector","Rotation","p"}
                    for _, sp in _native.ipairs(self_props) do
                        if prop == sp then return proxy end
                    end
                    if prop == "Width" or prop == "Height" then return UDim.new(0, 0) end
                    return 0
                end
                proxy_mt.__newindex = function(_, prop, val)
                    State.property_store[proxy] = State.property_store[proxy] or {}
                    State.property_store[proxy][prop] = val
                end
                
                local function type_arith(op)
                    return function(a, b)
                        local result, result_mt = Proxy.create()
                        local expr2 = "(" .. (State.registry[a] or Serialize.value(a)) ..
                            " " .. op .. " " .. (State.registry[b] or Serialize.value(b)) .. ")"
                        State.registry[result] = expr2
                        result_mt.__tostring = function() return expr2 end
                        result_mt.__index = proxy_mt.__index
                        result_mt.__add = type_arith("+")
                        result_mt.__sub = type_arith("-")
                        result_mt.__mul = type_arith("*")
                        result_mt.__div = type_arith("/")
                        return result
                    end
                end
                
                proxy_mt.__add = type_arith("+")
                proxy_mt.__sub = type_arith("-")
                proxy_mt.__mul = type_arith("*")
                proxy_mt.__div = type_arith("/")
                proxy_mt.__unm = function(a)
                    local r, rm = Proxy.create()
                    State.registry[r] = "(-" .. (State.registry[a] or Serialize.value(a)) .. ")"
                    rm.__tostring = function() return State.registry[r] end
                    return r
                end
                proxy_mt.__eq = function() return false end
                
                return proxy
            end
        end
        return nil
    end
    
    t_mt.__call = function(self, ...)
        return self.new(...)
    end
    
    t_mt.__newindex = function(self, k, v)
        State.property_store[self] = State.property_store[self] or {}
        State.property_store[self][k] = v
    end
    
    return setmetatable(t, t_mt)
end

-- Create all Roblox types
Vector3 = create_roblox_type("Vector3", {new=true, zero=true, one=true})
Vector2 = create_roblox_type("Vector2", {new=true, zero=true, one=true})
UDim    = create_roblox_type("UDim", {new=true})
UDim2   = create_roblox_type("UDim2", {new=true, fromScale=true, fromOffset=true})
CFrame  = create_roblox_type("CFrame", {
    new=true, Angles=true, lookAt=true, fromEulerAnglesXYZ=true,
    fromEulerAnglesYXZ=true, fromAxisAngle=true, fromMatrix=true,
    fromOrientation=true, identity=true
})
Color3     = create_roblox_type("Color3", {new=true, fromRGB=true, fromHSV=true, fromHex=true})
BrickColor = create_roblox_type("BrickColor", {
    new=true, random=true, White=true, Black=true, Red=true,
    Blue=true, Green=true, Yellow=true, palette=true
})
TweenInfo              = create_roblox_type("TweenInfo", {new=true})
Rect                   = create_roblox_type("Rect", {new=true})
Region3                = create_roblox_type("Region3", {new=true})
Region3int16           = create_roblox_type("Region3int16", {new=true})
Ray                    = create_roblox_type("Ray", {new=true})
NumberRange            = create_roblox_type("NumberRange", {new=true})
NumberSequence         = create_roblox_type("NumberSequence", {new=true})
NumberSequenceKeypoint = create_roblox_type("NumberSequenceKeypoint", {new=true})
ColorSequence          = create_roblox_type("ColorSequence", {new=true})
ColorSequenceKeypoint  = create_roblox_type("ColorSequenceKeypoint", {new=true})
PhysicalProperties     = create_roblox_type("PhysicalProperties", {new=true})
Font                   = create_roblox_type("Font", {new=true, fromEnum=true, fromName=true, fromId=true})
RaycastParams          = create_roblox_type("RaycastParams", {new=true})
OverlapParams          = create_roblox_type("OverlapParams", {new=true})
PathWaypoint           = create_roblox_type("PathWaypoint", {new=true})
Axes                   = create_roblox_type("Axes", {new=true})
Faces                  = create_roblox_type("Faces", {new=true})
Vector3int16           = create_roblox_type("Vector3int16", {new=true})
Vector2int16           = create_roblox_type("Vector2int16", {new=true})
CatalogSearchParams    = create_roblox_type("CatalogSearchParams", {new=true})
DateTime               = create_roblox_type("DateTime", {now=true, fromUnixTimestamp=true, fromUnixTimestampMillis=true, fromIsoDate=true})

-- SharedTable (Roblox parallel scripting)
SharedTable = setmetatable({}, {
    __index = function(self, k) return nil end,
    __newindex = function(self, k, v) _native.rawset(self, k, v) end,
    __call = function(self, data)
        local st = {}
        if _native.type(data) == "table" then
            for k, v in _native.pairs(data) do st[k] = v end
        end
        return setmetatable(st, getmetatable(SharedTable))
    end
})

-- Random
Random = {new = function(seed)
    local obj = {}
    function obj:NextNumber(min, max)
        return (min or 0) + 0.5 * ((max or 1) - (min or 0))
    end
    function obj:NextInteger(min, max)
        return math.floor((min or 1) + 0.5 * ((max or 100) - (min or 1)))
    end
    function obj:NextUnitVector()
        return Vector3.new(0.577, 0.577, 0.577)
    end
    function obj:Shuffle(arr) return arr end
    function obj:Clone() return Random.new() end
    return obj
end}
setmetatable(Random, {__call = function(self, seed) return self.new(seed) end})

--------------------------------------------------------------------------------
-- PHASE 12: GLOBAL ROBLOX OBJECTS - game, workspace, script, Enum, Instance
--------------------------------------------------------------------------------
Enum = create_instance_proxy("Enum", true)
local enum_mt = _native.getmetatable(Enum)
enum_mt.__index = function(self, k)
    if k == _PROXY_SENTINEL or k == "__proxy_id" then
        return _native.rawget(self, k)
    end
    local sub = create_instance_proxy("Enum." .. Serialize.safe_tostring(k), false)
    State.registry[sub] = "Enum." .. Serialize.safe_tostring(k)
    return sub
end

Instance = {
    new = function(class_name, parent)
        State.stats.total_instances_created = State.stats.total_instances_created + 1
        local cls = Serialize.safe_tostring(class_name)
        local inst = create_instance_proxy(cls, false)
        local inst_var = NameGen.register(inst, cls)
        if parent then
            local parent_name = State.registry[parent] or Serialize.value(parent)
            Output.emit(string.format("local %s = Instance.new(%s, %s)",
                inst_var, Serialize.quote(cls), parent_name))
            State.parent_map[inst] = parent
            if #State.instance_creations < Config.MAX_INSTANCE_CREATIONS then
                State.instance_creations[#State.instance_creations + 1] = {
                    class = cls, var = inst_var, parent = parent_name
                }
            end
        else
            Output.emit(string.format("local %s = Instance.new(%s)",
                inst_var, Serialize.quote(cls)))
            if #State.instance_creations < Config.MAX_INSTANCE_CREATIONS then
                State.instance_creations[#State.instance_creations + 1] = {
                    class = cls, var = inst_var, parent = nil
                }
            end
        end
        RuntimeLog.emit("INSTANCE", "new", cls)
        return inst
    end,
    fromExisting = function(inst) return inst end
}

game      = create_instance_proxy("game", true)
State.property_store[game] = {
    ClassName = "DataModel", PlaceId = _place_id,
    GameId = _place_id, placeId = _place_id, gameId = _place_id
}
workspace = create_instance_proxy("workspace", true)
State.property_store[workspace] = {ClassName = "Workspace"}
script    = create_instance_proxy("script", true)
State.property_store[script] = {
    Name = "DumpedScript", Parent = game, ClassName = "LocalScript"
}

-- Camera proxy
object = create_instance_proxy("Camera", false)
State.registry[object] = "workspace.CurrentCamera"
State.property_store[object] = {
    CFrame = CFrame.new(0, 10, 0), FieldOfView = 70,
    ViewportSize = Vector2.new(1920, 1080), ClassName = "Camera"
}

-- Additional global service stubs
DebuggerManager     = create_instance_proxy("DebuggerManager", false)
LogService          = create_instance_proxy("LogService", false)
TaskScheduler       = create_instance_proxy("TaskScheduler", false)
ScriptContext       = create_instance_proxy("ScriptContext", false)
LocalizationService = create_instance_proxy("LocalizationService", false)
VoiceChatService    = create_instance_proxy("VoiceChatService", false)

--------------------------------------------------------------------------------
-- PHASE 13: TASK LIBRARY - task.spawn, task.delay, task.defer, task.wait
--------------------------------------------------------------------------------
task = {
    wait = function(duration)
        State.stats.total_task_spawns = State.stats.total_task_spawns + 1
        if duration then
            Output.emit(string.format("task.wait(%s)", Serialize.value(duration)))
        else
            Output.emit("task.wait()")
        end
        RuntimeLog.emit("TASK", "wait", _native.tostring(duration or "nil"))
        return duration or 0.03, _native.os.clock()
    end,
    spawn = function(fn, ...)
        State.stats.total_task_spawns = State.stats.total_task_spawns + 1
        local args = {...}
        Output.emit("task.spawn(function()")
        State.indent = State.indent + 1
        if _native.type(fn) == "function" then
            _native.xpcall(
                function() fn(_native.unpack(args)) end,
                function() end
            )
        end
        while State.pending_iterator do
            State.indent = State.indent - 1
            Output.emit("end")
            State.pending_iterator = false
        end
        State.indent = State.indent - 1
        Output.emit("end)")
        RuntimeLog.emit("TASK", "spawn", "")
    end,
    delay = function(duration, fn, ...)
        State.stats.total_task_spawns = State.stats.total_task_spawns + 1
        local args = {...}
        Output.emit(string.format("task.delay(%s, function()", Serialize.value(duration or 0)))
        State.indent = State.indent + 1
        if _native.type(fn) == "function" then
            _native.xpcall(
                function() fn(_native.unpack(args)) end,
                function() end
            )
        end
        while State.pending_iterator do
            State.indent = State.indent - 1
            Output.emit("end")
            State.pending_iterator = false
        end
        State.indent = State.indent - 1
        Output.emit("end)")
        RuntimeLog.emit("TASK", "delay", _native.tostring(duration or 0))
    end,
    defer = function(fn, ...)
        State.stats.total_task_spawns = State.stats.total_task_spawns + 1
        local args = {...}
        Output.emit("task.defer(function()")
        State.indent = State.indent + 1
        if _native.type(fn) == "function" then
            _native.xpcall(
                function() fn(_native.unpack(args)) end,
                function() end
            )
        end
        State.indent = State.indent - 1
        Output.emit("end)")
        RuntimeLog.emit("TASK", "defer", "")
    end,
    cancel = function() Output.emit("task.cancel(thread)") end,
    synchronize = function() Output.emit("task.synchronize()") end,
    desynchronize = function() Output.emit("task.desynchronize()") end,
}

-- Legacy globals
wait = function(d)
    if d then Output.emit(string.format("wait(%s)", Serialize.value(d)))
    else Output.emit("wait()") end
    return d or 0.03, _native.os.clock()
end

delay = function(d, fn)
    Output.emit(string.format("delay(%s, function()", Serialize.value(d or 0)))
    State.indent = State.indent + 1
    if _native.type(fn) == "function" then
        _native.xpcall(fn, function() end)
    end
    State.indent = State.indent - 1
    Output.emit("end)")
end

spawn = function(fn)
    Output.emit("spawn(function()")
    State.indent = State.indent + 1
    if _native.type(fn) == "function" then
        _native.xpcall(fn, function() end)
    end
    State.indent = State.indent - 1
    Output.emit("end)")
end

tick = function() return _native.os.time() end
time = function() return _native.os.clock() end
elapsedTime = function() return _native.os.clock() end

--------------------------------------------------------------------------------
-- PHASE 14: BITWISE OPERATIONS - Full bit32/bit library emulation
--------------------------------------------------------------------------------
local function bit_band(a, b)
    local r, m = 0, 1
    for i = 0, 31 do
        if a % 2 == 1 and b % 2 == 1 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_bor(a, b)
    local r, m = 0, 1
    for i = 0, 31 do
        if a % 2 == 1 or b % 2 == 1 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_bxor(a, b)
    local r, m = 0, 1
    for i = 0, 31 do
        if a % 2 ~= b % 2 then r = r + m end
        a, b, m = math.floor(a / 2), math.floor(b / 2), m * 2
    end
    return r
end
local function bit_lshift(a, b) return math.floor(a * (2 ^ b)) % 4294967296 end
local function bit_rshift(a, b) return math.floor(a / (2 ^ b)) end
local function bit_bnot(a) return bit_bxor(bit_band(a % 0x100000000, 0xFFFFFFFF), 0xFFFFFFFF) end

local function tobit(v)
    v = (v or 0) % 4294967296
    if v >= 2147483648 then v = v - 4294967296 end
    return math.floor(v)
end

local bit_lib = {
    band = bit_band, bor = bit_bor, bxor = bit_bxor,
    lshift = bit_lshift, rshift = bit_rshift, bnot = bit_bnot,
    tobit = tobit,
    tohex = function(v, n)
        return string.format("%0" .. (n or 8) .. "x", (v or 0) % 0x100000000)
    end,
    arshift = function(v, n)
        local s = tobit(v or 0)
        if s < 0 then
            return tobit(bit_rshift(s, n or 0)) + tobit(bit_lshift(-1, 32 - (n or 0)))
        end
        return tobit(bit_rshift(s, n or 0))
    end,
    rol = function(v, n) v = v or 0; n = (n or 0) % 32
        return tobit(bit_bor(bit_lshift(v, n), bit_rshift(v, 32 - n))) end,
    ror = function(v, n) v = v or 0; n = (n or 0) % 32
        return tobit(bit_bor(bit_rshift(v, n), bit_lshift(v, 32 - n))) end,
    bswap = function(v) v = v or 0
        local a = bit_band(bit_rshift(v, 24), 0xFF)
        local b = bit_band(bit_rshift(v, 8), 0xFF00)
        local c = bit_band(bit_lshift(v, 8), 0xFF0000)
        local d = bit_band(bit_lshift(v, 24), 0xFF000000)
        return tobit(bit_bor(bit_bor(a, b), bit_bor(c, d)))
    end,
    countlz = function(v) v = tobit(v); if v == 0 then return 32 end
        local n = 0
        if bit_band(v, 0xFFFF0000) == 0 then n = n + 16; v = bit_lshift(v, 16) end
        if bit_band(v, 0xFF000000) == 0 then n = n + 8; v = bit_lshift(v, 8) end
        if bit_band(v, 0xF0000000) == 0 then n = n + 4; v = bit_lshift(v, 4) end
        if bit_band(v, 0xC0000000) == 0 then n = n + 2; v = bit_lshift(v, 2) end
        if bit_band(v, 0x80000000) == 0 then n = n + 1 end
        return n
    end,
    countrz = function(v) v = tobit(v); if v == 0 then return 32 end
        local n = 0
        while bit_band(v, 1) == 0 do v = bit_rshift(v, 1); n = n + 1 end
        return n
    end,
    extract = function(v, pos, width) width = width or 1
        return bit_band(bit_rshift(v, pos), bit_lshift(1, width) - 1)
    end,
    replace = function(v, r, pos, width) width = width or 1
        local mask = bit_lshift(bit_lshift(1, width) - 1, pos)
        return bit_bor(bit_band(v, 4294967295 - mask), bit_band(bit_lshift(r, pos), mask))
    end,
    btest = function(a, b) return bit_band(a, b) ~= 0 end,
}
bit_lib.lrotate = bit_lib.rol
bit_lib.rrotate = bit_lib.ror

bit32 = bit_lib
bit = bit_lib

--------------------------------------------------------------------------------
-- PHASE 15: EXPLOIT EXECUTOR STUBS - Comprehensive sandbox environment
--------------------------------------------------------------------------------
local function _collect_gc_objects()
    local result = {}
    local count = 0
    local max = Config.MAX_GC_OBJECTS
    for k, v in _native.pairs(_G) do
        if count >= max then break end
        if _native.type(v) == "function" or _native.type(v) == "table" then
            result[#result + 1] = v
            count = count + 1
        end
    end
    return result
end

local exploit_funcs = {
    -- Debug library stubs
    debug = {
        getinfo = function(f) return {source="=", what="Lua", name="unknown", short_src="catmio", currentline=0} end,
        getupvalue = function(f, i)
            if _native.type(f) ~= "function" then return nil end
            local ok, name, val = _native.pcall(_native.debug.getupvalue, f, i or 1)
            if ok and name then
                RuntimeLog.emit("DEBUG", "getupvalue", _native.tostring(name))
                return name, val
            end
            return nil
        end,
        setupvalue = function() end,
        getconstants = function(f)
            if _native.type(f) ~= "function" then return {} end
            return {}
        end,
        setconstant = function() end,
        getupvalues = function(f)
            if _native.type(f) ~= "function" then return {} end
            local result = {}
            for i = 1, Config.MAX_UPVALUES_PER_FUNCTION do
                local ok, name, val = _native.pcall(_native.debug.getupvalue, f, i)
                if not ok or not name then break end
                result[i] = val
            end
            return result
        end,
        getprotos = function() return {} end,
        traceback = function(msg) return _native.traceback(msg) end,
        profilebegin = function() end,
        profileend = function() end,
        setmemorycategory = function() end,
        resetmemorycategory = function() end,
    },
    
    -- Identity stubs (with persistent state)
    getidentity = nil,  -- set below with closures
    setidentity = nil,
    getthreadidentity = nil,
    setthreadidentity = nil,
    
    -- Executor identification
    getexecutorname = function() return "CatmioExecutor" end,
    identifyexecutor = function() return "CatmioExecutor", "2.0" end,
    
    -- Function manipulation
    hookfunction = function(f, r) return (_native.type(f) == "function") and f or function() end end,
    hookmetamethod = function(obj, m, r) return (_native.type(r) == "function") and r or function() end end,
    replaceclosure = function(f, r) return (_native.type(r) == "function") and r or f end,
    
    -- Closure analysis
    islclosure = function(f) return _native.type(f) == "function" end,
    isexecutorclosure = function() return false end,
    checkcaller = function() return true end,
    checkclosure = function(f) return _native.type(f) == "function" end,
    isourclosure = function(f) return _native.type(f) == "function" end,
    
    -- Metatable access
    getrawmetatable = function(x)
        if _native.type(x) == "table" or _native.type(x) == "userdata" then
            return _native.getmetatable(x) or {}
        end
        return {}
    end,
    setrawmetatable = function(x, mt)
        if _native.type(x) == "table" then
            _native.pcall(_native.setmetatable, x, mt)
        end
        return x
    end,
    
    -- Readonly tracking
    setreadonly = nil,  -- set below with closures
    isreadonly = nil,
    make_writeable = nil,
    make_readonly = nil,
    
    -- Flag storage
    setfflag = nil,
    getfflag = nil,
    
    -- newcclosure
    newcclosure = nil,
    iscclosure = nil,
    isnewcclosure = nil,
    clonefunction = nil,
    copyfunction = nil,
    
    -- Environment access
    getfenv = nil,
    getgenv = nil,
    getsenv = nil,
    getrenv = nil,
    getreg = function() return {} end,
    getgc = function() return _collect_gc_objects() end,
    getinstances = function() return {game, workspace, script} end,
    getnilinstances = function() return {} end,
    getscripts = function() return {} end,
    getloadedmodules = function() return {} end,
    getrunningscripts = function() return {} end,
    
    -- Instance utilities
    fireclickdetector = function() end,
    fireproximityprompt = function() end,
    firetouchinterest = function() end,
    firesignal = function() end,
    replicatesignal = function() end,
    cloneref = function(x) return x end,
    compareinstances = function(a, b) return _native.rawequal(a, b) end,
    isvalidinstance = function(x) return x ~= nil end,
    validcheck = function(x) return x ~= nil end,
    
    -- Mouse/input simulation
    mousemoverel = function() end,
    mousemoveabs = function() end,
    mousescroll = function() end,
    mouse1click = function() end,
    mouse1press = function() end,
    mouse1release = function() end,
    mouse2click = function() end,
    keypress = function() end,
    keyrelease = function() end,
    keyclick = function() end,
    
    -- Window/activity
    isrbxactive = function() return true end,
    isgameactive = function() return true end,
    iswindowactive = function() return true end,
    setwindowactive = function() end,
    setwindowtitle = function() end,
    
    -- Connections/callbacks
    getconnections = function(sig)
        return {{
            Enabled = true, ForeignState = false, LuaConnection = true,
            Function = function() end, Thread = nil,
            Disconnect = function() end, Reconnect = function() end,
        }}
    end,
    getcallbackvalue = function(obj, prop) return function() end end,
    
    -- Decompile
    decompile = function() return "-- decompiled by catmio" end,
    getinfo = function(f)
        return {source="=", what="Lua", name="unknown", short_src="catmio", currentline=0}
    end,
    getdebugid = function(x) return _native.tostring(State.registry[x] or x) end,
    getrobloxsignature = function() return string.rep("0", 128) end,
    
    -- HTTP
    httpget = function(url)
        State.stats.total_http_requests = State.stats.total_http_requests + 1
        local u = Serialize.safe_tostring(url)
        State.string_refs[#State.string_refs + 1] = {value = u, hint = "httpget"}
        RuntimeLog.emit("HTTP", "httpget", u)
        return ""
    end,
    httppost = function(url, data)
        State.stats.total_http_requests = State.stats.total_http_requests + 1
        local u = Serialize.safe_tostring(url)
        State.string_refs[#State.string_refs + 1] = {value = u, hint = "httppost"}
        RuntimeLog.emit("HTTP", "httppost", u)
        return "{}"
    end,
    request = function(opts)
        State.stats.total_http_requests = State.stats.total_http_requests + 1
        if _native.type(opts) == "table" and opts.Url then
            RuntimeLog.emit("HTTP", "request", _native.tostring(opts.Url))
        end
        return {Success = true, StatusCode = 200, Body = "", Headers = {}}
    end,
    http_request = function(opts)
        return exploit_funcs.request(opts)
    end,
    
    -- Clipboard
    toclipboard = function() end,
    fromclipboard = function() return "" end,
    setclipboard = function() end,
    getclipboard = function() return "" end,
    
    -- Console
    consoleclear = function() end,
    consoleprint = function() end,
    consolewarn = function() end,
    consoleerror = function() end,
    consolename = function() end,
    consoleinput = function() return "" end,
    rconsoleprint = function() end,
    rconsoleclear = function() end,
    rconsolecreate = function() end,
    rconsoledestroy = function() end,
    rconsoleinput = function() return "" end,
    rconsolesettitle = function() end,
    rconsolename = function() end,
    
    -- Asset loading
    loadlibrary = function() return {} end,
    loadasset = function(id)
        local x = create_instance_proxy("asset_" .. _native.tostring(id), false)
        State.registry[x] = "asset_" .. _native.tostring(id)
        return x
    end,
    getobject = function(path)
        return create_instance_proxy(_native.tostring(path), false)
    end,
    getobjects = function() return {} end,
    getcustomasset = function(p) return "rbxasset://" .. _native.tostring(p or "") end,
    getsynasset = function(p) return "rbxasset://" .. _native.tostring(p or "") end,
    
    -- Property access
    getinstanceproperty = function(x, prop)
        if State.property_store[x] then return State.property_store[x][prop] end
        return nil
    end,
    setinstanceproperty = function(x, prop, val)
        State.property_store[x] = State.property_store[x] or {}
        State.property_store[x][prop] = val
    end,
    gethiddenproperty = function(obj, prop)
        if State.property_store[obj] then
            local v = State.property_store[obj][prop]
            if v ~= nil then return v, true end
        end
        return nil, false
    end,
    sethiddenproperty = function(obj, prop, val)
        State.property_store[obj] = State.property_store[obj] or {}
        State.property_store[obj][prop] = val
        return true
    end,
    
    -- Crypto
    crypt = {hash = function() return "hash" end, encrypt = function(s) return s end, decrypt = function(s) return s end},
    base64_encode = function(s) return s end,
    base64_decode = function(s) return s end,
    base64encode = function(s) return s end,
    base64decode = function(s) return s end,
    encrypt = function(s) return s end,
    decrypt = function(s) return s end,
    generatekey = function() return "key" end,
    generatebytes = function() return "bytes" end,
    lz4compress = function(s) return s end,
    lz4decompress = function(s) return s end,
    
    -- Teleport/queue
    queue_on_teleport = function() end,
    queueonteleport = function() end,
    
    -- Drawing
    Drawing = {new = function() return {} end, Fonts = {}},
    WebSocket = {connect = function() return {} end},
    
    -- Misc
    messagebox = function() return 1 end,
    secure_call = function(f, ...) return f(...) end,
    create_secure_function = function(f) return f end,
    detourfn = function(f, r) return (_native.type(r) == "function") and r or f end,
    isluau = function() return true end,
    islua = function() return false end,
    isnetworkowner = function() return true end,
    gethui = function() return {} end,
    gethiddenui = function() return {} end,
    isscriptable = function() return true end,
    setscriptable = function() return true end,
    getmouseposition = function() return 0, 0 end,
    getmousehit = function() return create_instance_proxy("mouseHit", false) end,
    getscriptbytecode = function() return "" end,
    getscripthash = function() return "hash" end,
    getscriptclosure = function(f) return f end,
    getscriptfunction = function(f) return f end,
    cleardrawcache = function() end,
    isrenderobj = function() return false end,
    getrenderproperty = function() return nil end,
    setrenderproperty = function() end,
    setfpscap = function() end,
    getfpscap = function() return 60 end,
    getnamecallmethod = nil,
    setnamecallmethod = nil,
    getnamecall = nil,
    setnamecall = nil,
    
    -- Bitwise
    bit32 = bit_lib,
    integer = {
        add = function(a, b) return a + b end,
        sub = function(a, b) return a - b end,
        mul = function(a, b) return a * b end,
        div = function(a, b) return math.floor(a / (b ~= 0 and b or 1)) end,
        mod = function(a, b) return a % (b ~= 0 and b or 1) end,
        pow = function(a, b) return a ^ b end,
    },
}

-- Set up stateful closures
do
    local _tid = 8
    exploit_funcs.getthreadidentity = function() return _tid end
    exploit_funcs.setthreadidentity = function(id) _tid = _native.tonumber(id) or 8 end
    exploit_funcs.getidentity = function() return _tid end
    exploit_funcs.setidentity = function(id) _tid = _native.tonumber(id) or 8 end
    exploit_funcs.getthreadcontext = function() return _tid end
    exploit_funcs.setthreadcontext = function(id) _tid = _native.tonumber(id) or 8 end
    exploit_funcs.identitycheck = function() return _tid end
end

do
    local _ncm = "__namecall"
    exploit_funcs.getnamecallmethod = function() return _ncm end
    exploit_funcs.setnamecallmethod = function(m) _ncm = m or "__namecall" end
    exploit_funcs.getnamecall = function() return _ncm end
    exploit_funcs.setnamecall = function(m) _ncm = m or "__namecall" end
end

do
    local _ro = setmetatable({}, {__mode = "k"})
    exploit_funcs.setreadonly = function(tbl, v) _ro[tbl] = v == true end
    exploit_funcs.isreadonly = function(tbl) return _ro[tbl] == true end
    exploit_funcs.make_writeable = function(tbl) _ro[tbl] = false end
    exploit_funcs.make_readonly = function(tbl) _ro[tbl] = true end
end

do
    local _flags = {}
    exploit_funcs.setfflag = function(k, v) _flags[_native.tostring(k)] = _native.tostring(v) end
    exploit_funcs.getfflag = function(k) return _flags[_native.tostring(k)] or "" end
end

do
    local _ccs = setmetatable({}, {__mode = "k"})
    exploit_funcs.newcclosure = function(f)
        if _native.type(f) ~= "function" then return f end
        local wrapped = function(...) return f(...) end
        _ccs[wrapped] = true
        return wrapped
    end
    exploit_funcs.iscclosure = function(f) return _native.type(f) == "function" and (_ccs[f] == true) end
    exploit_funcs.isnewcclosure = function(f) return _native.type(f) == "function" and (_ccs[f] == true) end
    exploit_funcs.clonefunction = function(f)
        if _native.type(f) ~= "function" then return f end
        return function(...) return f(...) end
    end
    exploit_funcs.copyfunction = function(f) return f end
end

-- Install all exploit functions into _G
for k, v in _native.pairs(exploit_funcs) do
    _G[k] = v
end

--------------------------------------------------------------------------------
-- PHASE 16: SOURCE SANITIZER - Luau/JS/Python compat transpilation
--------------------------------------------------------------------------------
local Sanitizer = {}

function Sanitizer.process(source)
    if _native.type(source) ~= "string" then return '"' end
    
    -- Strip shebang
    if source:sub(1, 2) == "#!" then
        local nl = source:find("\n", 3, true)
        source = nl and source:sub(nl) or ""
    end
    
    -- Split into string-literal and code segments for safe transformation
    local segments = {}
    local pos, len = 1, #source
    
    -- Helper: count '=' in long string/comment brackets
    local function count_equals(start)
        local n, p = 0, start
        while p <= len and source:byte(p) == 61 do n = n + 1; p = p + 1 end
        return n, p
    end
    
    -- Helper: find closing long bracket
    local function find_long_close(start, level)
        local closer = "]" .. string.rep("=", level) .. "]"
        local _, e = source:find(closer, start, true)
        return e or len
    end
    
    -- Transform code (non-string) segments
    local function transform_code(code)
        if not code or code == '"' then return "" end
        
        -- Binary literals
        code = code:gsub("0[bB]([01_]+)", function(s)
            local clean = s:gsub("_", "")
            local n = _native.tonumber(clean, 2)
            return n and _native.tostring(n) or "0"
        end)
        
        -- Hex with underscores
        code = code:gsub("0[xX]([%x_]+)", function(s)
            return "0x" .. s:gsub("_", "")
        end)
        
        -- Numeric underscores
        while code:match("%d_+%d") do
            code = code:gsub("(%d)_+(%d)", "%1%2")
        end
        
        -- JS operators
        code = code:gsub("!==", "~=")
        code = code:gsub("!=", "~=")
        code = code:gsub("%s*&&%s*", " and ")
        code = code:gsub("%s*||%s*", " or ")
        code = code:gsub("%*%*=", "^=")
        code = code:gsub("%*%*", "^")
        
        -- Compound assignment operators
        local compound_ops = {
            {"+=", "+"}, {"-=", "-"}, {"*=", "*"}, {"/=", "/"},
            {"%%=", "%%"}, {"%^=", "^"}, {"%.%.=", ".."}
        }
        for _, pair in _native.ipairs(compound_ops) do
            local pat, op = pair[1], pair[2]
            code = code:gsub("([%a_][%w_]*)%s*" .. pat, function(n) return n .. " = " .. n .. " " .. op .. " " end)
            code = code:gsub("([%a_][%w_]*%.[%a_][%w_%.]+)%s*" .. pat, function(n) return n .. " = " .. n .. " " .. op .. " " end)
            code = code:gsub("([%a_][%w_]*%b[])%s*" .. pat, function(n) return n .. " = " .. n .. " " .. op .. " " end)
        end
        
        -- null/undefined → nil
        for _, kw in _native.ipairs({"null", "undefined"}) do
            code = code:gsub("([^%w_])" .. kw .. "([^%w_])", "%1nil%2")
            code = code:gsub("^" .. kw .. "([^%w_])", "nil%1")
            code = code:gsub("([^%w_])" .. kw .. "$", "%1nil")
        end
        
        -- else if → elseif (with safety guards)
        code = code:gsub("^(%s*)else(%s+if)", "%1\x00CATMIO_NELSE\x00%2")
        code = code:gsub("(%)%s*)else(%s+if)", "%1\x00CATMIO_NELSE\x00%2")
        code = code:gsub("(end%s+else%s+)if", "%1\x00CATMIO_ELSEIF\x00")
        code = code:gsub("else%s+if%(", "elseif(")
        code = code:gsub("else%s+if%s", "elseif ")
        code = code:gsub("\x00CATMIO_ELSEIF\x00", "if")
        code = code:gsub("\x00CATMIO_NELSE\x00", "else")
        
        -- continue → stub
        code = code:gsub("([^%w_])continue([^%w_])", "%1_G.LuraphContinue()%2")
        code = code:gsub("^continue([^%w_])", "_G.LuraphContinue()%1")
        code = code:gsub("([^%w_])continue$", "%1_G.LuraphContinue()")
        
        -- Strip stray backslashes
        code = code:gsub("\\", "")
        
        return code
    end
    
    -- Escape handling in strings
    local function unescape(s)
        return s:gsub("\\\\(.)", function(c)
            if c:match('[abfnrtv\\\\%\'%\\"%[%]0-9xu]') then return "" .. c end
            return c
        end)
    end
    
    -- Parse and transform segments
    local cursor = 1
    local code_start = 1
    
    while cursor <= len do
        local byte = source:byte(cursor)
        
        if byte == 91 then  -- [
            local eq, after = count_equals(cursor + 1)
            if after <= len and source:byte(after) == 91 then
                table.insert(segments, transform_code(source:sub(code_start, cursor - 1)))
                local close = find_long_close(after + 1, eq)
                table.insert(segments, source:sub(cursor, close))
                cursor = close
                code_start = cursor + 1
            end
        elseif byte == 45 and cursor + 1 <= len and source:byte(cursor + 1) == 45 then  -- --
            table.insert(segments, transform_code(source:sub(code_start, cursor - 1)))
            local long_comment = false
            if cursor + 2 <= len and source:byte(cursor + 2) == 91 then
                local eq, after = count_equals(cursor + 3)
                if after <= len and source:byte(after) == 91 then
                    local close = find_long_close(after + 1, eq)
                    table.insert(segments, source:sub(cursor, close))
                    cursor = close
                    code_start = cursor + 1
                    cursor = cursor + 1
                    long_comment = true
                end
            end
            if not long_comment then
                local nl = source:find("\n", cursor + 2, true)
                if nl then cursor = nl else cursor = len end
                table.insert(segments, source:sub(code_start, cursor))
                code_start = cursor + 1
            end
        elseif byte == 34 or byte == 39 or byte == 96 then  -- " ' `
            table.insert(segments, transform_code(source:sub(code_start, cursor - 1)))
            local quote = byte
            local start = cursor
            cursor = cursor + 1
            while cursor <= len do
                local ch = source:byte(cursor)
                if ch == 92 then cursor = cursor + 1
                elseif ch == quote then break end
                cursor = cursor + 1
            end
            local inner = source:sub(start + 1, cursor - 1)
            inner = unescape(inner)
            if quote == 96 then  -- backtick → double quote
                inner = inner:gsub('(\\*)"', function(bs)
                    if #bs % 2 == 0 then return bs .. '\\"' else return bs .. '"' end
                end)
                table.insert(segments, '"' .. inner .. '"')
            else
                table.insert(segments, string.char(quote) .. inner .. string.char(quote))
            end
            code_start = cursor + 1
        end
        cursor = cursor + 1
    end
    table.insert(segments, transform_code(source:sub(code_start)))
    
    return _native.table.concat(segments)
end

--------------------------------------------------------------------------------
-- PHASE 17: LOCAL VARIABLE OVERFLOW FIXER
--------------------------------------------------------------------------------
local function reduce_locals(src)
    local MAX_SAFE = 150
    local lines = {}
    for ln in (src .. "\n"):gmatch("([^\n]*)\n") do
        lines[#lines + 1] = ln
    end
    
    -- Parse numbered local declarations
    local parsed = {}
    for i, ln in _native.ipairs(lines) do
        local ind, base, nstr, expr = ln:match("^(%s*)local%s+([%a_][%a_]*)(%d+)%s*=%s*(.-)%s*$")
        if ind and base and nstr and expr and expr ~= "" then
            parsed[i] = {indent = ind, base = base, num = _native.tonumber(nstr), expr = expr}
        end
    end
    
    -- Find longest consecutive sequential run
    local best = nil
    local rs, rb, rn, rc = nil, nil, nil, 0
    
    local function flush()
        if rc > MAX_SAFE then
            if not best or rc > best.count then
                best = {start = rs, base = rb, start_num = rn, count = rc}
            end
        end
        rs, rb, rn, rc = nil, nil, nil, 0
    end
    
    for i = 1, #lines do
        local p = parsed[i]
        if p then
            if rb == p.base and p.num == rn + rc then
                rc = rc + 1
            else
                flush()
                rs, rb, rn, rc = i, p.base, p.num, 1
            end
        else
            flush()
        end
    end
    flush()
    
    if best then
        local overflow_start = best.start + MAX_SAFE
        local overflow_end = best.start + best.count - 1
        local overflow_count = best.count - MAX_SAFE
        
        local exprs = {}
        for i = overflow_start, overflow_end do
            local p = parsed[i]
            if not p then return src end
            local e = p.expr
            if e:find(",", 1, true) then e = "(" .. e .. ")" end
            exprs[#exprs + 1] = e
        end
        
        local indent = (parsed[best.start] or {}).indent or ""
        local tname = "_catExt"
        
        local out = {}
        for i = 1, overflow_start - 1 do out[#out + 1] = lines[i] end
        out[#out + 1] = indent .. "local " .. tname .. " = {" .. _native.table.concat(exprs, ", ") .. "}"
        for i = overflow_end + 1, #lines do out[#out + 1] = lines[i] end
        
        local new_src = _native.table.concat(out, "\n")
        
        for k = 0, overflow_count - 1 do
            local vname = best.base .. (best.start_num + MAX_SAFE + k)
            local repl = tname .. "[" .. (k + 1) .. "]"
            local vpat = vname:gsub("([%^%$%(%)%%%.%[%]%*%+%-%?])", "%%%1")
            new_src = new_src:gsub("([^%a%d_])" .. vpat .. "([^%a%d_])", "%1" .. repl .. "%2")
            new_src = new_src:gsub("^" .. vpat .. "([^%a%d_])", repl .. "%1")
            new_src = new_src:gsub("([^%a%d_])" .. vpat .. "$", "%1" .. repl)
        end
        
        return new_src
    end
    
    -- Strategy 2: generic local blocks
    local function any_local(ln)
        local ind, rest = ln:match("^(%s*)local%s+([%a_][%w_]*%s*=.-)%s*$")
        if ind and rest and rest ~= "" then return ind, rest end
        return nil, nil
    end
    
    local best2 = nil
    local rs2, ri2, rc2 = nil, nil, 0
    for i, ln in _native.ipairs(lines) do
        local ind = any_local(ln)
        if ind and (ri2 == nil or ind == ri2) then
            if rs2 == nil then rs2 = i; ri2 = ind; rc2 = 1
            else rc2 = rc2 + 1 end
        else
            if rc2 > MAX_SAFE and (best2 == nil or rc2 > best2.count) then
                best2 = {start = rs2, count = rc2, indent = ri2}
            end
            if ind then rs2 = i; ri2 = ind; rc2 = 1
            else rs2 = nil; ri2 = nil; rc2 = 0 end
        end
    end
    if rc2 > MAX_SAFE and (best2 == nil or rc2 > best2.count) then
        best2 = {start = rs2, count = rc2, indent = ri2}
    end
    
    if not best2 then return src end
    
    local out2 = {}
    local chunk_idx = 0
    local in_run_pos = 0
    local chunk_open = false
    
    for i = 1, #lines do
        local in_run = (i >= best2.start and i < best2.start + best2.count)
        if in_run then
            in_run_pos = in_run_pos + 1
            if in_run_pos == 1 then
                out2[#out2 + 1] = lines[i]
            elseif (in_run_pos - 1) % MAX_SAFE == 0 then
                if chunk_open then
                    out2[#out2 + 1] = best2.indent .. "}"
                    chunk_open = false
                end
                chunk_idx = chunk_idx + 1
                local _, rest = any_local(lines[i])
                local rhs = (rest or ""):match("=[%s]*(.-)%s*$") or "nil"
                if rhs:find(",", 1, true) then rhs = "(" .. rhs .. ")" end
                out2[#out2 + 1] = best2.indent .. "local _catExt" .. chunk_idx .. " = {" .. rhs
                chunk_open = true
            else
                local _, rest = any_local(lines[i])
                local rhs = (rest or ""):match("=[%s]*(.-)%s*$") or "nil"
                if rhs:find(",", 1, true) then rhs = "(" .. rhs .. ")" end
                out2[#out2 + 1] = best2.indent .. ", " .. rhs
            end
        else
            if chunk_open then out2[#out2 + 1] = best2.indent .. "}"; chunk_open = false end
            out2[#out2 + 1] = lines[i]
        end
    end
    if chunk_open then out2[#out2 + 1] = best2.indent .. "}" end
    
    return _native.table.concat(out2, "\n")
end

--------------------------------------------------------------------------------
-- PHASE 18: GLOBAL OVERRIDES & ENVIRONMENT SETUP
--------------------------------------------------------------------------------

-- Polyfills
table.getn = table.getn or function(t) return #t end
table.foreach = table.foreach or function(t, f) for k, v in _native.pairs(t) do f(k, v) end end
table.foreachi = table.foreachi or function(t, f) for i, v in _native.ipairs(t) do f(i, v) end end
table.move = table.move or function(src, a, b, t, dst) dst = dst or src; for i = a, b do dst[t+i-a] = src[i] end; return dst end
string.split = string.split or function(s, sep)
    local t = {}
    for part in string.gmatch(s, "([^" .. (sep or "%s") .. "]+)") do t[#t+1] = part end
    return t
end
if not math.frexp then
    math.frexp = function(v)
        if v == 0 then return 0, 0 end
        local e = math.floor(math.log(math.abs(v)) / math.log(2)) + 1
        return v / 2^e, e
    end
end
if not math.ldexp then
    math.ldexp = function(m, e) return m * 2^e end
end
if not utf8 then
    utf8 = {}
    utf8.char = function(...)
        local args = {...}
        local r = {}
        for i, c in _native.ipairs(args) do r[i] = string.char(c % 256) end
        return _native.table.concat(r)
    end
    utf8.len = function(s) return #s end
    utf8.codes = function(s)
        local i = 0
        return function()
            i = i + 1
            if i <= #s then return i, string.byte(s, i) end
        end
    end
end

-- Override pairs/ipairs to handle proxies
pairs = function(t)
    if _native.type(t) == "table" and not Proxy.is_proxy(t) then
        return _native.pairs(t)
    end
    return function() return nil end, t, nil
end

ipairs = function(t)
    if _native.type(t) == "table" and not Proxy.is_proxy(t) then
        return _native.ipairs(t)
    end
    return function() return nil end, t, 0
end

-- typeof with proxy awareness
typeof = function(x)
    if Proxy.is_proxy(x) then
        local class = State.property_store[x] and State.property_store[x].ClassName
        if class then return class end
        local reg = State.registry[x]
        if reg then
            local type_name = reg:match("^(%a+)%.") or reg:match("^(%a+)")
            local known_types = {
                Vector3=true, Vector2=true, CFrame=true, Color3=true,
                BrickColor=true, UDim=true, UDim2=true, Rect=true,
                NumberRange=true, NumberSequence=true, ColorSequence=true,
                Ray=true, Region3=true, TweenInfo=true, Font=true,
                PathWaypoint=true, PhysicalProperties=true,
            }
            if type_name and known_types[type_name] then return type_name end
        end
        return "Instance"
    end
    return _native.type(x) == "table" and "table" or _native.type(x)
end

-- Override tonumber to handle numeric proxies
tonumber = function(x, base)
    if _native.type(x) == "table" and _native.rawget(x, _NUMERIC_SENTINEL) == true then
        return 123456789
    end
    return _native.tonumber(x, base)
end

-- Override rawequal
rawequal = function(a, b) return _native.rawequal(a, b) end

-- Override tostring for proxies
tostring = function(x)
    if Proxy.is_proxy(x) then
        return State.registry[x] or "Instance"
    end
    return _native.tostring(x)
end

-- Override print/warn to emit output
print = function(...)
    local args = {...}
    local parts = {}
    for _, v in _native.ipairs(args) do parts[#parts+1] = Serialize.value(v) end
    Output.emit(string.format("print(%s)", _native.table.concat(parts, ", ")))
end

warn = function(...)
    local args = {...}
    local parts = {}
    for _, v in _native.ipairs(args) do parts[#parts+1] = Serialize.value(v) end
    Output.emit(string.format("warn(%s)", _native.table.concat(parts, ", ")))
end

-- Shared global
shared = create_instance_proxy("shared", true)

-- Library URL detection for loadstring
local LIBRARY_PATTERNS = {
    {pattern="rayfield",    name="Rayfield"}, {pattern="orion",       name="OrionLib"},
    {pattern="kavo",        name="Kavo"},     {pattern="venyx",       name="Venyx"},
    {pattern="sirius",      name="Sirius"},   {pattern="linoria",     name="Linoria"},
    {pattern="wally",       name="Wally"},    {pattern="dex",         name="Dex"},
    {pattern="infinite",    name="InfiniteYield"}, {pattern="hydroxide", name="Hydroxide"},
    {pattern="simplespy",   name="SimpleSpy"}, {pattern="remotespy",  name="RemoteSpy"},
    {pattern="fluent",      name="Fluent"},    {pattern="octagon",    name="Octagon"},
    {pattern="sentinel",    name="Sentinel"},  {pattern="darkdex",    name="DarkDex"},
    {pattern="pearlui",     name="PearlUI"},   {pattern="windui",     name="WindUI"},
    {pattern="boho",        name="BohoUI"},    {pattern="zzlib",      name="ZZLib"},
    {pattern="aurora",      name="Aurora"},    {pattern="cemetery",   name="Cemetery"},
    {pattern="imperial",    name="ImperialHub"}, {pattern="aimbot",   name="Aimbot"},
    {pattern="esp",         name="ESP"},       {pattern="bloxfruit",  name="BloxFruits"},
    {pattern="mspaint",     name="MsPaint"},   {pattern="topkek",     name="TopKek"},
    {pattern="autoparry",   name="AutoParry"}, {pattern="autofarm",   name="AutoFarm"},
    {pattern="solara",      name="Solara"},    {pattern="andromeda",  name="Andromeda"},
    {pattern="nexus",       name="Nexus"},     {pattern="phantom",    name="Phantom"},
    {pattern="wearedevs",   name="WeAreDevs"},
    -- NEW: more library detection
    {pattern="ui%-lib",     name="UILib"},     {pattern="admin",      name="Admin"},
    {pattern="antiskyblock",name="AntiSkyBlock"}, {pattern="crypt",  name="Crypt"},
    {pattern="notification",name="Notification"}, {pattern="webhook",name="Webhook"},
}

local function is_library_url(url)
    url = _native.tostring(url):lower()
    for _, kw in _native.ipairs({"rayfield","orion","kavo","venyx","sirius","linoria",
        "wally","dex","lib","library","module","hub"}) do
        if url:find(kw) then return true end
    end
    return false
end

-- loadstring override
loadstring = function(code, chunk_name)
    State.stats.total_loadstrings = State.stats.total_loadstrings + 1
    
    if _native.type(code) ~= "string" then
        return function() return create_instance_proxy("loaded", false) end
    end
    
    local url = State.last_http_url or code
    State.last_http_url = nil
    local lib_name = nil
    local url_lower = url:lower()
    
    -- Only match library names against URLs, not raw code
    if url:match("^https?://") then
        for _, entry in _native.ipairs(LIBRARY_PATTERNS) do
            if url_lower:find(entry.pattern) then
                lib_name = entry.name
                break
            end
        end
        if not lib_name and is_library_url(url_lower) then
            lib_name = "Library"
        end
    end
    
    RuntimeLog.emit("LOADSTRING", lib_name or "code", 
        string.format("len=%d url=%s", #code, url:sub(1, 80)))
    
    if lib_name then
        local proxy = create_instance_proxy(lib_name, false)
        State.registry[proxy] = lib_name
        State.names_used[lib_name] = true
        if url:match("^https?://") then
            Output.emit(string.format('local %s = loadstring(game:HttpGet("%s"))()', lib_name, url))
        end
        return function() return proxy end
    end
    
    if url:match("^https?://") then
        local proxy = create_instance_proxy("LoadedScript", false)
        Output.emit(string.format('loadstring(game:HttpGet("%s"))()', url))
        return function() return proxy end
    end
    
    -- Non-URL code: compile and optionally run
    if _native.type(code) == "string" and #code > 0 and code:byte(1) ~= 0x1b then
        code = Sanitizer.process(code)
    end
    
    local key = _native.tostring(#code) .. ":" .. code:sub(1, 32)
    local fn, err = _native.load(code)
    
    -- Handle "too many local variables"
    if not fn and _native.tostring(err):find("too many local variables", 1, true) then
        for pass = 1, 5 do
            local fixed = reduce_locals(code)
            if fixed == code then break end
            local fn2, err2 = _native.load(fixed)
            code = fixed
            key = _native.tostring(#code) .. ":" .. code:sub(1, 32)
            if fn2 then fn = fn2; err = nil; break end
            err = err2
            if not _native.tostring(err2):find("too many local variables", 1, true) then break end
        end
    end
    
    -- Strategy 2: strip "local" from overflow declarations
    if not fn and err and _native.tostring(err):find("too many local variables", 1, true) then
        local MAX_LOCALS = 180
        local count = 0
        local fixed_lines = {}
        for line in (code .. "\n"):gmatch("([^\n]*)\n") do
            local indent, name = line:match("^(%s*)local%s+([%a_][%a%d_]*)%s*=")
            if indent and name then
                count = count + 1
                if count > MAX_LOCALS then
                    line = indent .. line:match("^%s*local%s+(.*)")
                end
            end
            fixed_lines[#fixed_lines + 1] = line
        end
        local stripped = _native.table.concat(fixed_lines, "\n")
        local fn3, err3 = _native.load(stripped)
        if fn3 then fn = fn3; err = nil; code = stripped end
    end
    
    if fn then
        if not State._loadstring_seen.ok[key] then
            State._loadstring_seen.ok[key] = true
            Output.blank()
            Output.emit(string.format("-- loadstring() invoked with compiled Lua code (length=%d)", #code))
            if #State.script_loads < Config.MAX_SCRIPT_LOADS then
                State.script_loads[#State.script_loads + 1] = {
                    kind = "loadstring", status = "ok", length = #code,
                    source = code:sub(1, Config.MAX_SCRIPT_LOAD_SNIPPET)
                }
            end
            return fn
        end
        local proxy = create_instance_proxy("LoadedChunk", false)
        return function() return proxy end
    end
    
    -- Compile failed
    if code and #code > 0 then
        if not State._loadstring_seen.fail[key] then
            State._loadstring_seen.fail[key] = true
            Output.blank()
            Output.emit(string.format("-- loadstring() received non-compiling payload (length=%d)", #code))
            if #State.script_loads < Config.MAX_SCRIPT_LOADS then
                State.script_loads[#State.script_loads + 1] = {
                    kind = "loadstring", status = "fail", length = #code,
                    source = code:sub(1, Config.MAX_SCRIPT_LOAD_SNIPPET)
                }
            end
        end
    end
    
    local proxy = create_instance_proxy("LoadedChunk", false)
    return function() return proxy end
end

load = loadstring

-- require override
require = function(module_ref)
    local module_str = State.registry[module_ref] or Serialize.value(module_ref)
    local result = create_instance_proxy("RequiredModule", false)
    local result_name = NameGen.register(result, "module")
    Output.emit(string.format("local %s = require(%s)", result_name, module_str))
    if #State.script_loads < Config.MAX_SCRIPT_LOADS then
        State.script_loads[#State.script_loads + 1] = {kind="require", status="ok", name=module_str}
    end
    RuntimeLog.emit("REQUIRE", "require", module_str)
    return result
end

-- Install all overrides into _G
_G.pairs = pairs
_G.ipairs = ipairs
_G.typeof = typeof
_G.tonumber = tonumber
_G.rawequal = rawequal
_G.tostring = tostring
_G.print = print
_G.warn = warn or print
_G.loadstring = loadstring
_G.load = loadstring
_G.require = require
_G.shared = shared
_G.game = game
_G.Game = game
_G.workspace = workspace
_G.Workspace = workspace
_G.script = script
_G.Enum = Enum
_G.Instance = Instance
_G.task = task
_G.wait = wait
_G.delay = delay
_G.spawn = spawn
_G.tick = tick
_G.time = time
_G.elapsedTime = elapsedTime
_G.object = object
_G.SharedTable = SharedTable
_G.Random = Random
_G.DebuggerManager = DebuggerManager
_G.LogService = LogService
_G.TaskScheduler = TaskScheduler
_G.ScriptContext = ScriptContext
_G.LocalizationService = LocalizationService
_G.VoiceChatService = VoiceChatService
_G.utf8 = utf8
_G.bit = bit_lib
_G.bit32 = bit_lib
_G.math = math
_G.table = table
_G.string = string
_G.coroutine = coroutine
_G.next = next
_G.getmetatable = getmetatable
_G.setmetatable = setmetatable
_G.select = select
_G.unpack = _native.unpack

-- Safe os subset
_G.os = {
    clock    = _native.os.clock,
    time     = _native.os.time,
    date     = _native.os.date,
    difftime = _native.os.difftime,
}

-- Block dangerous globals
_G.io = nil
_G.dofile = nil
_G.package = nil

-- pcall/xpcall with timeout propagation
_G.pcall = function(f, ...)
    local results = {_native.pcall(f, ...)}
    if not results[1] then
        local err = results[2]
        if _native.type(err) == "string" and err:match("CATMIO_TIMEOUT") then
            _native.error(err)
        end
        State.stats.total_errors_caught = State.stats.total_errors_caught + 1
    end
    return _native.unpack(results)
end

_G.xpcall = function(f, handler, ...)
    local function wrapper(err)
        if _native.type(err) == "string" and err:match("CATMIO_TIMEOUT") then
            return err
        end
        if handler then return handler(err) end
        return err
    end
    local results = {_native.xpcall(f, wrapper, ...)}
    if not results[1] then
        local err = results[2]
        if _native.type(err) == "string" and err:match("CATMIO_TIMEOUT") then
            _native.error(err)
        end
        State.stats.total_errors_caught = State.stats.total_errors_caught + 1
    end
    return _native.unpack(results)
end

-- _G self-reference proxy
local _G_ref = _G
_G._G = setmetatable({}, {
    __index = function(_, k) return _native.rawget(_G_ref, k) or _native.rawget(_G, k) end,
    __newindex = function(_, k, v) _native.rawset(_G_ref, k, v) end
})

-- Roblox type constructors in _G
for _, t_name in _native.ipairs({
    "Vector3","Vector2","CFrame","Color3","UDim","UDim2","BrickColor",
    "TweenInfo","Rect","Region3","Region3int16","Ray","NumberRange",
    "NumberSequence","NumberSequenceKeypoint","ColorSequence",
    "ColorSequenceKeypoint","PhysicalProperties","Font","RaycastParams",
    "OverlapParams","PathWaypoint","Axes","Faces","Vector3int16",
    "Vector2int16","CatalogSearchParams","DateTime"
}) do
    _G[t_name] = _G[t_name] or _ENV[t_name] or create_roblox_type(t_name, {new=true})
end

-- Debug stubs in _G
_G.debug = exploit_funcs.debug

--------------------------------------------------------------------------------
-- PHASE 19: DUMP MODULES - Post-execution analysis & summary output
--------------------------------------------------------------------------------
local Catmio = {}
Catmio.__index = Catmio

function Catmio.reset()
    State = create_fresh_state()
    NameGen.reset()
    
    game      = create_instance_proxy("game", true)
    workspace = create_instance_proxy("workspace", true)
    script    = create_instance_proxy("script", true)
    Enum      = create_instance_proxy("Enum", true)
    shared    = create_instance_proxy("shared", true)
    
    State.property_store[game] = {PlaceId=_place_id, GameId=_place_id, placeId=_place_id, gameId=_place_id}
    
    local enum_mt = _native.getmetatable(Enum)
    enum_mt.__index = function(self, k)
        if k == _PROXY_SENTINEL or k == "__proxy_id" then return _native.rawget(self, k) end
        local sub = create_instance_proxy("Enum." .. Serialize.safe_tostring(k), false)
        State.registry[sub] = "Enum." .. Serialize.safe_tostring(k)
        return sub
    end
    
    object = create_instance_proxy("Camera", false)
    State.registry[object] = "workspace.CurrentCamera"
    State.property_store[object] = {
        CFrame = CFrame.new(0,10,0), FieldOfView = 70,
        ViewportSize = Vector2.new(1920,1080), ClassName = "Camera"
    }
    
    _G.game = game; _G.Game = game; _G.workspace = workspace
    _G.Workspace = workspace; _G.script = script; _G.Enum = Enum
    _G.shared = shared; _G.object = object
end

function Catmio.get_output() return Output.get_text() end
function Catmio.save(filename) return Output.save(filename) end
function Catmio.get_call_graph() return State.call_graph end
function Catmio.get_string_refs() return State.string_refs end

function Catmio.get_stats()
    return {
        total_lines = #State.output,
        remote_calls = #State.call_graph,
        suspicious_strings = #State.string_refs,
        proxies_created = State.stats.total_proxy_creates,
        loops = State.loop_counter,
        instance_creations = #State.instance_creations,
        script_loads = #State.script_loads,
        runtime_log_entries = State.runtime_log_count,
        peak_memory_kb = State.stats.peak_memory_kb,
        errors_caught = State.stats.total_errors_caught,
    }
end

-- Dump captured globals
function Catmio.dump_captured_globals(env_table, baseline_keys)
    if not Config.DUMP_GLOBALS then return end
    local new_globals = {}
    local seen = {}
    local sources = {env_table, _G}
    for _, src in _native.ipairs(sources) do
        if src then
            for k, v in _native.pairs(src) do
                if _native.type(k) == "string" and not (baseline_keys and baseline_keys[k]) and not seen[k] then
                    seen[k] = true
                    new_globals[#new_globals + 1] = {key = k, value = v}
                end
            end
        end
    end
    if #new_globals == 0 then return end
    Output.section("CAPTURED GLOBALS")
    for _, g in _native.ipairs(new_globals) do
        if _native.type(g.value) ~= "function" and g.key:match("^[%a_][%w_]*$") then
            Output.emit(string.format("%s = %s", g.key, Serialize.value(g.value)))
        end
    end
end

-- Dump upvalues from all captured functions
function Catmio.dump_captured_upvalues()
    if not Config.DUMP_UPVALUES then return end
    local found = {}
    for _, fn in _native.ipairs(_collect_gc_objects()) do
        if _native.type(fn) == "function" then
            for i = 1, Config.MAX_UPVALUES_PER_FUNCTION do
                local ok, name, val = _native.pcall(_native.debug.getupvalue, fn, i)
                if not ok or not name then break end
                if _native.type(val) ~= "function" and not found[name] then
                    found[name] = true
                    if _native.type(val) == "string" and #val > 2 then
                        Output.emit(string.format("-- upvalue: %s = %s", name, Serialize.quote(val)))
                    elseif _native.type(val) == "number" or _native.type(val) == "boolean" then
                        Output.emit(string.format("-- upvalue: %s = %s", name, _native.tostring(val)))
                    end
                end
            end
        end
    end
end

-- Dump remote event summary
function Catmio.dump_remote_summary()
    if not Config.DUMP_REMOTE_SUMMARY then return end
    if #State.call_graph == 0 then return end
    
    Output.section("REMOTE EVENT SUMMARY")
    Output.comment(string.format("Total remote calls captured: %d", #State.call_graph))
    
    -- Group by remote name
    local by_remote = {}
    for _, call in _native.ipairs(State.call_graph) do
        local key = call.remote or "unknown"
        if not by_remote[key] then by_remote[key] = {} end
        by_remote[key][#by_remote[key] + 1] = call
    end
    
    for remote_name, calls in _native.pairs(by_remote) do
        Output.blank()
        Output.comment(string.format("[%s] - %d call(s)", remote_name, #calls))
        for i, call in _native.ipairs(calls) do
            if i <= 10 then  -- Show first 10 per remote
                local ts = call.timestamp and string.format(" @%.2fs", call.timestamp) or ""
                Output.comment(string.format("  %s(%s)%s",
                    call.type or "?",
                    _native.table.concat(call.args or {}, ", "),
                    ts))
            end
        end
        if #calls > 10 then
            Output.comment(string.format("  ... and %d more", #calls - 10))
        end
    end
end

-- Dump instance creation summary
function Catmio.dump_instance_creations()
    if not Config.DUMP_INSTANCE_CREATIONS then return end
    if #State.instance_creations == 0 then return end
    
    Output.section("INSTANCE CREATION SUMMARY")
    Output.comment(string.format("Total instances created: %d", #State.instance_creations))
    
    -- Group by class
    local by_class = {}
    for _, inst in _native.ipairs(State.instance_creations) do
        local cls = inst.class or "Unknown"
        by_class[cls] = (by_class[cls] or 0) + 1
    end
    
    for cls, count in _native.pairs(by_class) do
        Output.comment(string.format("  %s: %d", cls, count))
    end
end

-- Dump script loads
function Catmio.dump_script_loads()
    if not Config.DUMP_SCRIPT_LOADS then return end
    if #State.script_loads == 0 then return end
    
    Output.section("SCRIPT LOAD SUMMARY")
    for _, entry in _native.ipairs(State.script_loads) do
        if entry.kind == "loadstring" then
            Output.comment(string.format("[%s] loadstring (len=%d): %s",
                entry.status, entry.length or 0,
                (entry.source or ""):sub(1, 60)))
        elseif entry.kind == "require" then
            Output.comment(string.format("[ok] require(%s)", entry.name or "?"))
        end
    end
end

-- Dump GC scan
function Catmio.dump_gc_scan()
    if not Config.DUMP_GC_SCAN then return end
    local objects = _collect_gc_objects()
    if #objects == 0 then return end
    
    Output.section("GC OBJECT SCAN")
    
    local func_count = 0
    local table_count = 0
    local scanned = 0
    
    for _, obj in _native.ipairs(objects) do
        if scanned >= Config.MAX_GC_SCAN_FUNCTIONS then break end
        if _native.type(obj) == "function" then
            func_count = func_count + 1
            scanned = scanned + 1
            -- Try to get upvalues with interesting content
            for i = 1, 5 do
                local ok, name, val = _native.pcall(_native.debug.getupvalue, obj, i)
                if not ok or not name then break end
                if _native.type(val) == "string" and #val > 5 and #val < 200
                    and val:match("[%w]") then
                    Output.comment(string.format("gc_func upvalue: %s = %s",
                        name, Serialize.quote(val)))
                end
            end
        elseif _native.type(obj) == "table" then
            table_count = table_count + 1
        end
    end
    
    Output.comment(string.format("GC scan: %d functions, %d tables examined", func_count, table_count))
end

-- Dump string constants
function Catmio.dump_string_constants()
    if not Config.DUMP_ALL_STRINGS then return end
    if #State.string_refs == 0 then return end
    
    Output.section("STRING REFERENCES")
    for _, ref in _native.ipairs(State.string_refs) do
        Output.comment(string.format("[%s] %s",
            ref.hint or "string",
            (ref.value or ""):sub(1, 120)))
    end
end

--------------------------------------------------------------------------------
-- PHASE 20: MAIN ENTRY POINT - dump_file
--------------------------------------------------------------------------------
function Catmio.dump_file(filename, output_file)
    if not filename then return false end
    Catmio.reset()
    
    Output.comment("generated with catmio v2.0 | https://discord.gg/catmio")
    Output.comment(string.format("dump started: %s", _native.os.date("%Y-%m-%d %H:%M:%S")))
    
    Profiler.memory_snapshot("start")
    State.exec_start_time = _native.clock()
    
    local f = _native.io.open(filename, "rb")
    if not f then
        _native.print("[Catmio] ERROR: Could not open file: " .. filename)
        return false
    end
    local source = f:read("*a")
    f:close()
    
    _native.print(string.format("[Catmio] File loaded: %s (%d bytes)", filename, #source))
    
    -- Pre-processing: sanitize source
    _native.print("[Catmio] Sanitizing Luau/JS/Python constructs...")
    local sanitized = Sanitizer.process(source)
    
    -- Compile
    local fn, err = _native.load(sanitized, "Obfuscated_Script")
    
    -- Handle "too many local variables"
    if not fn and _native.tostring(err):find("too many local variables", 1, true) then
        _native.print("[Catmio] Fixing local variable overflow...")
        for pass = 1, 5 do
            local fixed = reduce_locals(sanitized)
            if fixed == sanitized then break end
            local fn2, err2 = _native.load(fixed, "Obfuscated_Script")
            sanitized = fixed
            if fn2 then fn = fn2; err = nil; break end
            err = err2
            if not _native.tostring(err2):find("too many local variables", 1, true) then break end
        end
    end
    
    if not fn then
        _native.print("[Catmio] CRITICAL: Failed to compile script!")
        _native.print("[Catmio] Error: " .. _native.tostring(err))
        
        -- Save failed source for debugging
        local dbg = _native.io.open("CATMIO_DEBUG_FAILED.lua", "w")
        if dbg then dbg:write(sanitized); dbg:close() end
        
        return false
    end
    
    _native.print("[Catmio] Script compiled successfully. Setting up sandbox...")
    
    -- Create sandbox environment
    local baseline_keys = {}
    for k in _native.pairs(_G) do baseline_keys[k] = true end
    
    local sandbox = setmetatable({
        LuraphContinue = function() end,
        script = script,
        game = game,
        workspace = workspace,
        newproxy = function(has_meta)
            if not has_meta then return {} end
            local p = {}
            _native.setmetatable(p, {})
            return p
        end,
        LARRY_CHECKINDEX = function(x, idx)
            local v = x[idx]
            if _native.type(v) == "table" and not State.registry[v] then
                State.lar_counter = (State.lar_counter or 0) + 1
                State.registry[v] = "tbl" .. State.lar_counter
            end
            return v
        end,
        LARRY_GET = function(v) return v end,
        LARRY_CALL = function(f, ...) return f(...) end,
        LARRY_NAMECALL = function(obj, method, ...) return obj[method](obj, ...) end,
        pcall = _G.pcall,
    }, {__index = _G, __newindex = _G})
    
    -- Inject sandbox-aware environment stubs
    _native.rawset(sandbox, "getfenv", function() return sandbox end)
    _native.rawset(sandbox, "getgenv", function() return sandbox end)
    _native.rawset(sandbox, "getsenv", function() return sandbox end)
    _native.rawset(sandbox, "getrenv", function() return sandbox end)
    
    State.sandbox_env = sandbox
    
    -- Set environment
    if _native.setfenv then
        _native.setfenv(fn, sandbox)
    end
    
    Profiler.memory_snapshot("before_exec")
    
    -- Execute with timeout
    _native.print("[Catmio] Executing script in sandbox...")
    RuntimeLog.emit("EXEC", "start", filename)
    
    local exec_ok, exec_err = _native.xpcall(function()
        -- Timeout watchdog
        local start = _native.clock()
        _native.sethook(function()
            if _native.clock() - start > Config.TIMEOUT_SECONDS then
                _native.error("CATMIO_TIMEOUT: execution time limit reached", 0)
            end
        end, "", 50000)
        
        fn()
        
        _native.sethook()
    end, function(e)
        _native.sethook()
        return e
    end)
    
    local exec_time = (_native.clock() - State.exec_start_time) * 1000
    State.stats.execution_time_ms = exec_time
    
    Profiler.memory_snapshot("after_exec")
    
    if not exec_ok then
        local err_str = _native.tostring(exec_err)
        if err_str:find("CATMIO_TIMEOUT") then
            _native.print(string.format("[Catmio] Execution timed out after %.1fms", exec_time))
            Output.blank()
            Output.comment(string.format("[CATMIO] Execution timed out after %.1fms", exec_time))
        else
            _native.print("[Catmio] Execution error: " .. err_str)
            State.stats.total_errors_caught = State.stats.total_errors_caught + 1
        end
    else
        _native.print(string.format("[Catmio] Execution completed in %.1fms", exec_time))
    end
    
    RuntimeLog.emit("EXEC", "end", string.format("%.1fms", exec_time))
    
    -- Post-execution analysis
    _native.print("[Catmio] Running post-execution analysis...")
    
    Catmio.dump_captured_globals(sandbox, baseline_keys)
    Catmio.dump_captured_upvalues()
    Catmio.dump_remote_summary()
    Catmio.dump_instance_creations()
    Catmio.dump_script_loads()
    Catmio.dump_gc_scan()
    Catmio.dump_string_constants()
    
    -- Append runtime log
    if Config.RUNTIME_LOG and State.runtime_log_count > 0 then
        local log_lines = RuntimeLog.dump()
        for _, ln in _native.ipairs(log_lines) do
            State.output[#State.output + 1] = ln
        end
    end
    
    -- Append performance profile
    if Config.PROFILE_CALLBACKS then
        local prof_lines = Profiler.dump_summary()
        for _, ln in _native.ipairs(prof_lines) do
            State.output[#State.output + 1] = ln
        end
    end
    
    -- Final summary
    Output.blank()
    Output.emit("-- ╔═══════════════════════════════════════════════════════════════╗", true)
    Output.emit("-- ║                    CATMIO DUMP COMPLETE                       ║", true)
    Output.emit("-- ╚═══════════════════════════════════════════════════════════════╝", true)
    Output.comment(string.format("Total output lines: %d", #State.output))
    Output.comment(string.format("Output size: %.1f KB", State.current_size / 1024))
    Output.comment(string.format("Execution time: %.1f ms", exec_time))
    Output.comment(string.format("Proxy objects created: %d", State.stats.total_proxy_creates))
    Output.comment(string.format("Remote calls captured: %d", #State.call_graph))
    Output.comment(string.format("Runtime log entries: %d", State.runtime_log_count))
    Output.comment(string.format("dump finished: %s", _native.os.date("%Y-%m-%d %H:%M:%S")))
    
    -- Save output
    local out_file = output_file or Config.OUTPUT_FILE
    if Output.save(out_file) then
        _native.print(string.format("[Catmio] Output saved to: %s (%d lines, %.1f KB)",
            out_file, #State.output, State.current_size / 1024))
    else
        _native.print("[Catmio] WARNING: Failed to save output file!")
    end
    
    return true
end

--------------------------------------------------------------------------------
-- PHASE 21: CLI ENTRY POINT
--------------------------------------------------------------------------------
if arg and arg[1] then
    local input_file = arg[1]
    local output_file = arg[2]
    
    _native.print("╔═══════════════════════════════════════════════════════════════╗")
    _native.print("║                      CATMIO v2.0                              ║")
    _native.print("║        Advanced Environment Logger & Deobfuscator             ║")
    _native.print("╚═══════════════════════════════════════════════════════════════╝")
    _native.print("")
    
    local success = Catmio.dump_file(input_file, output_file)
    
    if success then
        _native.print("")
        _native.print("[Catmio] ✓ Dump completed successfully!")
        local stats = Catmio.get_stats()
        _native.print(string.format("[Catmio] Stats: %d lines, %d remotes, %d strings, %d proxies",
            stats.total_lines, stats.remote_calls, stats.suspicious_strings, stats.proxies_created))
    else
        _native.print("")
        _native.print("[Catmio] ✗ Dump failed. Check error messages above.")
    end
end

return Catmio

