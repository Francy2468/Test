
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

