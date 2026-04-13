-- ============================================================
--  SECTION 20 – PROXY FACTORY & CODE GENERATION
--  Creates Roblox API proxy objects that log all calls.
-- ============================================================

local PROXY_META = {}
PROXY_META.__index = function(self, key)
    local info = rawget(self, "_catmio_info") or {}
    local path = (info.path or "?") .. "." .. tostring(key)
    if CFG.TRACK_ENV_READS then
        emit("-- [READ] " .. path)
    end
    -- Return a callable proxy for method calls
    return setmetatable({
        _catmio_info = { path = path, parent = self, key = key },
    }, PROXY_META)
end

PROXY_META.__newindex = function(self, key, val)
    local info = rawget(self, "_catmio_info") or {}
    local path = (info.path or "?") .. "." .. tostring(key)
    local vstr = safe_literal(val, CFG.MAX_INLINE_STRING)
    if CFG.TRACK_ENV_WRITES then
        emit("-- [WRITE] " .. path .. " = " .. vstr)
    end
    if CFG.ENABLE_CODE_GEN then
        codegen_emit(path .. " = " .. vstr)
    end
    rawset(self, key, val)
end

PROXY_META.__call = function(self, ...)
    local info = rawget(self, "_catmio_info") or {}
    local path = info.path or "?"
    local args = {...}
    local arg_strs = {}
    for _, a in ipairs(args) do
        table.insert(arg_strs, safe_literal(a, 60))
    end
    local args_str = table.concat(arg_strs, ", ")
    emit("-- [CALL] " .. path .. "(" .. args_str .. ")")
    -- Code generation
    if CFG.ENABLE_CODE_GEN then
        local key = tostring(info.key or "")
        -- Special case: Connect → emit event handler stub
        if key == "Connect" or key == "connect" then
            local handler_name = codegen_new_var("handler")
            codegen_emit("local function " .. handler_name .. "(...)")
            codegen_emit("    -- TODO: implement " .. path .. " handler")
            codegen_emit("end")
            codegen_emit(path .. "(" .. handler_name .. ")")
        -- GetService → emit local var
        elseif key == "GetService" and args[1] then
            local svc = tostring(args[1])
            local var_name = string.lower(svc:sub(1,1)) .. svc:sub(2)
            codegen_emit("local " .. var_name .. " = game:GetService('" .. svc .. "')")
            state.codegen_vars[svc] = var_name
        -- WaitForChild → emit navigation
        elseif key == "WaitForChild" and args[1] then
            local child = tostring(args[1])
            local var_name = codegen_new_var("child")
            local parent_path = tostring(info.parent and
                (rawget(info.parent, "_catmio_info") or {}).path or "?")
            codegen_emit("local " .. var_name .. " = " ..
                parent_path .. ":WaitForChild('" .. child .. "')")
        -- FindFirstChild
        elseif key == "FindFirstChild" and args[1] then
            local child = tostring(args[1])
            local var_name = codegen_new_var("child")
            local parent_path = tostring(info.parent and
                (rawget(info.parent, "_catmio_info") or {}).path or "?")
            codegen_emit("local " .. var_name .. " = " ..
                parent_path .. ":FindFirstChild('" .. child .. "')")
        -- FireServer / FireAllClients
        elseif key == "FireServer" or key == "FireAllClients" or key == "FireClient" then
            table.insert(state.call_graph, {
                type = "Remote:" .. key,
                path = path,
                args = args_str,
            })
        -- InvokeServer
        elseif key == "InvokeServer" then
            table.insert(state.call_graph, {
                type = "RemoteFunction:InvokeServer",
                path = path,
                args = args_str,
            })
        else
            codegen_emit(path .. "(" .. args_str .. ")")
        end
    end
    -- Track remote calls
    if #state.call_graph < CFG.MAX_REMOTE_CALLS then
        local key = tostring(info.key or "")
        if key == "FireServer" or key == "FireAllClients" or
           key == "InvokeServer" or key == "FireClient" then
            table.insert(state.call_graph, {
                type = "remote:" .. key,
                path = path,
                args = args_str,
            })
        end
    end
    -- Return a proxy result
    state.proxy_id = (state.proxy_id or 0) + 1
    return setmetatable({
        _catmio_info = {
            path   = path .. "()",
            parent = self,
            key    = "result_" .. state.proxy_id,
        },
    }, PROXY_META)
end

PROXY_META.__tostring = function(self)
    local info = rawget(self, "_catmio_info") or {}
    return "[CatMio Proxy: " .. (info.path or "?") .. "]"
end

PROXY_META.__len = function(self) return 0 end
PROXY_META.__eq  = function(a, b) return rawequal(a, b) end

-- Create a named proxy object
local function make_proxy(path, extra)
    local t = extra or {}
    t._catmio_info = { path = path }
    return setmetatable(t, PROXY_META)
end

-- ============================================================
--  SECTION 21 – ROBLOX TYPE CONSTRUCTORS
--  Stub implementations of all Roblox built-in types.
-- ============================================================

-- Helper: make a readonly type object with tostring
local function make_type(name, fields, tostr_fn)
    local obj = {}
    for k, v in pairs(fields or {}) do obj[k] = v end
    return setmetatable(obj, {
        __index    = function(_, k)
            return rawget(obj, k) or make_proxy(name .. "." .. tostring(k))
        end,
        __newindex = function(t, k, v) rawset(t, k, v) end,
        __tostring = tostr_fn or function() return name end,
        __eq       = function(a, b)
            if rawequal(a, b) then return true end
            return false
        end,
    })
end

-- Vector3
local function Vector3_new(x, y, z)
    x, y, z = tonumber(x) or 0, tonumber(y) or 0, tonumber(z) or 0
    return make_type("Vector3", {
        X = x, Y = y, Z = z,
        Magnitude = math.sqrt(x*x + y*y + z*z),
        Unit = nil,  -- set below
    }, function() return string.format("Vector3(%g, %g, %g)", x, y, z) end)
end

-- Vector2
local function Vector2_new(x, y)
    x, y = tonumber(x) or 0, tonumber(y) or 0
    return make_type("Vector2", {
        X = x, Y = y,
        Magnitude = math.sqrt(x*x + y*y),
    }, function() return string.format("Vector2(%g, %g)", x, y) end)
end

-- Vector3int16
local function Vector3int16_new(x, y, z)
    x = math.floor(tonumber(x) or 0) % 65536
    y = math.floor(tonumber(y) or 0) % 65536
    z = math.floor(tonumber(z) or 0) % 65536
    return make_type("Vector3int16", { X = x, Y = y, Z = z },
        function() return string.format("Vector3int16(%d, %d, %d)", x, y, z) end)
end

-- Vector2int16
local function Vector2int16_new(x, y)
    x = math.floor(tonumber(x) or 0) % 65536
    y = math.floor(tonumber(y) or 0) % 65536
    return make_type("Vector2int16", { X = x, Y = y },
        function() return string.format("Vector2int16(%d, %d)", x, y) end)
end

-- Color3
local function Color3_new(r, g, b)
    r, g, b = tonumber(r) or 0, tonumber(g) or 0, tonumber(b) or 0
    r = math.max(0, math.min(1, r))
    g = math.max(0, math.min(1, g))
    b = math.max(0, math.min(1, b))
    return make_type("Color3", { R = r, G = g, B = b },
        function() return string.format("Color3(%.3f, %.3f, %.3f)", r, g, b) end)
end

local function Color3_fromRGB(r, g, b)
    return Color3_new((r or 0)/255, (g or 0)/255, (b or 0)/255)
end

local function Color3_fromHSV(h, s, v)
    h, s, v = tonumber(h) or 0, tonumber(s) or 0, tonumber(v) or 0
    return make_type("Color3", { H = h, S = s, V = v },
        function() return string.format("Color3.fromHSV(%g, %g, %g)", h, s, v) end)
end

-- CFrame
local function CFrame_new(...)
    local args = {...}
    local pos_str = ""
    if #args >= 3 then
        pos_str = string.format("(%g,%g,%g)", args[1] or 0, args[2] or 0, args[3] or 0)
    end
    local cf = make_type("CFrame", {
        X = args[1] or 0, Y = args[2] or 0, Z = args[3] or 0,
        Position = Vector3_new(args[1], args[2], args[3]),
        LookVector = Vector3_new(0, 0, -1),
        RightVector = Vector3_new(1, 0, 0),
        UpVector = Vector3_new(0, 1, 0),
    }, function() return "CFrame" .. pos_str end)
    return cf
end

-- UDim
local function UDim_new(scale, offset)
    scale, offset = tonumber(scale) or 0, tonumber(offset) or 0
    return make_type("UDim", { Scale = scale, Offset = offset },
        function() return string.format("UDim(%g, %d)", scale, offset) end)
end

-- UDim2
local function UDim2_new(xs, xo, ys, yo)
    xs, xo = tonumber(xs) or 0, tonumber(xo) or 0
    ys, yo = tonumber(ys) or 0, tonumber(yo) or 0
    return make_type("UDim2", {
        X = UDim_new(xs, xo), Y = UDim_new(ys, yo),
    }, function() return string.format("UDim2(%g,%d,%g,%d)", xs, xo, ys, yo) end)
end

local function UDim2_fromScale(x, y)
    return UDim2_new(x or 0, 0, y or 0, 0)
end

local function UDim2_fromOffset(x, y)
    return UDim2_new(0, x or 0, 0, y or 0)
end

-- BrickColor
local function BrickColor_new(val)
    local name = tostring(val or "Medium stone grey")
    return make_type("BrickColor", {
        Name = name, Number = 0,
        Color = Color3_new(0.5, 0.5, 0.5),
    }, function() return "BrickColor('" .. name .. "')" end)
end

-- Enum stub
local function make_enum(name, members)
    local enum_obj = {}
    for _, member in ipairs(members or {}) do
        enum_obj[member] = make_type("EnumItem", { Name = member, Value = 0 },
            function() return "Enum." .. name .. "." .. member end)
    end
    return setmetatable(enum_obj, {
        __index = function(_, k)
            local item = make_type("EnumItem", { Name = tostring(k), Value = 0 },
                function() return "Enum." .. name .. "." .. tostring(k) end)
            return item
        end,
        __tostring = function() return "Enum." .. name end,
    })
end

-- NumberSequenceKeypoint
local function NumberSequenceKeypoint_new(t, v, e)
    t, v, e = tonumber(t) or 0, tonumber(v) or 0, tonumber(e) or 0
    return make_type("NumberSequenceKeypoint", { Time = t, Value = v, Envelope = e },
        function() return string.format("NumberSequenceKeypoint(%g,%g,%g)", t, v, e) end)
end

-- NumberSequence
local function NumberSequence_new(v_or_kps)
    if type(v_or_kps) == "number" then
        return make_type("NumberSequence", { Keypoints = {} },
            function() return "NumberSequence(" .. v_or_kps .. ")" end)
    end
    return make_type("NumberSequence", { Keypoints = v_or_kps or {} },
        function() return "NumberSequence(...)" end)
end

-- ColorSequenceKeypoint
local function ColorSequenceKeypoint_new(t, c)
    t = tonumber(t) or 0
    return make_type("ColorSequenceKeypoint", { Time = t, Value = c },
        function() return string.format("ColorSequenceKeypoint(%g,...)", t) end)
end

-- ColorSequence
local function ColorSequence_new(c_or_kps)
    return make_type("ColorSequence", { Keypoints = {} },
        function() return "ColorSequence(...)" end)
end

-- Rect
local function Rect_new(x0, y0, x1, y1)
    x0, y0 = tonumber(x0) or 0, tonumber(y0) or 0
    x1, y1 = tonumber(x1) or 0, tonumber(y1) or 0
    return make_type("Rect", {
        Min = Vector2_new(x0, y0), Max = Vector2_new(x1, y1),
        Width = x1 - x0, Height = y1 - y0,
    }, function() return string.format("Rect(%g,%g,%g,%g)", x0, y0, x1, y1) end)
end

-- Region3
local function Region3_new(min_v, max_v)
    return make_type("Region3", {
        CFrame = CFrame_new(), Size = Vector3_new(1, 1, 1),
    }, function() return "Region3(...)" end)
end

-- Region3int16
local function Region3int16_new(min_v, max_v)
    return make_type("Region3int16", {},
        function() return "Region3int16(...)" end)
end

-- Ray
local function Ray_new(origin, direction)
    return make_type("Ray", {
        Origin = origin or Vector3_new(),
        Direction = direction or Vector3_new(0, 0, -1),
    }, function() return "Ray(...)" end)
end

-- TweenInfo
local function TweenInfo_new(t, easingstyle, easingdir, rc, rev, dp)
    t = tonumber(t) or 1
    return make_type("TweenInfo", {
        Time = t,
        EasingStyle = easingstyle,
        EasingDirection = easingdir,
        RepeatCount = tonumber(rc) or 0,
        Reverses = rev or false,
        DelayTime = tonumber(dp) or 0,
    }, function() return string.format("TweenInfo(%g,...)", t) end)
end

-- PhysicalProperties
local function PhysicalProperties_new(density, friction, elasticity, fw, ew)
    density     = tonumber(density) or 0.7
    friction    = tonumber(friction) or 0.3
    elasticity  = tonumber(elasticity) or 0.5
    fw          = tonumber(fw) or 1
    ew          = tonumber(ew) or 1
    return make_type("PhysicalProperties", {
        Density = density, Friction = friction, Elasticity = elasticity,
        FrictionWeight = fw, ElasticityWeight = ew,
    }, function() return string.format("PhysicalProperties(%g,%g,%g)", density, friction, elasticity) end)
end

-- RaycastParams
local function RaycastParams_new()
    return make_type("RaycastParams", {
        FilterDescendantsInstances = {},
        FilterType = make_proxy("RaycastFilterType"),
        IgnoreWater = false,
        CollisionGroup = "Default",
    }, function() return "RaycastParams" end)
end

-- OverlapParams
local function OverlapParams_new()
    return make_type("OverlapParams", {
        FilterDescendantsInstances = {},
        FilterType = make_proxy("RaycastFilterType"),
        MaxParts = 0,
        CollisionGroup = "Default",
    }, function() return "OverlapParams" end)
end

-- PathWaypoint
local function PathWaypoint_new(pos, action, label)
    return make_type("PathWaypoint", {
        Position = pos or Vector3_new(),
        Action = action,
        Label = label or "",
    }, function() return "PathWaypoint(...)" end)
end

-- RotationCurveKey
local function RotationCurveKey_new(t, r, it, ot)
    return make_type("RotationCurveKey", {
        Time = tonumber(t) or 0, Value = r,
        InterpolationMode = it, OutgoingTangent = ot,
    }, function() return "RotationCurveKey(...)" end)
end

-- FloatCurveKey
local function FloatCurveKey_new(t, v, it)
    return make_type("FloatCurveKey", {
        Time = tonumber(t) or 0, Value = tonumber(v) or 0,
        InterpolationMode = it,
    }, function() return string.format("FloatCurveKey(%g,%g)", t or 0, v or 0) end)
end

-- CatalogSearchParams
local function CatalogSearchParams_new()
    return make_type("CatalogSearchParams", {
        SearchKeyword = "", MinPrice = 0, MaxPrice = math.huge,
        SortType = make_proxy("CatalogSortType"),
        CategoryFilter = make_proxy("CatalogCategoryFilter"),
        BundleTypes = {}, AssetTypes = {},
    }, function() return "CatalogSearchParams" end)
end

-- SharedTable stub
local SharedTable = {}
SharedTable.__index = SharedTable
function SharedTable.new()
    return setmetatable({_data = {}}, SharedTable)
end
function SharedTable:Get(k) return self._data[k] end
function SharedTable:Set(k, v) self._data[k] = v end
function SharedTable:Increment(k, d)
    self._data[k] = (self._data[k] or 0) + (d or 1)
end

-- Font
local function Font_new(family, weight, style)
    family = tostring(family or "rbxasset://fonts/families/Arial.json")
    return make_type("Font", {
        Family = family,
        Weight = weight or make_proxy("FontWeight"),
        Style = style or make_proxy("FontStyle"),
        Bold = false,
    }, function() return "Font(" .. family .. ")" end)
end

-- Axes
local function Axes_new(...)
    return make_type("Axes", {},
        function() return "Axes(...)" end)
end

-- Faces
local function Faces_new(...)
    return make_type("Faces", {},
        function() return "Faces(...)" end)
end

-- Build Enum table
local ENUM_DEFS = {
    KeyCode = {
        "Unknown","Backspace","Tab","Return","Pause","Escape","Space",
        "Quote","Comma","Minus","Period","Slash","Zero","One","Two","Three",
        "Four","Five","Six","Seven","Eight","Nine","Semicolon","Equals",
        "LeftBracket","Backslash","RightBracket","BackQuote",
        "A","B","C","D","E","F","G","H","I","J","K","L","M",
        "N","O","P","Q","R","S","T","U","V","W","X","Y","Z",
        "LeftMeta","RightMeta","Insert","Home","PageUp","Delete","End","PageDown",
        "Up","Down","Right","Left",
        "F1","F2","F3","F4","F5","F6","F7","F8","F9","F10","F11","F12",
        "NumLock","ScrollLock","LeftShift","RightShift","LeftControl","RightControl",
        "LeftAlt","RightAlt","LeftSuper","RightSuper","Print","Break","CapsLock",
        "ButtonX","ButtonY","ButtonA","ButtonB","ButtonR1","ButtonL1",
        "ButtonR2","ButtonL2","ButtonR3","ButtonL3","ButtonStart","ButtonSelect",
        "DPadLeft","DPadRight","DPadUp","DPadDown",
        "MouseButton1","MouseButton2","MouseButton3","MouseWheelForward","MouseWheelBackward",
    },
    UserInputType = {
        "MouseButton1","MouseButton2","MouseButton3","MouseWheel",
        "MouseMovement","Touch","Keyboard","Focus","Accelerometer","Gyro",
        "Gamepad1","Gamepad2","Gamepad3","Gamepad4","None",
    },
    UserInputState = { "Begin","Change","End","Cancel","None" },
    RenderFidelity = { "Automatic","Precise","Performance","Disabled" },
    Material = {
        "Plastic","Wood","Slate","Concrete","CorrodedMetal","DiamondPlate",
        "Foil","Grass","Ice","Marble","Granite","Brick","Pebble","Sand",
        "Fabric","SmoothPlastic","Metal","WoodPlanks","Cobblestone","Air",
        "Water","Rock","Glacier","Snow","Sandstone","Mud","Basalt","Ground",
        "CrackedLava","Asphalt","LeafyGrass","Salt","Limestone","Pavement",
        "ForceField","Neon","Glass","Cardboard","Clay","Cork",
    },
    HumanoidStateType = {
        "FallingDown","Running","RunningNoPhysics","Climbing","StrafingNoPhysics",
        "Ragdoll","GettingUp","Jumping","Landed","Flying","Swimming",
        "Freefall","Seated","PlatformStanding","Dead","Physics","None",
    },
    PartType = { "Ball","Block","Cylinder" },
    SurfaceType = {
        "Smooth","Glue","Weld","Studs","Inlet","Universal","Hinge","Motor",
        "StepMotor","SmoothNoOutlines",
    },
    NormalId = { "Top","Bottom","Front","Back","Right","Left" },
    Axis = { "X","Y","Z" },
    EasingStyle = {
        "Linear","Sine","Back","Bounce","Elastic","Exponential","Circular","Quad","Quart","Quint","Cubic",
    },
    EasingDirection = { "In","Out","InOut" },
    TweenStatus = { "Playing","Canceled","Completed" },
    AnimationPriority = { "Core","Idle","Movement","Action","Action2","Action3","Action4" },
    SortOrder = { "LayoutOrder","Name","Custom" },
    FillDirection = { "Horizontal","Vertical" },
    HorizontalAlignment = { "Left","Center","Right" },
    VerticalAlignment = { "Top","Center","Bottom" },
    ScaleType = { "Stretch","Slice","Tile","Fit","Crop" },
    Font = {
        "Legacy","Arial","ArialBold","SourceSans","SourceSansBold","SourceSansSemibold",
        "SourceSansLight","SourceSansItalic","Bodoni","Garamond","Cartoon","Code",
        "Highway","SciFi","Arcade","Fantasy","Antique","Gotham","GothamMedium",
        "GothamBold","GothamBlack","Montserrat","TitilliumWeb","Oswald","Nunito",
        "Merriweather","Ubuntu","Bangers","Sarpanch","FredokaOne","GrenzeGotisch",
        "PermanentMarker","Creepster","IndieFlower","Balthazar","Fondamento",
        "Kalam","PatrickHand","AmaticSC","RobotoCondensed","Roboto","RobotoMono",
        "BuilderSans","BuilderSansMedium","BuilderSansBold","BuilderSansExtraBold",
        "Jura","Zekton","SpecialElite","DenkOne","Arimo",
    },
    TextTruncate = { "None","AtEnd" },
    TextXAlignment = { "Left","Center","Right" },
    TextYAlignment = { "Top","Center","Bottom" },
    ZIndexBehavior = { "Global","Sibling" },
    MeshType = {
        "Head","Torso","Wedge","Prism","Pyramid","ParallelRamp","RightAngleRamp",
        "CornerWedge","Cylinder","Sphere","FileMesh","Brick","Skull","SpecialMesh",
    },
    DataStoreRequestType = {
        "GetAsync","SetIncrementAsync","UpdateAsync","GetSortedAsync","SetIncrementSortedAsync","OnUpdate",
    },
    PathStatus = { "FullPath","PartialPath","NoPath" },
    CollisionFidelity = { "Default","Hull","Box","Precise" },
    DevCameraOcclusionMode = { "Zoom","Invisicam" },
    DevComputerMovementMode = {
        "UserChoice","KeyboardMouse","ClickToMove","Scriptable","DynamicThumbstick",
    },
    CameraMode = { "Classic","LockFirstPerson" },
    CameraType = { "Fixed","Attach","Watch","Track","Follow","Custom","Scriptable","Orbital" },
    StreamingPauseMode = { "Default","Disabled","ClientPhysicsPause" },
    ReplicationFocus = { "None","Radius","Distance" },
    AccessoryType = {
        "Unknown","Hat","Hair","Face","Neck","Shoulder","Front","Back","Waist",
        "TShirt","Shirt","Pants","Jacket","Sweater","Shorts","LeftShoe","RightShoe",
        "DressSkirt","Eyebrow","Eyelash",
    },
    HumanoidRigType = { "R6","R15" },
    BodyPart = { "Head","Torso","LeftArm","RightArm","LeftLeg","RightLeg" },
    R15CollisionType = { "OuterBox","InnerBox" },
}

local Enum = setmetatable({}, {
    __index = function(_, name)
        return make_enum(name, ENUM_DEFS[name])
    end,
    __tostring = function() return "Enum" end,
})

