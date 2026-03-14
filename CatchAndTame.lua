-- CatchAndTame.lua
-- Script for Roblox "Catch and Tame" style games
-- Uses the Catmio UI Library

-- ── Load library (protected) ──────────────────────────────────────────────────
local Library
do
    local ok, result = pcall(function()
        return loadstring(game:HttpGet("https://raw.githubusercontent.com/Francy2468/Catmio/refs/heads/main/Catmio-Library.lua"))()
    end)
    if not ok or not result then
        error("[CatchAndTame] Failed to load Catmio library: " .. tostring(result))
    end
    Library = result
end

-- ── Services ──────────────────────────────────────────────────────────────────
local Players           = game:GetService("Players")
local RunService        = game:GetService("RunService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local Workspace         = game:GetService("Workspace")

local LocalPlayer = Players.LocalPlayer
local Character   = LocalPlayer.Character or LocalPlayer.CharacterAdded:Wait()
local Humanoid    = Character:WaitForChild("Humanoid")
local HRP         = Character:WaitForChild("HumanoidRootPart")

-- ── State flags ───────────────────────────────────────────────────────────────
local autoCatch = false
local autoFarm  = false
local autoSell  = false
local autoHatch = false
local antiAFK   = false

-- ── Configurable settings (updated by UI) ────────────────────────────────────
local catchRadius       = 60
local showNotifications = true
local desiredWalkSpeed  = 16
local desiredJumpPower  = 50

-- ── Loop intervals (seconds) ──────────────────────────────────────────────────
local CATCH_INTERVAL       = 0.5
local FARM_INTERVAL        = 1.0
local SELL_INTERVAL        = 5.0
local HATCH_INTERVAL       = 1.0
local COIN_COLLECT_RADIUS  = 20

-- ── Remote discovery ─────────────────────────────────────────────────────────
-- Remote names are searched in order; first match wins and is cached.
local CATCH_REMOTE_NAMES = {
    "CatchCreature", "Catch", "TameCreature", "Tame", "CapturePet",
    "CatchPet", "TamePet", "CaptureAnimal", "CatchAnimal", "ThrowBall",
    "Throw", "UseItem", "AttemptCatch", "TryTame", "PetCatch", "Capture",
    "CatchMob", "TameMob",
}
local SELL_REMOTE_NAMES = {
    "SellPets", "Sell", "SellAll", "SellPet", "SellAnimals",
    "SellCreature", "SellCreatures",
}
local HATCH_REMOTE_NAMES = {
    "HatchEgg", "Hatch", "OpenEgg", "HatchPet",
}
local COLLECT_REMOTE_NAMES = {
    "CollectCoin", "Collect", "PickupCoin", "CollectResource", "GatherCoin",
}

local _remoteCache = {}

local function findRemote(names)
    for _, name in ipairs(names) do
        if _remoteCache[name] then return _remoteCache[name] end
        local r = ReplicatedStorage:FindFirstChild(name, true)
        if r then
            _remoteCache[name] = r
            return r
        end
    end
    return nil
end

local function fireRemote(remote, ...)
    if not remote then return end
    pcall(function()
        if remote:IsA("RemoteEvent") then
            remote:FireServer(...)
        elseif remote:IsA("RemoteFunction") then
            remote:InvokeServer(...)
        end
    end)
end

-- ── Creature detection ────────────────────────────────────────────────────────
-- Searched in order; all matching folders are checked.
local CREATURE_FOLDER_NAMES = {
    "Creatures", "Animals", "Pets", "Mobs", "Entities", "NPCs",
    "Monsters", "WildAnimals", "Wild", "CatchableCreatures", "CatchablePets",
}

local function isCreature(obj)
    if not obj:IsA("Model") then return false end
    return obj:FindFirstChildWhichIsA("Humanoid") ~= nil
        or obj:FindFirstChild("HumanoidRootPart") ~= nil
        or obj:FindFirstChild("RootPart") ~= nil
end

local function getObjectRootPart(obj)
    return obj:FindFirstChild("HumanoidRootPart")
        or obj:FindFirstChild("RootPart")
        or obj.PrimaryPart
end

local function getNearestCreature(maxDist)
    maxDist = maxDist or catchRadius
    local nearest, nearestDist = nil, maxDist
    if not HRP or not HRP.Parent then return nil, maxDist end

    local function checkObj(obj)
        if isCreature(obj) and obj ~= Character then
            local root = getObjectRootPart(obj)
            if root and root.Parent then
                local ok, dist = pcall(function()
                    return (HRP.Position - root.Position).Magnitude
                end)
                if ok and dist < nearestDist then
                    nearest = obj
                    nearestDist = dist
                end
            end
        end
    end

    -- 1. Check known creature folders
    for _, folderName in ipairs(CREATURE_FOLDER_NAMES) do
        local folder = Workspace:FindFirstChild(folderName)
        if folder then
            for _, obj in ipairs(folder:GetChildren()) do
                checkObj(obj)
            end
        end
    end

    -- 2. Fallback: scan workspace top-level
    if not nearest then
        for _, obj in ipairs(Workspace:GetChildren()) do
            checkObj(obj)
        end
    end

    return nearest, nearestDist
end

-- ── Teleport helper ───────────────────────────────────────────────────────────
local function teleportTo(position, yOffset)
    if not HRP or not HRP.Parent then return end
    pcall(function()
        HRP.CFrame = CFrame.new(position + Vector3.new(0, yOffset or 3, 0))
    end)
end

-- Finds first matching object in workspace by a list of names and teleports to it.
-- Falls back to `fallback` CFrame if none found.
local function teleportToObject(names, fallbackCF)
    for _, name in ipairs(names) do
        local obj = Workspace:FindFirstChild(name, true)
        if obj then
            local part = (obj:IsA("BasePart") and obj)
                or obj:FindFirstChildWhichIsA("BasePart")
            if part then
                teleportTo(part.Position, 5)
                return
            end
        end
    end
    if HRP and HRP.Parent then
        pcall(function() HRP.CFrame = fallbackCF end)
    end
end

-- ── ProximityPrompt helper ────────────────────────────────────────────────────
local function tryFirePrompts(creature)
    for _, desc in ipairs(creature:GetDescendants()) do
        if desc:IsA("ProximityPrompt") then
            pcall(function()
                -- Standard executor API; silently skipped if unavailable
                fireproximityprompt(desc)
            end)
        end
    end
end

-- ── Core game actions ─────────────────────────────────────────────────────────
-- Cached catch argument pattern (nil = undiscovered, 1/2/3 = which pattern works)
local _catchArgPattern = nil

local function tryCatchCreature(creature)
    if not creature or not creature.Parent then return end
    local remote = findRemote(CATCH_REMOTE_NAMES)
    if remote then
        if _catchArgPattern == 1 then
            fireRemote(remote, creature)
        elseif _catchArgPattern == 2 then
            fireRemote(remote, creature.Name)
        elseif _catchArgPattern == 3 then
            fireRemote(remote)
        else
            -- Discovery phase: try all three common argument patterns
            fireRemote(remote, creature)
            fireRemote(remote, creature.Name)
            fireRemote(remote)
        end
    end
    -- Also trigger any ProximityPrompts on the creature
    pcall(tryFirePrompts, creature)
end

local function trySell()
    local remote = findRemote(SELL_REMOTE_NAMES)
    if remote then
        fireRemote(remote)
        fireRemote(remote, "All")
    end
end

local function tryHatchEgg()
    local remote = findRemote(HATCH_REMOTE_NAMES)
    if remote then
        fireRemote(remote)
    end
end

local function tryCollectCoins()
    if not HRP or not HRP.Parent then return end
    local coinFolderNames = {"Coins", "Resources", "Collectibles", "Drops", "Items", "Gems"}
    for _, folderName in ipairs(coinFolderNames) do
        local folder = Workspace:FindFirstChild(folderName)
        if folder then
            for _, coin in ipairs(folder:GetChildren()) do
                local part = (coin:IsA("BasePart") and coin)
                    or coin:FindFirstChildWhichIsA("BasePart")
                if part and part.Parent then
                    local ok, dist = pcall(function()
                        return (HRP.Position - part.Position).Magnitude
                    end)
                    if ok and dist < COIN_COLLECT_RADIUS then
                        teleportTo(part.Position)
                    end
                end
            end
        end
    end
    local remote = findRemote(COLLECT_REMOTE_NAMES)
    if remote then
        fireRemote(remote)
    end
end

-- ── Anti-AFK ──────────────────────────────────────────────────────────────────
local _antiAFKConn
local function startAntiAFK()
    if _antiAFKConn then return end
    _antiAFKConn = LocalPlayer.Idled:Connect(function()
        if antiAFK and HRP and HRP.Parent then
            pcall(function()
                local cf = HRP.CFrame
                HRP.CFrame = cf * CFrame.new(0, 0, 0.001)
            end)
        end
    end)
end

local function stopAntiAFK()
    if _antiAFKConn then
        _antiAFKConn:Disconnect()
        _antiAFKConn = nil
    end
end

-- ── Respawn handler ───────────────────────────────────────────────────────────
LocalPlayer.CharacterAdded:Connect(function(newChar)
    Character = newChar
    Humanoid  = newChar:WaitForChild("Humanoid")
    HRP       = newChar:WaitForChild("HumanoidRootPart")
    Humanoid.WalkSpeed = desiredWalkSpeed
    Humanoid.JumpPower = desiredJumpPower
end)

-- ─── UI Setup ────────────────────────────────────────────────────────────────

local Window = Library:Window({
    Title    = "Catch & Tame",
    SubTitle = "by Catmio",
})

local MainPage     = Window:NewPage({ Title = "Main",     Desc = "Core Features",        Icon = 127194456372995 })
local FarmPage     = Window:NewPage({ Title = "Farm",     Desc = "Farming Utilities",    Icon = 127194456372995 })
local TeleportPage = Window:NewPage({ Title = "Teleport", Desc = "Teleport Locations",   Icon = 127194456372995 })
local SettingsPage = Window:NewPage({ Title = "Settings", Desc = "Script Configuration", Icon = 127194456372995 })

-- ─── Main Page ────────────────────────────────────────────────────────────────

MainPage:Section("Creature")

MainPage:Toggle({
    Title    = "Auto Catch",
    Desc     = "Teleport to and catch nearby creatures automatically",
    Value    = false,
    Callback = function(value)
        autoCatch = value
        if value then
            task.spawn(function()
                while autoCatch do
                    local ok = pcall(function()
                        local creature = getNearestCreature(catchRadius)
                        if creature then
                            local root = getObjectRootPart(creature)
                            if root and root.Parent then
                                teleportTo(root.Position)
                                task.wait(0.1)   -- let server register new position before catch remote
                            end
                            tryCatchCreature(creature)
                        end
                    end)
                    if not ok then task.wait(1) end
                    task.wait(CATCH_INTERVAL)
                end
            end)
        end
    end,
})

MainPage:Toggle({
    Title    = "Auto Hatch Eggs",
    Desc     = "Continuously hatch eggs from your inventory",
    Value    = false,
    Callback = function(value)
        autoHatch = value
        if value then
            task.spawn(function()
                while autoHatch do
                    pcall(tryHatchEgg)
                    task.wait(HATCH_INTERVAL)
                end
            end)
        end
    end,
})

MainPage:Toggle({
    Title    = "Anti-AFK",
    Desc     = "Prevent automatic disconnection from idle",
    Value    = false,
    Callback = function(value)
        antiAFK = value
        if value then
            startAntiAFK()
        else
            stopAntiAFK()
        end
    end,
})

MainPage:Section("Player")

MainPage:Slider({
    Title    = "Walk Speed",
    Min      = 16,
    Max      = 500,
    Rounding = 1,
    Value    = 16,
    Callback = function(value)
        desiredWalkSpeed = value
        if Humanoid and Humanoid.Parent then
            pcall(function() Humanoid.WalkSpeed = value end)
        end
    end,
})

MainPage:Slider({
    Title    = "Jump Power",
    Min      = 50,
    Max      = 500,
    Rounding = 1,
    Value    = 50,
    Callback = function(value)
        desiredJumpPower = value
        if Humanoid and Humanoid.Parent then
            pcall(function() Humanoid.JumpPower = value end)
        end
    end,
})

MainPage:RightLabel({
    Title = "Player",
    Desc  = "Current user",
    Right = LocalPlayer.Name,
})

-- ─── Farm Page ────────────────────────────────────────────────────────────────

FarmPage:Section("Resources")

FarmPage:Toggle({
    Title    = "Auto Farm",
    Desc     = "Automatically collect coins and resources",
    Value    = false,
    Callback = function(value)
        autoFarm = value
        if value then
            task.spawn(function()
                while autoFarm do
                    pcall(tryCollectCoins)
                    task.wait(FARM_INTERVAL)
                end
            end)
        end
    end,
})

FarmPage:Toggle({
    Title    = "Auto Sell",
    Desc     = "Automatically sell all pets / creatures",
    Value    = false,
    Callback = function(value)
        autoSell = value
        if value then
            task.spawn(function()
                while autoSell do
                    pcall(trySell)
                    task.wait(SELL_INTERVAL)
                end
            end)
        end
    end,
})

FarmPage:Section("Actions")

FarmPage:Button({
    Title    = "Collect Coins Now",
    Desc     = "Instantly collect all nearby coins",
    Text     = "Collect",
    Callback = function()
        pcall(tryCollectCoins)
    end,
})

FarmPage:Button({
    Title    = "Sell All Now",
    Desc     = "Instantly sell all your pets",
    Text     = "Sell",
    Callback = function()
        pcall(trySell)
    end,
})

FarmPage:Dropdown({
    Title    = "Farm Target",
    List     = {"Coins", "Gems", "Food", "All"},
    Value    = "All",
    Callback = function(selected)
        print("Farm target set to:", selected)
    end,
})

-- ─── Teleport Page ────────────────────────────────────────────────────────────

TeleportPage:Section("Locations")

TeleportPage:Button({
    Title    = "Spawn",
    Desc     = "Teleport back to the spawn point",
    Text     = "TP",
    Callback = function()
        teleportToObject(
            {"SpawnLocation", "Spawn", "StartPoint"},
            CFrame.new(0, 5, 0)
        )
    end,
})

TeleportPage:Button({
    Title    = "Catch Zone",
    Desc     = "Teleport to the creature catch area",
    Text     = "TP",
    Callback = function()
        teleportToObject(
            {"CatchZone", "CatchArea", "Wild Zone", "WildZone", "HuntingZone", "CatchRegion"},
            CFrame.new(200, 5, 200)
        )
    end,
})

TeleportPage:Button({
    Title    = "Farm Zone",
    Desc     = "Teleport to the resource farming area",
    Text     = "TP",
    Callback = function()
        teleportToObject(
            {"FarmZone", "FarmArea", "Farm", "ResourceZone", "GatherZone"},
            CFrame.new(-200, 5, -200)
        )
    end,
})

TeleportPage:Button({
    Title    = "Shop",
    Desc     = "Teleport to the in-game shop",
    Text     = "TP",
    Callback = function()
        teleportToObject(
            {"Shop", "Store", "Market", "ShopArea", "ShopZone", "StoreZone"},
            CFrame.new(0, 5, 100)
        )
    end,
})

TeleportPage:Button({
    Title    = "Egg Zone",
    Desc     = "Teleport to the egg hatching area",
    Text     = "TP",
    Callback = function()
        teleportToObject(
            {"EggZone", "EggArea", "Hatchery", "EggShop", "HatchZone"},
            CFrame.new(100, 5, -100)
        )
    end,
})

-- ─── Settings Page ────────────────────────────────────────────────────────────

SettingsPage:Section("Interface")

SettingsPage:Toggle({
    Title    = "Notifications",
    Desc     = "Show in-game status notifications",
    Value    = true,
    Callback = function(value)
        showNotifications = value
    end,
})

SettingsPage:Slider({
    Title    = "Auto Catch Radius",
    Min      = 10,
    Max      = 500,
    Rounding = 1,
    Value    = 60,
    Callback = function(value)
        catchRadius = value
    end,
})

SettingsPage:Slider({
    Title    = "Catch Interval (s)",
    Min      = 0.1,
    Max      = 5.0,
    Rounding = 0.1,
    Value    = 0.5,
    Callback = function(value)
        CATCH_INTERVAL = value
    end,
})

SettingsPage:Dropdown({
    Title    = "Catch Arg Pattern",
    Desc     = "Which argument to send with the catch remote (Auto tries all three)",
    List     = {"Auto", "CreatureRef", "CreatureName", "NoArgs"},
    Value    = "Auto",
    Callback = function(selected)
        if     selected == "CreatureRef"  then _catchArgPattern = 1
        elseif selected == "CreatureName" then _catchArgPattern = 2
        elseif selected == "NoArgs"       then _catchArgPattern = 3
        else                                   _catchArgPattern = nil
        end
    end,
})

SettingsPage:Paragraph({
    Title = "About",
    Desc  = "Catch & Tame script powered by Catmio UI Library.\nUse responsibly.",
    Image = 127194456372995,
})

-- SetTimeValue sets the expiry countdown shown in the UI header
Library:SetTimeValue("23:59:59 Hours")
