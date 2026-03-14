-- CatchAndTame.lua
-- Script for the Roblox game "Catch and Tame"
-- Uses the Catmio UI Library

-- Load the Catmio UI library
local Library = loadstring(game:HttpGet("https://raw.githubusercontent.com/Francy2468/Catmio/refs/heads/main/Catmio-Library.lua"))()

-- Services
local Players = game:GetService("Players")
local Workspace = game:GetService("Workspace")

local LocalPlayer = Players.LocalPlayer
local Character = LocalPlayer.Character or LocalPlayer.CharacterAdded:Wait()
local Humanoid = Character:WaitForChild("Humanoid")
local HRP = Character:WaitForChild("HumanoidRootPart")

-- State flags
local autoCatch = false
local autoFarm = false
local autoSell = false
local autoHatch = false

-- Configurable settings (updated by Settings page sliders/toggles)
local catchRadius = 60        -- default auto-catch search radius (studs)
local showNotifications = true

-- Persisted player modifier values (reapplied on respawn)
local desiredWalkSpeed = 16
local desiredJumpPower = 50

-- Debounce timers for auto-loops (seconds between actions)
local CATCH_INTERVAL  = 0.5   -- attempt a catch twice per second
local FARM_INTERVAL   = 1.0   -- scan for coins once per second
local SELL_INTERVAL   = 5.0   -- sell at most once every 5 seconds
local HATCH_INTERVAL  = 1.0   -- hatch attempt once per second

local COIN_COLLECT_RADIUS = 20 -- studs; coins within this range are picked up

-- Utility: safely get nearest creature in workspace
local function getNearestCreature(maxDist)
    maxDist = maxDist or catchRadius
    local nearest, nearestDist = nil, maxDist
    -- Creatures are typically stored under a folder in Workspace; adjust folder name as needed
    local creaturesFolder = Workspace:FindFirstChild("Creatures") or Workspace:FindFirstChild("Animals") or Workspace:FindFirstChild("Pets")
    if creaturesFolder then
        for _, obj in ipairs(creaturesFolder:GetChildren()) do
            local rootPart = obj:FindFirstChild("HumanoidRootPart") or obj:FindFirstChild("RootPart") or obj.PrimaryPart
            if rootPart then
                local dist = (HRP.Position - rootPart.Position).Magnitude
                if dist < nearestDist then
                    nearest = obj
                    nearestDist = dist
                end
            end
        end
    end
    return nearest, nearestDist
end

-- Utility: try to catch a creature (fires the catch remote)
local function tryCatchCreature(creature)
    local catchRemote = game:GetService("ReplicatedStorage"):FindFirstChild("CatchCreature", true)
        or game:GetService("ReplicatedStorage"):FindFirstChild("Catch", true)
        or game:GetService("ReplicatedStorage"):FindFirstChild("TameCreature", true)
    if catchRemote and catchRemote:IsA("RemoteEvent") then
        catchRemote:FireServer(creature)
    elseif catchRemote and catchRemote:IsA("RemoteFunction") then
        catchRemote:InvokeServer(creature)
    end
end

-- Utility: try to sell all pets/creatures
local function trySell()
    local sellRemote = game:GetService("ReplicatedStorage"):FindFirstChild("SellPets", true)
        or game:GetService("ReplicatedStorage"):FindFirstChild("Sell", true)
        or game:GetService("ReplicatedStorage"):FindFirstChild("SellAll", true)
    if sellRemote and sellRemote:IsA("RemoteEvent") then
        sellRemote:FireServer()
    elseif sellRemote and sellRemote:IsA("RemoteFunction") then
        sellRemote:InvokeServer()
    end
end

-- Utility: try to collect coins / farm resources
local function tryCollectCoins()
    -- Coins/resources are often physical parts; walk over them or fire a remote
    local coinsFolder = Workspace:FindFirstChild("Coins") or Workspace:FindFirstChild("Resources") or Workspace:FindFirstChild("Collectibles")
    if coinsFolder then
        for _, coin in ipairs(coinsFolder:GetChildren()) do
            local part = coin:IsA("BasePart") and coin or coin:FindFirstChildWhichIsA("BasePart")
            if part then
                local dist = (HRP.Position - part.Position).Magnitude
                if dist < COIN_COLLECT_RADIUS then
                    HRP.CFrame = CFrame.new(part.Position + Vector3.new(0, 3, 0))
                end
            end
        end
    end
    -- Also try a collect remote if one exists
    local collectRemote = game:GetService("ReplicatedStorage"):FindFirstChild("CollectCoin", true)
        or game:GetService("ReplicatedStorage"):FindFirstChild("Collect", true)
    if collectRemote and collectRemote:IsA("RemoteEvent") then
        collectRemote:FireServer()
    end
end

-- Utility: try to hatch eggs
local function tryHatchEgg()
    local hatchRemote = game:GetService("ReplicatedStorage"):FindFirstChild("HatchEgg", true)
        or game:GetService("ReplicatedStorage"):FindFirstChild("Hatch", true)
    if hatchRemote and hatchRemote:IsA("RemoteEvent") then
        hatchRemote:FireServer()
    elseif hatchRemote and hatchRemote:IsA("RemoteFunction") then
        hatchRemote:InvokeServer()
    end
end

-- Re-grab character references on respawn and reapply player modifiers
LocalPlayer.CharacterAdded:Connect(function(newChar)
    Character = newChar
    Humanoid = newChar:WaitForChild("Humanoid")
    HRP = newChar:WaitForChild("HumanoidRootPart")
    -- Reapply persisted modifier values after respawn
    Humanoid.WalkSpeed = desiredWalkSpeed
    Humanoid.JumpPower = desiredJumpPower
end)

-- ─── UI Setup ────────────────────────────────────────────────────────────────

local Window = Library:Window({
    Title = "Catch & Tame",
    SubTitle = "by Catmio"
})

-- Pages
local MainPage = Window:NewPage({
    Title = "Main",
    Desc = "Core Features",
    Icon = 127194456372995
})

local FarmPage = Window:NewPage({
    Title = "Farm",
    Desc = "Farming Utilities",
    Icon = 127194456372995
})

local TeleportPage = Window:NewPage({
    Title = "Teleport",
    Desc = "Teleport Locations",
    Icon = 127194456372995
})

local SettingsPage = Window:NewPage({
    Title = "Settings",
    Desc = "Script Configuration",
    Icon = 127194456372995
})

-- ─── Main Page ────────────────────────────────────────────────────────────────

MainPage:Section("Creature")

MainPage:Toggle({
    Title = "Auto Catch",
    Desc = "Automatically catch nearby creatures",
    Value = false,
    Callback = function(value)
        autoCatch = value
        if value then
            task.spawn(function()
                while autoCatch do
                    local creature = getNearestCreature(catchRadius)
                    if creature then
                        local rootPart = creature:FindFirstChild("HumanoidRootPart")
                            or creature:FindFirstChild("RootPart")
                            or creature.PrimaryPart
                        if rootPart then
                            HRP.CFrame = CFrame.new(rootPart.Position + Vector3.new(0, 3, 0))
                        end
                        tryCatchCreature(creature)
                    end
                    task.wait(CATCH_INTERVAL)
                end
            end)
        end
    end
})

MainPage:Toggle({
    Title = "Auto Hatch Eggs",
    Desc = "Continuously hatch eggs from your inventory",
    Value = false,
    Callback = function(value)
        autoHatch = value
        if value then
            task.spawn(function()
                while autoHatch do
                    tryHatchEgg()
                    task.wait(HATCH_INTERVAL)
                end
            end)
        end
    end
})

MainPage:Section("Player")

MainPage:Slider({
    Title = "Walk Speed",
    Min = 16,
    Max = 200,
    Rounding = 1,
    Value = 16,
    Callback = function(value)
        desiredWalkSpeed = value
        if Humanoid then
            Humanoid.WalkSpeed = value
        end
    end
})

MainPage:Slider({
    Title = "Jump Power",
    Min = 50,
    Max = 300,
    Rounding = 1,
    Value = 50,
    Callback = function(value)
        desiredJumpPower = value
        if Humanoid then
            Humanoid.JumpPower = value
        end
    end
})

MainPage:RightLabel({
    Title = "Player",
    Desc = "Current user",
    Right = LocalPlayer.Name
})

-- ─── Farm Page ────────────────────────────────────────────────────────────────

FarmPage:Section("Resources")

FarmPage:Toggle({
    Title = "Auto Farm",
    Desc = "Automatically collect coins and resources",
    Value = false,
    Callback = function(value)
        autoFarm = value
        if value then
            task.spawn(function()
                while autoFarm do
                    tryCollectCoins()
                    task.wait(FARM_INTERVAL)
                end
            end)
        end
    end
})

FarmPage:Toggle({
    Title = "Auto Sell",
    Desc = "Automatically sell all pets / creatures",
    Value = false,
    Callback = function(value)
        autoSell = value
        if value then
            task.spawn(function()
                while autoSell do
                    trySell()
                    task.wait(SELL_INTERVAL)
                end
            end)
        end
    end
})

FarmPage:Section("Actions")

FarmPage:Button({
    Title = "Collect Coins Now",
    Desc = "Instantly collect all nearby coins",
    Text = "Collect",
    Callback = function()
        tryCollectCoins()
    end
})

FarmPage:Button({
    Title = "Sell All Now",
    Desc = "Instantly sell all your pets",
    Text = "Sell",
    Callback = function()
        trySell()
    end
})

FarmPage:Dropdown({
    Title = "Farm Target",
    List = {"Coins", "Gems", "Food", "All"},
    Value = "All",
    Callback = function(selected)
        -- Placeholder: extend tryCollectCoins() logic per target
        print("Farm target set to:", selected)
    end
})

-- ─── Teleport Page ────────────────────────────────────────────────────────────

TeleportPage:Section("Locations")

TeleportPage:Button({
    Title = "Spawn",
    Desc = "Teleport back to the spawn point",
    Text = "TP",
    Callback = function()
        HRP.CFrame = CFrame.new(0, 5, 0)
    end
})

TeleportPage:Button({
    Title = "Catch Zone",
    Desc = "Teleport to the creature catch area",
    Text = "TP",
    Callback = function()
        -- Locate the catch zone by name; adjust as needed for the actual map
        local catchZone = Workspace:FindFirstChild("CatchZone")
            or Workspace:FindFirstChild("CatchArea")
            or Workspace:FindFirstChild("Wild Zone")
        if catchZone then
            local part = catchZone:IsA("BasePart") and catchZone
                or catchZone:FindFirstChildWhichIsA("BasePart")
            if part then
                HRP.CFrame = CFrame.new(part.Position + Vector3.new(0, 5, 0))
                return
            end
        end
        -- Fallback coordinates
        HRP.CFrame = CFrame.new(200, 5, 200)
    end
})

TeleportPage:Button({
    Title = "Farm Zone",
    Desc = "Teleport to the resource farming area",
    Text = "TP",
    Callback = function()
        local farmZone = Workspace:FindFirstChild("FarmZone")
            or Workspace:FindFirstChild("FarmArea")
            or Workspace:FindFirstChild("Farm")
        if farmZone then
            local part = farmZone:IsA("BasePart") and farmZone
                or farmZone:FindFirstChildWhichIsA("BasePart")
            if part then
                HRP.CFrame = CFrame.new(part.Position + Vector3.new(0, 5, 0))
                return
            end
        end
        HRP.CFrame = CFrame.new(-200, 5, -200)
    end
})

TeleportPage:Button({
    Title = "Shop",
    Desc = "Teleport to the in-game shop",
    Text = "TP",
    Callback = function()
        local shop = Workspace:FindFirstChild("Shop")
            or Workspace:FindFirstChild("Store")
            or Workspace:FindFirstChild("Market")
        if shop then
            local part = shop:IsA("BasePart") and shop
                or shop:FindFirstChildWhichIsA("BasePart")
            if part then
                HRP.CFrame = CFrame.new(part.Position + Vector3.new(0, 5, 0))
                return
            end
        end
        HRP.CFrame = CFrame.new(0, 5, 100)
    end
})

TeleportPage:Button({
    Title = "Egg Zone",
    Desc = "Teleport to the egg hatching area",
    Text = "TP",
    Callback = function()
        local eggZone = Workspace:FindFirstChild("EggZone")
            or Workspace:FindFirstChild("EggArea")
            or Workspace:FindFirstChild("Hatchery")
        if eggZone then
            local part = eggZone:IsA("BasePart") and eggZone
                or eggZone:FindFirstChildWhichIsA("BasePart")
            if part then
                HRP.CFrame = CFrame.new(part.Position + Vector3.new(0, 5, 0))
                return
            end
        end
        HRP.CFrame = CFrame.new(100, 5, -100)
    end
})

-- ─── Settings Page ────────────────────────────────────────────────────────────

SettingsPage:Section("Interface")

SettingsPage:Toggle({
    Title = "Notifications",
    Desc = "Show in-game status notifications",
    Value = true,
    Callback = function(value)
        showNotifications = value
    end
})

SettingsPage:Slider({
    Title = "Auto Catch Radius",
    Min = 10,
    Max = 200,
    Rounding = 1,
    Value = 60,
    Callback = function(value)
        catchRadius = value
    end
})

SettingsPage:Paragraph({
    Title = "About",
    Desc = "Catch & Tame script powered by Catmio UI Library.\nUse responsibly.",
    Image = 127194456372995
})

-- SetTimeValue sets the expiry countdown shown in the UI header
Library:SetTimeValue("23:59:59 Hours")
