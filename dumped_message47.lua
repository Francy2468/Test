-- generated with catmio | https://discord.gg/cq9GkRKX2V
local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local Workspace = game:GetService("Workspace")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local RunService = game:GetService("RunService")
local CoreGui = game:GetService("CoreGui")
local localPlayer = Players.LocalPlayer
local data = localPlayer:WaitForChild("Data")
local _Zone = Workspace:FindFirstChild("0Zone")
local WindUI = loadstring(game:HttpGet("https://github.com/Footagesus/WindUI/releases/latest/download/main.lua"))()
local magentaZone = Workspace:FindFirstChild("MagentaZone")
local new_YellerZone = Workspace:FindFirstChild("New YellerZone")
local blackZone = Workspace:FindFirstChild("BlackZone")
local whiteZone = Workspace:FindFirstChild("WhiteZone")
local camoZone = Workspace:FindFirstChild("CamoZone")
local really_blueZone = Workspace:FindFirstChild("Really blueZone")
local really_redZone = Workspace:FindFirstChild("Really redZone")
local buildPreview = Workspace:FindFirstChild("BuildPreview")
buildPreview.Name = "BuildPreview"
buildPreview.Parent = Workspace
local previewPart = buildPreview:FindFirstChild("PreviewPart")
previewPart.Name = "PreviewPart"
previewPart.Transparency = 1
previewPart.Anchored = true
previewPart.CanCollide = false
previewPart.Size = Vector3.new(5, 5, 5)
previewPart.CFrame = CFrame.new(0, 5, 0)
previewPart.Parent = buildPreview
local model = Instance.new("Model")
local HttpService2 = game:GetService("HttpService")
local Players2 = game:GetService("Players")
local Workspace2 = game:GetService("Workspace")
local localPlayer2 = Players2.LocalPlayer
local HttpService3 = game:GetService("HttpService")
local shape_Preview = workspace:FindFirstChild("Shape Preview")
shape_Preview.Name = "Shape Preview"
shape_Preview.Parent = workspace
local popup = WindUI:Popup({
    Buttons = {
        [1] = {
            Variant = "Tertiary",
            Callback = function() end,
            Title = "Cancel"
        },
        [2] = {
            Variant = "Primary",
            Callback = function() end,
            Icon = "arrow-right",
            Title = "Continue"
        }
    },
    Content = "",
    Icon = "info",
    Title = "Welcome To Lexushub don't forgot to join our official Discord server!"
})
local previewModel = workspace:FindFirstChild("PreviewModel")
local Players3 = game:GetService("Players")
local Workspace3 = game:GetService("Workspace")
local HttpService4 = game:GetService("HttpService")
local TeleportService = game:GetService("TeleportService")
local ReplicatedStorage2 = game:GetService("ReplicatedStorage")
local MarketplaceService = game:GetService("MarketplaceService")
local localPlayer3 = Players3.LocalPlayer
local WindUI = loadstring(game:HttpGet("https://raw.githubusercontent.com/amd156935-create/Modified-Windui/refs/heads/main/Credits%20to%20footagsus%2C."))()
local magentaZone2 = Workspace3:FindFirstChild("MagentaZone")
local new_YellerZone2 = Workspace3:FindFirstChild("New YellerZone")
local blackZone2 = Workspace3:FindFirstChild("BlackZone")
local whiteZone2 = Workspace3:FindFirstChild("WhiteZone")
local camoZone2 = Workspace3:FindFirstChild("CamoZone")
local really_blueZone2 = Workspace3:FindFirstChild("Really blueZone")
local really_redZone2 = Workspace3:FindFirstChild("Really redZone")
local conn = Players3.PlayerAdded:Connect(function(player)
    task.wait(3)
end)
local window = WindUI:CreateWindow({
    Theme = "Dark",
    Transparent = false,
    Folder = "LexushubData",
    Topbar = {
        ButtonsType = "Mac",
        Height = 44
    },
    SideBarWidth = 180,
    Title = "Lexushub",
    Size = UDim2.fromOffset(1000, 1000),
    Background = "",
    Icon = "rbxassetid://85535661400738",
    HideSearchBar = false,
    NewElements = true,
    Author = "Yt - Xploit_Zone1, Maded by K I R A",
    BackgroundImageTransparency = 0.01,
    HasOutline = true
})
local dialog = window:Dialog({
    Buttons = {
        [1] = {
            Callback = function() end,
            Title = "Copy Invite"
        },
        [2] = {
            Callback = function() end,
            Title = "Cancel"
        }
    },
    Content = "JOIN THE DISCORD FOR 1K + FILES A DAY",
    Icon = "bird",
    Title = "Join our Discord"
})
local tag = window:Tag({
    Radius = 13,
    Color = Color3.fromHex("#8A1212"),
    Icon = "car",
    Title = "XPro 22.991"
})
local tab = window:Tab({
    Icon = "palette",
    Title = "Background Settings"
})
local tab2 = window:Tab({
    Desc = "Guides",
    Icon = "book-open",
    Title = "Guide"
})
local tab3 = window:Tab({
    Desc = "Load and Build from .Build files",
    Icon = "hammer",
    Title = "AutoBuilder"
})
local tab4 = window:Tab({
    Desc = "Load and Build from .Build files",
    Icon = "hard-drive-download",
    Title = "SaveBuilder"
})
local tab5 = window:Tab({
    Icon = "hammer",
    Title = "DuperTab"
})
local tab6 = window:Tab({
    Desc = "Load text",
    Icon = "upload",
    Title = "TextLoader"
})
local tab7 = window:Tab({
    Desc = "Load Shape",
    Icon = "upload",
    Title = "ShapeLoader"
})
local tab8 = window:Tab({
    Icon = "upload",
    Title = "ObjModel Loader"
})
local tab9 = window:Tab({
    Desc = "Voxel model and load them as a Model with mesh",
    Icon = "upload",
    Title = "Model Voxelizer"
})
local tab10 = window:Tab({
    Icon = "file",
    Title = "File Manager"
})
local tab11 = window:Tab({
    Desc = "Farm Builds",
    Icon = "arrow-down-to-line",
    Title = "Builds Farmer"
})
local tab12 = window:Tab({
    Desc = "Check your block inventory",
    Icon = "box",
    Title = "Block Lister"
})
local tab13 = window:Tab({
    Desc = "Adjust position, size, and rotation of BuildPreview",
    Icon = "columns-3-cog",
    Title = "Adjuster"
})
local tab14 = window:Tab({
    Desc = "Change blocks in a Build file to blocks in your inventory",
    Icon = "replace",
    Title = "Block Changer"
})
local tab15 = window:SelectTab(1)
local screenGui = Instance.new("ScreenGui")
local CoreGui2 = game:GetService("CoreGui")
screenGui.Parent = CoreGui2
screenGui.Name = "BuildProgressGui"
screenGui.ResetOnSpawn = false
local imageLabel = Instance.new("ImageLabel")
imageLabel.Parent = screenGui
imageLabel.BackgroundTransparency = 1
imageLabel.Position = UDim2.fromOffset(0, 0)
imageLabel.Size = UDim2.fromOffset(300, 160)
imageLabel.ImageTransparency = 1
imageLabel.ImageColor3 = Color3.new(1, 1, 1)
imageLabel.ScaleType = Enum.ScaleType.Slice
imageLabel.SliceCenter = Rect.new(12, 12, 12, 12)
local textLabel = Instance.new("TextLabel")
textLabel.Parent = imageLabel
textLabel.BackgroundTransparency = 1
textLabel.TextTransparency = 1
textLabel.Position = UDim2.fromOffset(10, 5)
textLabel.Size = UDim2.fromOffset(280, 25)
textLabel.Font = Enum.Font.GothamBold
textLabel.Text = "Build Progress"
textLabel.TextColor3 = Color3.new(1, 1, 1)
textLabel.TextSize = 16
textLabel.TextXAlignment = Enum.TextXAlignment.Left
local imageLabel2 = Instance.new("ImageLabel")
imageLabel2.Parent = imageLabel
imageLabel2.BackgroundTransparency = 1
imageLabel2.ImageTransparency = 1
imageLabel2.Position = UDim2.fromOffset(10, 35)
imageLabel2.Size = UDim2.fromOffset(280, 20)
imageLabel2.ImageColor3 = Color3.new(1, 1, 1)
imageLabel2.ScaleType = Enum.ScaleType.Slice
imageLabel2.SliceCenter = Rect.new(12, 12, 12, 12)
local imageLabel3 = Instance.new("ImageLabel")
imageLabel3.Parent = imageLabel2
imageLabel3.BackgroundTransparency = 1
imageLabel3.ImageTransparency = 1
imageLabel3.Position = UDim2.fromOffset(0, 0)
imageLabel3.Size = UDim2.fromOffset(0, 0)
imageLabel3.ImageColor3 = Color3.new(1, 1, 1)
imageLabel3.ScaleType = Enum.ScaleType.Slice
imageLabel3.SliceCenter = Rect.new(12, 12, 12, 12)
local conn2 = imageLabel2:GetPropertyChangedSignal("AbsoluteSize"):Connect(function(value)
    imageLabel3.Size = UDim2.fromOffset(0, 0)
end)
local imageLabel4 = Instance.new("ImageLabel")
imageLabel4.Parent = imageLabel
imageLabel4.BackgroundTransparency = 1
imageLabel4.ImageTransparency = 1
imageLabel4.Position = UDim2.fromOffset(10, 60)
imageLabel4.Size = UDim2.fromOffset(280, 20)
local textLabel2 = Instance.new("TextLabel")
textLabel2.Parent = imageLabel4
textLabel2.BackgroundTransparency = 1
textLabel2.TextTransparency = 1
textLabel2.Position = UDim2.fromOffset(5, 0)
textLabel2.Size = UDim2.fromOffset(140, 20)
textLabel2.Font = Enum.Font.GothamBold
textLabel2.Text = "Progress:"
textLabel2.TextColor3 = Color3.new(1, 1, 1)
textLabel2.TextSize = 14
textLabel2.TextXAlignment = Enum.TextXAlignment.Left
local textLabel3 = Instance.new("TextLabel")
textLabel3.Parent = imageLabel4
textLabel3.BackgroundTransparency = 1
textLabel3.TextTransparency = 1
textLabel3.Position = UDim2.fromOffset(150, 0)
textLabel3.Size = UDim2.fromOffset(130, 20)
textLabel3.Font = Enum.Font.GothamBold
textLabel3.TextColor3 = Color3.new(1, 1, 1)
textLabel3.TextSize = 14
textLabel3.TextXAlignment = Enum.TextXAlignment.Left
local imageLabel5 = Instance.new("ImageLabel")
imageLabel5.Parent = imageLabel
imageLabel5.BackgroundTransparency = 1
imageLabel5.ImageTransparency = 1
imageLabel5.Position = UDim2.fromOffset(10, 85)
imageLabel5.Size = UDim2.fromOffset(280, 20)
local textLabel4 = Instance.new("TextLabel")
textLabel4.Parent = imageLabel5
textLabel4.BackgroundTransparency = 1
textLabel4.TextTransparency = 1
textLabel4.Position = UDim2.fromOffset(5, 0)
textLabel4.Size = UDim2.fromOffset(140, 20)
textLabel4.Font = Enum.Font.GothamBold
textLabel4.Text = "Blocks:"
textLabel4.TextColor3 = Color3.new(1, 1, 1)
textLabel4.TextSize = 14
textLabel4.TextXAlignment = Enum.TextXAlignment.Left
local textLabel5 = Instance.new("TextLabel")
textLabel5.Parent = imageLabel5
textLabel5.BackgroundTransparency = 1
textLabel5.TextTransparency = 1
textLabel5.Position = UDim2.fromOffset(150, 0)
textLabel5.Size = UDim2.fromOffset(130, 20)
textLabel5.Font = Enum.Font.GothamBold
textLabel5.TextColor3 = Color3.new(1, 1, 1)
textLabel5.TextSize = 14
textLabel5.TextXAlignment = Enum.TextXAlignment.Left
local imageLabel6 = Instance.new("ImageLabel")
imageLabel6.Parent = imageLabel
imageLabel6.BackgroundTransparency = 1
imageLabel6.ImageTransparency = 1
imageLabel6.Position = UDim2.fromOffset(10, 110)
imageLabel6.Size = UDim2.fromOffset(280, 20)
local textLabel6 = Instance.new("TextLabel")
textLabel6.Parent = imageLabel6
textLabel6.BackgroundTransparency = 1
textLabel6.TextTransparency = 1
textLabel6.Position = UDim2.fromOffset(5, 0)
textLabel6.Size = UDim2.fromOffset(140, 20)
textLabel6.Font = Enum.Font.GothamBold
textLabel6.Text = "Total Time:"
textLabel6.TextColor3 = Color3.new(1, 1, 1)
textLabel6.TextSize = 14
textLabel6.TextXAlignment = Enum.TextXAlignment.Left
local textLabel7 = Instance.new("TextLabel")
textLabel7.Parent = imageLabel6
textLabel7.BackgroundTransparency = 1
textLabel7.TextTransparency = 1
textLabel7.Position = UDim2.fromOffset(150, 0)
textLabel7.Size = UDim2.fromOffset(130, 20)
textLabel7.Font = Enum.Font.GothamBold
textLabel7.TextColor3 = Color3.new(1, 1, 1)
textLabel7.TextSize = 14
textLabel7.TextXAlignment = Enum.TextXAlignment.Left
local textButton = Instance.new("TextButton")
textButton.Parent = imageLabel
textButton.BackgroundTransparency = 1
textButton.TextTransparency = 1
textButton.Position = UDim2.fromOffset(10, 135)
textButton.Size = UDim2.fromOffset(280, 20)
textButton.Font = Enum.Font.GothamBold
textButton.TextColor3 = Color3.new(1, 1, 1)
textButton.TextSize = 14
imageLabel3.Size = UDim2.fromOffset(0, 0)
textLabel3.Text = "0%"
textLabel5.Text = "0/0"
textLabel7.Text = "Waiting..."
local dropdown = tab3:Dropdown({
    Values = {},
    Callback = function(selected) end,
    Title = "Select Build File"
})
local button = tab3:Button({
    Callback = function()
        local refresh = dropdown:Refresh({})
        local notify = WindUI:Notify({
    Duration = 3,
    Content = "File list updated (0 files)",
    Icon = "check",
    Title = "Files Refreshed"
})
    end,
    Desc = "Refresh the list of .Build files",
    Icon = "refresh",
    Title = "Refresh List"
})
local button2 = tab3:Button({
    Callback = function()
        local notify2 = WindUI:Notify({
    Duration = 5,
    Content = "Please select a file!",
    Icon = "triangle-alert",
    Title = "Error"
})
    end,
    Desc = "This will use InstantBlock V1.2",
    Icon = "ev-charger",
    Title = "Load Build Fast"
})
local space = tab3:Space()
local paragraph = tab3:Paragraph({
    Color = "Green",
    Buttons = {},
    Desc = "Progress: 0% Blocks: 0/0 Total Time: Waiting...",
    ImageSize = 30,
    ThumbnailSize = 80,
    Title = "Build Progress",
    Thumbnail = "",
    Image = "",
    Locked = false
})
local space2 = tab3:Space()
local toggle = tab3:Toggle({
    Callback = function(enabled)
        local notify3 = WindUI:Notify({
    Duration = 4,
    Content = "!",
    Icon = "check",
    Title = "Inifinite Block v1"
})
    end,
    Type = "Checkbox",
    Icon = "wrench",
    Locked = true,
    LockedTitle = "WORK IN PROGRESS",
    Value = false,
    Desc = "Inf blocks",
    Title = "Infinite Blocks v1"
})
local toggle2 = tab3:Toggle({
    Type = "Checkbox",
    Icon = "wrench",
    Desc = "Unanchors all blocks, and starting welding,, USES weld v1",
    Callback = function(enabled)
        local notify4 = WindUI:Notify({
    Duration = 4,
    Content = "THIS WILL USE AUTO WELD 1 MIGHT CAUSE A LITTLE LAG!",
    Icon = "check",
    Title = "Auto Weld V1"
})
    end,
    Value = false,
    Title = "Auto Weld V1"
})
local toggle3 = tab3:Toggle({
    Type = "Checkbox",
    Icon = "wifi-cog",
    Desc = "Teleports you far away during Build to reduce lag, then returns you back",
    Callback = function(enabled)
        local notify5 = WindUI:Notify({
    Duration = 4,
    Content = "0LAG V1 ENABLED — You'll be teleported far away during Build",
    Icon = "check",
    Title = "0LAG V1"
})
    end,
    Value = false,
    Title = "ZeroLagV1"
})
local button3 = tab3:Button({
    Callback = function()
        local setDesc = paragraph:SetDesc("")
        local setDesc2 = paragraph:SetDesc("Progress: 0%\nBlocks: 0/0\nTotal Time: Waiting...")
        local clearAllPlayersBoatParts = workspace:WaitForChild("ClearAllPlayersBoatParts")
        clearAllPlayersBoatParts:FireServer()
    end,
    Desc = "Stop the Build progress/ClearBuild",
    Icon = "eraser",
    Title = "Abort"
})
local button4 = tab3:Button({
    Callback = function()
        local notify6 = WindUI:Notify({
    Duration = 5,
    Content = "Please select a file first!",
    Icon = "triangle-alert",
    Title = "Error"
})
    end,
    Desc = "Load selected .Build file into BuildPreview",
    Icon = "image",
    Title = "Preview File"
})
local button5 = tab3:Button({
    Callback = function()
        for _, child in buildPreview:GetChildren() do
        local notify7 = WindUI:Notify({
        Duration = 5,
        Content = "No blocks in BuildPreview!",
        Icon = "triangle-alert",
        Title = "Error"
    })
        end
    end,
    Desc = "Load adjusted BuildPreview blocks to workspace",
    Icon = "play",
    Title = "Build Adjusted"
})
local button6 = tab3:Button({
    Callback = function()
        buildPreview:ClearAllChildren()
        previewPart:Destroy()
        buildPreview.PrimaryPart = nil
        local notify8 = WindUI:Notify({
    Duration = 5,
    Content = "Preview cleared successfully",
    Icon = "check",
    Title = "Success"
})
        local setDesc3 = paragraph:SetDesc("")
        local setDesc4 = paragraph:SetDesc("Progress: 0%\nBlocks: 0/0\nTotal Time: Waiting...")
    end,
    Desc = "Clear all blocks from BuildPreview",
    Icon = "trash",
    Title = "Clear Preview"
})
    local toggle4 = tab3:Toggle({
        Callback = function(enabled)
            for _, child in buildPreview:GetChildren() do
            local buildPreviewHighlight = buildPreview:FindFirstChild("BuildPreviewHighlight")
            buildPreviewHighlight:Destroy()
            for _, child in buildPreview:GetChildren() do
            local notify9 = WindUI:Notify({
            Duration = 3,
            Content = "Using per-block highlights",
            Icon = "check",
            Title = "Highlight Mode Updated"
        })
            end
        end
    end,
        Desc = "Enable to highlight each block individually instead of the whole model",
        Default = false,
        Title = "Highlight Some Preview Blocks[Beta]"
    })
    local HttpService5 = game:GetService("HttpService")
    local addTheme = WindUI:AddTheme({
        Name = "LiveCustom"
    })
    local setTheme = WindUI:SetTheme("LiveCustom")
    local colorPicker = tab:Colorpicker({
        Callback = function(color)
            local addTheme2 = WindUI:AddTheme({
        Name = "LiveCustom",
        Accent = Color3.fromRGB(255, 255, 255)
    })
            local setTheme2 = WindUI:SetTheme("LiveCustom")
        end,
        Title = "Accent"
    })
    local colorPicker2 = tab:Colorpicker({
        Callback = function(color)
            local addTheme3 = WindUI:AddTheme({
        Background = Color3.fromRGB(255, 255, 255),
        Name = "LiveCustom",
        Accent = Color3.fromRGB(255, 255, 255)
    })
            local setTheme3 = WindUI:SetTheme("LiveCustom")
        end,
        Title = "Background"
    })
    local colorPicker3 = tab:Colorpicker({
        Callback = function(color)
            local addTheme4 = WindUI:AddTheme({
        Background = Color3.fromRGB(255, 255, 255),
        Name = "LiveCustom",
        Accent = Color3.fromRGB(255, 255, 255),
        Outline = Color3.fromRGB(255, 255, 255)
    })
            local setTheme4 = WindUI:SetTheme("LiveCustom")
        end,
        Title = "Outline"
    })
    local colorPicker4 = tab:Colorpicker({
        Callback = function(color)
            local addTheme5 = WindUI:AddTheme({
        Background = Color3.fromRGB(255, 255, 255),
        Name = "LiveCustom",
        Accent = Color3.fromRGB(255, 255, 255),
        Text = Color3.fromRGB(255, 255, 255),
        Outline = Color3.fromRGB(255, 255, 255)
    })
            local setTheme5 = WindUI:SetTheme("LiveCustom")
        end,
        Title = "Text"
    })
    local colorPicker5 = tab:Colorpicker({
        Callback = function(color)
            local addTheme6 = WindUI:AddTheme({
        Background = Color3.fromRGB(255, 255, 255),
        Name = "LiveCustom",
        Accent = Color3.fromRGB(255, 255, 255),
        Text = Color3.fromRGB(255, 255, 255),
        Outline = Color3.fromRGB(255, 255, 255),
        Button = Color3.fromRGB(255, 255, 255)
    })
            local setTheme6 = WindUI:SetTheme("LiveCustom")
        end,
        Title = "Button"
    })
    local colorPicker6 = tab:Colorpicker({
        Callback = function(color)
            local addTheme7 = WindUI:AddTheme({
        Background = Color3.fromRGB(255, 255, 255),
        Name = "LiveCustom",
        Accent = Color3.fromRGB(255, 255, 255),
        Text = Color3.fromRGB(255, 255, 255),
        Icon = Color3.fromRGB(255, 255, 255),
        Outline = Color3.fromRGB(255, 255, 255),
        Button = Color3.fromRGB(255, 255, 255)
    })
            local setTheme7 = WindUI:SetTheme("LiveCustom")
        end,
        Title = "Icon"
    })
    local keybind = tab:Keybind({
        Callback = function(key)
            local uIS = game:GetService("UserInputService")
            local conn3 = uIS.InputBegan:Connect(function(input, gameProcessed)
            end)
        end,
        Value = "G",
        Desc = "Keybind to open window",
        Title = "Open Window"
    })
    local keybind2 = tab:Keybind({
        Callback = function(key)
            local uIS2 = game:GetService("UserInputService")
            local conn4 = uIS2.InputBegan:Connect(function(input, gameProcessed)
            end)
        end,
        Value = "H",
        Desc = "Press to close the UI",
        Title = "Close Window"
    })
    local paragraph2 = tab8:Paragraph({
        Size = 14,
        Content = "",
        Title = "Tutorial in Discord"
    })
    local input = tab8:Input({
        Placeholder = "model.obj",
        Type = "Input",
        Value = "",
        Title = "OBJ File"
    })
    local input2 = tab8:Input({
        Placeholder = "model.mtl",
        Type = "Input",
        Value = "",
        Title = "MTL File(optional For colors)"
    })
    local input3 = tab8:Input({
        Type = "Input",
        Value = "+11",
        Title = "Y Offset"
    })
    local lock = input3:Lock()
    local input4 = tab8:Input({
        Type = "Input",
        Value = "1",
        Title = "Scale"
    })
    local input5 = tab8:Input({
        Type = "Input",
        Value = "0.5",
        Title = "Thickness"
    })
    local dropdown2 = tab8:Dropdown({
        Values = {"Wire", ""},
        Callback = function(selected) end,
        Value = "Wire",
        Title = "Mode"
    })
    local HttpService6 = game:GetService("HttpService")
    local button7 = tab8:Button({
        Callback = function()
            for _, child in workspace:GetChildren() do
            paragraph2.Content = "Zone not found!"
            end
        end,
        Desc = "Preview OBJ",
        Title = "Preview"
    })
    local button8 = tab8:Button({
        Callback = function()
            for _, child in workspace:GetChildren() do
            paragraph2.Content = "Zone not found!"
            end
        end,
        Desc = "Save OBJ as .build",
        Title = "Save .BUILD"
    })
    local button9 = tab8:Button({
        Callback = function()
            paragraph2.Content = "Cleared"
        end,
        Desc = "Delete preview",
        Title = "Clear Preview"
    })
    local button10 = tab8:Button({
        Callback = function() end,
        Desc = "Must Preview obj first",
        Icon = "play",
        Title = "Build Obj From preview"
    })
    local shape_Preview2 = workspace:FindFirstChild("Shape Preview")
    shape_Preview2.Name = "Shape Preview"
    shape_Preview2.Parent = workspace
    local paragraph3 = tab9:Paragraph({
        Color = "Blue",
        Buttons = {},
        Desc = "The Model Voxelizer is a code  made by Kira that converts 3D models into a voxel format. \nIt’s kind of like a mesh loader, but instead of just loading models locally, \nit transforms them into cube-based voxels. This is useful for games, simulations, \nor stylized 3D visuals, making models blocky and easy to manipulate and uses 10x more blocks.This tab is basically Model loader But can load Mesh And uses More blocks(if ur loading a Model it will be invisible (kinda Go closer to it to see it if ur far away u won't see it it's in the center of team btw.\n",
        ImageSize = 30,
        ThumbnailSize = 80,
        Title = "Model Voxelizer Info(keep in Mind)",
        Thumbnail = "",
        Image = "",
        Locked = false
    })
    local input6 = tab9:Input({
        Callback = function(text) end,
        Desc = "Enter Asset ID",
        Title = "Asset ID"
    })
    local slider = tab9:Slider({
        Step = 1,
        Desc = "Batch per yield",
        Callback = function(value) end,
        Value = {
        Min = 50,
        Max = 5000,
        Default = 300
    },
        Title = "Speed"
    })
    local paragraph4 = tab9:Paragraph({
        Desc = "Ready",
        Title = "Status"
    })
    local paragraph5 = tab9:Paragraph({
        Desc = "Parts: 0 / 0\nPercent: 0%",
        Title = "Progress"
    })
    local paragraph6 = tab9:Paragraph({
        Desc = "Waiting...",
        Title = "Estimated Time"
    })
    local button11 = tab9:Button({
        Callback = function()
            local setDesc5 = paragraph4:SetDesc("Stopped")
        end,
        Desc = "Stop voxelization",
        Title = "Stop"
    })
    local button12 = tab9:Button({
        Callback = function() end,
        Desc = "Clear voxel preview",
        Title = "Clear"
    })
    local button13 = tab9:Button({
        Callback = function()
            local setDesc6 = paragraph4:SetDesc("Loading model...")
            for _, child in shape_Preview2:GetChildren() do
            local getObjects = game:GetObjects("rbxassetid://NoKey")
            local setDesc7 = paragraph4:SetDesc("Invalid Asset ID")
            end
        end,
        Desc = "Start voxelization",
        Title = "Load & Voxelize"
    })
    local button14 = tab9:Button({
        Callback = function() end,
        Desc = "Must preview Voxeled Model first",
        Icon = "play",
        Title = "Build VoxelModel From Preview"
    })
    local input7 = tab5:Input({
        Type = "Input",
        Desc = "How many times to dupe (1–50)",
        Callback = function(text) end,
        Placeholder = "Enter amount...",
        Value = "10",
        Title = "Dupe Amount"
    })
    local input8 = tab5:Input({
        Type = "Input",
        Desc = "Boat slot to load (1–99)",
        Callback = function(text) end,
        Placeholder = "Enter slot...",
        Value = "42",
        Title = "Slot Number"
    })
    local button15 = tab5:Button({
        Callback = function()
            local notify10 = WindUI:Notify({
        Icon = "loader",
        Content = "Duping build 10 times...",
        Duration = 3,
        Title = "Duping Started"
    })
            task.spawn(function()
            local fireServer = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer2 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer3 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer4 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer5 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer6 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer7 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer8 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer9 = Workspace3.LoadBoatData:FireServer(42, 0)
            local fireServer10 = Workspace3.LoadBoatData:FireServer(42, 0)
            local notify11 = WindUI:Notify({
            Icon = "check",
            Content = "Successfully duped build 10x",
            Duration = 4,
            Title = "Dupe Complete"
        })
            end)
        end,
        Locked = false,
        Desc = "Start duping the build",
        Title = "Dupe Build"
    })
    local paragraph7 = tab11:Paragraph({
        Color = "Red",
        Desc = "",
        Title = "(If the script Serverhops u, Press Force stop"
    })
    local paragraph8 = tab11:Paragraph({
        Color = "Red",
        Desc = "",
        Title = "(ON AUTO EXEC IF U WANNA FARM"
    })
    local paragraph9 = tab11:Paragraph({
        Desc = "STOPPED",
        Color = "Red",
        Buttons = {
            [1] = {
                Callback = function() end,
                Icon = "play",
                Title = "Force Start"
            },
            [2] = {
                Callback = function() end,
                Icon = "square",
                Title = "Force Stop"
            }
        },
        Title = "System Status"
    })
    local paragraph10 = tab11:Paragraph({
        Desc = "Loading...",
        Color = "Blue",
        Buttons = {
            [1] = {
                Callback = function() end,
                Icon = "save",
                Title = "Save All Players"
            },
            [2] = {
                Callback = function() end,
                Icon = "refresh-cw",
                Title = "Server Hop"
            },
            [3] = {
                Callback = function() end,
                Icon = "trash",
                Title = "Reset Visited Servers"
            }
        },
        Title = "Live Stats"
    })
    task.spawn(function()
        task.wait(1)
        local setTitle = paragraph9:SetTitle("System Status • STOPPED")
        local setDesc8 = paragraph9:SetDesc("Auto farm is inactive")
        local setColor = paragraph9:SetColor("Red")
        local setDesc9 = paragraph10:SetDesc("Saves: 0\nHops: 0\nPlayers: 0\nLast File: -")
        task.wait(1)
        local setTitle2 = paragraph9:SetTitle("System Status • STOPPED")
        local setDesc10 = paragraph9:SetDesc("Auto farm is inactive")
        local setColor2 = paragraph9:SetColor("Red")
        local setDesc11 = paragraph10:SetDesc("Saves: 0\nHops: 0\nPlayers: 0\nLast File: -")
        task.wait(1)
        local setTitle3 = paragraph9:SetTitle("System Status • STOPPED")
        local setDesc12 = paragraph9:SetDesc("Auto farm is inactive")
        local setColor3 = paragraph9:SetColor("Red")
        local setDesc13 = paragraph10:SetDesc("Saves: 0\nHops: 0\nPlayers: 0\nLast File: -")
        -- [similar block repeated 2789 more time(s), omitted for clarity]

        batchSize = 50
        Paragraph = paragraph3
        ghostParts = {}
        BlockChangerTab = tab14
        AutoBuilderTab = tab3
        ModelVoxelizerTab = tab9
        LoadTextTab = tab6
        LX_AutoLoadConfig = true
        LX_AutoFarm = false
        voxelStop = false
        AdjusterTab = tab13
        ListTab = tab12
        BuildFarmerTab = tab11
        radius = 5
        MustReadTab = tab2
        color = Color3.fromRGB(0, 255, 0)
        SaveBuilderTab = tab4
        transparency = 0
        rotZ = 0
        rotY = 0
        rotX = 0
        yOffset = 10.7
        size = 0.3
        shapeTab = tab7
        density = 100
        shape = "Sphere"
        PreviewModel = shape_Preview
end)
