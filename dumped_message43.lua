-- generated with catmio | https://discord.gg/cq9GkRKX2V
local isLoaded = game:IsLoaded()
local Players = game:GetService("Players")
local uIS = game:GetService("UserInputService")
local RunService = game:GetService("RunService")
local TweenService = game:GetService("TweenService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local virtualUser = game:GetService("VirtualUser")
local TeleportService = game:GetService("TeleportService")
local HttpService = game:GetService("HttpService")
local localPlayer = Players.LocalPlayer
local playerGui = localPlayer:WaitForChild("PlayerGui")
local zenithHub_V2 = playerGui:FindFirstChild("ZenithHub_V2")
local destroy = playerGui.ZenithHub_V2:Destroy()
local screenGui = Instance.new("ScreenGui")
screenGui.Name = "ZenithHub_V2"
screenGui.ResetOnSpawn = false
screenGui.Parent = playerGui
local frame = Instance.new("Frame", screenGui)
frame.Size = UDim2.new(0, 0, 0, 0)
frame.Position = UDim2.new(0.5, 0, 0.5, 0)
frame.BackgroundColor3 = Color3.fromRGB(8, 8, 8)
frame.Visible = false
local uICorner = Instance.new("UICorner", frame)
local uIStroke = Instance.new("UIStroke", frame)
uIStroke.Color = Color3.fromRGB(255, 220, 50)
uIStroke.Thickness = 2
local frame2 = Instance.new("Frame", frame)
frame2.Size = UDim2.new(0, 72, 1, -10)
frame2.Position = UDim2.new(0, 5, 0, 5)
frame2.BackgroundColor3 = Color3.fromRGB(12, 12, 12)
frame2.ClipsDescendants = true
local uICorner2 = Instance.new("UICorner", frame2)
local uIStroke2 = Instance.new("UIStroke", frame2)
uIStroke2.Color = Color3.fromRGB(255, 220, 50)
uIStroke2.Thickness = 1.5
local textLabel = Instance.new("TextLabel", frame2)
textLabel.Size = UDim2.new(1, 0, 0, 35)
textLabel.Text = "ZENITH"
textLabel.TextColor3 = Color3.fromRGB(255, 220, 50)
textLabel.Font = Enum.Font.GothamBlack
textLabel.TextSize = 11
textLabel.BackgroundTransparency = 1
local scrollingFrame = Instance.new("ScrollingFrame", frame2)
scrollingFrame.Size = UDim2.new(1, 0, 1, -40)
scrollingFrame.Position = UDim2.new(0, 0, 0, 40)
scrollingFrame.BackgroundTransparency = 1
scrollingFrame.ScrollBarThickness = 0
scrollingFrame.AutomaticCanvasSize = 0
scrollingFrame.BorderSizePixel = 0
local uIListLayout = Instance.new("UIListLayout", scrollingFrame)
uIListLayout.Padding = UDim.new(0, 4)
uIListLayout.HorizontalAlignment = Enum.HorizontalAlignment.Center
uIListLayout.SortOrder = 0
local uIPadding = Instance.new("UIPadding", scrollingFrame)
uIPadding.PaddingTop = UDim.new(0, 4)
uIPadding.PaddingBottom = UDim.new(0, 4)
local frame3 = Instance.new("Frame", frame)
frame3.Size = UDim2.new(1, -87, 1, -10)
frame3.Position = UDim2.new(0, 82, 0, 5)
frame3.BackgroundTransparency = 1
frame3.ClipsDescendants = true
local scrollingFrame2 = Instance.new("ScrollingFrame", frame3)
scrollingFrame2.Size = UDim2.new(1, 0, 1, 0)
scrollingFrame2.BackgroundTransparency = 1
scrollingFrame2.ScrollBarThickness = 3
scrollingFrame2.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
scrollingFrame2.BorderSizePixel = 0
scrollingFrame2.AutomaticCanvasSize = 0
scrollingFrame2.CanvasSize = UDim2.new(0, 0, 0, 0)
scrollingFrame2.Visible = false
scrollingFrame2.ScrollingDirection = 0
scrollingFrame2.ElasticBehavior = Enum.ElasticBehavior.Always
local frame4 = Instance.new("Frame", scrollingFrame2)
frame4.Size = UDim2.new(1, 0, 0, 0)
frame4.BackgroundTransparency = 1
frame4.AutomaticSize = 0
local uIListLayout2 = Instance.new("UIListLayout", frame4)
uIListLayout2.Padding = UDim.new(0, 6)
uIListLayout2.HorizontalAlignment = Enum.HorizontalAlignment.Center
uIListLayout2.SortOrder = 0
local uIPadding2 = Instance.new("UIPadding", frame4)
uIPadding2.PaddingTop = UDim.new(0, 6)
uIPadding2.PaddingBottom = UDim.new(0, 10)
local textButton = Instance.new("TextButton", scrollingFrame)
textButton.Size = UDim2.new(0.9, 0, 0, 26)
textButton.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
textButton.Text = "Main"
textButton.TextColor3 = Color3.fromRGB(180, 180, 180)
textButton.Font = Enum.Font.GothamBold
textButton.TextSize = 9
local uICorner3 = Instance.new("UICorner", textButton)
local conn = textButton.MouseButton1Click:Connect(function()
    scrollingFrame2.Visible = true
    textButton.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    textButton.TextColor3 = Color3.fromRGB(0, 0, 0)
end)
local scrollingFrame3 = Instance.new("ScrollingFrame", frame3)
scrollingFrame3.Size = UDim2.new(1, 0, 1, 0)
scrollingFrame3.BackgroundTransparency = 1
scrollingFrame3.ScrollBarThickness = 3
scrollingFrame3.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
scrollingFrame3.BorderSizePixel = 0
scrollingFrame3.AutomaticCanvasSize = 0
scrollingFrame3.CanvasSize = UDim2.new(0, 0, 0, 0)
scrollingFrame3.Visible = false
scrollingFrame3.ScrollingDirection = 0
scrollingFrame3.ElasticBehavior = Enum.ElasticBehavior.Always
local frame5 = Instance.new("Frame", scrollingFrame3)
frame5.Size = UDim2.new(1, 0, 0, 0)
frame5.BackgroundTransparency = 1
frame5.AutomaticSize = 0
local uIListLayout3 = Instance.new("UIListLayout", frame5)
uIListLayout3.Padding = UDim.new(0, 6)
uIListLayout3.HorizontalAlignment = Enum.HorizontalAlignment.Center
uIListLayout3.SortOrder = 0
local uIPadding3 = Instance.new("UIPadding", frame5)
uIPadding3.PaddingTop = UDim.new(0, 6)
uIPadding3.PaddingBottom = UDim.new(0, 10)
local textButton2 = Instance.new("TextButton", scrollingFrame)
textButton2.Size = UDim2.new(0.9, 0, 0, 26)
textButton2.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
textButton2.Text = "Buy"
textButton2.TextColor3 = Color3.fromRGB(180, 180, 180)
textButton2.Font = Enum.Font.GothamBold
textButton2.TextSize = 9
local uICorner4 = Instance.new("UICorner", textButton2)
local conn2 = textButton2.MouseButton1Click:Connect(function()
    scrollingFrame2.Visible = false
    textButton.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame3.Visible = true
    textButton2.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    textButton2.TextColor3 = Color3.fromRGB(0, 0, 0)
end)
local scrollingFrame4 = Instance.new("ScrollingFrame", frame3)
scrollingFrame4.Size = UDim2.new(1, 0, 1, 0)
scrollingFrame4.BackgroundTransparency = 1
scrollingFrame4.ScrollBarThickness = 3
scrollingFrame4.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
scrollingFrame4.BorderSizePixel = 0
scrollingFrame4.AutomaticCanvasSize = 0
scrollingFrame4.CanvasSize = UDim2.new(0, 0, 0, 0)
scrollingFrame4.Visible = false
scrollingFrame4.ScrollingDirection = 0
scrollingFrame4.ElasticBehavior = Enum.ElasticBehavior.Always
local frame6 = Instance.new("Frame", scrollingFrame4)
frame6.Size = UDim2.new(1, 0, 0, 0)
frame6.BackgroundTransparency = 1
frame6.AutomaticSize = 0
local uIListLayout4 = Instance.new("UIListLayout", frame6)
uIListLayout4.Padding = UDim.new(0, 6)
uIListLayout4.HorizontalAlignment = Enum.HorizontalAlignment.Center
uIListLayout4.SortOrder = 0
local uIPadding4 = Instance.new("UIPadding", frame6)
uIPadding4.PaddingTop = UDim.new(0, 6)
uIPadding4.PaddingBottom = UDim.new(0, 10)
local textButton3 = Instance.new("TextButton", scrollingFrame)
textButton3.Size = UDim2.new(0.9, 0, 0, 26)
textButton3.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
textButton3.Text = "Farm"
textButton3.TextColor3 = Color3.fromRGB(180, 180, 180)
textButton3.Font = Enum.Font.GothamBold
textButton3.TextSize = 9
local uICorner5 = Instance.new("UICorner", textButton3)
local conn3 = textButton3.MouseButton1Click:Connect(function()
    scrollingFrame3.Visible = false
    textButton2.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton2.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame2.Visible = false
    textButton.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame4.Visible = true
    textButton3.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    textButton3.TextColor3 = Color3.fromRGB(0, 0, 0)
end)
local scrollingFrame5 = Instance.new("ScrollingFrame", frame3)
scrollingFrame5.Size = UDim2.new(1, 0, 1, 0)
scrollingFrame5.BackgroundTransparency = 1
scrollingFrame5.ScrollBarThickness = 3
scrollingFrame5.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
scrollingFrame5.BorderSizePixel = 0
scrollingFrame5.AutomaticCanvasSize = 0
scrollingFrame5.CanvasSize = UDim2.new(0, 0, 0, 0)
scrollingFrame5.Visible = false
scrollingFrame5.ScrollingDirection = 0
scrollingFrame5.ElasticBehavior = Enum.ElasticBehavior.Always
local frame7 = Instance.new("Frame", scrollingFrame5)
frame7.Size = UDim2.new(1, 0, 0, 0)
frame7.BackgroundTransparency = 1
frame7.AutomaticSize = 0
local uIListLayout5 = Instance.new("UIListLayout", frame7)
uIListLayout5.Padding = UDim.new(0, 6)
uIListLayout5.HorizontalAlignment = Enum.HorizontalAlignment.Center
uIListLayout5.SortOrder = 0
local uIPadding5 = Instance.new("UIPadding", frame7)
uIPadding5.PaddingTop = UDim.new(0, 6)
uIPadding5.PaddingBottom = UDim.new(0, 10)
local textButton4 = Instance.new("TextButton", scrollingFrame)
textButton4.Size = UDim2.new(0.9, 0, 0, 26)
textButton4.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
textButton4.Text = "Config"
textButton4.TextColor3 = Color3.fromRGB(180, 180, 180)
textButton4.Font = Enum.Font.GothamBold
textButton4.TextSize = 9
local uICorner6 = Instance.new("UICorner", textButton4)
local conn4 = textButton4.MouseButton1Click:Connect(function()
    scrollingFrame4.Visible = false
    textButton3.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton3.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame3.Visible = false
    textButton2.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton2.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame2.Visible = false
    textButton.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame5.Visible = true
    textButton4.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    textButton4.TextColor3 = Color3.fromRGB(0, 0, 0)
end)
local scrollingFrame6 = Instance.new("ScrollingFrame", frame3)
scrollingFrame6.Size = UDim2.new(1, 0, 1, 0)
scrollingFrame6.BackgroundTransparency = 1
scrollingFrame6.ScrollBarThickness = 3
scrollingFrame6.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
scrollingFrame6.BorderSizePixel = 0
scrollingFrame6.AutomaticCanvasSize = 0
scrollingFrame6.CanvasSize = UDim2.new(0, 0, 0, 0)
scrollingFrame6.Visible = false
scrollingFrame6.ScrollingDirection = 0
scrollingFrame6.ElasticBehavior = Enum.ElasticBehavior.Always
local frame8 = Instance.new("Frame", scrollingFrame6)
frame8.Size = UDim2.new(1, 0, 0, 0)
frame8.BackgroundTransparency = 1
frame8.AutomaticSize = 0
local uIListLayout6 = Instance.new("UIListLayout", frame8)
uIListLayout6.Padding = UDim.new(0, 6)
uIListLayout6.HorizontalAlignment = Enum.HorizontalAlignment.Center
uIListLayout6.SortOrder = 0
local uIPadding6 = Instance.new("UIPadding", frame8)
uIPadding6.PaddingTop = UDim.new(0, 6)
uIPadding6.PaddingBottom = UDim.new(0, 10)
local textButton5 = Instance.new("TextButton", scrollingFrame)
textButton5.Size = UDim2.new(0.9, 0, 0, 26)
textButton5.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
textButton5.Text = "Creditos"
textButton5.TextColor3 = Color3.fromRGB(180, 180, 180)
textButton5.Font = Enum.Font.GothamBold
textButton5.TextSize = 9
local uICorner7 = Instance.new("UICorner", textButton5)
local conn5 = textButton5.MouseButton1Click:Connect(function()
    scrollingFrame4.Visible = false
    textButton3.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton3.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame5.Visible = false
    textButton4.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton4.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame3.Visible = false
    textButton2.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton2.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame2.Visible = false
    textButton.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
    textButton.TextColor3 = Color3.fromRGB(180, 180, 180)
    scrollingFrame6.Visible = true
    textButton5.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    textButton5.TextColor3 = Color3.fromRGB(0, 0, 0)
end)
local frame9 = Instance.new("Frame", frame4)
frame9.Size = UDim2.new(0.96, 0, 0, 32)
frame9.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
local uICorner8 = Instance.new("UICorner", frame9)
local uIStroke3 = Instance.new("UIStroke", frame9)
uIStroke3.Color = Color3.fromRGB(255, 220, 50)
uIStroke3.Thickness = 1.5
local textLabel2 = Instance.new("TextLabel", frame9)
textLabel2.Text = "Auto Rebirth"
textLabel2.Size = UDim2.new(1, -50, 1, 0)
textLabel2.Position = UDim2.new(0, 10, 0, 0)
textLabel2.TextColor3 = Color3.new(1, 1, 1)
textLabel2.BackgroundTransparency = 1
textLabel2.Font = Enum.Font.GothamBold
textLabel2.TextXAlignment = Enum.TextXAlignment.Left
textLabel2.TextSize = 9
local textButton6 = Instance.new("TextButton", frame9)
textButton6.Size = UDim2.new(0, 30, 0, 14)
textButton6.Position = UDim2.new(1, -38, 0.5, -7)
textButton6.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
textButton6.Text = ""
local uICorner9 = Instance.new("UICorner", textButton6)
uICorner9.CornerRadius = UDim.new(1, 0)
local frame10 = Instance.new("Frame", textButton6)
frame10.Size = UDim2.new(0, 10, 0, 10)
frame10.Position = UDim2.new(0, 2, 0.5, -5)
frame10.BackgroundColor3 = Color3.new(1, 1, 1)
local uICorner10 = Instance.new("UICorner", frame10)
uICorner10.CornerRadius = UDim.new(1, 0)
local conn6 = textButton6.MouseButton1Click:Connect(function()
    local tween = TweenService:Create(frame10, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        Position = UDim2.new(0, 18, 0.5, -5)
    })
    tween:Play()
    local tween2 = TweenService:Create(textButton6, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    })
    tween2:Play()
    local frame11 = Instance.new("Frame", screenGui)
    frame11.Size = UDim2.new(0, 220, 0, 60)
    frame11.Position = UDim2.new(1, 20, 1, -80)
    frame11.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner11 = Instance.new("UICorner", frame11)
    local uIStroke4 = Instance.new("UIStroke", frame11)
    uIStroke4.Color = Color3.fromRGB(255, 220, 50)
    uIStroke4.Thickness = 1.5
    local textLabel3 = Instance.new("TextLabel", frame11)
    textLabel3.Size = UDim2.new(1, -16, 0, 20)
    textLabel3.Position = UDim2.new(0, 8, 0, 10)
    textLabel3.Text = "Auto Rebirth"
    textLabel3.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel3.Font = Enum.Font.GothamBlack
    textLabel3.TextSize = 13
    textLabel3.BackgroundTransparency = 1
    textLabel3.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel4 = Instance.new("TextLabel", frame11)
    textLabel4.Size = UDim2.new(1, -16, 0, 18)
    textLabel4.Position = UDim2.new(0, 8, 0, 30)
    textLabel4.Text = "Ativado"
    textLabel4.TextColor3 = Color3.new(1, 1, 1)
    textLabel4.Font = Enum.Font.GothamBold
    textLabel4.TextSize = 11
    textLabel4.BackgroundTransparency = 1
    textLabel4.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition = frame11:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition2 = frame11:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame11:Destroy()
    end)
end)
task.spawn(function()
    local frame12 = Instance.new("Frame", screenGui)
    frame12.Size = UDim2.new(0, 220, 0, 60)
    frame12.Position = UDim2.new(1, 20, 1, -80)
    frame12.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner12 = Instance.new("UICorner", frame12)
    local uIStroke5 = Instance.new("UIStroke", frame12)
    uIStroke5.Color = Color3.fromRGB(255, 220, 50)
    uIStroke5.Thickness = 1.5
    local textLabel5 = Instance.new("TextLabel", frame12)
    textLabel5.Size = UDim2.new(1, -16, 0, 20)
    textLabel5.Position = UDim2.new(0, 8, 0, 10)
    textLabel5.Text = "Auto Rebirth"
    textLabel5.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel5.Font = Enum.Font.GothamBlack
    textLabel5.TextSize = 13
    textLabel5.BackgroundTransparency = 1
    textLabel5.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel6 = Instance.new("TextLabel", frame12)
    textLabel6.Size = UDim2.new(1, -16, 0, 18)
    textLabel6.Position = UDim2.new(0, 8, 0, 30)
    textLabel6.Text = "Ativado"
    textLabel6.TextColor3 = Color3.new(1, 1, 1)
    textLabel6.Font = Enum.Font.GothamBold
    textLabel6.TextSize = 11
    textLabel6.BackgroundTransparency = 1
    textLabel6.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition3 = frame12:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition4 = frame12:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame12:Destroy()
    end)
end)
local frame13 = Instance.new("Frame", frame4)
frame13.Size = UDim2.new(0.96, 0, 0, 32)
frame13.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
local uICorner13 = Instance.new("UICorner", frame13)
local uIStroke6 = Instance.new("UIStroke", frame13)
uIStroke6.Color = Color3.fromRGB(255, 220, 50)
uIStroke6.Thickness = 1.5
local textLabel7 = Instance.new("TextLabel", frame13)
textLabel7.Text = "Auto Buy Brainrots"
textLabel7.Size = UDim2.new(1, -50, 1, 0)
textLabel7.Position = UDim2.new(0, 10, 0, 0)
textLabel7.TextColor3 = Color3.new(1, 1, 1)
textLabel7.BackgroundTransparency = 1
textLabel7.Font = Enum.Font.GothamBold
textLabel7.TextXAlignment = Enum.TextXAlignment.Left
textLabel7.TextSize = 9
local textButton7 = Instance.new("TextButton", frame13)
textButton7.Size = UDim2.new(0, 30, 0, 14)
textButton7.Position = UDim2.new(1, -38, 0.5, -7)
textButton7.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
textButton7.Text = ""
local uICorner14 = Instance.new("UICorner", textButton7)
uICorner14.CornerRadius = UDim.new(1, 0)
local frame14 = Instance.new("Frame", textButton7)
frame14.Size = UDim2.new(0, 10, 0, 10)
frame14.Position = UDim2.new(0, 2, 0.5, -5)
frame14.BackgroundColor3 = Color3.new(1, 1, 1)
local uICorner15 = Instance.new("UICorner", frame14)
uICorner15.CornerRadius = UDim.new(1, 0)
local conn7 = textButton7.MouseButton1Click:Connect(function()
    local tween3 = TweenService:Create(frame14, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        Position = UDim2.new(0, 18, 0.5, -5)
    })
    tween3:Play()
    local tween4 = TweenService:Create(textButton7, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    })
    tween4:Play()
    local frame15 = Instance.new("Frame", screenGui)
    frame15.Size = UDim2.new(0, 220, 0, 60)
    frame15.Position = UDim2.new(1, 20, 1, -80)
    frame15.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner16 = Instance.new("UICorner", frame15)
    local uIStroke7 = Instance.new("UIStroke", frame15)
    uIStroke7.Color = Color3.fromRGB(255, 220, 50)
    uIStroke7.Thickness = 1.5
    local textLabel8 = Instance.new("TextLabel", frame15)
    textLabel8.Size = UDim2.new(1, -16, 0, 20)
    textLabel8.Position = UDim2.new(0, 8, 0, 10)
    textLabel8.Text = "Auto Buy Brainrots"
    textLabel8.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel8.Font = Enum.Font.GothamBlack
    textLabel8.TextSize = 13
    textLabel8.BackgroundTransparency = 1
    textLabel8.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel9 = Instance.new("TextLabel", frame15)
    textLabel9.Size = UDim2.new(1, -16, 0, 18)
    textLabel9.Position = UDim2.new(0, 8, 0, 30)
    textLabel9.Text = "Ativado"
    textLabel9.TextColor3 = Color3.new(1, 1, 1)
    textLabel9.Font = Enum.Font.GothamBold
    textLabel9.TextSize = 11
    textLabel9.BackgroundTransparency = 1
    textLabel9.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition5 = frame15:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition6 = frame15:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame15:Destroy()
    end)
end)
task.spawn(function()
    local frame16 = Instance.new("Frame", screenGui)
    frame16.Size = UDim2.new(0, 220, 0, 60)
    frame16.Position = UDim2.new(1, 20, 1, -80)
    frame16.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner17 = Instance.new("UICorner", frame16)
    local uIStroke8 = Instance.new("UIStroke", frame16)
    uIStroke8.Color = Color3.fromRGB(255, 220, 50)
    uIStroke8.Thickness = 1.5
    local textLabel10 = Instance.new("TextLabel", frame16)
    textLabel10.Size = UDim2.new(1, -16, 0, 20)
    textLabel10.Position = UDim2.new(0, 8, 0, 10)
    textLabel10.Text = "Auto Buy Brainrots"
    textLabel10.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel10.Font = Enum.Font.GothamBlack
    textLabel10.TextSize = 13
    textLabel10.BackgroundTransparency = 1
    textLabel10.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel11 = Instance.new("TextLabel", frame16)
    textLabel11.Size = UDim2.new(1, -16, 0, 18)
    textLabel11.Position = UDim2.new(0, 8, 0, 30)
    textLabel11.Text = "Ativado"
    textLabel11.TextColor3 = Color3.new(1, 1, 1)
    textLabel11.Font = Enum.Font.GothamBold
    textLabel11.TextSize = 11
    textLabel11.BackgroundTransparency = 1
    textLabel11.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition7 = frame16:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition8 = frame16:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame16:Destroy()
    end)
end)
local frame17 = Instance.new("Frame", frame4)
frame17.Size = UDim2.new(0.96, 0, 0, 32)
frame17.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
local uICorner18 = Instance.new("UICorner", frame17)
local uIStroke9 = Instance.new("UIStroke", frame17)
uIStroke9.Color = Color3.fromRGB(255, 220, 50)
uIStroke9.Thickness = 1.5
local textLabel12 = Instance.new("TextLabel", frame17)
textLabel12.Text = "Auto Collect Money"
textLabel12.Size = UDim2.new(1, -50, 1, 0)
textLabel12.Position = UDim2.new(0, 10, 0, 0)
textLabel12.TextColor3 = Color3.new(1, 1, 1)
textLabel12.BackgroundTransparency = 1
textLabel12.Font = Enum.Font.GothamBold
textLabel12.TextXAlignment = Enum.TextXAlignment.Left
textLabel12.TextSize = 9
local textButton8 = Instance.new("TextButton", frame17)
textButton8.Size = UDim2.new(0, 30, 0, 14)
textButton8.Position = UDim2.new(1, -38, 0.5, -7)
textButton8.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
textButton8.Text = ""
local uICorner19 = Instance.new("UICorner", textButton8)
uICorner19.CornerRadius = UDim.new(1, 0)
local frame18 = Instance.new("Frame", textButton8)
frame18.Size = UDim2.new(0, 10, 0, 10)
frame18.Position = UDim2.new(0, 2, 0.5, -5)
frame18.BackgroundColor3 = Color3.new(1, 1, 1)
local uICorner20 = Instance.new("UICorner", frame18)
uICorner20.CornerRadius = UDim.new(1, 0)
local conn8 = textButton8.MouseButton1Click:Connect(function()
    local tween5 = TweenService:Create(frame18, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        Position = UDim2.new(0, 18, 0.5, -5)
    })
    tween5:Play()
    local tween6 = TweenService:Create(textButton8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    })
    tween6:Play()
    local frame19 = Instance.new("Frame", screenGui)
    frame19.Size = UDim2.new(0, 220, 0, 60)
    frame19.Position = UDim2.new(1, 20, 1, -80)
    frame19.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner21 = Instance.new("UICorner", frame19)
    local uIStroke10 = Instance.new("UIStroke", frame19)
    uIStroke10.Color = Color3.fromRGB(255, 220, 50)
    uIStroke10.Thickness = 1.5
    local textLabel13 = Instance.new("TextLabel", frame19)
    textLabel13.Size = UDim2.new(1, -16, 0, 20)
    textLabel13.Position = UDim2.new(0, 8, 0, 10)
    textLabel13.Text = "Auto Collect"
    textLabel13.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel13.Font = Enum.Font.GothamBlack
    textLabel13.TextSize = 13
    textLabel13.BackgroundTransparency = 1
    textLabel13.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel14 = Instance.new("TextLabel", frame19)
    textLabel14.Size = UDim2.new(1, -16, 0, 18)
    textLabel14.Position = UDim2.new(0, 8, 0, 30)
    textLabel14.Text = "Ativado"
    textLabel14.TextColor3 = Color3.new(1, 1, 1)
    textLabel14.Font = Enum.Font.GothamBold
    textLabel14.TextSize = 11
    textLabel14.BackgroundTransparency = 1
    textLabel14.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition9 = frame19:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition10 = frame19:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame19:Destroy()
    end)
end)
task.spawn(function()
    local frame20 = Instance.new("Frame", screenGui)
    frame20.Size = UDim2.new(0, 220, 0, 60)
    frame20.Position = UDim2.new(1, 20, 1, -80)
    frame20.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner22 = Instance.new("UICorner", frame20)
    local uIStroke11 = Instance.new("UIStroke", frame20)
    uIStroke11.Color = Color3.fromRGB(255, 220, 50)
    uIStroke11.Thickness = 1.5
    local textLabel15 = Instance.new("TextLabel", frame20)
    textLabel15.Size = UDim2.new(1, -16, 0, 20)
    textLabel15.Position = UDim2.new(0, 8, 0, 10)
    textLabel15.Text = "Auto Collect"
    textLabel15.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel15.Font = Enum.Font.GothamBlack
    textLabel15.TextSize = 13
    textLabel15.BackgroundTransparency = 1
    textLabel15.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel16 = Instance.new("TextLabel", frame20)
    textLabel16.Size = UDim2.new(1, -16, 0, 18)
    textLabel16.Position = UDim2.new(0, 8, 0, 30)
    textLabel16.Text = "Ativado"
    textLabel16.TextColor3 = Color3.new(1, 1, 1)
    textLabel16.Font = Enum.Font.GothamBold
    textLabel16.TextSize = 11
    textLabel16.BackgroundTransparency = 1
    textLabel16.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition11 = frame20:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition12 = frame20:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame20:Destroy()
    end)
end)
local frame21 = Instance.new("Frame", frame4)
frame21.Size = UDim2.new(0.96, 0, 0, 32)
frame21.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
local uICorner23 = Instance.new("UICorner", frame21)
local uIStroke12 = Instance.new("UIStroke", frame21)
uIStroke12.Color = Color3.fromRGB(255, 220, 50)
uIStroke12.Thickness = 1.5
local textLabel17 = Instance.new("TextLabel", frame21)
textLabel17.Text = "Instant Collect Brainrots"
textLabel17.Size = UDim2.new(1, -50, 1, 0)
textLabel17.Position = UDim2.new(0, 10, 0, 0)
textLabel17.TextColor3 = Color3.new(1, 1, 1)
textLabel17.BackgroundTransparency = 1
textLabel17.Font = Enum.Font.GothamBold
textLabel17.TextXAlignment = Enum.TextXAlignment.Left
textLabel17.TextSize = 9
local textButton9 = Instance.new("TextButton", frame21)
textButton9.Size = UDim2.new(0, 30, 0, 14)
textButton9.Position = UDim2.new(1, -38, 0.5, -7)
textButton9.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
textButton9.Text = ""
local uICorner24 = Instance.new("UICorner", textButton9)
uICorner24.CornerRadius = UDim.new(1, 0)
local frame22 = Instance.new("Frame", textButton9)
frame22.Size = UDim2.new(0, 10, 0, 10)
frame22.Position = UDim2.new(0, 2, 0.5, -5)
frame22.BackgroundColor3 = Color3.new(1, 1, 1)
local uICorner25 = Instance.new("UICorner", frame22)
uICorner25.CornerRadius = UDim.new(1, 0)
local conn9 = textButton9.MouseButton1Click:Connect(function()
    local tween7 = TweenService:Create(frame22, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        Position = UDim2.new(0, 18, 0.5, -5)
    })
    tween7:Play()
    local tween8 = TweenService:Create(textButton9, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    })
    tween8:Play()
    local frame23 = Instance.new("Frame", screenGui)
    frame23.Size = UDim2.new(0, 220, 0, 60)
    frame23.Position = UDim2.new(1, 20, 1, -80)
    frame23.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner26 = Instance.new("UICorner", frame23)
    local uIStroke13 = Instance.new("UIStroke", frame23)
    uIStroke13.Color = Color3.fromRGB(255, 220, 50)
    uIStroke13.Thickness = 1.5
    local textLabel18 = Instance.new("TextLabel", frame23)
    textLabel18.Size = UDim2.new(1, -16, 0, 20)
    textLabel18.Position = UDim2.new(0, 8, 0, 10)
    textLabel18.Text = "Instant Collect"
    textLabel18.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel18.Font = Enum.Font.GothamBlack
    textLabel18.TextSize = 13
    textLabel18.BackgroundTransparency = 1
    textLabel18.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel19 = Instance.new("TextLabel", frame23)
    textLabel19.Size = UDim2.new(1, -16, 0, 18)
    textLabel19.Position = UDim2.new(0, 8, 0, 30)
    textLabel19.Text = "Ativado"
    textLabel19.TextColor3 = Color3.new(1, 1, 1)
    textLabel19.Font = Enum.Font.GothamBold
    textLabel19.TextSize = 11
    textLabel19.BackgroundTransparency = 1
    textLabel19.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition13 = frame23:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition14 = frame23:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame23:Destroy()
    end)
end)
task.spawn(function()
    local frame24 = Instance.new("Frame", screenGui)
    frame24.Size = UDim2.new(0, 220, 0, 60)
    frame24.Position = UDim2.new(1, 20, 1, -80)
    frame24.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner27 = Instance.new("UICorner", frame24)
    local uIStroke14 = Instance.new("UIStroke", frame24)
    uIStroke14.Color = Color3.fromRGB(255, 220, 50)
    uIStroke14.Thickness = 1.5
    local textLabel20 = Instance.new("TextLabel", frame24)
    textLabel20.Size = UDim2.new(1, -16, 0, 20)
    textLabel20.Position = UDim2.new(0, 8, 0, 10)
    textLabel20.Text = "Instant Collect"
    textLabel20.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel20.Font = Enum.Font.GothamBlack
    textLabel20.TextSize = 13
    textLabel20.BackgroundTransparency = 1
    textLabel20.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel21 = Instance.new("TextLabel", frame24)
    textLabel21.Size = UDim2.new(1, -16, 0, 18)
    textLabel21.Position = UDim2.new(0, 8, 0, 30)
    textLabel21.Text = "Ativado"
    textLabel21.TextColor3 = Color3.new(1, 1, 1)
    textLabel21.Font = Enum.Font.GothamBold
    textLabel21.TextSize = 11
    textLabel21.BackgroundTransparency = 1
    textLabel21.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition15 = frame24:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition16 = frame24:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame24:Destroy()
    end)
end)
local frame25 = Instance.new("Frame", frame4)
frame25.Size = UDim2.new(0.96, 0, 0, 32)
frame25.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
local uICorner28 = Instance.new("UICorner", frame25)
local uIStroke15 = Instance.new("UIStroke", frame25)
uIStroke15.Color = Color3.fromRGB(255, 220, 50)
uIStroke15.Thickness = 1.5
local textLabel22 = Instance.new("TextLabel", frame25)
textLabel22.Text = "Safe Lucky Block AFK"
textLabel22.Size = UDim2.new(1, -50, 1, 0)
textLabel22.Position = UDim2.new(0, 10, 0, 0)
textLabel22.TextColor3 = Color3.new(1, 1, 1)
textLabel22.BackgroundTransparency = 1
textLabel22.Font = Enum.Font.GothamBold
textLabel22.TextXAlignment = Enum.TextXAlignment.Left
textLabel22.TextSize = 9
local textButton10 = Instance.new("TextButton", frame25)
textButton10.Size = UDim2.new(0, 30, 0, 14)
textButton10.Position = UDim2.new(1, -38, 0.5, -7)
textButton10.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
textButton10.Text = ""
local uICorner29 = Instance.new("UICorner", textButton10)
uICorner29.CornerRadius = UDim.new(1, 0)
local frame26 = Instance.new("Frame", textButton10)
frame26.Size = UDim2.new(0, 10, 0, 10)
frame26.Position = UDim2.new(0, 2, 0.5, -5)
frame26.BackgroundColor3 = Color3.new(1, 1, 1)
local uICorner30 = Instance.new("UICorner", frame26)
uICorner30.CornerRadius = UDim.new(1, 0)
local conn10 = textButton10.MouseButton1Click:Connect(function()
    local tween9 = TweenService:Create(frame26, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        Position = UDim2.new(0, 18, 0.5, -5)
    })
    tween9:Play()
    local tween10 = TweenService:Create(textButton10, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    })
    tween10:Play()
    local frame27 = Instance.new("Frame", screenGui)
    frame27.Size = UDim2.new(0, 220, 0, 60)
    frame27.Position = UDim2.new(1, 20, 1, -80)
    frame27.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner31 = Instance.new("UICorner", frame27)
    local uIStroke16 = Instance.new("UIStroke", frame27)
    uIStroke16.Color = Color3.fromRGB(255, 220, 50)
    uIStroke16.Thickness = 1.5
    local textLabel23 = Instance.new("TextLabel", frame27)
    textLabel23.Size = UDim2.new(1, -16, 0, 20)
    textLabel23.Position = UDim2.new(0, 8, 0, 10)
    textLabel23.Text = "Safe Lucky Block AFK"
    textLabel23.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel23.Font = Enum.Font.GothamBlack
    textLabel23.TextSize = 13
    textLabel23.BackgroundTransparency = 1
    textLabel23.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel24 = Instance.new("TextLabel", frame27)
    textLabel24.Size = UDim2.new(1, -16, 0, 18)
    textLabel24.Position = UDim2.new(0, 8, 0, 30)
    textLabel24.Text = "Ativado"
    textLabel24.TextColor3 = Color3.new(1, 1, 1)
    textLabel24.Font = Enum.Font.GothamBold
    textLabel24.TextSize = 11
    textLabel24.BackgroundTransparency = 1
    textLabel24.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition17 = frame27:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition18 = frame27:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame27:Destroy()
    end)
    local humanoidRootPart = object:FindFirstChild("HumanoidRootPart")
    local humanoid = object:FindFirstChildOfClass("Humanoid")
    local server = workspace:FindFirstChild("Server")
    local findFirstChild = workspace.Server:FindFirstChild("Bases")
    for _, child in findFirstChild:GetChildren() do
    end
end)
task.spawn(function()
    local frame28 = Instance.new("Frame", screenGui)
    frame28.Size = UDim2.new(0, 220, 0, 60)
    frame28.Position = UDim2.new(1, 20, 1, -80)
    frame28.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
    local uICorner32 = Instance.new("UICorner", frame28)
    local uIStroke17 = Instance.new("UIStroke", frame28)
    uIStroke17.Color = Color3.fromRGB(255, 220, 50)
    uIStroke17.Thickness = 1.5
    local textLabel25 = Instance.new("TextLabel", frame28)
    textLabel25.Size = UDim2.new(1, -16, 0, 20)
    textLabel25.Position = UDim2.new(0, 8, 0, 10)
    textLabel25.Text = "Safe Lucky Block AFK"
    textLabel25.TextColor3 = Color3.fromRGB(255, 220, 50)
    textLabel25.Font = Enum.Font.GothamBlack
    textLabel25.TextSize = 13
    textLabel25.BackgroundTransparency = 1
    textLabel25.TextXAlignment = Enum.TextXAlignment.Left
    local textLabel26 = Instance.new("TextLabel", frame28)
    textLabel26.Size = UDim2.new(1, -16, 0, 18)
    textLabel26.Position = UDim2.new(0, 8, 0, 30)
    textLabel26.Text = "Ativado"
    textLabel26.TextColor3 = Color3.new(1, 1, 1)
    textLabel26.Font = Enum.Font.GothamBold
    textLabel26.TextSize = 11
    textLabel26.BackgroundTransparency = 1
    textLabel26.TextXAlignment = Enum.TextXAlignment.Left
    local tweenPosition19 = frame28:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
    task.delay(3, function()
        local tweenPosition20 = frame28:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
        task.wait(0.5)
        frame28:Destroy()
    end)
    local humanoidRootPart2 = object:FindFirstChild("HumanoidRootPart")
    local humanoid2 = object:FindFirstChildOfClass("Humanoid")
    local server2 = workspace:FindFirstChild("Server")
    local findFirstChild2 = workspace.Server:FindFirstChild("Bases")
    for _, child in findFirstChild2:GetChildren() do
    end
end)
local frame29 = Instance.new("Frame", frame4)
frame29.Size = UDim2.new(0.96, 0, 0, 32)
frame29.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
local uICorner33 = Instance.new("UICorner", frame29)
local uIStroke18 = Instance.new("UIStroke", frame29)
uIStroke18.Color = Color3.fromRGB(255, 220, 50)
uIStroke18.Thickness = 1.5
local textLabel27 = Instance.new("TextLabel", frame29)
textLabel27.Text = "Low Mode"
textLabel27.Size = UDim2.new(1, -50, 1, 0)
textLabel27.Position = UDim2.new(0, 10, 0, 0)
textLabel27.TextColor3 = Color3.new(1, 1, 1)
textLabel27.BackgroundTransparency = 1
textLabel27.Font = Enum.Font.GothamBold
textLabel27.TextXAlignment = Enum.TextXAlignment.Left
textLabel27.TextSize = 9
local textButton11 = Instance.new("TextButton", frame29)
textButton11.Size = UDim2.new(0, 30, 0, 14)
textButton11.Position = UDim2.new(1, -38, 0.5, -7)
textButton11.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
textButton11.Text = ""
local uICorner34 = Instance.new("UICorner", textButton11)
uICorner34.CornerRadius = UDim.new(1, 0)
local frame30 = Instance.new("Frame", textButton11)
frame30.Size = UDim2.new(0, 10, 0, 10)
frame30.Position = UDim2.new(0, 2, 0.5, -5)
frame30.BackgroundColor3 = Color3.new(1, 1, 1)
local uICorner35 = Instance.new("UICorner", frame30)
uICorner35.CornerRadius = UDim.new(1, 0)
local conn11 = textButton11.MouseButton1Click:Connect(function()
    local tween11 = TweenService:Create(frame30, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        Position = UDim2.new(0, 18, 0.5, -5)
    })
    tween11:Play()
    local tween12 = TweenService:Create(textButton11, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
        BackgroundColor3 = Color3.fromRGB(255, 220, 50)
    })
    tween12:Play()
    for _, obj in workspace:GetDescendants() do
        local getChildren = game.Lighting:GetChildren()
        local conn12 = workspace.DescendantAdded:Connect(function(descendant)
            task.wait()
        end)
        local frame31 = Instance.new("Frame", screenGui)
        frame31.Size = UDim2.new(0, 220, 0, 60)
        frame31.Position = UDim2.new(1, 20, 1, -80)
        frame31.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
        local uICorner36 = Instance.new("UICorner", frame31)
        local uIStroke19 = Instance.new("UIStroke", frame31)
        uIStroke19.Color = Color3.fromRGB(255, 220, 50)
        uIStroke19.Thickness = 1.5
        local textLabel28 = Instance.new("TextLabel", frame31)
        textLabel28.Size = UDim2.new(1, -16, 0, 20)
        textLabel28.Position = UDim2.new(0, 8, 0, 10)
        textLabel28.Text = "Low Mode"
        textLabel28.TextColor3 = Color3.fromRGB(255, 220, 50)
        textLabel28.Font = Enum.Font.GothamBlack
        textLabel28.TextSize = 13
        textLabel28.BackgroundTransparency = 1
        textLabel28.TextXAlignment = Enum.TextXAlignment.Left
        local textLabel29 = Instance.new("TextLabel", frame31)
        textLabel29.Size = UDim2.new(1, -16, 0, 18)
        textLabel29.Position = UDim2.new(0, 8, 0, 30)
        textLabel29.Text = "Ativado"
        textLabel29.TextColor3 = Color3.new(1, 1, 1)
        textLabel29.Font = Enum.Font.GothamBold
        textLabel29.TextSize = 11
        textLabel29.BackgroundTransparency = 1
        textLabel29.TextXAlignment = Enum.TextXAlignment.Left
        local tweenPosition21 = frame31:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
        task.delay(3, function()
            local tweenPosition22 = frame31:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
            task.wait(0.5)
            frame31:Destroy()
        end)
    end)
    task.spawn(function()
        for _, obj in workspace:GetDescendants() do
            local getChildren2 = game.Lighting:GetChildren()
            local conn13 = workspace.DescendantAdded:Connect(function(descendant)
                task.wait()
            end)
            local frame32 = Instance.new("Frame", screenGui)
            frame32.Size = UDim2.new(0, 220, 0, 60)
            frame32.Position = UDim2.new(1, 20, 1, -80)
            frame32.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner37 = Instance.new("UICorner", frame32)
            local uIStroke20 = Instance.new("UIStroke", frame32)
            uIStroke20.Color = Color3.fromRGB(255, 220, 50)
            uIStroke20.Thickness = 1.5
            local textLabel30 = Instance.new("TextLabel", frame32)
            textLabel30.Size = UDim2.new(1, -16, 0, 20)
            textLabel30.Position = UDim2.new(0, 8, 0, 10)
            textLabel30.Text = "Low Mode"
            textLabel30.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel30.Font = Enum.Font.GothamBlack
            textLabel30.TextSize = 13
            textLabel30.BackgroundTransparency = 1
            textLabel30.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel31 = Instance.new("TextLabel", frame32)
            textLabel31.Size = UDim2.new(1, -16, 0, 18)
            textLabel31.Position = UDim2.new(0, 8, 0, 30)
            textLabel31.Text = "Ativado"
            textLabel31.TextColor3 = Color3.new(1, 1, 1)
            textLabel31.Font = Enum.Font.GothamBold
            textLabel31.TextSize = 11
            textLabel31.BackgroundTransparency = 1
            textLabel31.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition23 = frame32:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition24 = frame32:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame32:Destroy()
            end)
        end)
        local frame33 = Instance.new("Frame", frame4)
        frame33.Size = UDim2.new(0.96, 0, 0, 32)
        frame33.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner38 = Instance.new("UICorner", frame33)
        local uIStroke21 = Instance.new("UIStroke", frame33)
        uIStroke21.Color = Color3.fromRGB(255, 220, 50)
        uIStroke21.Thickness = 1.5
        local textLabel32 = Instance.new("TextLabel", frame33)
        textLabel32.Text = "Player ESP"
        textLabel32.Size = UDim2.new(1, -50, 1, 0)
        textLabel32.Position = UDim2.new(0, 10, 0, 0)
        textLabel32.TextColor3 = Color3.new(1, 1, 1)
        textLabel32.BackgroundTransparency = 1
        textLabel32.Font = Enum.Font.GothamBold
        textLabel32.TextXAlignment = Enum.TextXAlignment.Left
        textLabel32.TextSize = 9
        local textButton12 = Instance.new("TextButton", frame33)
        textButton12.Size = UDim2.new(0, 30, 0, 14)
        textButton12.Position = UDim2.new(1, -38, 0.5, -7)
        textButton12.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton12.Text = ""
        local uICorner39 = Instance.new("UICorner", textButton12)
        uICorner39.CornerRadius = UDim.new(1, 0)
        local frame34 = Instance.new("Frame", textButton12)
        frame34.Size = UDim2.new(0, 10, 0, 10)
        frame34.Position = UDim2.new(0, 2, 0.5, -5)
        frame34.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner40 = Instance.new("UICorner", frame34)
        uICorner40.CornerRadius = UDim.new(1, 0)
        local conn14 = textButton12.MouseButton1Click:Connect(function()
            local tween13 = TweenService:Create(frame34, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween13:Play()
            local tween14 = TweenService:Create(textButton12, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween14:Play()
            local frame35 = Instance.new("Frame", screenGui)
            frame35.Size = UDim2.new(0, 220, 0, 60)
            frame35.Position = UDim2.new(1, 20, 1, -80)
            frame35.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner41 = Instance.new("UICorner", frame35)
            local uIStroke22 = Instance.new("UIStroke", frame35)
            uIStroke22.Color = Color3.fromRGB(255, 220, 50)
            uIStroke22.Thickness = 1.5
            local textLabel33 = Instance.new("TextLabel", frame35)
            textLabel33.Size = UDim2.new(1, -16, 0, 20)
            textLabel33.Position = UDim2.new(0, 8, 0, 10)
            textLabel33.Text = "Player ESP"
            textLabel33.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel33.Font = Enum.Font.GothamBlack
            textLabel33.TextSize = 13
            textLabel33.BackgroundTransparency = 1
            textLabel33.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel34 = Instance.new("TextLabel", frame35)
            textLabel34.Size = UDim2.new(1, -16, 0, 18)
            textLabel34.Position = UDim2.new(0, 8, 0, 30)
            textLabel34.Text = "Ativado"
            textLabel34.TextColor3 = Color3.new(1, 1, 1)
            textLabel34.Font = Enum.Font.GothamBold
            textLabel34.TextSize = 11
            textLabel34.BackgroundTransparency = 1
            textLabel34.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition25 = frame35:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition26 = frame35:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame35:Destroy()
            end)
        end)
        task.spawn(function()
            local frame36 = Instance.new("Frame", screenGui)
            frame36.Size = UDim2.new(0, 220, 0, 60)
            frame36.Position = UDim2.new(1, 20, 1, -80)
            frame36.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner42 = Instance.new("UICorner", frame36)
            local uIStroke23 = Instance.new("UIStroke", frame36)
            uIStroke23.Color = Color3.fromRGB(255, 220, 50)
            uIStroke23.Thickness = 1.5
            local textLabel35 = Instance.new("TextLabel", frame36)
            textLabel35.Size = UDim2.new(1, -16, 0, 20)
            textLabel35.Position = UDim2.new(0, 8, 0, 10)
            textLabel35.Text = "Player ESP"
            textLabel35.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel35.Font = Enum.Font.GothamBlack
            textLabel35.TextSize = 13
            textLabel35.BackgroundTransparency = 1
            textLabel35.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel36 = Instance.new("TextLabel", frame36)
            textLabel36.Size = UDim2.new(1, -16, 0, 18)
            textLabel36.Position = UDim2.new(0, 8, 0, 30)
            textLabel36.Text = "Ativado"
            textLabel36.TextColor3 = Color3.new(1, 1, 1)
            textLabel36.Font = Enum.Font.GothamBold
            textLabel36.TextSize = 11
            textLabel36.BackgroundTransparency = 1
            textLabel36.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition27 = frame36:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition28 = frame36:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame36:Destroy()
            end)
        end)
        local frame37 = Instance.new("Frame", frame4)
        frame37.Size = UDim2.new(0.96, 0, 0, 32)
        frame37.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner43 = Instance.new("UICorner", frame37)
        local uIStroke24 = Instance.new("UIStroke", frame37)
        uIStroke24.Color = Color3.fromRGB(255, 220, 50)
        uIStroke24.Thickness = 1.5
        local textLabel37 = Instance.new("TextLabel", frame37)
        textLabel37.Text = "Anti Ragdoll"
        textLabel37.Size = UDim2.new(1, -50, 1, 0)
        textLabel37.Position = UDim2.new(0, 10, 0, 0)
        textLabel37.TextColor3 = Color3.new(1, 1, 1)
        textLabel37.BackgroundTransparency = 1
        textLabel37.Font = Enum.Font.GothamBold
        textLabel37.TextXAlignment = Enum.TextXAlignment.Left
        textLabel37.TextSize = 9
        local textButton13 = Instance.new("TextButton", frame37)
        textButton13.Size = UDim2.new(0, 30, 0, 14)
        textButton13.Position = UDim2.new(1, -38, 0.5, -7)
        textButton13.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton13.Text = ""
        local uICorner44 = Instance.new("UICorner", textButton13)
        uICorner44.CornerRadius = UDim.new(1, 0)
        local frame38 = Instance.new("Frame", textButton13)
        frame38.Size = UDim2.new(0, 10, 0, 10)
        frame38.Position = UDim2.new(0, 18, 0.5, -5)
        frame38.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner45 = Instance.new("UICorner", frame38)
        uICorner45.CornerRadius = UDim.new(1, 0)
        local conn15 = textButton13.MouseButton1Click:Connect(function()
            local tween15 = TweenService:Create(frame38, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 2, 0.5, -5)
            })
            tween15:Play()
            local tween16 = TweenService:Create(textButton13, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(30, 30, 30)
            })
            tween16:Play()
            local frame39 = Instance.new("Frame", screenGui)
            frame39.Size = UDim2.new(0, 220, 0, 60)
            frame39.Position = UDim2.new(1, 20, 1, -80)
            frame39.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner46 = Instance.new("UICorner", frame39)
            local uIStroke25 = Instance.new("UIStroke", frame39)
            uIStroke25.Color = Color3.fromRGB(255, 220, 50)
            uIStroke25.Thickness = 1.5
            local textLabel38 = Instance.new("TextLabel", frame39)
            textLabel38.Size = UDim2.new(1, -16, 0, 20)
            textLabel38.Position = UDim2.new(0, 8, 0, 10)
            textLabel38.Text = "Anti Ragdoll"
            textLabel38.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel38.Font = Enum.Font.GothamBlack
            textLabel38.TextSize = 13
            textLabel38.BackgroundTransparency = 1
            textLabel38.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel39 = Instance.new("TextLabel", frame39)
            textLabel39.Size = UDim2.new(1, -16, 0, 18)
            textLabel39.Position = UDim2.new(0, 8, 0, 30)
            textLabel39.Text = "Desativado"
            textLabel39.TextColor3 = Color3.new(1, 1, 1)
            textLabel39.Font = Enum.Font.GothamBold
            textLabel39.TextSize = 11
            textLabel39.BackgroundTransparency = 1
            textLabel39.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition29 = frame39:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition30 = frame39:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame39:Destroy()
            end)
        end)
        local frame40 = Instance.new("Frame", frame4)
        frame40.Size = UDim2.new(0.96, 0, 0, 36)
        frame40.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner47 = Instance.new("UICorner", frame40)
        local uIStroke26 = Instance.new("UIStroke", frame40)
        uIStroke26.Color = Color3.fromRGB(255, 220, 50)
        uIStroke26.Thickness = 1.5
        local textButton14 = Instance.new("TextButton", frame40)
        textButton14.Size = UDim2.new(1, -50, 1, 0)
        textButton14.Position = UDim2.new(0, 10, 0, 0)
        textButton14.BackgroundTransparency = 1
        textButton14.Text = "Auto Sell Brainrots  [Click for Select]"
        textButton14.TextColor3 = Color3.new(1, 1, 1)
        textButton14.Font = Enum.Font.GothamBold
        textButton14.TextXAlignment = Enum.TextXAlignment.Left
        textButton14.TextSize = 10
        textButton14.ZIndex = 5
        local textButton15 = Instance.new("TextButton", frame40)
        textButton15.Size = UDim2.new(0, 30, 0, 14)
        textButton15.Position = UDim2.new(1, -38, 0.5, -7)
        textButton15.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton15.Text = ""
        textButton15.ZIndex = 10
        local uICorner48 = Instance.new("UICorner", textButton15)
        uICorner48.CornerRadius = UDim.new(1, 0)
        local frame41 = Instance.new("Frame", textButton15)
        frame41.Size = UDim2.new(0, 10, 0, 10)
        frame41.Position = UDim2.new(0, 2, 0.5, -5)
        frame41.BackgroundColor3 = Color3.new(1, 1, 1)
        frame41.ZIndex = 11
        local uICorner49 = Instance.new("UICorner", frame41)
        uICorner49.CornerRadius = UDim.new(1, 0)
        local conn16 = textButton15.MouseButton1Click:Connect(function()
            local tween17 = TweenService:Create(frame41, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween17:Play()
            local tween18 = TweenService:Create(textButton15, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween18:Play()
            local frame42 = Instance.new("Frame", screenGui)
            frame42.Size = UDim2.new(0, 220, 0, 60)
            frame42.Position = UDim2.new(1, 20, 1, -80)
            frame42.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner50 = Instance.new("UICorner", frame42)
            local uIStroke27 = Instance.new("UIStroke", frame42)
            uIStroke27.Color = Color3.fromRGB(255, 220, 50)
            uIStroke27.Thickness = 1.5
            local textLabel40 = Instance.new("TextLabel", frame42)
            textLabel40.Size = UDim2.new(1, -16, 0, 20)
            textLabel40.Position = UDim2.new(0, 8, 0, 10)
            textLabel40.Text = "Auto Sell"
            textLabel40.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel40.Font = Enum.Font.GothamBlack
            textLabel40.TextSize = 13
            textLabel40.BackgroundTransparency = 1
            textLabel40.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel41 = Instance.new("TextLabel", frame42)
            textLabel41.Size = UDim2.new(1, -16, 0, 18)
            textLabel41.Position = UDim2.new(0, 8, 0, 30)
            textLabel41.Text = "Ativado"
            textLabel41.TextColor3 = Color3.new(1, 1, 1)
            textLabel41.Font = Enum.Font.GothamBold
            textLabel41.TextSize = 11
            textLabel41.BackgroundTransparency = 1
            textLabel41.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition31 = frame42:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition32 = frame42:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame42:Destroy()
            end)
        end)
        local conn17 = textButton14.MouseButton1Click:Connect(function()
        end)
        local frame43 = Instance.new("Frame", frame4)
        frame43.Size = UDim2.new(0.96, 0, 0, 36)
        frame43.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner51 = Instance.new("UICorner", frame43)
        local uIStroke28 = Instance.new("UIStroke", frame43)
        uIStroke28.Color = Color3.fromRGB(255, 220, 50)
        local textLabel42 = Instance.new("TextLabel", frame43)
        textLabel42.Size = UDim2.new(0.45, 0, 1, 0)
        textLabel42.Position = UDim2.new(0, 8, 0, 0)
        textLabel42.Text = "Min Earn/s:"
        textLabel42.TextColor3 = Color3.new(1, 1, 1)
        textLabel42.Font = Enum.Font.GothamBold
        textLabel42.TextSize = 10
        textLabel42.BackgroundTransparency = 1
        textLabel42.TextXAlignment = Enum.TextXAlignment.Left
        local textBox = Instance.new("TextBox", frame43)
        textBox.Size = UDim2.new(0.48, 0, 0, 22)
        textBox.Position = UDim2.new(0.5, 0, 0.5, -11)
        textBox.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textBox.TextColor3 = Color3.new(1, 1, 1)
        textBox.PlaceholderText = "Ex: 1M, 500K"
        textBox.Font = Enum.Font.GothamBold
        textBox.TextSize = 10
        textBox.Text = ""
        local uICorner52 = Instance.new("UICorner", textBox)
        uICorner52.CornerRadius = UDim.new(0, 4)
        local conn18 = textBox.FocusLost:Connect(function(enterPressed, inputObject)
        end)
        local frame44 = Instance.new("Frame", frame4)
        frame44.Size = UDim2.new(0.96, 0, 0, 200)
        frame44.BackgroundColor3 = Color3.fromRGB(12, 12, 15)
        frame44.Visible = false
        frame44.ClipsDescendants = true
        local uICorner53 = Instance.new("UICorner", frame44)
        local uIStroke29 = Instance.new("UIStroke", frame44)
        uIStroke29.Color = Color3.fromRGB(255, 220, 50)
        local scrollingFrame7 = Instance.new("ScrollingFrame", frame44)
        scrollingFrame7.Size = UDim2.new(1, 0, 1, 0)
        scrollingFrame7.BackgroundTransparency = 1
        scrollingFrame7.ScrollBarThickness = 3
        scrollingFrame7.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
        scrollingFrame7.AutomaticCanvasSize = 0
        scrollingFrame7.CanvasSize = UDim2.new(0, 0, 0, 0)
        local uIListLayout7 = Instance.new("UIListLayout", scrollingFrame7)
        uIListLayout7.Padding = UDim.new(0, 2)
        uIListLayout7.SortOrder = 0
        local uIPadding7 = Instance.new("UIPadding", scrollingFrame7)
        uIPadding7.PaddingTop = UDim.new(0, 4)
        uIPadding7.PaddingBottom = UDim.new(0, 4)
        uIPadding7.PaddingLeft = UDim.new(0, 4)
        uIPadding7.PaddingRight = UDim.new(0, 4)
        local frame45 = Instance.new("Frame", scrollingFrame7)
        frame45.Size = UDim2.new(1, 0, 0, 28)
        frame45.BackgroundTransparency = 1
        local textButton16 = Instance.new("TextButton", frame45)
        textButton16.Size = UDim2.new(0.72, 0, 1, 0)
        textButton16.BackgroundTransparency = 1
        textButton16.Text = "Noobini Pizzanini"
        textButton16.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton16.TextXAlignment = Enum.TextXAlignment.Left
        textButton16.Font = Enum.Font.Gotham
        textButton16.TextSize = 10
        local textButton17 = Instance.new("TextButton", frame45)
        textButton17.Size = UDim2.new(0, 16, 0, 16)
        textButton17.Position = UDim2.new(1, -20, 0.5, -8)
        textButton17.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton17.Text = ""
        local uICorner54 = Instance.new("UICorner", textButton17)
        uICorner54.CornerRadius = UDim.new(0, 3)
        local frame46 = Instance.new("Frame", scrollingFrame7)
        frame46.Size = UDim2.new(1, 0, 0, 26)
        frame46.BackgroundTransparency = 1
        frame46.Visible = false
        local uIGridLayout = Instance.new("UIGridLayout", frame46)
        uIGridLayout.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton18 = Instance.new("TextButton", frame46)
        textButton18.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton18.Text = "Nor"
        textButton18.TextSize = 9
        textButton18.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton18.Font = Enum.Font.GothamBold
        local uICorner55 = Instance.new("UICorner", textButton18)
        local conn19 = textButton18.MouseButton1Click:Connect(function()
            textButton18.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton18.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton19 = Instance.new("TextButton", frame46)
        textButton19.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton19.Text = "Gol"
        textButton19.TextSize = 9
        textButton19.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton19.Font = Enum.Font.GothamBold
        local uICorner56 = Instance.new("UICorner", textButton19)
        local conn20 = textButton19.MouseButton1Click:Connect(function()
            textButton19.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton19.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton20 = Instance.new("TextButton", frame46)
        textButton20.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton20.Text = "Dia"
        textButton20.TextSize = 9
        textButton20.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton20.Font = Enum.Font.GothamBold
        local uICorner57 = Instance.new("UICorner", textButton20)
        local conn21 = textButton20.MouseButton1Click:Connect(function()
            textButton20.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton20.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton21 = Instance.new("TextButton", frame46)
        textButton21.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton21.Text = "Rai"
        textButton21.TextSize = 9
        textButton21.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton21.Font = Enum.Font.GothamBold
        local uICorner58 = Instance.new("UICorner", textButton21)
        local conn22 = textButton21.MouseButton1Click:Connect(function()
            textButton21.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton21.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton22 = Instance.new("TextButton", frame46)
        textButton22.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton22.Text = "Lav"
        textButton22.TextSize = 9
        textButton22.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton22.Font = Enum.Font.GothamBold
        local uICorner59 = Instance.new("UICorner", textButton22)
        local conn23 = textButton22.MouseButton1Click:Connect(function()
            textButton22.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton22.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn24 = textButton16.MouseButton1Click:Connect(function()
            frame46.Visible = true
        end)
        local conn25 = textButton17.MouseButton1Click:Connect(function()
            textButton17.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame47 = Instance.new("Frame", scrollingFrame7)
        frame47.Size = UDim2.new(1, 0, 0, 28)
        frame47.BackgroundTransparency = 1
        local textButton23 = Instance.new("TextButton", frame47)
        textButton23.Size = UDim2.new(0.72, 0, 1, 0)
        textButton23.BackgroundTransparency = 1
        textButton23.Text = "LiriliLarila"
        textButton23.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton23.TextXAlignment = Enum.TextXAlignment.Left
        textButton23.Font = Enum.Font.Gotham
        textButton23.TextSize = 10
        local textButton24 = Instance.new("TextButton", frame47)
        textButton24.Size = UDim2.new(0, 16, 0, 16)
        textButton24.Position = UDim2.new(1, -20, 0.5, -8)
        textButton24.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton24.Text = ""
        local uICorner60 = Instance.new("UICorner", textButton24)
        uICorner60.CornerRadius = UDim.new(0, 3)
        local frame48 = Instance.new("Frame", scrollingFrame7)
        frame48.Size = UDim2.new(1, 0, 0, 26)
        frame48.BackgroundTransparency = 1
        frame48.Visible = false
        local uIGridLayout2 = Instance.new("UIGridLayout", frame48)
        uIGridLayout2.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout2.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton25 = Instance.new("TextButton", frame48)
        textButton25.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton25.Text = "Nor"
        textButton25.TextSize = 9
        textButton25.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton25.Font = Enum.Font.GothamBold
        local uICorner61 = Instance.new("UICorner", textButton25)
        local conn26 = textButton25.MouseButton1Click:Connect(function()
            textButton25.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton25.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton26 = Instance.new("TextButton", frame48)
        textButton26.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton26.Text = "Gol"
        textButton26.TextSize = 9
        textButton26.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton26.Font = Enum.Font.GothamBold
        local uICorner62 = Instance.new("UICorner", textButton26)
        local conn27 = textButton26.MouseButton1Click:Connect(function()
            textButton26.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton26.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton27 = Instance.new("TextButton", frame48)
        textButton27.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton27.Text = "Dia"
        textButton27.TextSize = 9
        textButton27.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton27.Font = Enum.Font.GothamBold
        local uICorner63 = Instance.new("UICorner", textButton27)
        local conn28 = textButton27.MouseButton1Click:Connect(function()
            textButton27.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton27.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton28 = Instance.new("TextButton", frame48)
        textButton28.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton28.Text = "Rai"
        textButton28.TextSize = 9
        textButton28.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton28.Font = Enum.Font.GothamBold
        local uICorner64 = Instance.new("UICorner", textButton28)
        local conn29 = textButton28.MouseButton1Click:Connect(function()
            textButton28.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton28.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton29 = Instance.new("TextButton", frame48)
        textButton29.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton29.Text = "Lav"
        textButton29.TextSize = 9
        textButton29.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton29.Font = Enum.Font.GothamBold
        local uICorner65 = Instance.new("UICorner", textButton29)
        local conn30 = textButton29.MouseButton1Click:Connect(function()
            textButton29.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton29.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn31 = textButton23.MouseButton1Click:Connect(function()
            frame48.Visible = true
        end)
        local conn32 = textButton24.MouseButton1Click:Connect(function()
            textButton24.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame49 = Instance.new("Frame", scrollingFrame7)
        frame49.Size = UDim2.new(1, 0, 0, 28)
        frame49.BackgroundTransparency = 1
        local textButton30 = Instance.new("TextButton", frame49)
        textButton30.Size = UDim2.new(0.72, 0, 1, 0)
        textButton30.BackgroundTransparency = 1
        textButton30.Text = "Fluri Flura"
        textButton30.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton30.TextXAlignment = Enum.TextXAlignment.Left
        textButton30.Font = Enum.Font.Gotham
        textButton30.TextSize = 10
        local textButton31 = Instance.new("TextButton", frame49)
        textButton31.Size = UDim2.new(0, 16, 0, 16)
        textButton31.Position = UDim2.new(1, -20, 0.5, -8)
        textButton31.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton31.Text = ""
        local uICorner66 = Instance.new("UICorner", textButton31)
        uICorner66.CornerRadius = UDim.new(0, 3)
        local frame50 = Instance.new("Frame", scrollingFrame7)
        frame50.Size = UDim2.new(1, 0, 0, 26)
        frame50.BackgroundTransparency = 1
        frame50.Visible = false
        local uIGridLayout3 = Instance.new("UIGridLayout", frame50)
        uIGridLayout3.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout3.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton32 = Instance.new("TextButton", frame50)
        textButton32.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton32.Text = "Nor"
        textButton32.TextSize = 9
        textButton32.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton32.Font = Enum.Font.GothamBold
        local uICorner67 = Instance.new("UICorner", textButton32)
        local conn33 = textButton32.MouseButton1Click:Connect(function()
            textButton32.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton32.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton33 = Instance.new("TextButton", frame50)
        textButton33.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton33.Text = "Gol"
        textButton33.TextSize = 9
        textButton33.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton33.Font = Enum.Font.GothamBold
        local uICorner68 = Instance.new("UICorner", textButton33)
        local conn34 = textButton33.MouseButton1Click:Connect(function()
            textButton33.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton33.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton34 = Instance.new("TextButton", frame50)
        textButton34.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton34.Text = "Dia"
        textButton34.TextSize = 9
        textButton34.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton34.Font = Enum.Font.GothamBold
        local uICorner69 = Instance.new("UICorner", textButton34)
        local conn35 = textButton34.MouseButton1Click:Connect(function()
            textButton34.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton34.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton35 = Instance.new("TextButton", frame50)
        textButton35.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton35.Text = "Rai"
        textButton35.TextSize = 9
        textButton35.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton35.Font = Enum.Font.GothamBold
        local uICorner70 = Instance.new("UICorner", textButton35)
        local conn36 = textButton35.MouseButton1Click:Connect(function()
            textButton35.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton35.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton36 = Instance.new("TextButton", frame50)
        textButton36.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton36.Text = "Lav"
        textButton36.TextSize = 9
        textButton36.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton36.Font = Enum.Font.GothamBold
        local uICorner71 = Instance.new("UICorner", textButton36)
        local conn37 = textButton36.MouseButton1Click:Connect(function()
            textButton36.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton36.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn38 = textButton30.MouseButton1Click:Connect(function()
            frame50.Visible = true
        end)
        local conn39 = textButton31.MouseButton1Click:Connect(function()
            textButton31.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame51 = Instance.new("Frame", scrollingFrame7)
        frame51.Size = UDim2.new(1, 0, 0, 28)
        frame51.BackgroundTransparency = 1
        local textButton37 = Instance.new("TextButton", frame51)
        textButton37.Size = UDim2.new(0.72, 0, 1, 0)
        textButton37.BackgroundTransparency = 1
        textButton37.Text = "Cacto Hipopotamo"
        textButton37.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton37.TextXAlignment = Enum.TextXAlignment.Left
        textButton37.Font = Enum.Font.Gotham
        textButton37.TextSize = 10
        local textButton38 = Instance.new("TextButton", frame51)
        textButton38.Size = UDim2.new(0, 16, 0, 16)
        textButton38.Position = UDim2.new(1, -20, 0.5, -8)
        textButton38.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton38.Text = ""
        local uICorner72 = Instance.new("UICorner", textButton38)
        uICorner72.CornerRadius = UDim.new(0, 3)
        local frame52 = Instance.new("Frame", scrollingFrame7)
        frame52.Size = UDim2.new(1, 0, 0, 26)
        frame52.BackgroundTransparency = 1
        frame52.Visible = false
        local uIGridLayout4 = Instance.new("UIGridLayout", frame52)
        uIGridLayout4.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout4.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton39 = Instance.new("TextButton", frame52)
        textButton39.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton39.Text = "Nor"
        textButton39.TextSize = 9
        textButton39.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton39.Font = Enum.Font.GothamBold
        local uICorner73 = Instance.new("UICorner", textButton39)
        local conn40 = textButton39.MouseButton1Click:Connect(function()
            textButton39.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton39.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton40 = Instance.new("TextButton", frame52)
        textButton40.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton40.Text = "Gol"
        textButton40.TextSize = 9
        textButton40.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton40.Font = Enum.Font.GothamBold
        local uICorner74 = Instance.new("UICorner", textButton40)
        local conn41 = textButton40.MouseButton1Click:Connect(function()
            textButton40.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton40.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton41 = Instance.new("TextButton", frame52)
        textButton41.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton41.Text = "Dia"
        textButton41.TextSize = 9
        textButton41.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton41.Font = Enum.Font.GothamBold
        local uICorner75 = Instance.new("UICorner", textButton41)
        local conn42 = textButton41.MouseButton1Click:Connect(function()
            textButton41.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton41.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton42 = Instance.new("TextButton", frame52)
        textButton42.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton42.Text = "Rai"
        textButton42.TextSize = 9
        textButton42.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton42.Font = Enum.Font.GothamBold
        local uICorner76 = Instance.new("UICorner", textButton42)
        local conn43 = textButton42.MouseButton1Click:Connect(function()
            textButton42.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton42.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton43 = Instance.new("TextButton", frame52)
        textButton43.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton43.Text = "Lav"
        textButton43.TextSize = 9
        textButton43.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton43.Font = Enum.Font.GothamBold
        local uICorner77 = Instance.new("UICorner", textButton43)
        local conn44 = textButton43.MouseButton1Click:Connect(function()
            textButton43.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton43.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn45 = textButton37.MouseButton1Click:Connect(function()
            frame52.Visible = true
        end)
        local conn46 = textButton38.MouseButton1Click:Connect(function()
            textButton38.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame53 = Instance.new("Frame", scrollingFrame7)
        frame53.Size = UDim2.new(1, 0, 0, 28)
        frame53.BackgroundTransparency = 1
        local textButton44 = Instance.new("TextButton", frame53)
        textButton44.Size = UDim2.new(0.72, 0, 1, 0)
        textButton44.BackgroundTransparency = 1
        textButton44.Text = "Pipi Potato"
        textButton44.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton44.TextXAlignment = Enum.TextXAlignment.Left
        textButton44.Font = Enum.Font.Gotham
        textButton44.TextSize = 10
        local textButton45 = Instance.new("TextButton", frame53)
        textButton45.Size = UDim2.new(0, 16, 0, 16)
        textButton45.Position = UDim2.new(1, -20, 0.5, -8)
        textButton45.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton45.Text = ""
        local uICorner78 = Instance.new("UICorner", textButton45)
        uICorner78.CornerRadius = UDim.new(0, 3)
        local frame54 = Instance.new("Frame", scrollingFrame7)
        frame54.Size = UDim2.new(1, 0, 0, 26)
        frame54.BackgroundTransparency = 1
        frame54.Visible = false
        local uIGridLayout5 = Instance.new("UIGridLayout", frame54)
        uIGridLayout5.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout5.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton46 = Instance.new("TextButton", frame54)
        textButton46.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton46.Text = "Nor"
        textButton46.TextSize = 9
        textButton46.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton46.Font = Enum.Font.GothamBold
        local uICorner79 = Instance.new("UICorner", textButton46)
        local conn47 = textButton46.MouseButton1Click:Connect(function()
            textButton46.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton46.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton47 = Instance.new("TextButton", frame54)
        textButton47.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton47.Text = "Gol"
        textButton47.TextSize = 9
        textButton47.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton47.Font = Enum.Font.GothamBold
        local uICorner80 = Instance.new("UICorner", textButton47)
        local conn48 = textButton47.MouseButton1Click:Connect(function()
            textButton47.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton47.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton48 = Instance.new("TextButton", frame54)
        textButton48.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton48.Text = "Dia"
        textButton48.TextSize = 9
        textButton48.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton48.Font = Enum.Font.GothamBold
        local uICorner81 = Instance.new("UICorner", textButton48)
        local conn49 = textButton48.MouseButton1Click:Connect(function()
            textButton48.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton48.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton49 = Instance.new("TextButton", frame54)
        textButton49.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton49.Text = "Rai"
        textButton49.TextSize = 9
        textButton49.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton49.Font = Enum.Font.GothamBold
        local uICorner82 = Instance.new("UICorner", textButton49)
        local conn50 = textButton49.MouseButton1Click:Connect(function()
            textButton49.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton49.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton50 = Instance.new("TextButton", frame54)
        textButton50.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton50.Text = "Lav"
        textButton50.TextSize = 9
        textButton50.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton50.Font = Enum.Font.GothamBold
        local uICorner83 = Instance.new("UICorner", textButton50)
        local conn51 = textButton50.MouseButton1Click:Connect(function()
            textButton50.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton50.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn52 = textButton44.MouseButton1Click:Connect(function()
            frame54.Visible = true
        end)
        local conn53 = textButton45.MouseButton1Click:Connect(function()
            textButton45.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame55 = Instance.new("Frame", scrollingFrame7)
        frame55.Size = UDim2.new(1, 0, 0, 28)
        frame55.BackgroundTransparency = 1
        local textButton51 = Instance.new("TextButton", frame55)
        textButton51.Size = UDim2.new(0.72, 0, 1, 0)
        textButton51.BackgroundTransparency = 1
        textButton51.Text = "Tric Trac Barabum"
        textButton51.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton51.TextXAlignment = Enum.TextXAlignment.Left
        textButton51.Font = Enum.Font.Gotham
        textButton51.TextSize = 10
        local textButton52 = Instance.new("TextButton", frame55)
        textButton52.Size = UDim2.new(0, 16, 0, 16)
        textButton52.Position = UDim2.new(1, -20, 0.5, -8)
        textButton52.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton52.Text = ""
        local uICorner84 = Instance.new("UICorner", textButton52)
        uICorner84.CornerRadius = UDim.new(0, 3)
        local frame56 = Instance.new("Frame", scrollingFrame7)
        frame56.Size = UDim2.new(1, 0, 0, 26)
        frame56.BackgroundTransparency = 1
        frame56.Visible = false
        local uIGridLayout6 = Instance.new("UIGridLayout", frame56)
        uIGridLayout6.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout6.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton53 = Instance.new("TextButton", frame56)
        textButton53.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton53.Text = "Nor"
        textButton53.TextSize = 9
        textButton53.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton53.Font = Enum.Font.GothamBold
        local uICorner85 = Instance.new("UICorner", textButton53)
        local conn54 = textButton53.MouseButton1Click:Connect(function()
            textButton53.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton53.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton54 = Instance.new("TextButton", frame56)
        textButton54.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton54.Text = "Gol"
        textButton54.TextSize = 9
        textButton54.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton54.Font = Enum.Font.GothamBold
        local uICorner86 = Instance.new("UICorner", textButton54)
        local conn55 = textButton54.MouseButton1Click:Connect(function()
            textButton54.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton54.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton55 = Instance.new("TextButton", frame56)
        textButton55.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton55.Text = "Dia"
        textButton55.TextSize = 9
        textButton55.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton55.Font = Enum.Font.GothamBold
        local uICorner87 = Instance.new("UICorner", textButton55)
        local conn56 = textButton55.MouseButton1Click:Connect(function()
            textButton55.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton55.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton56 = Instance.new("TextButton", frame56)
        textButton56.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton56.Text = "Rai"
        textButton56.TextSize = 9
        textButton56.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton56.Font = Enum.Font.GothamBold
        local uICorner88 = Instance.new("UICorner", textButton56)
        local conn57 = textButton56.MouseButton1Click:Connect(function()
            textButton56.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton56.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton57 = Instance.new("TextButton", frame56)
        textButton57.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton57.Text = "Lav"
        textButton57.TextSize = 9
        textButton57.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton57.Font = Enum.Font.GothamBold
        local uICorner89 = Instance.new("UICorner", textButton57)
        local conn58 = textButton57.MouseButton1Click:Connect(function()
            textButton57.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton57.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn59 = textButton51.MouseButton1Click:Connect(function()
            frame56.Visible = true
        end)
        local conn60 = textButton52.MouseButton1Click:Connect(function()
            textButton52.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame57 = Instance.new("Frame", scrollingFrame7)
        frame57.Size = UDim2.new(1, 0, 0, 28)
        frame57.BackgroundTransparency = 1
        local textButton58 = Instance.new("TextButton", frame57)
        textButton58.Size = UDim2.new(0.72, 0, 1, 0)
        textButton58.BackgroundTransparency = 1
        textButton58.Text = "Burbaloni Loliloli"
        textButton58.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton58.TextXAlignment = Enum.TextXAlignment.Left
        textButton58.Font = Enum.Font.Gotham
        textButton58.TextSize = 10
        local textButton59 = Instance.new("TextButton", frame57)
        textButton59.Size = UDim2.new(0, 16, 0, 16)
        textButton59.Position = UDim2.new(1, -20, 0.5, -8)
        textButton59.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton59.Text = ""
        local uICorner90 = Instance.new("UICorner", textButton59)
        uICorner90.CornerRadius = UDim.new(0, 3)
        local frame58 = Instance.new("Frame", scrollingFrame7)
        frame58.Size = UDim2.new(1, 0, 0, 26)
        frame58.BackgroundTransparency = 1
        frame58.Visible = false
        local uIGridLayout7 = Instance.new("UIGridLayout", frame58)
        uIGridLayout7.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout7.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton60 = Instance.new("TextButton", frame58)
        textButton60.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton60.Text = "Nor"
        textButton60.TextSize = 9
        textButton60.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton60.Font = Enum.Font.GothamBold
        local uICorner91 = Instance.new("UICorner", textButton60)
        local conn61 = textButton60.MouseButton1Click:Connect(function()
            textButton60.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton60.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton61 = Instance.new("TextButton", frame58)
        textButton61.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton61.Text = "Gol"
        textButton61.TextSize = 9
        textButton61.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton61.Font = Enum.Font.GothamBold
        local uICorner92 = Instance.new("UICorner", textButton61)
        local conn62 = textButton61.MouseButton1Click:Connect(function()
            textButton61.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton61.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton62 = Instance.new("TextButton", frame58)
        textButton62.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton62.Text = "Dia"
        textButton62.TextSize = 9
        textButton62.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton62.Font = Enum.Font.GothamBold
        local uICorner93 = Instance.new("UICorner", textButton62)
        local conn63 = textButton62.MouseButton1Click:Connect(function()
            textButton62.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton62.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton63 = Instance.new("TextButton", frame58)
        textButton63.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton63.Text = "Rai"
        textButton63.TextSize = 9
        textButton63.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton63.Font = Enum.Font.GothamBold
        local uICorner94 = Instance.new("UICorner", textButton63)
        local conn64 = textButton63.MouseButton1Click:Connect(function()
            textButton63.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton63.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton64 = Instance.new("TextButton", frame58)
        textButton64.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton64.Text = "Lav"
        textButton64.TextSize = 9
        textButton64.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton64.Font = Enum.Font.GothamBold
        local uICorner95 = Instance.new("UICorner", textButton64)
        local conn65 = textButton64.MouseButton1Click:Connect(function()
            textButton64.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton64.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn66 = textButton58.MouseButton1Click:Connect(function()
            frame58.Visible = true
        end)
        local conn67 = textButton59.MouseButton1Click:Connect(function()
            textButton59.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame59 = Instance.new("Frame", scrollingFrame7)
        frame59.Size = UDim2.new(1, 0, 0, 28)
        frame59.BackgroundTransparency = 1
        local textButton65 = Instance.new("TextButton", frame59)
        textButton65.Size = UDim2.new(0.72, 0, 1, 0)
        textButton65.BackgroundTransparency = 1
        textButton65.Text = "Boneca Ambalabu"
        textButton65.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton65.TextXAlignment = Enum.TextXAlignment.Left
        textButton65.Font = Enum.Font.Gotham
        textButton65.TextSize = 10
        local textButton66 = Instance.new("TextButton", frame59)
        textButton66.Size = UDim2.new(0, 16, 0, 16)
        textButton66.Position = UDim2.new(1, -20, 0.5, -8)
        textButton66.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton66.Text = ""
        local uICorner96 = Instance.new("UICorner", textButton66)
        uICorner96.CornerRadius = UDim.new(0, 3)
        local frame60 = Instance.new("Frame", scrollingFrame7)
        frame60.Size = UDim2.new(1, 0, 0, 26)
        frame60.BackgroundTransparency = 1
        frame60.Visible = false
        local uIGridLayout8 = Instance.new("UIGridLayout", frame60)
        uIGridLayout8.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout8.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton67 = Instance.new("TextButton", frame60)
        textButton67.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton67.Text = "Nor"
        textButton67.TextSize = 9
        textButton67.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton67.Font = Enum.Font.GothamBold
        local uICorner97 = Instance.new("UICorner", textButton67)
        local conn68 = textButton67.MouseButton1Click:Connect(function()
            textButton67.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton67.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton68 = Instance.new("TextButton", frame60)
        textButton68.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton68.Text = "Gol"
        textButton68.TextSize = 9
        textButton68.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton68.Font = Enum.Font.GothamBold
        local uICorner98 = Instance.new("UICorner", textButton68)
        local conn69 = textButton68.MouseButton1Click:Connect(function()
            textButton68.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton68.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton69 = Instance.new("TextButton", frame60)
        textButton69.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton69.Text = "Dia"
        textButton69.TextSize = 9
        textButton69.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton69.Font = Enum.Font.GothamBold
        local uICorner99 = Instance.new("UICorner", textButton69)
        local conn70 = textButton69.MouseButton1Click:Connect(function()
            textButton69.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton69.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton70 = Instance.new("TextButton", frame60)
        textButton70.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton70.Text = "Rai"
        textButton70.TextSize = 9
        textButton70.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton70.Font = Enum.Font.GothamBold
        local uICorner100 = Instance.new("UICorner", textButton70)
        local conn71 = textButton70.MouseButton1Click:Connect(function()
            textButton70.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton70.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton71 = Instance.new("TextButton", frame60)
        textButton71.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton71.Text = "Lav"
        textButton71.TextSize = 9
        textButton71.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton71.Font = Enum.Font.GothamBold
        local uICorner101 = Instance.new("UICorner", textButton71)
        local conn72 = textButton71.MouseButton1Click:Connect(function()
            textButton71.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton71.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn73 = textButton65.MouseButton1Click:Connect(function()
            frame60.Visible = true
        end)
        local conn74 = textButton66.MouseButton1Click:Connect(function()
            textButton66.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame61 = Instance.new("Frame", scrollingFrame7)
        frame61.Size = UDim2.new(1, 0, 0, 28)
        frame61.BackgroundTransparency = 1
        local textButton72 = Instance.new("TextButton", frame61)
        textButton72.Size = UDim2.new(0.72, 0, 1, 0)
        textButton72.BackgroundTransparency = 1
        textButton72.Text = "Trippi Troppi"
        textButton72.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton72.TextXAlignment = Enum.TextXAlignment.Left
        textButton72.Font = Enum.Font.Gotham
        textButton72.TextSize = 10
        local textButton73 = Instance.new("TextButton", frame61)
        textButton73.Size = UDim2.new(0, 16, 0, 16)
        textButton73.Position = UDim2.new(1, -20, 0.5, -8)
        textButton73.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton73.Text = ""
        local uICorner102 = Instance.new("UICorner", textButton73)
        uICorner102.CornerRadius = UDim.new(0, 3)
        local frame62 = Instance.new("Frame", scrollingFrame7)
        frame62.Size = UDim2.new(1, 0, 0, 26)
        frame62.BackgroundTransparency = 1
        frame62.Visible = false
        local uIGridLayout9 = Instance.new("UIGridLayout", frame62)
        uIGridLayout9.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout9.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton74 = Instance.new("TextButton", frame62)
        textButton74.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton74.Text = "Nor"
        textButton74.TextSize = 9
        textButton74.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton74.Font = Enum.Font.GothamBold
        local uICorner103 = Instance.new("UICorner", textButton74)
        local conn75 = textButton74.MouseButton1Click:Connect(function()
            textButton74.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton74.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton75 = Instance.new("TextButton", frame62)
        textButton75.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton75.Text = "Gol"
        textButton75.TextSize = 9
        textButton75.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton75.Font = Enum.Font.GothamBold
        local uICorner104 = Instance.new("UICorner", textButton75)
        local conn76 = textButton75.MouseButton1Click:Connect(function()
            textButton75.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton75.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton76 = Instance.new("TextButton", frame62)
        textButton76.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton76.Text = "Dia"
        textButton76.TextSize = 9
        textButton76.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton76.Font = Enum.Font.GothamBold
        local uICorner105 = Instance.new("UICorner", textButton76)
        local conn77 = textButton76.MouseButton1Click:Connect(function()
            textButton76.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton76.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton77 = Instance.new("TextButton", frame62)
        textButton77.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton77.Text = "Rai"
        textButton77.TextSize = 9
        textButton77.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton77.Font = Enum.Font.GothamBold
        local uICorner106 = Instance.new("UICorner", textButton77)
        local conn78 = textButton77.MouseButton1Click:Connect(function()
            textButton77.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton77.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton78 = Instance.new("TextButton", frame62)
        textButton78.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton78.Text = "Lav"
        textButton78.TextSize = 9
        textButton78.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton78.Font = Enum.Font.GothamBold
        local uICorner107 = Instance.new("UICorner", textButton78)
        local conn79 = textButton78.MouseButton1Click:Connect(function()
            textButton78.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton78.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn80 = textButton72.MouseButton1Click:Connect(function()
            frame62.Visible = true
        end)
        local conn81 = textButton73.MouseButton1Click:Connect(function()
            textButton73.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame63 = Instance.new("Frame", scrollingFrame7)
        frame63.Size = UDim2.new(1, 0, 0, 28)
        frame63.BackgroundTransparency = 1
        local textButton79 = Instance.new("TextButton", frame63)
        textButton79.Size = UDim2.new(0.72, 0, 1, 0)
        textButton79.BackgroundTransparency = 1
        textButton79.Text = "Svinina Bombardino"
        textButton79.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton79.TextXAlignment = Enum.TextXAlignment.Left
        textButton79.Font = Enum.Font.Gotham
        textButton79.TextSize = 10
        local textButton80 = Instance.new("TextButton", frame63)
        textButton80.Size = UDim2.new(0, 16, 0, 16)
        textButton80.Position = UDim2.new(1, -20, 0.5, -8)
        textButton80.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton80.Text = ""
        local uICorner108 = Instance.new("UICorner", textButton80)
        uICorner108.CornerRadius = UDim.new(0, 3)
        local frame64 = Instance.new("Frame", scrollingFrame7)
        frame64.Size = UDim2.new(1, 0, 0, 26)
        frame64.BackgroundTransparency = 1
        frame64.Visible = false
        local uIGridLayout10 = Instance.new("UIGridLayout", frame64)
        uIGridLayout10.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout10.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton81 = Instance.new("TextButton", frame64)
        textButton81.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton81.Text = "Nor"
        textButton81.TextSize = 9
        textButton81.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton81.Font = Enum.Font.GothamBold
        local uICorner109 = Instance.new("UICorner", textButton81)
        local conn82 = textButton81.MouseButton1Click:Connect(function()
            textButton81.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton81.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton82 = Instance.new("TextButton", frame64)
        textButton82.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton82.Text = "Gol"
        textButton82.TextSize = 9
        textButton82.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton82.Font = Enum.Font.GothamBold
        local uICorner110 = Instance.new("UICorner", textButton82)
        local conn83 = textButton82.MouseButton1Click:Connect(function()
            textButton82.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton82.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton83 = Instance.new("TextButton", frame64)
        textButton83.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton83.Text = "Dia"
        textButton83.TextSize = 9
        textButton83.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton83.Font = Enum.Font.GothamBold
        local uICorner111 = Instance.new("UICorner", textButton83)
        local conn84 = textButton83.MouseButton1Click:Connect(function()
            textButton83.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton83.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton84 = Instance.new("TextButton", frame64)
        textButton84.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton84.Text = "Rai"
        textButton84.TextSize = 9
        textButton84.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton84.Font = Enum.Font.GothamBold
        local uICorner112 = Instance.new("UICorner", textButton84)
        local conn85 = textButton84.MouseButton1Click:Connect(function()
            textButton84.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton84.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton85 = Instance.new("TextButton", frame64)
        textButton85.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton85.Text = "Lav"
        textButton85.TextSize = 9
        textButton85.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton85.Font = Enum.Font.GothamBold
        local uICorner113 = Instance.new("UICorner", textButton85)
        local conn86 = textButton85.MouseButton1Click:Connect(function()
            textButton85.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton85.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn87 = textButton79.MouseButton1Click:Connect(function()
            frame64.Visible = true
        end)
        local conn88 = textButton80.MouseButton1Click:Connect(function()
            textButton80.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame65 = Instance.new("Frame", scrollingFrame7)
        frame65.Size = UDim2.new(1, 0, 0, 28)
        frame65.BackgroundTransparency = 1
        local textButton86 = Instance.new("TextButton", frame65)
        textButton86.Size = UDim2.new(0.72, 0, 1, 0)
        textButton86.BackgroundTransparency = 1
        textButton86.Text = "Bambini Crostini"
        textButton86.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton86.TextXAlignment = Enum.TextXAlignment.Left
        textButton86.Font = Enum.Font.Gotham
        textButton86.TextSize = 10
        local textButton87 = Instance.new("TextButton", frame65)
        textButton87.Size = UDim2.new(0, 16, 0, 16)
        textButton87.Position = UDim2.new(1, -20, 0.5, -8)
        textButton87.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton87.Text = ""
        local uICorner114 = Instance.new("UICorner", textButton87)
        uICorner114.CornerRadius = UDim.new(0, 3)
        local frame66 = Instance.new("Frame", scrollingFrame7)
        frame66.Size = UDim2.new(1, 0, 0, 26)
        frame66.BackgroundTransparency = 1
        frame66.Visible = false
        local uIGridLayout11 = Instance.new("UIGridLayout", frame66)
        uIGridLayout11.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout11.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton88 = Instance.new("TextButton", frame66)
        textButton88.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton88.Text = "Nor"
        textButton88.TextSize = 9
        textButton88.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton88.Font = Enum.Font.GothamBold
        local uICorner115 = Instance.new("UICorner", textButton88)
        local conn89 = textButton88.MouseButton1Click:Connect(function()
            textButton88.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton88.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton89 = Instance.new("TextButton", frame66)
        textButton89.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton89.Text = "Gol"
        textButton89.TextSize = 9
        textButton89.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton89.Font = Enum.Font.GothamBold
        local uICorner116 = Instance.new("UICorner", textButton89)
        local conn90 = textButton89.MouseButton1Click:Connect(function()
            textButton89.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton89.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton90 = Instance.new("TextButton", frame66)
        textButton90.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton90.Text = "Dia"
        textButton90.TextSize = 9
        textButton90.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton90.Font = Enum.Font.GothamBold
        local uICorner117 = Instance.new("UICorner", textButton90)
        local conn91 = textButton90.MouseButton1Click:Connect(function()
            textButton90.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton90.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton91 = Instance.new("TextButton", frame66)
        textButton91.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton91.Text = "Rai"
        textButton91.TextSize = 9
        textButton91.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton91.Font = Enum.Font.GothamBold
        local uICorner118 = Instance.new("UICorner", textButton91)
        local conn92 = textButton91.MouseButton1Click:Connect(function()
            textButton91.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton91.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton92 = Instance.new("TextButton", frame66)
        textButton92.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton92.Text = "Lav"
        textButton92.TextSize = 9
        textButton92.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton92.Font = Enum.Font.GothamBold
        local uICorner119 = Instance.new("UICorner", textButton92)
        local conn93 = textButton92.MouseButton1Click:Connect(function()
            textButton92.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton92.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn94 = textButton86.MouseButton1Click:Connect(function()
            frame66.Visible = true
        end)
        local conn95 = textButton87.MouseButton1Click:Connect(function()
            textButton87.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame67 = Instance.new("Frame", scrollingFrame7)
        frame67.Size = UDim2.new(1, 0, 0, 28)
        frame67.BackgroundTransparency = 1
        local textButton93 = Instance.new("TextButton", frame67)
        textButton93.Size = UDim2.new(0.72, 0, 1, 0)
        textButton93.BackgroundTransparency = 1
        textButton93.Text = "Avocadini Guffo"
        textButton93.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton93.TextXAlignment = Enum.TextXAlignment.Left
        textButton93.Font = Enum.Font.Gotham
        textButton93.TextSize = 10
        local textButton94 = Instance.new("TextButton", frame67)
        textButton94.Size = UDim2.new(0, 16, 0, 16)
        textButton94.Position = UDim2.new(1, -20, 0.5, -8)
        textButton94.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton94.Text = ""
        local uICorner120 = Instance.new("UICorner", textButton94)
        uICorner120.CornerRadius = UDim.new(0, 3)
        local frame68 = Instance.new("Frame", scrollingFrame7)
        frame68.Size = UDim2.new(1, 0, 0, 26)
        frame68.BackgroundTransparency = 1
        frame68.Visible = false
        local uIGridLayout12 = Instance.new("UIGridLayout", frame68)
        uIGridLayout12.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout12.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton95 = Instance.new("TextButton", frame68)
        textButton95.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton95.Text = "Nor"
        textButton95.TextSize = 9
        textButton95.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton95.Font = Enum.Font.GothamBold
        local uICorner121 = Instance.new("UICorner", textButton95)
        local conn96 = textButton95.MouseButton1Click:Connect(function()
            textButton95.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton95.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton96 = Instance.new("TextButton", frame68)
        textButton96.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton96.Text = "Gol"
        textButton96.TextSize = 9
        textButton96.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton96.Font = Enum.Font.GothamBold
        local uICorner122 = Instance.new("UICorner", textButton96)
        local conn97 = textButton96.MouseButton1Click:Connect(function()
            textButton96.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton96.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton97 = Instance.new("TextButton", frame68)
        textButton97.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton97.Text = "Dia"
        textButton97.TextSize = 9
        textButton97.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton97.Font = Enum.Font.GothamBold
        local uICorner123 = Instance.new("UICorner", textButton97)
        local conn98 = textButton97.MouseButton1Click:Connect(function()
            textButton97.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton97.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton98 = Instance.new("TextButton", frame68)
        textButton98.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton98.Text = "Rai"
        textButton98.TextSize = 9
        textButton98.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton98.Font = Enum.Font.GothamBold
        local uICorner124 = Instance.new("UICorner", textButton98)
        local conn99 = textButton98.MouseButton1Click:Connect(function()
            textButton98.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton98.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton99 = Instance.new("TextButton", frame68)
        textButton99.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton99.Text = "Lav"
        textButton99.TextSize = 9
        textButton99.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton99.Font = Enum.Font.GothamBold
        local uICorner125 = Instance.new("UICorner", textButton99)
        local conn100 = textButton99.MouseButton1Click:Connect(function()
            textButton99.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton99.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn101 = textButton93.MouseButton1Click:Connect(function()
            frame68.Visible = true
        end)
        local conn102 = textButton94.MouseButton1Click:Connect(function()
            textButton94.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame69 = Instance.new("Frame", scrollingFrame7)
        frame69.Size = UDim2.new(1, 0, 0, 28)
        frame69.BackgroundTransparency = 1
        local textButton100 = Instance.new("TextButton", frame69)
        textButton100.Size = UDim2.new(0.72, 0, 1, 0)
        textButton100.BackgroundTransparency = 1
        textButton100.Text = "Bandito Bobrito"
        textButton100.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton100.TextXAlignment = Enum.TextXAlignment.Left
        textButton100.Font = Enum.Font.Gotham
        textButton100.TextSize = 10
        local textButton101 = Instance.new("TextButton", frame69)
        textButton101.Size = UDim2.new(0, 16, 0, 16)
        textButton101.Position = UDim2.new(1, -20, 0.5, -8)
        textButton101.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton101.Text = ""
        local uICorner126 = Instance.new("UICorner", textButton101)
        uICorner126.CornerRadius = UDim.new(0, 3)
        local frame70 = Instance.new("Frame", scrollingFrame7)
        frame70.Size = UDim2.new(1, 0, 0, 26)
        frame70.BackgroundTransparency = 1
        frame70.Visible = false
        local uIGridLayout13 = Instance.new("UIGridLayout", frame70)
        uIGridLayout13.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout13.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton102 = Instance.new("TextButton", frame70)
        textButton102.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton102.Text = "Nor"
        textButton102.TextSize = 9
        textButton102.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton102.Font = Enum.Font.GothamBold
        local uICorner127 = Instance.new("UICorner", textButton102)
        local conn103 = textButton102.MouseButton1Click:Connect(function()
            textButton102.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton102.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton103 = Instance.new("TextButton", frame70)
        textButton103.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton103.Text = "Gol"
        textButton103.TextSize = 9
        textButton103.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton103.Font = Enum.Font.GothamBold
        local uICorner128 = Instance.new("UICorner", textButton103)
        local conn104 = textButton103.MouseButton1Click:Connect(function()
            textButton103.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton103.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton104 = Instance.new("TextButton", frame70)
        textButton104.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton104.Text = "Dia"
        textButton104.TextSize = 9
        textButton104.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton104.Font = Enum.Font.GothamBold
        local uICorner129 = Instance.new("UICorner", textButton104)
        local conn105 = textButton104.MouseButton1Click:Connect(function()
            textButton104.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton104.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton105 = Instance.new("TextButton", frame70)
        textButton105.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton105.Text = "Rai"
        textButton105.TextSize = 9
        textButton105.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton105.Font = Enum.Font.GothamBold
        local uICorner130 = Instance.new("UICorner", textButton105)
        local conn106 = textButton105.MouseButton1Click:Connect(function()
            textButton105.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton105.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton106 = Instance.new("TextButton", frame70)
        textButton106.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton106.Text = "Lav"
        textButton106.TextSize = 9
        textButton106.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton106.Font = Enum.Font.GothamBold
        local uICorner131 = Instance.new("UICorner", textButton106)
        local conn107 = textButton106.MouseButton1Click:Connect(function()
            textButton106.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton106.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn108 = textButton100.MouseButton1Click:Connect(function()
            frame70.Visible = true
        end)
        local conn109 = textButton101.MouseButton1Click:Connect(function()
            textButton101.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame71 = Instance.new("Frame", scrollingFrame7)
        frame71.Size = UDim2.new(1, 0, 0, 28)
        frame71.BackgroundTransparency = 1
        local textButton107 = Instance.new("TextButton", frame71)
        textButton107.Size = UDim2.new(0.72, 0, 1, 0)
        textButton107.BackgroundTransparency = 1
        textButton107.Text = "Tatatata Sahur"
        textButton107.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton107.TextXAlignment = Enum.TextXAlignment.Left
        textButton107.Font = Enum.Font.Gotham
        textButton107.TextSize = 10
        local textButton108 = Instance.new("TextButton", frame71)
        textButton108.Size = UDim2.new(0, 16, 0, 16)
        textButton108.Position = UDim2.new(1, -20, 0.5, -8)
        textButton108.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton108.Text = ""
        local uICorner132 = Instance.new("UICorner", textButton108)
        uICorner132.CornerRadius = UDim.new(0, 3)
        local frame72 = Instance.new("Frame", scrollingFrame7)
        frame72.Size = UDim2.new(1, 0, 0, 26)
        frame72.BackgroundTransparency = 1
        frame72.Visible = false
        local uIGridLayout14 = Instance.new("UIGridLayout", frame72)
        uIGridLayout14.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout14.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton109 = Instance.new("TextButton", frame72)
        textButton109.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton109.Text = "Nor"
        textButton109.TextSize = 9
        textButton109.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton109.Font = Enum.Font.GothamBold
        local uICorner133 = Instance.new("UICorner", textButton109)
        local conn110 = textButton109.MouseButton1Click:Connect(function()
            textButton109.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton109.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton110 = Instance.new("TextButton", frame72)
        textButton110.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton110.Text = "Gol"
        textButton110.TextSize = 9
        textButton110.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton110.Font = Enum.Font.GothamBold
        local uICorner134 = Instance.new("UICorner", textButton110)
        local conn111 = textButton110.MouseButton1Click:Connect(function()
            textButton110.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton110.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton111 = Instance.new("TextButton", frame72)
        textButton111.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton111.Text = "Dia"
        textButton111.TextSize = 9
        textButton111.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton111.Font = Enum.Font.GothamBold
        local uICorner135 = Instance.new("UICorner", textButton111)
        local conn112 = textButton111.MouseButton1Click:Connect(function()
            textButton111.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton111.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton112 = Instance.new("TextButton", frame72)
        textButton112.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton112.Text = "Rai"
        textButton112.TextSize = 9
        textButton112.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton112.Font = Enum.Font.GothamBold
        local uICorner136 = Instance.new("UICorner", textButton112)
        local conn113 = textButton112.MouseButton1Click:Connect(function()
            textButton112.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton112.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton113 = Instance.new("TextButton", frame72)
        textButton113.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton113.Text = "Lav"
        textButton113.TextSize = 9
        textButton113.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton113.Font = Enum.Font.GothamBold
        local uICorner137 = Instance.new("UICorner", textButton113)
        local conn114 = textButton113.MouseButton1Click:Connect(function()
            textButton113.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton113.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn115 = textButton107.MouseButton1Click:Connect(function()
            frame72.Visible = true
        end)
        local conn116 = textButton108.MouseButton1Click:Connect(function()
            textButton108.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame73 = Instance.new("Frame", scrollingFrame7)
        frame73.Size = UDim2.new(1, 0, 0, 28)
        frame73.BackgroundTransparency = 1
        local textButton114 = Instance.new("TextButton", frame73)
        textButton114.Size = UDim2.new(0.72, 0, 1, 0)
        textButton114.BackgroundTransparency = 1
        textButton114.Text = "Gangster Footera"
        textButton114.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton114.TextXAlignment = Enum.TextXAlignment.Left
        textButton114.Font = Enum.Font.Gotham
        textButton114.TextSize = 10
        local textButton115 = Instance.new("TextButton", frame73)
        textButton115.Size = UDim2.new(0, 16, 0, 16)
        textButton115.Position = UDim2.new(1, -20, 0.5, -8)
        textButton115.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton115.Text = ""
        local uICorner138 = Instance.new("UICorner", textButton115)
        uICorner138.CornerRadius = UDim.new(0, 3)
        local frame74 = Instance.new("Frame", scrollingFrame7)
        frame74.Size = UDim2.new(1, 0, 0, 26)
        frame74.BackgroundTransparency = 1
        frame74.Visible = false
        local uIGridLayout15 = Instance.new("UIGridLayout", frame74)
        uIGridLayout15.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout15.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton116 = Instance.new("TextButton", frame74)
        textButton116.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton116.Text = "Nor"
        textButton116.TextSize = 9
        textButton116.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton116.Font = Enum.Font.GothamBold
        local uICorner139 = Instance.new("UICorner", textButton116)
        local conn117 = textButton116.MouseButton1Click:Connect(function()
            textButton116.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton116.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton117 = Instance.new("TextButton", frame74)
        textButton117.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton117.Text = "Gol"
        textButton117.TextSize = 9
        textButton117.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton117.Font = Enum.Font.GothamBold
        local uICorner140 = Instance.new("UICorner", textButton117)
        local conn118 = textButton117.MouseButton1Click:Connect(function()
            textButton117.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton117.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton118 = Instance.new("TextButton", frame74)
        textButton118.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton118.Text = "Dia"
        textButton118.TextSize = 9
        textButton118.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton118.Font = Enum.Font.GothamBold
        local uICorner141 = Instance.new("UICorner", textButton118)
        local conn119 = textButton118.MouseButton1Click:Connect(function()
            textButton118.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton118.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton119 = Instance.new("TextButton", frame74)
        textButton119.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton119.Text = "Rai"
        textButton119.TextSize = 9
        textButton119.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton119.Font = Enum.Font.GothamBold
        local uICorner142 = Instance.new("UICorner", textButton119)
        local conn120 = textButton119.MouseButton1Click:Connect(function()
            textButton119.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton119.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton120 = Instance.new("TextButton", frame74)
        textButton120.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton120.Text = "Lav"
        textButton120.TextSize = 9
        textButton120.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton120.Font = Enum.Font.GothamBold
        local uICorner143 = Instance.new("UICorner", textButton120)
        local conn121 = textButton120.MouseButton1Click:Connect(function()
            textButton120.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton120.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn122 = textButton114.MouseButton1Click:Connect(function()
            frame74.Visible = true
        end)
        local conn123 = textButton115.MouseButton1Click:Connect(function()
            textButton115.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame75 = Instance.new("Frame", scrollingFrame7)
        frame75.Size = UDim2.new(1, 0, 0, 28)
        frame75.BackgroundTransparency = 1
        local textButton121 = Instance.new("TextButton", frame75)
        textButton121.Size = UDim2.new(0.72, 0, 1, 0)
        textButton121.BackgroundTransparency = 1
        textButton121.Text = "Tung Tung Sahur"
        textButton121.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton121.TextXAlignment = Enum.TextXAlignment.Left
        textButton121.Font = Enum.Font.Gotham
        textButton121.TextSize = 10
        local textButton122 = Instance.new("TextButton", frame75)
        textButton122.Size = UDim2.new(0, 16, 0, 16)
        textButton122.Position = UDim2.new(1, -20, 0.5, -8)
        textButton122.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton122.Text = ""
        local uICorner144 = Instance.new("UICorner", textButton122)
        uICorner144.CornerRadius = UDim.new(0, 3)
        local frame76 = Instance.new("Frame", scrollingFrame7)
        frame76.Size = UDim2.new(1, 0, 0, 26)
        frame76.BackgroundTransparency = 1
        frame76.Visible = false
        local uIGridLayout16 = Instance.new("UIGridLayout", frame76)
        uIGridLayout16.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout16.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton123 = Instance.new("TextButton", frame76)
        textButton123.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton123.Text = "Nor"
        textButton123.TextSize = 9
        textButton123.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton123.Font = Enum.Font.GothamBold
        local uICorner145 = Instance.new("UICorner", textButton123)
        local conn124 = textButton123.MouseButton1Click:Connect(function()
            textButton123.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton123.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton124 = Instance.new("TextButton", frame76)
        textButton124.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton124.Text = "Gol"
        textButton124.TextSize = 9
        textButton124.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton124.Font = Enum.Font.GothamBold
        local uICorner146 = Instance.new("UICorner", textButton124)
        local conn125 = textButton124.MouseButton1Click:Connect(function()
            textButton124.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton124.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton125 = Instance.new("TextButton", frame76)
        textButton125.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton125.Text = "Dia"
        textButton125.TextSize = 9
        textButton125.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton125.Font = Enum.Font.GothamBold
        local uICorner147 = Instance.new("UICorner", textButton125)
        local conn126 = textButton125.MouseButton1Click:Connect(function()
            textButton125.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton125.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton126 = Instance.new("TextButton", frame76)
        textButton126.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton126.Text = "Rai"
        textButton126.TextSize = 9
        textButton126.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton126.Font = Enum.Font.GothamBold
        local uICorner148 = Instance.new("UICorner", textButton126)
        local conn127 = textButton126.MouseButton1Click:Connect(function()
            textButton126.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton126.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton127 = Instance.new("TextButton", frame76)
        textButton127.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton127.Text = "Lav"
        textButton127.TextSize = 9
        textButton127.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton127.Font = Enum.Font.GothamBold
        local uICorner149 = Instance.new("UICorner", textButton127)
        local conn128 = textButton127.MouseButton1Click:Connect(function()
            textButton127.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton127.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn129 = textButton121.MouseButton1Click:Connect(function()
            frame76.Visible = true
        end)
        local conn130 = textButton122.MouseButton1Click:Connect(function()
            textButton122.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame77 = Instance.new("Frame", scrollingFrame7)
        frame77.Size = UDim2.new(1, 0, 0, 28)
        frame77.BackgroundTransparency = 1
        local textButton128 = Instance.new("TextButton", frame77)
        textButton128.Size = UDim2.new(0.72, 0, 1, 0)
        textButton128.BackgroundTransparency = 1
        textButton128.Text = "Cappuccino Assassino"
        textButton128.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton128.TextXAlignment = Enum.TextXAlignment.Left
        textButton128.Font = Enum.Font.Gotham
        textButton128.TextSize = 10
        local textButton129 = Instance.new("TextButton", frame77)
        textButton129.Size = UDim2.new(0, 16, 0, 16)
        textButton129.Position = UDim2.new(1, -20, 0.5, -8)
        textButton129.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton129.Text = ""
        local uICorner150 = Instance.new("UICorner", textButton129)
        uICorner150.CornerRadius = UDim.new(0, 3)
        local frame78 = Instance.new("Frame", scrollingFrame7)
        frame78.Size = UDim2.new(1, 0, 0, 26)
        frame78.BackgroundTransparency = 1
        frame78.Visible = false
        local uIGridLayout17 = Instance.new("UIGridLayout", frame78)
        uIGridLayout17.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout17.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton130 = Instance.new("TextButton", frame78)
        textButton130.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton130.Text = "Nor"
        textButton130.TextSize = 9
        textButton130.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton130.Font = Enum.Font.GothamBold
        local uICorner151 = Instance.new("UICorner", textButton130)
        local conn131 = textButton130.MouseButton1Click:Connect(function()
            textButton130.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton130.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton131 = Instance.new("TextButton", frame78)
        textButton131.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton131.Text = "Gol"
        textButton131.TextSize = 9
        textButton131.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton131.Font = Enum.Font.GothamBold
        local uICorner152 = Instance.new("UICorner", textButton131)
        local conn132 = textButton131.MouseButton1Click:Connect(function()
            textButton131.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton131.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton132 = Instance.new("TextButton", frame78)
        textButton132.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton132.Text = "Dia"
        textButton132.TextSize = 9
        textButton132.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton132.Font = Enum.Font.GothamBold
        local uICorner153 = Instance.new("UICorner", textButton132)
        local conn133 = textButton132.MouseButton1Click:Connect(function()
            textButton132.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton132.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton133 = Instance.new("TextButton", frame78)
        textButton133.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton133.Text = "Rai"
        textButton133.TextSize = 9
        textButton133.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton133.Font = Enum.Font.GothamBold
        local uICorner154 = Instance.new("UICorner", textButton133)
        local conn134 = textButton133.MouseButton1Click:Connect(function()
            textButton133.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton133.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton134 = Instance.new("TextButton", frame78)
        textButton134.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton134.Text = "Lav"
        textButton134.TextSize = 9
        textButton134.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton134.Font = Enum.Font.GothamBold
        local uICorner155 = Instance.new("UICorner", textButton134)
        local conn135 = textButton134.MouseButton1Click:Connect(function()
            textButton134.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton134.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn136 = textButton128.MouseButton1Click:Connect(function()
            frame78.Visible = true
        end)
        local conn137 = textButton129.MouseButton1Click:Connect(function()
            textButton129.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame79 = Instance.new("Frame", scrollingFrame7)
        frame79.Size = UDim2.new(1, 0, 0, 28)
        frame79.BackgroundTransparency = 1
        local textButton135 = Instance.new("TextButton", frame79)
        textButton135.Size = UDim2.new(0.72, 0, 1, 0)
        textButton135.BackgroundTransparency = 1
        textButton135.Text = "Pipi Kiwi"
        textButton135.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton135.TextXAlignment = Enum.TextXAlignment.Left
        textButton135.Font = Enum.Font.Gotham
        textButton135.TextSize = 10
        local textButton136 = Instance.new("TextButton", frame79)
        textButton136.Size = UDim2.new(0, 16, 0, 16)
        textButton136.Position = UDim2.new(1, -20, 0.5, -8)
        textButton136.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton136.Text = ""
        local uICorner156 = Instance.new("UICorner", textButton136)
        uICorner156.CornerRadius = UDim.new(0, 3)
        local frame80 = Instance.new("Frame", scrollingFrame7)
        frame80.Size = UDim2.new(1, 0, 0, 26)
        frame80.BackgroundTransparency = 1
        frame80.Visible = false
        local uIGridLayout18 = Instance.new("UIGridLayout", frame80)
        uIGridLayout18.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout18.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton137 = Instance.new("TextButton", frame80)
        textButton137.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton137.Text = "Nor"
        textButton137.TextSize = 9
        textButton137.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton137.Font = Enum.Font.GothamBold
        local uICorner157 = Instance.new("UICorner", textButton137)
        local conn138 = textButton137.MouseButton1Click:Connect(function()
            textButton137.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton137.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton138 = Instance.new("TextButton", frame80)
        textButton138.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton138.Text = "Gol"
        textButton138.TextSize = 9
        textButton138.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton138.Font = Enum.Font.GothamBold
        local uICorner158 = Instance.new("UICorner", textButton138)
        local conn139 = textButton138.MouseButton1Click:Connect(function()
            textButton138.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton138.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton139 = Instance.new("TextButton", frame80)
        textButton139.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton139.Text = "Dia"
        textButton139.TextSize = 9
        textButton139.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton139.Font = Enum.Font.GothamBold
        local uICorner159 = Instance.new("UICorner", textButton139)
        local conn140 = textButton139.MouseButton1Click:Connect(function()
            textButton139.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton139.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton140 = Instance.new("TextButton", frame80)
        textButton140.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton140.Text = "Rai"
        textButton140.TextSize = 9
        textButton140.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton140.Font = Enum.Font.GothamBold
        local uICorner160 = Instance.new("UICorner", textButton140)
        local conn141 = textButton140.MouseButton1Click:Connect(function()
            textButton140.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton140.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton141 = Instance.new("TextButton", frame80)
        textButton141.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton141.Text = "Lav"
        textButton141.TextSize = 9
        textButton141.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton141.Font = Enum.Font.GothamBold
        local uICorner161 = Instance.new("UICorner", textButton141)
        local conn142 = textButton141.MouseButton1Click:Connect(function()
            textButton141.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton141.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn143 = textButton135.MouseButton1Click:Connect(function()
            frame80.Visible = true
        end)
        local conn144 = textButton136.MouseButton1Click:Connect(function()
            textButton136.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame81 = Instance.new("Frame", scrollingFrame7)
        frame81.Size = UDim2.new(1, 0, 0, 28)
        frame81.BackgroundTransparency = 1
        local textButton142 = Instance.new("TextButton", frame81)
        textButton142.Size = UDim2.new(0.72, 0, 1, 0)
        textButton142.BackgroundTransparency = 1
        textButton142.Text = "Orangutini Ananassini"
        textButton142.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton142.TextXAlignment = Enum.TextXAlignment.Left
        textButton142.Font = Enum.Font.Gotham
        textButton142.TextSize = 10
        local textButton143 = Instance.new("TextButton", frame81)
        textButton143.Size = UDim2.new(0, 16, 0, 16)
        textButton143.Position = UDim2.new(1, -20, 0.5, -8)
        textButton143.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton143.Text = ""
        local uICorner162 = Instance.new("UICorner", textButton143)
        uICorner162.CornerRadius = UDim.new(0, 3)
        local frame82 = Instance.new("Frame", scrollingFrame7)
        frame82.Size = UDim2.new(1, 0, 0, 26)
        frame82.BackgroundTransparency = 1
        frame82.Visible = false
        local uIGridLayout19 = Instance.new("UIGridLayout", frame82)
        uIGridLayout19.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout19.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton144 = Instance.new("TextButton", frame82)
        textButton144.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton144.Text = "Nor"
        textButton144.TextSize = 9
        textButton144.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton144.Font = Enum.Font.GothamBold
        local uICorner163 = Instance.new("UICorner", textButton144)
        local conn145 = textButton144.MouseButton1Click:Connect(function()
            textButton144.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton144.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton145 = Instance.new("TextButton", frame82)
        textButton145.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton145.Text = "Gol"
        textButton145.TextSize = 9
        textButton145.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton145.Font = Enum.Font.GothamBold
        local uICorner164 = Instance.new("UICorner", textButton145)
        local conn146 = textButton145.MouseButton1Click:Connect(function()
            textButton145.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton145.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton146 = Instance.new("TextButton", frame82)
        textButton146.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton146.Text = "Dia"
        textButton146.TextSize = 9
        textButton146.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton146.Font = Enum.Font.GothamBold
        local uICorner165 = Instance.new("UICorner", textButton146)
        local conn147 = textButton146.MouseButton1Click:Connect(function()
            textButton146.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton146.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton147 = Instance.new("TextButton", frame82)
        textButton147.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton147.Text = "Rai"
        textButton147.TextSize = 9
        textButton147.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton147.Font = Enum.Font.GothamBold
        local uICorner166 = Instance.new("UICorner", textButton147)
        local conn148 = textButton147.MouseButton1Click:Connect(function()
            textButton147.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton147.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton148 = Instance.new("TextButton", frame82)
        textButton148.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton148.Text = "Lav"
        textButton148.TextSize = 9
        textButton148.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton148.Font = Enum.Font.GothamBold
        local uICorner167 = Instance.new("UICorner", textButton148)
        local conn149 = textButton148.MouseButton1Click:Connect(function()
            textButton148.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton148.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn150 = textButton142.MouseButton1Click:Connect(function()
            frame82.Visible = true
        end)
        local conn151 = textButton143.MouseButton1Click:Connect(function()
            textButton143.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame83 = Instance.new("Frame", scrollingFrame7)
        frame83.Size = UDim2.new(1, 0, 0, 28)
        frame83.BackgroundTransparency = 1
        local textButton149 = Instance.new("TextButton", frame83)
        textButton149.Size = UDim2.new(0.72, 0, 1, 0)
        textButton149.BackgroundTransparency = 1
        textButton149.Text = "Talpa Di Fero"
        textButton149.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton149.TextXAlignment = Enum.TextXAlignment.Left
        textButton149.Font = Enum.Font.Gotham
        textButton149.TextSize = 10
        local textButton150 = Instance.new("TextButton", frame83)
        textButton150.Size = UDim2.new(0, 16, 0, 16)
        textButton150.Position = UDim2.new(1, -20, 0.5, -8)
        textButton150.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton150.Text = ""
        local uICorner168 = Instance.new("UICorner", textButton150)
        uICorner168.CornerRadius = UDim.new(0, 3)
        local frame84 = Instance.new("Frame", scrollingFrame7)
        frame84.Size = UDim2.new(1, 0, 0, 26)
        frame84.BackgroundTransparency = 1
        frame84.Visible = false
        local uIGridLayout20 = Instance.new("UIGridLayout", frame84)
        uIGridLayout20.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout20.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton151 = Instance.new("TextButton", frame84)
        textButton151.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton151.Text = "Nor"
        textButton151.TextSize = 9
        textButton151.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton151.Font = Enum.Font.GothamBold
        local uICorner169 = Instance.new("UICorner", textButton151)
        local conn152 = textButton151.MouseButton1Click:Connect(function()
            textButton151.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton151.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton152 = Instance.new("TextButton", frame84)
        textButton152.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton152.Text = "Gol"
        textButton152.TextSize = 9
        textButton152.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton152.Font = Enum.Font.GothamBold
        local uICorner170 = Instance.new("UICorner", textButton152)
        local conn153 = textButton152.MouseButton1Click:Connect(function()
            textButton152.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton152.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton153 = Instance.new("TextButton", frame84)
        textButton153.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton153.Text = "Dia"
        textButton153.TextSize = 9
        textButton153.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton153.Font = Enum.Font.GothamBold
        local uICorner171 = Instance.new("UICorner", textButton153)
        local conn154 = textButton153.MouseButton1Click:Connect(function()
            textButton153.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton153.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton154 = Instance.new("TextButton", frame84)
        textButton154.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton154.Text = "Rai"
        textButton154.TextSize = 9
        textButton154.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton154.Font = Enum.Font.GothamBold
        local uICorner172 = Instance.new("UICorner", textButton154)
        local conn155 = textButton154.MouseButton1Click:Connect(function()
            textButton154.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton154.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton155 = Instance.new("TextButton", frame84)
        textButton155.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton155.Text = "Lav"
        textButton155.TextSize = 9
        textButton155.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton155.Font = Enum.Font.GothamBold
        local uICorner173 = Instance.new("UICorner", textButton155)
        local conn156 = textButton155.MouseButton1Click:Connect(function()
            textButton155.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton155.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn157 = textButton149.MouseButton1Click:Connect(function()
            frame84.Visible = true
        end)
        local conn158 = textButton150.MouseButton1Click:Connect(function()
            textButton150.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame85 = Instance.new("Frame", scrollingFrame7)
        frame85.Size = UDim2.new(1, 0, 0, 28)
        frame85.BackgroundTransparency = 1
        local textButton156 = Instance.new("TextButton", frame85)
        textButton156.Size = UDim2.new(0.72, 0, 1, 0)
        textButton156.BackgroundTransparency = 1
        textButton156.Text = "Espresso Signora"
        textButton156.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton156.TextXAlignment = Enum.TextXAlignment.Left
        textButton156.Font = Enum.Font.Gotham
        textButton156.TextSize = 10
        local textButton157 = Instance.new("TextButton", frame85)
        textButton157.Size = UDim2.new(0, 16, 0, 16)
        textButton157.Position = UDim2.new(1, -20, 0.5, -8)
        textButton157.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton157.Text = ""
        local uICorner174 = Instance.new("UICorner", textButton157)
        uICorner174.CornerRadius = UDim.new(0, 3)
        local frame86 = Instance.new("Frame", scrollingFrame7)
        frame86.Size = UDim2.new(1, 0, 0, 26)
        frame86.BackgroundTransparency = 1
        frame86.Visible = false
        local uIGridLayout21 = Instance.new("UIGridLayout", frame86)
        uIGridLayout21.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout21.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton158 = Instance.new("TextButton", frame86)
        textButton158.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton158.Text = "Nor"
        textButton158.TextSize = 9
        textButton158.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton158.Font = Enum.Font.GothamBold
        local uICorner175 = Instance.new("UICorner", textButton158)
        local conn159 = textButton158.MouseButton1Click:Connect(function()
            textButton158.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton158.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton159 = Instance.new("TextButton", frame86)
        textButton159.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton159.Text = "Gol"
        textButton159.TextSize = 9
        textButton159.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton159.Font = Enum.Font.GothamBold
        local uICorner176 = Instance.new("UICorner", textButton159)
        local conn160 = textButton159.MouseButton1Click:Connect(function()
            textButton159.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton159.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton160 = Instance.new("TextButton", frame86)
        textButton160.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton160.Text = "Dia"
        textButton160.TextSize = 9
        textButton160.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton160.Font = Enum.Font.GothamBold
        local uICorner177 = Instance.new("UICorner", textButton160)
        local conn161 = textButton160.MouseButton1Click:Connect(function()
            textButton160.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton160.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton161 = Instance.new("TextButton", frame86)
        textButton161.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton161.Text = "Rai"
        textButton161.TextSize = 9
        textButton161.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton161.Font = Enum.Font.GothamBold
        local uICorner178 = Instance.new("UICorner", textButton161)
        local conn162 = textButton161.MouseButton1Click:Connect(function()
            textButton161.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton161.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton162 = Instance.new("TextButton", frame86)
        textButton162.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton162.Text = "Lav"
        textButton162.TextSize = 9
        textButton162.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton162.Font = Enum.Font.GothamBold
        local uICorner179 = Instance.new("UICorner", textButton162)
        local conn163 = textButton162.MouseButton1Click:Connect(function()
            textButton162.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton162.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn164 = textButton156.MouseButton1Click:Connect(function()
            frame86.Visible = true
        end)
        local conn165 = textButton157.MouseButton1Click:Connect(function()
            textButton157.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame87 = Instance.new("Frame", scrollingFrame7)
        frame87.Size = UDim2.new(1, 0, 0, 28)
        frame87.BackgroundTransparency = 1
        local textButton163 = Instance.new("TextButton", frame87)
        textButton163.Size = UDim2.new(0.72, 0, 1, 0)
        textButton163.BackgroundTransparency = 1
        textButton163.Text = "Brr Brr Patapim"
        textButton163.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton163.TextXAlignment = Enum.TextXAlignment.Left
        textButton163.Font = Enum.Font.Gotham
        textButton163.TextSize = 10
        local textButton164 = Instance.new("TextButton", frame87)
        textButton164.Size = UDim2.new(0, 16, 0, 16)
        textButton164.Position = UDim2.new(1, -20, 0.5, -8)
        textButton164.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton164.Text = ""
        local uICorner180 = Instance.new("UICorner", textButton164)
        uICorner180.CornerRadius = UDim.new(0, 3)
        local frame88 = Instance.new("Frame", scrollingFrame7)
        frame88.Size = UDim2.new(1, 0, 0, 26)
        frame88.BackgroundTransparency = 1
        frame88.Visible = false
        local uIGridLayout22 = Instance.new("UIGridLayout", frame88)
        uIGridLayout22.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout22.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton165 = Instance.new("TextButton", frame88)
        textButton165.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton165.Text = "Nor"
        textButton165.TextSize = 9
        textButton165.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton165.Font = Enum.Font.GothamBold
        local uICorner181 = Instance.new("UICorner", textButton165)
        local conn166 = textButton165.MouseButton1Click:Connect(function()
            textButton165.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton165.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton166 = Instance.new("TextButton", frame88)
        textButton166.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton166.Text = "Gol"
        textButton166.TextSize = 9
        textButton166.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton166.Font = Enum.Font.GothamBold
        local uICorner182 = Instance.new("UICorner", textButton166)
        local conn167 = textButton166.MouseButton1Click:Connect(function()
            textButton166.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton166.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton167 = Instance.new("TextButton", frame88)
        textButton167.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton167.Text = "Dia"
        textButton167.TextSize = 9
        textButton167.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton167.Font = Enum.Font.GothamBold
        local uICorner183 = Instance.new("UICorner", textButton167)
        local conn168 = textButton167.MouseButton1Click:Connect(function()
            textButton167.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton167.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton168 = Instance.new("TextButton", frame88)
        textButton168.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton168.Text = "Rai"
        textButton168.TextSize = 9
        textButton168.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton168.Font = Enum.Font.GothamBold
        local uICorner184 = Instance.new("UICorner", textButton168)
        local conn169 = textButton168.MouseButton1Click:Connect(function()
            textButton168.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton168.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton169 = Instance.new("TextButton", frame88)
        textButton169.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton169.Text = "Lav"
        textButton169.TextSize = 9
        textButton169.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton169.Font = Enum.Font.GothamBold
        local uICorner185 = Instance.new("UICorner", textButton169)
        local conn170 = textButton169.MouseButton1Click:Connect(function()
            textButton169.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton169.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn171 = textButton163.MouseButton1Click:Connect(function()
            frame88.Visible = true
        end)
        local conn172 = textButton164.MouseButton1Click:Connect(function()
            textButton164.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame89 = Instance.new("Frame", scrollingFrame7)
        frame89.Size = UDim2.new(1, 0, 0, 28)
        frame89.BackgroundTransparency = 1
        local textButton170 = Instance.new("TextButton", frame89)
        textButton170.Size = UDim2.new(0.72, 0, 1, 0)
        textButton170.BackgroundTransparency = 1
        textButton170.Text = "Rhino Toasterino"
        textButton170.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton170.TextXAlignment = Enum.TextXAlignment.Left
        textButton170.Font = Enum.Font.Gotham
        textButton170.TextSize = 10
        local textButton171 = Instance.new("TextButton", frame89)
        textButton171.Size = UDim2.new(0, 16, 0, 16)
        textButton171.Position = UDim2.new(1, -20, 0.5, -8)
        textButton171.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton171.Text = ""
        local uICorner186 = Instance.new("UICorner", textButton171)
        uICorner186.CornerRadius = UDim.new(0, 3)
        local frame90 = Instance.new("Frame", scrollingFrame7)
        frame90.Size = UDim2.new(1, 0, 0, 26)
        frame90.BackgroundTransparency = 1
        frame90.Visible = false
        local uIGridLayout23 = Instance.new("UIGridLayout", frame90)
        uIGridLayout23.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout23.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton172 = Instance.new("TextButton", frame90)
        textButton172.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton172.Text = "Nor"
        textButton172.TextSize = 9
        textButton172.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton172.Font = Enum.Font.GothamBold
        local uICorner187 = Instance.new("UICorner", textButton172)
        local conn173 = textButton172.MouseButton1Click:Connect(function()
            textButton172.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton172.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton173 = Instance.new("TextButton", frame90)
        textButton173.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton173.Text = "Gol"
        textButton173.TextSize = 9
        textButton173.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton173.Font = Enum.Font.GothamBold
        local uICorner188 = Instance.new("UICorner", textButton173)
        local conn174 = textButton173.MouseButton1Click:Connect(function()
            textButton173.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton173.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton174 = Instance.new("TextButton", frame90)
        textButton174.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton174.Text = "Dia"
        textButton174.TextSize = 9
        textButton174.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton174.Font = Enum.Font.GothamBold
        local uICorner189 = Instance.new("UICorner", textButton174)
        local conn175 = textButton174.MouseButton1Click:Connect(function()
            textButton174.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton174.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton175 = Instance.new("TextButton", frame90)
        textButton175.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton175.Text = "Rai"
        textButton175.TextSize = 9
        textButton175.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton175.Font = Enum.Font.GothamBold
        local uICorner190 = Instance.new("UICorner", textButton175)
        local conn176 = textButton175.MouseButton1Click:Connect(function()
            textButton175.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton175.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton176 = Instance.new("TextButton", frame90)
        textButton176.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton176.Text = "Lav"
        textButton176.TextSize = 9
        textButton176.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton176.Font = Enum.Font.GothamBold
        local uICorner191 = Instance.new("UICorner", textButton176)
        local conn177 = textButton176.MouseButton1Click:Connect(function()
            textButton176.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton176.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn178 = textButton170.MouseButton1Click:Connect(function()
            frame90.Visible = true
        end)
        local conn179 = textButton171.MouseButton1Click:Connect(function()
            textButton171.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame91 = Instance.new("Frame", scrollingFrame7)
        frame91.Size = UDim2.new(1, 0, 0, 28)
        frame91.BackgroundTransparency = 1
        local textButton177 = Instance.new("TextButton", frame91)
        textButton177.Size = UDim2.new(0.72, 0, 1, 0)
        textButton177.BackgroundTransparency = 1
        textButton177.Text = "Brr Bicus Dicus"
        textButton177.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton177.TextXAlignment = Enum.TextXAlignment.Left
        textButton177.Font = Enum.Font.Gotham
        textButton177.TextSize = 10
        local textButton178 = Instance.new("TextButton", frame91)
        textButton178.Size = UDim2.new(0, 16, 0, 16)
        textButton178.Position = UDim2.new(1, -20, 0.5, -8)
        textButton178.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton178.Text = ""
        local uICorner192 = Instance.new("UICorner", textButton178)
        uICorner192.CornerRadius = UDim.new(0, 3)
        local frame92 = Instance.new("Frame", scrollingFrame7)
        frame92.Size = UDim2.new(1, 0, 0, 26)
        frame92.BackgroundTransparency = 1
        frame92.Visible = false
        local uIGridLayout24 = Instance.new("UIGridLayout", frame92)
        uIGridLayout24.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout24.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton179 = Instance.new("TextButton", frame92)
        textButton179.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton179.Text = "Nor"
        textButton179.TextSize = 9
        textButton179.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton179.Font = Enum.Font.GothamBold
        local uICorner193 = Instance.new("UICorner", textButton179)
        local conn180 = textButton179.MouseButton1Click:Connect(function()
            textButton179.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton179.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton180 = Instance.new("TextButton", frame92)
        textButton180.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton180.Text = "Gol"
        textButton180.TextSize = 9
        textButton180.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton180.Font = Enum.Font.GothamBold
        local uICorner194 = Instance.new("UICorner", textButton180)
        local conn181 = textButton180.MouseButton1Click:Connect(function()
            textButton180.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton180.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton181 = Instance.new("TextButton", frame92)
        textButton181.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton181.Text = "Dia"
        textButton181.TextSize = 9
        textButton181.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton181.Font = Enum.Font.GothamBold
        local uICorner195 = Instance.new("UICorner", textButton181)
        local conn182 = textButton181.MouseButton1Click:Connect(function()
            textButton181.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton181.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton182 = Instance.new("TextButton", frame92)
        textButton182.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton182.Text = "Rai"
        textButton182.TextSize = 9
        textButton182.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton182.Font = Enum.Font.GothamBold
        local uICorner196 = Instance.new("UICorner", textButton182)
        local conn183 = textButton182.MouseButton1Click:Connect(function()
            textButton182.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton182.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton183 = Instance.new("TextButton", frame92)
        textButton183.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton183.Text = "Lav"
        textButton183.TextSize = 9
        textButton183.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton183.Font = Enum.Font.GothamBold
        local uICorner197 = Instance.new("UICorner", textButton183)
        local conn184 = textButton183.MouseButton1Click:Connect(function()
            textButton183.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton183.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn185 = textButton177.MouseButton1Click:Connect(function()
            frame92.Visible = true
        end)
        local conn186 = textButton178.MouseButton1Click:Connect(function()
            textButton178.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame93 = Instance.new("Frame", scrollingFrame7)
        frame93.Size = UDim2.new(1, 0, 0, 28)
        frame93.BackgroundTransparency = 1
        local textButton184 = Instance.new("TextButton", frame93)
        textButton184.Size = UDim2.new(0.72, 0, 1, 0)
        textButton184.BackgroundTransparency = 1
        textButton184.Text = "Strawberrelli Flamingelli"
        textButton184.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton184.TextXAlignment = Enum.TextXAlignment.Left
        textButton184.Font = Enum.Font.Gotham
        textButton184.TextSize = 10
        local textButton185 = Instance.new("TextButton", frame93)
        textButton185.Size = UDim2.new(0, 16, 0, 16)
        textButton185.Position = UDim2.new(1, -20, 0.5, -8)
        textButton185.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton185.Text = ""
        local uICorner198 = Instance.new("UICorner", textButton185)
        uICorner198.CornerRadius = UDim.new(0, 3)
        local frame94 = Instance.new("Frame", scrollingFrame7)
        frame94.Size = UDim2.new(1, 0, 0, 26)
        frame94.BackgroundTransparency = 1
        frame94.Visible = false
        local uIGridLayout25 = Instance.new("UIGridLayout", frame94)
        uIGridLayout25.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout25.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton186 = Instance.new("TextButton", frame94)
        textButton186.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton186.Text = "Nor"
        textButton186.TextSize = 9
        textButton186.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton186.Font = Enum.Font.GothamBold
        local uICorner199 = Instance.new("UICorner", textButton186)
        local conn187 = textButton186.MouseButton1Click:Connect(function()
            textButton186.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton186.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton187 = Instance.new("TextButton", frame94)
        textButton187.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton187.Text = "Gol"
        textButton187.TextSize = 9
        textButton187.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton187.Font = Enum.Font.GothamBold
        local uICorner200 = Instance.new("UICorner", textButton187)
        local conn188 = textButton187.MouseButton1Click:Connect(function()
            textButton187.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton187.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton188 = Instance.new("TextButton", frame94)
        textButton188.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton188.Text = "Dia"
        textButton188.TextSize = 9
        textButton188.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton188.Font = Enum.Font.GothamBold
        local uICorner201 = Instance.new("UICorner", textButton188)
        local conn189 = textButton188.MouseButton1Click:Connect(function()
            textButton188.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton188.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton189 = Instance.new("TextButton", frame94)
        textButton189.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton189.Text = "Rai"
        textButton189.TextSize = 9
        textButton189.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton189.Font = Enum.Font.GothamBold
        local uICorner202 = Instance.new("UICorner", textButton189)
        local conn190 = textButton189.MouseButton1Click:Connect(function()
            textButton189.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton189.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton190 = Instance.new("TextButton", frame94)
        textButton190.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton190.Text = "Lav"
        textButton190.TextSize = 9
        textButton190.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton190.Font = Enum.Font.GothamBold
        local uICorner203 = Instance.new("UICorner", textButton190)
        local conn191 = textButton190.MouseButton1Click:Connect(function()
            textButton190.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton190.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn192 = textButton184.MouseButton1Click:Connect(function()
            frame94.Visible = true
        end)
        local conn193 = textButton185.MouseButton1Click:Connect(function()
            textButton185.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame95 = Instance.new("Frame", scrollingFrame7)
        frame95.Size = UDim2.new(1, 0, 0, 28)
        frame95.BackgroundTransparency = 1
        local textButton191 = Instance.new("TextButton", frame95)
        textButton191.Size = UDim2.new(0.72, 0, 1, 0)
        textButton191.BackgroundTransparency = 1
        textButton191.Text = "Bananito Delfinito"
        textButton191.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton191.TextXAlignment = Enum.TextXAlignment.Left
        textButton191.Font = Enum.Font.Gotham
        textButton191.TextSize = 10
        local textButton192 = Instance.new("TextButton", frame95)
        textButton192.Size = UDim2.new(0, 16, 0, 16)
        textButton192.Position = UDim2.new(1, -20, 0.5, -8)
        textButton192.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton192.Text = ""
        local uICorner204 = Instance.new("UICorner", textButton192)
        uICorner204.CornerRadius = UDim.new(0, 3)
        local frame96 = Instance.new("Frame", scrollingFrame7)
        frame96.Size = UDim2.new(1, 0, 0, 26)
        frame96.BackgroundTransparency = 1
        frame96.Visible = false
        local uIGridLayout26 = Instance.new("UIGridLayout", frame96)
        uIGridLayout26.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout26.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton193 = Instance.new("TextButton", frame96)
        textButton193.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton193.Text = "Nor"
        textButton193.TextSize = 9
        textButton193.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton193.Font = Enum.Font.GothamBold
        local uICorner205 = Instance.new("UICorner", textButton193)
        local conn194 = textButton193.MouseButton1Click:Connect(function()
            textButton193.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton193.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton194 = Instance.new("TextButton", frame96)
        textButton194.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton194.Text = "Gol"
        textButton194.TextSize = 9
        textButton194.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton194.Font = Enum.Font.GothamBold
        local uICorner206 = Instance.new("UICorner", textButton194)
        local conn195 = textButton194.MouseButton1Click:Connect(function()
            textButton194.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton194.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton195 = Instance.new("TextButton", frame96)
        textButton195.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton195.Text = "Dia"
        textButton195.TextSize = 9
        textButton195.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton195.Font = Enum.Font.GothamBold
        local uICorner207 = Instance.new("UICorner", textButton195)
        local conn196 = textButton195.MouseButton1Click:Connect(function()
            textButton195.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton195.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton196 = Instance.new("TextButton", frame96)
        textButton196.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton196.Text = "Rai"
        textButton196.TextSize = 9
        textButton196.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton196.Font = Enum.Font.GothamBold
        local uICorner208 = Instance.new("UICorner", textButton196)
        local conn197 = textButton196.MouseButton1Click:Connect(function()
            textButton196.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton196.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton197 = Instance.new("TextButton", frame96)
        textButton197.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton197.Text = "Lav"
        textButton197.TextSize = 9
        textButton197.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton197.Font = Enum.Font.GothamBold
        local uICorner209 = Instance.new("UICorner", textButton197)
        local conn198 = textButton197.MouseButton1Click:Connect(function()
            textButton197.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton197.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn199 = textButton191.MouseButton1Click:Connect(function()
            frame96.Visible = true
        end)
        local conn200 = textButton192.MouseButton1Click:Connect(function()
            textButton192.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame97 = Instance.new("Frame", scrollingFrame7)
        frame97.Size = UDim2.new(1, 0, 0, 28)
        frame97.BackgroundTransparency = 1
        local textButton198 = Instance.new("TextButton", frame97)
        textButton198.Size = UDim2.new(0.72, 0, 1, 0)
        textButton198.BackgroundTransparency = 1
        textButton198.Text = "Balerina Capucina"
        textButton198.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton198.TextXAlignment = Enum.TextXAlignment.Left
        textButton198.Font = Enum.Font.Gotham
        textButton198.TextSize = 10
        local textButton199 = Instance.new("TextButton", frame97)
        textButton199.Size = UDim2.new(0, 16, 0, 16)
        textButton199.Position = UDim2.new(1, -20, 0.5, -8)
        textButton199.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton199.Text = ""
        local uICorner210 = Instance.new("UICorner", textButton199)
        uICorner210.CornerRadius = UDim.new(0, 3)
        local frame98 = Instance.new("Frame", scrollingFrame7)
        frame98.Size = UDim2.new(1, 0, 0, 26)
        frame98.BackgroundTransparency = 1
        frame98.Visible = false
        local uIGridLayout27 = Instance.new("UIGridLayout", frame98)
        uIGridLayout27.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout27.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton200 = Instance.new("TextButton", frame98)
        textButton200.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton200.Text = "Nor"
        textButton200.TextSize = 9
        textButton200.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton200.Font = Enum.Font.GothamBold
        local uICorner211 = Instance.new("UICorner", textButton200)
        local conn201 = textButton200.MouseButton1Click:Connect(function()
            textButton200.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton200.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton201 = Instance.new("TextButton", frame98)
        textButton201.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton201.Text = "Gol"
        textButton201.TextSize = 9
        textButton201.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton201.Font = Enum.Font.GothamBold
        local uICorner212 = Instance.new("UICorner", textButton201)
        local conn202 = textButton201.MouseButton1Click:Connect(function()
            textButton201.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton201.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton202 = Instance.new("TextButton", frame98)
        textButton202.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton202.Text = "Dia"
        textButton202.TextSize = 9
        textButton202.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton202.Font = Enum.Font.GothamBold
        local uICorner213 = Instance.new("UICorner", textButton202)
        local conn203 = textButton202.MouseButton1Click:Connect(function()
            textButton202.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton202.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton203 = Instance.new("TextButton", frame98)
        textButton203.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton203.Text = "Rai"
        textButton203.TextSize = 9
        textButton203.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton203.Font = Enum.Font.GothamBold
        local uICorner214 = Instance.new("UICorner", textButton203)
        local conn204 = textButton203.MouseButton1Click:Connect(function()
            textButton203.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton203.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton204 = Instance.new("TextButton", frame98)
        textButton204.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton204.Text = "Lav"
        textButton204.TextSize = 9
        textButton204.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton204.Font = Enum.Font.GothamBold
        local uICorner215 = Instance.new("UICorner", textButton204)
        local conn205 = textButton204.MouseButton1Click:Connect(function()
            textButton204.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton204.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn206 = textButton198.MouseButton1Click:Connect(function()
            frame98.Visible = true
        end)
        local conn207 = textButton199.MouseButton1Click:Connect(function()
            textButton199.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame99 = Instance.new("Frame", scrollingFrame7)
        frame99.Size = UDim2.new(1, 0, 0, 28)
        frame99.BackgroundTransparency = 1
        local textButton205 = Instance.new("TextButton", frame99)
        textButton205.Size = UDim2.new(0.72, 0, 1, 0)
        textButton205.BackgroundTransparency = 1
        textButton205.Text = "Glorbo Fruttodrillo"
        textButton205.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton205.TextXAlignment = Enum.TextXAlignment.Left
        textButton205.Font = Enum.Font.Gotham
        textButton205.TextSize = 10
        local textButton206 = Instance.new("TextButton", frame99)
        textButton206.Size = UDim2.new(0, 16, 0, 16)
        textButton206.Position = UDim2.new(1, -20, 0.5, -8)
        textButton206.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton206.Text = ""
        local uICorner216 = Instance.new("UICorner", textButton206)
        uICorner216.CornerRadius = UDim.new(0, 3)
        local frame100 = Instance.new("Frame", scrollingFrame7)
        frame100.Size = UDim2.new(1, 0, 0, 26)
        frame100.BackgroundTransparency = 1
        frame100.Visible = false
        local uIGridLayout28 = Instance.new("UIGridLayout", frame100)
        uIGridLayout28.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout28.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton207 = Instance.new("TextButton", frame100)
        textButton207.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton207.Text = "Nor"
        textButton207.TextSize = 9
        textButton207.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton207.Font = Enum.Font.GothamBold
        local uICorner217 = Instance.new("UICorner", textButton207)
        local conn208 = textButton207.MouseButton1Click:Connect(function()
            textButton207.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton207.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton208 = Instance.new("TextButton", frame100)
        textButton208.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton208.Text = "Gol"
        textButton208.TextSize = 9
        textButton208.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton208.Font = Enum.Font.GothamBold
        local uICorner218 = Instance.new("UICorner", textButton208)
        local conn209 = textButton208.MouseButton1Click:Connect(function()
            textButton208.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton208.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton209 = Instance.new("TextButton", frame100)
        textButton209.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton209.Text = "Dia"
        textButton209.TextSize = 9
        textButton209.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton209.Font = Enum.Font.GothamBold
        local uICorner219 = Instance.new("UICorner", textButton209)
        local conn210 = textButton209.MouseButton1Click:Connect(function()
            textButton209.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton209.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton210 = Instance.new("TextButton", frame100)
        textButton210.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton210.Text = "Rai"
        textButton210.TextSize = 9
        textButton210.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton210.Font = Enum.Font.GothamBold
        local uICorner220 = Instance.new("UICorner", textButton210)
        local conn211 = textButton210.MouseButton1Click:Connect(function()
            textButton210.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton210.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton211 = Instance.new("TextButton", frame100)
        textButton211.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton211.Text = "Lav"
        textButton211.TextSize = 9
        textButton211.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton211.Font = Enum.Font.GothamBold
        local uICorner221 = Instance.new("UICorner", textButton211)
        local conn212 = textButton211.MouseButton1Click:Connect(function()
            textButton211.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton211.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn213 = textButton205.MouseButton1Click:Connect(function()
            frame100.Visible = true
        end)
        local conn214 = textButton206.MouseButton1Click:Connect(function()
            textButton206.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame101 = Instance.new("Frame", scrollingFrame7)
        frame101.Size = UDim2.new(1, 0, 0, 28)
        frame101.BackgroundTransparency = 1
        local textButton212 = Instance.new("TextButton", frame101)
        textButton212.Size = UDim2.new(0.72, 0, 1, 0)
        textButton212.BackgroundTransparency = 1
        textButton212.Text = "Blueberrinni Octopusini"
        textButton212.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton212.TextXAlignment = Enum.TextXAlignment.Left
        textButton212.Font = Enum.Font.Gotham
        textButton212.TextSize = 10
        local textButton213 = Instance.new("TextButton", frame101)
        textButton213.Size = UDim2.new(0, 16, 0, 16)
        textButton213.Position = UDim2.new(1, -20, 0.5, -8)
        textButton213.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton213.Text = ""
        local uICorner222 = Instance.new("UICorner", textButton213)
        uICorner222.CornerRadius = UDim.new(0, 3)
        local frame102 = Instance.new("Frame", scrollingFrame7)
        frame102.Size = UDim2.new(1, 0, 0, 26)
        frame102.BackgroundTransparency = 1
        frame102.Visible = false
        local uIGridLayout29 = Instance.new("UIGridLayout", frame102)
        uIGridLayout29.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout29.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton214 = Instance.new("TextButton", frame102)
        textButton214.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton214.Text = "Nor"
        textButton214.TextSize = 9
        textButton214.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton214.Font = Enum.Font.GothamBold
        local uICorner223 = Instance.new("UICorner", textButton214)
        local conn215 = textButton214.MouseButton1Click:Connect(function()
            textButton214.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton214.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton215 = Instance.new("TextButton", frame102)
        textButton215.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton215.Text = "Gol"
        textButton215.TextSize = 9
        textButton215.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton215.Font = Enum.Font.GothamBold
        local uICorner224 = Instance.new("UICorner", textButton215)
        local conn216 = textButton215.MouseButton1Click:Connect(function()
            textButton215.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton215.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton216 = Instance.new("TextButton", frame102)
        textButton216.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton216.Text = "Dia"
        textButton216.TextSize = 9
        textButton216.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton216.Font = Enum.Font.GothamBold
        local uICorner225 = Instance.new("UICorner", textButton216)
        local conn217 = textButton216.MouseButton1Click:Connect(function()
            textButton216.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton216.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton217 = Instance.new("TextButton", frame102)
        textButton217.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton217.Text = "Rai"
        textButton217.TextSize = 9
        textButton217.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton217.Font = Enum.Font.GothamBold
        local uICorner226 = Instance.new("UICorner", textButton217)
        local conn218 = textButton217.MouseButton1Click:Connect(function()
            textButton217.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton217.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton218 = Instance.new("TextButton", frame102)
        textButton218.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton218.Text = "Lav"
        textButton218.TextSize = 9
        textButton218.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton218.Font = Enum.Font.GothamBold
        local uICorner227 = Instance.new("UICorner", textButton218)
        local conn219 = textButton218.MouseButton1Click:Connect(function()
            textButton218.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton218.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn220 = textButton212.MouseButton1Click:Connect(function()
            frame102.Visible = true
        end)
        local conn221 = textButton213.MouseButton1Click:Connect(function()
            textButton213.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame103 = Instance.new("Frame", scrollingFrame7)
        frame103.Size = UDim2.new(1, 0, 0, 28)
        frame103.BackgroundTransparency = 1
        local textButton219 = Instance.new("TextButton", frame103)
        textButton219.Size = UDim2.new(0.72, 0, 1, 0)
        textButton219.BackgroundTransparency = 1
        textButton219.Text = "Chimpanzini Bananini"
        textButton219.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton219.TextXAlignment = Enum.TextXAlignment.Left
        textButton219.Font = Enum.Font.Gotham
        textButton219.TextSize = 10
        local textButton220 = Instance.new("TextButton", frame103)
        textButton220.Size = UDim2.new(0, 16, 0, 16)
        textButton220.Position = UDim2.new(1, -20, 0.5, -8)
        textButton220.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton220.Text = ""
        local uICorner228 = Instance.new("UICorner", textButton220)
        uICorner228.CornerRadius = UDim.new(0, 3)
        local frame104 = Instance.new("Frame", scrollingFrame7)
        frame104.Size = UDim2.new(1, 0, 0, 26)
        frame104.BackgroundTransparency = 1
        frame104.Visible = false
        local uIGridLayout30 = Instance.new("UIGridLayout", frame104)
        uIGridLayout30.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout30.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton221 = Instance.new("TextButton", frame104)
        textButton221.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton221.Text = "Nor"
        textButton221.TextSize = 9
        textButton221.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton221.Font = Enum.Font.GothamBold
        local uICorner229 = Instance.new("UICorner", textButton221)
        local conn222 = textButton221.MouseButton1Click:Connect(function()
            textButton221.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton221.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton222 = Instance.new("TextButton", frame104)
        textButton222.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton222.Text = "Gol"
        textButton222.TextSize = 9
        textButton222.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton222.Font = Enum.Font.GothamBold
        local uICorner230 = Instance.new("UICorner", textButton222)
        local conn223 = textButton222.MouseButton1Click:Connect(function()
            textButton222.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton222.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton223 = Instance.new("TextButton", frame104)
        textButton223.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton223.Text = "Dia"
        textButton223.TextSize = 9
        textButton223.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton223.Font = Enum.Font.GothamBold
        local uICorner231 = Instance.new("UICorner", textButton223)
        local conn224 = textButton223.MouseButton1Click:Connect(function()
            textButton223.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton223.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton224 = Instance.new("TextButton", frame104)
        textButton224.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton224.Text = "Rai"
        textButton224.TextSize = 9
        textButton224.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton224.Font = Enum.Font.GothamBold
        local uICorner232 = Instance.new("UICorner", textButton224)
        local conn225 = textButton224.MouseButton1Click:Connect(function()
            textButton224.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton224.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton225 = Instance.new("TextButton", frame104)
        textButton225.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton225.Text = "Lav"
        textButton225.TextSize = 9
        textButton225.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton225.Font = Enum.Font.GothamBold
        local uICorner233 = Instance.new("UICorner", textButton225)
        local conn226 = textButton225.MouseButton1Click:Connect(function()
            textButton225.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton225.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn227 = textButton219.MouseButton1Click:Connect(function()
            frame104.Visible = true
        end)
        local conn228 = textButton220.MouseButton1Click:Connect(function()
            textButton220.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame105 = Instance.new("Frame", scrollingFrame7)
        frame105.Size = UDim2.new(1, 0, 0, 28)
        frame105.BackgroundTransparency = 1
        local textButton226 = Instance.new("TextButton", frame105)
        textButton226.Size = UDim2.new(0.72, 0, 1, 0)
        textButton226.BackgroundTransparency = 1
        textButton226.Text = "Bombardiro Crocodilo"
        textButton226.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton226.TextXAlignment = Enum.TextXAlignment.Left
        textButton226.Font = Enum.Font.Gotham
        textButton226.TextSize = 10
        local textButton227 = Instance.new("TextButton", frame105)
        textButton227.Size = UDim2.new(0, 16, 0, 16)
        textButton227.Position = UDim2.new(1, -20, 0.5, -8)
        textButton227.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton227.Text = ""
        local uICorner234 = Instance.new("UICorner", textButton227)
        uICorner234.CornerRadius = UDim.new(0, 3)
        local frame106 = Instance.new("Frame", scrollingFrame7)
        frame106.Size = UDim2.new(1, 0, 0, 26)
        frame106.BackgroundTransparency = 1
        frame106.Visible = false
        local uIGridLayout31 = Instance.new("UIGridLayout", frame106)
        uIGridLayout31.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout31.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton228 = Instance.new("TextButton", frame106)
        textButton228.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton228.Text = "Nor"
        textButton228.TextSize = 9
        textButton228.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton228.Font = Enum.Font.GothamBold
        local uICorner235 = Instance.new("UICorner", textButton228)
        local conn229 = textButton228.MouseButton1Click:Connect(function()
            textButton228.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton228.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton229 = Instance.new("TextButton", frame106)
        textButton229.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton229.Text = "Gol"
        textButton229.TextSize = 9
        textButton229.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton229.Font = Enum.Font.GothamBold
        local uICorner236 = Instance.new("UICorner", textButton229)
        local conn230 = textButton229.MouseButton1Click:Connect(function()
            textButton229.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton229.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton230 = Instance.new("TextButton", frame106)
        textButton230.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton230.Text = "Dia"
        textButton230.TextSize = 9
        textButton230.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton230.Font = Enum.Font.GothamBold
        local uICorner237 = Instance.new("UICorner", textButton230)
        local conn231 = textButton230.MouseButton1Click:Connect(function()
            textButton230.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton230.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton231 = Instance.new("TextButton", frame106)
        textButton231.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton231.Text = "Rai"
        textButton231.TextSize = 9
        textButton231.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton231.Font = Enum.Font.GothamBold
        local uICorner238 = Instance.new("UICorner", textButton231)
        local conn232 = textButton231.MouseButton1Click:Connect(function()
            textButton231.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton231.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton232 = Instance.new("TextButton", frame106)
        textButton232.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton232.Text = "Lav"
        textButton232.TextSize = 9
        textButton232.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton232.Font = Enum.Font.GothamBold
        local uICorner239 = Instance.new("UICorner", textButton232)
        local conn233 = textButton232.MouseButton1Click:Connect(function()
            textButton232.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton232.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn234 = textButton226.MouseButton1Click:Connect(function()
            frame106.Visible = true
        end)
        local conn235 = textButton227.MouseButton1Click:Connect(function()
            textButton227.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame107 = Instance.new("Frame", scrollingFrame7)
        frame107.Size = UDim2.new(1, 0, 0, 28)
        frame107.BackgroundTransparency = 1
        local textButton233 = Instance.new("TextButton", frame107)
        textButton233.Size = UDim2.new(0.72, 0, 1, 0)
        textButton233.BackgroundTransparency = 1
        textButton233.Text = "Elefanto Cocofanto"
        textButton233.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton233.TextXAlignment = Enum.TextXAlignment.Left
        textButton233.Font = Enum.Font.Gotham
        textButton233.TextSize = 10
        local textButton234 = Instance.new("TextButton", frame107)
        textButton234.Size = UDim2.new(0, 16, 0, 16)
        textButton234.Position = UDim2.new(1, -20, 0.5, -8)
        textButton234.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton234.Text = ""
        local uICorner240 = Instance.new("UICorner", textButton234)
        uICorner240.CornerRadius = UDim.new(0, 3)
        local frame108 = Instance.new("Frame", scrollingFrame7)
        frame108.Size = UDim2.new(1, 0, 0, 26)
        frame108.BackgroundTransparency = 1
        frame108.Visible = false
        local uIGridLayout32 = Instance.new("UIGridLayout", frame108)
        uIGridLayout32.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout32.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton235 = Instance.new("TextButton", frame108)
        textButton235.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton235.Text = "Nor"
        textButton235.TextSize = 9
        textButton235.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton235.Font = Enum.Font.GothamBold
        local uICorner241 = Instance.new("UICorner", textButton235)
        local conn236 = textButton235.MouseButton1Click:Connect(function()
            textButton235.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton235.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton236 = Instance.new("TextButton", frame108)
        textButton236.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton236.Text = "Gol"
        textButton236.TextSize = 9
        textButton236.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton236.Font = Enum.Font.GothamBold
        local uICorner242 = Instance.new("UICorner", textButton236)
        local conn237 = textButton236.MouseButton1Click:Connect(function()
            textButton236.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton236.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton237 = Instance.new("TextButton", frame108)
        textButton237.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton237.Text = "Dia"
        textButton237.TextSize = 9
        textButton237.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton237.Font = Enum.Font.GothamBold
        local uICorner243 = Instance.new("UICorner", textButton237)
        local conn238 = textButton237.MouseButton1Click:Connect(function()
            textButton237.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton237.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton238 = Instance.new("TextButton", frame108)
        textButton238.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton238.Text = "Rai"
        textButton238.TextSize = 9
        textButton238.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton238.Font = Enum.Font.GothamBold
        local uICorner244 = Instance.new("UICorner", textButton238)
        local conn239 = textButton238.MouseButton1Click:Connect(function()
            textButton238.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton238.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton239 = Instance.new("TextButton", frame108)
        textButton239.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton239.Text = "Lav"
        textButton239.TextSize = 9
        textButton239.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton239.Font = Enum.Font.GothamBold
        local uICorner245 = Instance.new("UICorner", textButton239)
        local conn240 = textButton239.MouseButton1Click:Connect(function()
            textButton239.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton239.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn241 = textButton233.MouseButton1Click:Connect(function()
            frame108.Visible = true
        end)
        local conn242 = textButton234.MouseButton1Click:Connect(function()
            textButton234.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame109 = Instance.new("Frame", scrollingFrame7)
        frame109.Size = UDim2.new(1, 0, 0, 28)
        frame109.BackgroundTransparency = 1
        local textButton240 = Instance.new("TextButton", frame109)
        textButton240.Size = UDim2.new(0.72, 0, 1, 0)
        textButton240.BackgroundTransparency = 1
        textButton240.Text = "Bombombini Gusini"
        textButton240.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton240.TextXAlignment = Enum.TextXAlignment.Left
        textButton240.Font = Enum.Font.Gotham
        textButton240.TextSize = 10
        local textButton241 = Instance.new("TextButton", frame109)
        textButton241.Size = UDim2.new(0, 16, 0, 16)
        textButton241.Position = UDim2.new(1, -20, 0.5, -8)
        textButton241.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton241.Text = ""
        local uICorner246 = Instance.new("UICorner", textButton241)
        uICorner246.CornerRadius = UDim.new(0, 3)
        local frame110 = Instance.new("Frame", scrollingFrame7)
        frame110.Size = UDim2.new(1, 0, 0, 26)
        frame110.BackgroundTransparency = 1
        frame110.Visible = false
        local uIGridLayout33 = Instance.new("UIGridLayout", frame110)
        uIGridLayout33.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout33.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton242 = Instance.new("TextButton", frame110)
        textButton242.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton242.Text = "Nor"
        textButton242.TextSize = 9
        textButton242.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton242.Font = Enum.Font.GothamBold
        local uICorner247 = Instance.new("UICorner", textButton242)
        local conn243 = textButton242.MouseButton1Click:Connect(function()
            textButton242.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton242.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton243 = Instance.new("TextButton", frame110)
        textButton243.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton243.Text = "Gol"
        textButton243.TextSize = 9
        textButton243.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton243.Font = Enum.Font.GothamBold
        local uICorner248 = Instance.new("UICorner", textButton243)
        local conn244 = textButton243.MouseButton1Click:Connect(function()
            textButton243.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton243.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton244 = Instance.new("TextButton", frame110)
        textButton244.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton244.Text = "Dia"
        textButton244.TextSize = 9
        textButton244.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton244.Font = Enum.Font.GothamBold
        local uICorner249 = Instance.new("UICorner", textButton244)
        local conn245 = textButton244.MouseButton1Click:Connect(function()
            textButton244.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton244.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton245 = Instance.new("TextButton", frame110)
        textButton245.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton245.Text = "Rai"
        textButton245.TextSize = 9
        textButton245.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton245.Font = Enum.Font.GothamBold
        local uICorner250 = Instance.new("UICorner", textButton245)
        local conn246 = textButton245.MouseButton1Click:Connect(function()
            textButton245.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton245.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton246 = Instance.new("TextButton", frame110)
        textButton246.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton246.Text = "Lav"
        textButton246.TextSize = 9
        textButton246.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton246.Font = Enum.Font.GothamBold
        local uICorner251 = Instance.new("UICorner", textButton246)
        local conn247 = textButton246.MouseButton1Click:Connect(function()
            textButton246.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton246.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn248 = textButton240.MouseButton1Click:Connect(function()
            frame110.Visible = true
        end)
        local conn249 = textButton241.MouseButton1Click:Connect(function()
            textButton241.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame111 = Instance.new("Frame", scrollingFrame7)
        frame111.Size = UDim2.new(1, 0, 0, 28)
        frame111.BackgroundTransparency = 1
        local textButton247 = Instance.new("TextButton", frame111)
        textButton247.Size = UDim2.new(0.72, 0, 1, 0)
        textButton247.BackgroundTransparency = 1
        textButton247.Text = "Pandaccini Bananini"
        textButton247.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton247.TextXAlignment = Enum.TextXAlignment.Left
        textButton247.Font = Enum.Font.Gotham
        textButton247.TextSize = 10
        local textButton248 = Instance.new("TextButton", frame111)
        textButton248.Size = UDim2.new(0, 16, 0, 16)
        textButton248.Position = UDim2.new(1, -20, 0.5, -8)
        textButton248.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton248.Text = ""
        local uICorner252 = Instance.new("UICorner", textButton248)
        uICorner252.CornerRadius = UDim.new(0, 3)
        local frame112 = Instance.new("Frame", scrollingFrame7)
        frame112.Size = UDim2.new(1, 0, 0, 26)
        frame112.BackgroundTransparency = 1
        frame112.Visible = false
        local uIGridLayout34 = Instance.new("UIGridLayout", frame112)
        uIGridLayout34.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout34.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton249 = Instance.new("TextButton", frame112)
        textButton249.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton249.Text = "Nor"
        textButton249.TextSize = 9
        textButton249.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton249.Font = Enum.Font.GothamBold
        local uICorner253 = Instance.new("UICorner", textButton249)
        local conn250 = textButton249.MouseButton1Click:Connect(function()
            textButton249.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton249.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton250 = Instance.new("TextButton", frame112)
        textButton250.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton250.Text = "Gol"
        textButton250.TextSize = 9
        textButton250.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton250.Font = Enum.Font.GothamBold
        local uICorner254 = Instance.new("UICorner", textButton250)
        local conn251 = textButton250.MouseButton1Click:Connect(function()
            textButton250.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton250.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton251 = Instance.new("TextButton", frame112)
        textButton251.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton251.Text = "Dia"
        textButton251.TextSize = 9
        textButton251.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton251.Font = Enum.Font.GothamBold
        local uICorner255 = Instance.new("UICorner", textButton251)
        local conn252 = textButton251.MouseButton1Click:Connect(function()
            textButton251.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton251.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton252 = Instance.new("TextButton", frame112)
        textButton252.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton252.Text = "Rai"
        textButton252.TextSize = 9
        textButton252.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton252.Font = Enum.Font.GothamBold
        local uICorner256 = Instance.new("UICorner", textButton252)
        local conn253 = textButton252.MouseButton1Click:Connect(function()
            textButton252.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton252.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton253 = Instance.new("TextButton", frame112)
        textButton253.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton253.Text = "Lav"
        textButton253.TextSize = 9
        textButton253.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton253.Font = Enum.Font.GothamBold
        local uICorner257 = Instance.new("UICorner", textButton253)
        local conn254 = textButton253.MouseButton1Click:Connect(function()
            textButton253.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton253.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn255 = textButton247.MouseButton1Click:Connect(function()
            frame112.Visible = true
        end)
        local conn256 = textButton248.MouseButton1Click:Connect(function()
            textButton248.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame113 = Instance.new("Frame", scrollingFrame7)
        frame113.Size = UDim2.new(1, 0, 0, 28)
        frame113.BackgroundTransparency = 1
        local textButton254 = Instance.new("TextButton", frame113)
        textButton254.Size = UDim2.new(0.72, 0, 1, 0)
        textButton254.BackgroundTransparency = 1
        textButton254.Text = "Chef Crabracadabra"
        textButton254.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton254.TextXAlignment = Enum.TextXAlignment.Left
        textButton254.Font = Enum.Font.Gotham
        textButton254.TextSize = 10
        local textButton255 = Instance.new("TextButton", frame113)
        textButton255.Size = UDim2.new(0, 16, 0, 16)
        textButton255.Position = UDim2.new(1, -20, 0.5, -8)
        textButton255.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton255.Text = ""
        local uICorner258 = Instance.new("UICorner", textButton255)
        uICorner258.CornerRadius = UDim.new(0, 3)
        local frame114 = Instance.new("Frame", scrollingFrame7)
        frame114.Size = UDim2.new(1, 0, 0, 26)
        frame114.BackgroundTransparency = 1
        frame114.Visible = false
        local uIGridLayout35 = Instance.new("UIGridLayout", frame114)
        uIGridLayout35.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout35.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton256 = Instance.new("TextButton", frame114)
        textButton256.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton256.Text = "Nor"
        textButton256.TextSize = 9
        textButton256.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton256.Font = Enum.Font.GothamBold
        local uICorner259 = Instance.new("UICorner", textButton256)
        local conn257 = textButton256.MouseButton1Click:Connect(function()
            textButton256.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton256.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton257 = Instance.new("TextButton", frame114)
        textButton257.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton257.Text = "Gol"
        textButton257.TextSize = 9
        textButton257.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton257.Font = Enum.Font.GothamBold
        local uICorner260 = Instance.new("UICorner", textButton257)
        local conn258 = textButton257.MouseButton1Click:Connect(function()
            textButton257.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton257.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton258 = Instance.new("TextButton", frame114)
        textButton258.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton258.Text = "Dia"
        textButton258.TextSize = 9
        textButton258.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton258.Font = Enum.Font.GothamBold
        local uICorner261 = Instance.new("UICorner", textButton258)
        local conn259 = textButton258.MouseButton1Click:Connect(function()
            textButton258.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton258.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton259 = Instance.new("TextButton", frame114)
        textButton259.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton259.Text = "Rai"
        textButton259.TextSize = 9
        textButton259.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton259.Font = Enum.Font.GothamBold
        local uICorner262 = Instance.new("UICorner", textButton259)
        local conn260 = textButton259.MouseButton1Click:Connect(function()
            textButton259.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton259.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton260 = Instance.new("TextButton", frame114)
        textButton260.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton260.Text = "Lav"
        textButton260.TextSize = 9
        textButton260.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton260.Font = Enum.Font.GothamBold
        local uICorner263 = Instance.new("UICorner", textButton260)
        local conn261 = textButton260.MouseButton1Click:Connect(function()
            textButton260.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton260.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn262 = textButton254.MouseButton1Click:Connect(function()
            frame114.Visible = true
        end)
        local conn263 = textButton255.MouseButton1Click:Connect(function()
            textButton255.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame115 = Instance.new("Frame", scrollingFrame7)
        frame115.Size = UDim2.new(1, 0, 0, 28)
        frame115.BackgroundTransparency = 1
        local textButton261 = Instance.new("TextButton", frame115)
        textButton261.Size = UDim2.new(0.72, 0, 1, 0)
        textButton261.BackgroundTransparency = 1
        textButton261.Text = "Gorillo Watermelondrillo"
        textButton261.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton261.TextXAlignment = Enum.TextXAlignment.Left
        textButton261.Font = Enum.Font.Gotham
        textButton261.TextSize = 10
        local textButton262 = Instance.new("TextButton", frame115)
        textButton262.Size = UDim2.new(0, 16, 0, 16)
        textButton262.Position = UDim2.new(1, -20, 0.5, -8)
        textButton262.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton262.Text = ""
        local uICorner264 = Instance.new("UICorner", textButton262)
        uICorner264.CornerRadius = UDim.new(0, 3)
        local frame116 = Instance.new("Frame", scrollingFrame7)
        frame116.Size = UDim2.new(1, 0, 0, 26)
        frame116.BackgroundTransparency = 1
        frame116.Visible = false
        local uIGridLayout36 = Instance.new("UIGridLayout", frame116)
        uIGridLayout36.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout36.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton263 = Instance.new("TextButton", frame116)
        textButton263.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton263.Text = "Nor"
        textButton263.TextSize = 9
        textButton263.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton263.Font = Enum.Font.GothamBold
        local uICorner265 = Instance.new("UICorner", textButton263)
        local conn264 = textButton263.MouseButton1Click:Connect(function()
            textButton263.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton263.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton264 = Instance.new("TextButton", frame116)
        textButton264.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton264.Text = "Gol"
        textButton264.TextSize = 9
        textButton264.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton264.Font = Enum.Font.GothamBold
        local uICorner266 = Instance.new("UICorner", textButton264)
        local conn265 = textButton264.MouseButton1Click:Connect(function()
            textButton264.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton264.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton265 = Instance.new("TextButton", frame116)
        textButton265.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton265.Text = "Dia"
        textButton265.TextSize = 9
        textButton265.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton265.Font = Enum.Font.GothamBold
        local uICorner267 = Instance.new("UICorner", textButton265)
        local conn266 = textButton265.MouseButton1Click:Connect(function()
            textButton265.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton265.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton266 = Instance.new("TextButton", frame116)
        textButton266.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton266.Text = "Rai"
        textButton266.TextSize = 9
        textButton266.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton266.Font = Enum.Font.GothamBold
        local uICorner268 = Instance.new("UICorner", textButton266)
        local conn267 = textButton266.MouseButton1Click:Connect(function()
            textButton266.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton266.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton267 = Instance.new("TextButton", frame116)
        textButton267.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton267.Text = "Lav"
        textButton267.TextSize = 9
        textButton267.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton267.Font = Enum.Font.GothamBold
        local uICorner269 = Instance.new("UICorner", textButton267)
        local conn268 = textButton267.MouseButton1Click:Connect(function()
            textButton267.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton267.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn269 = textButton261.MouseButton1Click:Connect(function()
            frame116.Visible = true
        end)
        local conn270 = textButton262.MouseButton1Click:Connect(function()
            textButton262.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame117 = Instance.new("Frame", scrollingFrame7)
        frame117.Size = UDim2.new(1, 0, 0, 28)
        frame117.BackgroundTransparency = 1
        local textButton268 = Instance.new("TextButton", frame117)
        textButton268.Size = UDim2.new(0.72, 0, 1, 0)
        textButton268.BackgroundTransparency = 1
        textButton268.Text = "Frigo Camelo"
        textButton268.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton268.TextXAlignment = Enum.TextXAlignment.Left
        textButton268.Font = Enum.Font.Gotham
        textButton268.TextSize = 10
        local textButton269 = Instance.new("TextButton", frame117)
        textButton269.Size = UDim2.new(0, 16, 0, 16)
        textButton269.Position = UDim2.new(1, -20, 0.5, -8)
        textButton269.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton269.Text = ""
        local uICorner270 = Instance.new("UICorner", textButton269)
        uICorner270.CornerRadius = UDim.new(0, 3)
        local frame118 = Instance.new("Frame", scrollingFrame7)
        frame118.Size = UDim2.new(1, 0, 0, 26)
        frame118.BackgroundTransparency = 1
        frame118.Visible = false
        local uIGridLayout37 = Instance.new("UIGridLayout", frame118)
        uIGridLayout37.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout37.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton270 = Instance.new("TextButton", frame118)
        textButton270.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton270.Text = "Nor"
        textButton270.TextSize = 9
        textButton270.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton270.Font = Enum.Font.GothamBold
        local uICorner271 = Instance.new("UICorner", textButton270)
        local conn271 = textButton270.MouseButton1Click:Connect(function()
            textButton270.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton270.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton271 = Instance.new("TextButton", frame118)
        textButton271.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton271.Text = "Gol"
        textButton271.TextSize = 9
        textButton271.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton271.Font = Enum.Font.GothamBold
        local uICorner272 = Instance.new("UICorner", textButton271)
        local conn272 = textButton271.MouseButton1Click:Connect(function()
            textButton271.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton271.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton272 = Instance.new("TextButton", frame118)
        textButton272.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton272.Text = "Dia"
        textButton272.TextSize = 9
        textButton272.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton272.Font = Enum.Font.GothamBold
        local uICorner273 = Instance.new("UICorner", textButton272)
        local conn273 = textButton272.MouseButton1Click:Connect(function()
            textButton272.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton272.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton273 = Instance.new("TextButton", frame118)
        textButton273.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton273.Text = "Rai"
        textButton273.TextSize = 9
        textButton273.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton273.Font = Enum.Font.GothamBold
        local uICorner274 = Instance.new("UICorner", textButton273)
        local conn274 = textButton273.MouseButton1Click:Connect(function()
            textButton273.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton273.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton274 = Instance.new("TextButton", frame118)
        textButton274.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton274.Text = "Lav"
        textButton274.TextSize = 9
        textButton274.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton274.Font = Enum.Font.GothamBold
        local uICorner275 = Instance.new("UICorner", textButton274)
        local conn275 = textButton274.MouseButton1Click:Connect(function()
            textButton274.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton274.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn276 = textButton268.MouseButton1Click:Connect(function()
            frame118.Visible = true
        end)
        local conn277 = textButton269.MouseButton1Click:Connect(function()
            textButton269.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame119 = Instance.new("Frame", scrollingFrame7)
        frame119.Size = UDim2.new(1, 0, 0, 28)
        frame119.BackgroundTransparency = 1
        local textButton275 = Instance.new("TextButton", frame119)
        textButton275.Size = UDim2.new(0.72, 0, 1, 0)
        textButton275.BackgroundTransparency = 1
        textButton275.Text = "Girafa Celestre"
        textButton275.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton275.TextXAlignment = Enum.TextXAlignment.Left
        textButton275.Font = Enum.Font.Gotham
        textButton275.TextSize = 10
        local textButton276 = Instance.new("TextButton", frame119)
        textButton276.Size = UDim2.new(0, 16, 0, 16)
        textButton276.Position = UDim2.new(1, -20, 0.5, -8)
        textButton276.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton276.Text = ""
        local uICorner276 = Instance.new("UICorner", textButton276)
        uICorner276.CornerRadius = UDim.new(0, 3)
        local frame120 = Instance.new("Frame", scrollingFrame7)
        frame120.Size = UDim2.new(1, 0, 0, 26)
        frame120.BackgroundTransparency = 1
        frame120.Visible = false
        local uIGridLayout38 = Instance.new("UIGridLayout", frame120)
        uIGridLayout38.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout38.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton277 = Instance.new("TextButton", frame120)
        textButton277.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton277.Text = "Nor"
        textButton277.TextSize = 9
        textButton277.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton277.Font = Enum.Font.GothamBold
        local uICorner277 = Instance.new("UICorner", textButton277)
        local conn278 = textButton277.MouseButton1Click:Connect(function()
            textButton277.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton277.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton278 = Instance.new("TextButton", frame120)
        textButton278.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton278.Text = "Gol"
        textButton278.TextSize = 9
        textButton278.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton278.Font = Enum.Font.GothamBold
        local uICorner278 = Instance.new("UICorner", textButton278)
        local conn279 = textButton278.MouseButton1Click:Connect(function()
            textButton278.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton278.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton279 = Instance.new("TextButton", frame120)
        textButton279.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton279.Text = "Dia"
        textButton279.TextSize = 9
        textButton279.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton279.Font = Enum.Font.GothamBold
        local uICorner279 = Instance.new("UICorner", textButton279)
        local conn280 = textButton279.MouseButton1Click:Connect(function()
            textButton279.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton279.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton280 = Instance.new("TextButton", frame120)
        textButton280.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton280.Text = "Rai"
        textButton280.TextSize = 9
        textButton280.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton280.Font = Enum.Font.GothamBold
        local uICorner280 = Instance.new("UICorner", textButton280)
        local conn281 = textButton280.MouseButton1Click:Connect(function()
            textButton280.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton280.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton281 = Instance.new("TextButton", frame120)
        textButton281.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton281.Text = "Lav"
        textButton281.TextSize = 9
        textButton281.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton281.Font = Enum.Font.GothamBold
        local uICorner281 = Instance.new("UICorner", textButton281)
        local conn282 = textButton281.MouseButton1Click:Connect(function()
            textButton281.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton281.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn283 = textButton275.MouseButton1Click:Connect(function()
            frame120.Visible = true
        end)
        local conn284 = textButton276.MouseButton1Click:Connect(function()
            textButton276.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame121 = Instance.new("Frame", scrollingFrame7)
        frame121.Size = UDim2.new(1, 0, 0, 28)
        frame121.BackgroundTransparency = 1
        local textButton282 = Instance.new("TextButton", frame121)
        textButton282.Size = UDim2.new(0.72, 0, 1, 0)
        textButton282.BackgroundTransparency = 1
        textButton282.Text = "Ganganzelli Trulala"
        textButton282.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton282.TextXAlignment = Enum.TextXAlignment.Left
        textButton282.Font = Enum.Font.Gotham
        textButton282.TextSize = 10
        local textButton283 = Instance.new("TextButton", frame121)
        textButton283.Size = UDim2.new(0, 16, 0, 16)
        textButton283.Position = UDim2.new(1, -20, 0.5, -8)
        textButton283.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton283.Text = ""
        local uICorner282 = Instance.new("UICorner", textButton283)
        uICorner282.CornerRadius = UDim.new(0, 3)
        local frame122 = Instance.new("Frame", scrollingFrame7)
        frame122.Size = UDim2.new(1, 0, 0, 26)
        frame122.BackgroundTransparency = 1
        frame122.Visible = false
        local uIGridLayout39 = Instance.new("UIGridLayout", frame122)
        uIGridLayout39.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout39.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton284 = Instance.new("TextButton", frame122)
        textButton284.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton284.Text = "Nor"
        textButton284.TextSize = 9
        textButton284.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton284.Font = Enum.Font.GothamBold
        local uICorner283 = Instance.new("UICorner", textButton284)
        local conn285 = textButton284.MouseButton1Click:Connect(function()
            textButton284.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton284.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton285 = Instance.new("TextButton", frame122)
        textButton285.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton285.Text = "Gol"
        textButton285.TextSize = 9
        textButton285.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton285.Font = Enum.Font.GothamBold
        local uICorner284 = Instance.new("UICorner", textButton285)
        local conn286 = textButton285.MouseButton1Click:Connect(function()
            textButton285.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton285.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton286 = Instance.new("TextButton", frame122)
        textButton286.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton286.Text = "Dia"
        textButton286.TextSize = 9
        textButton286.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton286.Font = Enum.Font.GothamBold
        local uICorner285 = Instance.new("UICorner", textButton286)
        local conn287 = textButton286.MouseButton1Click:Connect(function()
            textButton286.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton286.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton287 = Instance.new("TextButton", frame122)
        textButton287.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton287.Text = "Rai"
        textButton287.TextSize = 9
        textButton287.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton287.Font = Enum.Font.GothamBold
        local uICorner286 = Instance.new("UICorner", textButton287)
        local conn288 = textButton287.MouseButton1Click:Connect(function()
            textButton287.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton287.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton288 = Instance.new("TextButton", frame122)
        textButton288.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton288.Text = "Lav"
        textButton288.TextSize = 9
        textButton288.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton288.Font = Enum.Font.GothamBold
        local uICorner287 = Instance.new("UICorner", textButton288)
        local conn289 = textButton288.MouseButton1Click:Connect(function()
            textButton288.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton288.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn290 = textButton282.MouseButton1Click:Connect(function()
            frame122.Visible = true
        end)
        local conn291 = textButton283.MouseButton1Click:Connect(function()
            textButton283.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame123 = Instance.new("Frame", scrollingFrame7)
        frame123.Size = UDim2.new(1, 0, 0, 28)
        frame123.BackgroundTransparency = 1
        local textButton289 = Instance.new("TextButton", frame123)
        textButton289.Size = UDim2.new(0.72, 0, 1, 0)
        textButton289.BackgroundTransparency = 1
        textButton289.Text = "Tigroligre Frutonni"
        textButton289.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton289.TextXAlignment = Enum.TextXAlignment.Left
        textButton289.Font = Enum.Font.Gotham
        textButton289.TextSize = 10
        local textButton290 = Instance.new("TextButton", frame123)
        textButton290.Size = UDim2.new(0, 16, 0, 16)
        textButton290.Position = UDim2.new(1, -20, 0.5, -8)
        textButton290.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton290.Text = ""
        local uICorner288 = Instance.new("UICorner", textButton290)
        uICorner288.CornerRadius = UDim.new(0, 3)
        local frame124 = Instance.new("Frame", scrollingFrame7)
        frame124.Size = UDim2.new(1, 0, 0, 26)
        frame124.BackgroundTransparency = 1
        frame124.Visible = false
        local uIGridLayout40 = Instance.new("UIGridLayout", frame124)
        uIGridLayout40.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout40.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton291 = Instance.new("TextButton", frame124)
        textButton291.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton291.Text = "Nor"
        textButton291.TextSize = 9
        textButton291.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton291.Font = Enum.Font.GothamBold
        local uICorner289 = Instance.new("UICorner", textButton291)
        local conn292 = textButton291.MouseButton1Click:Connect(function()
            textButton291.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton291.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton292 = Instance.new("TextButton", frame124)
        textButton292.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton292.Text = "Gol"
        textButton292.TextSize = 9
        textButton292.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton292.Font = Enum.Font.GothamBold
        local uICorner290 = Instance.new("UICorner", textButton292)
        local conn293 = textButton292.MouseButton1Click:Connect(function()
            textButton292.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton292.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton293 = Instance.new("TextButton", frame124)
        textButton293.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton293.Text = "Dia"
        textButton293.TextSize = 9
        textButton293.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton293.Font = Enum.Font.GothamBold
        local uICorner291 = Instance.new("UICorner", textButton293)
        local conn294 = textButton293.MouseButton1Click:Connect(function()
            textButton293.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton293.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton294 = Instance.new("TextButton", frame124)
        textButton294.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton294.Text = "Rai"
        textButton294.TextSize = 9
        textButton294.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton294.Font = Enum.Font.GothamBold
        local uICorner292 = Instance.new("UICorner", textButton294)
        local conn295 = textButton294.MouseButton1Click:Connect(function()
            textButton294.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton294.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton295 = Instance.new("TextButton", frame124)
        textButton295.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton295.Text = "Lav"
        textButton295.TextSize = 9
        textButton295.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton295.Font = Enum.Font.GothamBold
        local uICorner293 = Instance.new("UICorner", textButton295)
        local conn296 = textButton295.MouseButton1Click:Connect(function()
            textButton295.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton295.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn297 = textButton289.MouseButton1Click:Connect(function()
            frame124.Visible = true
        end)
        local conn298 = textButton290.MouseButton1Click:Connect(function()
            textButton290.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame125 = Instance.new("Frame", scrollingFrame7)
        frame125.Size = UDim2.new(1, 0, 0, 28)
        frame125.BackgroundTransparency = 1
        local textButton296 = Instance.new("TextButton", frame125)
        textButton296.Size = UDim2.new(0.72, 0, 1, 0)
        textButton296.BackgroundTransparency = 1
        textButton296.Text = "Matteo"
        textButton296.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton296.TextXAlignment = Enum.TextXAlignment.Left
        textButton296.Font = Enum.Font.Gotham
        textButton296.TextSize = 10
        local textButton297 = Instance.new("TextButton", frame125)
        textButton297.Size = UDim2.new(0, 16, 0, 16)
        textButton297.Position = UDim2.new(1, -20, 0.5, -8)
        textButton297.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton297.Text = ""
        local uICorner294 = Instance.new("UICorner", textButton297)
        uICorner294.CornerRadius = UDim.new(0, 3)
        local frame126 = Instance.new("Frame", scrollingFrame7)
        frame126.Size = UDim2.new(1, 0, 0, 26)
        frame126.BackgroundTransparency = 1
        frame126.Visible = false
        local uIGridLayout41 = Instance.new("UIGridLayout", frame126)
        uIGridLayout41.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout41.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton298 = Instance.new("TextButton", frame126)
        textButton298.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton298.Text = "Nor"
        textButton298.TextSize = 9
        textButton298.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton298.Font = Enum.Font.GothamBold
        local uICorner295 = Instance.new("UICorner", textButton298)
        local conn299 = textButton298.MouseButton1Click:Connect(function()
            textButton298.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton298.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton299 = Instance.new("TextButton", frame126)
        textButton299.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton299.Text = "Gol"
        textButton299.TextSize = 9
        textButton299.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton299.Font = Enum.Font.GothamBold
        local uICorner296 = Instance.new("UICorner", textButton299)
        local conn300 = textButton299.MouseButton1Click:Connect(function()
            textButton299.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton299.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton300 = Instance.new("TextButton", frame126)
        textButton300.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton300.Text = "Dia"
        textButton300.TextSize = 9
        textButton300.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton300.Font = Enum.Font.GothamBold
        local uICorner297 = Instance.new("UICorner", textButton300)
        local conn301 = textButton300.MouseButton1Click:Connect(function()
            textButton300.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton300.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton301 = Instance.new("TextButton", frame126)
        textButton301.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton301.Text = "Rai"
        textButton301.TextSize = 9
        textButton301.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton301.Font = Enum.Font.GothamBold
        local uICorner298 = Instance.new("UICorner", textButton301)
        local conn302 = textButton301.MouseButton1Click:Connect(function()
            textButton301.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton301.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton302 = Instance.new("TextButton", frame126)
        textButton302.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton302.Text = "Lav"
        textButton302.TextSize = 9
        textButton302.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton302.Font = Enum.Font.GothamBold
        local uICorner299 = Instance.new("UICorner", textButton302)
        local conn303 = textButton302.MouseButton1Click:Connect(function()
            textButton302.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton302.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn304 = textButton296.MouseButton1Click:Connect(function()
            frame126.Visible = true
        end)
        local conn305 = textButton297.MouseButton1Click:Connect(function()
            textButton297.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame127 = Instance.new("Frame", scrollingFrame7)
        frame127.Size = UDim2.new(1, 0, 0, 28)
        frame127.BackgroundTransparency = 1
        local textButton303 = Instance.new("TextButton", frame127)
        textButton303.Size = UDim2.new(0.72, 0, 1, 0)
        textButton303.BackgroundTransparency = 1
        textButton303.Text = "Cavallo Virtuoso"
        textButton303.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton303.TextXAlignment = Enum.TextXAlignment.Left
        textButton303.Font = Enum.Font.Gotham
        textButton303.TextSize = 10
        local textButton304 = Instance.new("TextButton", frame127)
        textButton304.Size = UDim2.new(0, 16, 0, 16)
        textButton304.Position = UDim2.new(1, -20, 0.5, -8)
        textButton304.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton304.Text = ""
        local uICorner300 = Instance.new("UICorner", textButton304)
        uICorner300.CornerRadius = UDim.new(0, 3)
        local frame128 = Instance.new("Frame", scrollingFrame7)
        frame128.Size = UDim2.new(1, 0, 0, 26)
        frame128.BackgroundTransparency = 1
        frame128.Visible = false
        local uIGridLayout42 = Instance.new("UIGridLayout", frame128)
        uIGridLayout42.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout42.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton305 = Instance.new("TextButton", frame128)
        textButton305.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton305.Text = "Nor"
        textButton305.TextSize = 9
        textButton305.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton305.Font = Enum.Font.GothamBold
        local uICorner301 = Instance.new("UICorner", textButton305)
        local conn306 = textButton305.MouseButton1Click:Connect(function()
            textButton305.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton305.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton306 = Instance.new("TextButton", frame128)
        textButton306.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton306.Text = "Gol"
        textButton306.TextSize = 9
        textButton306.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton306.Font = Enum.Font.GothamBold
        local uICorner302 = Instance.new("UICorner", textButton306)
        local conn307 = textButton306.MouseButton1Click:Connect(function()
            textButton306.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton306.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton307 = Instance.new("TextButton", frame128)
        textButton307.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton307.Text = "Dia"
        textButton307.TextSize = 9
        textButton307.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton307.Font = Enum.Font.GothamBold
        local uICorner303 = Instance.new("UICorner", textButton307)
        local conn308 = textButton307.MouseButton1Click:Connect(function()
            textButton307.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton307.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton308 = Instance.new("TextButton", frame128)
        textButton308.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton308.Text = "Rai"
        textButton308.TextSize = 9
        textButton308.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton308.Font = Enum.Font.GothamBold
        local uICorner304 = Instance.new("UICorner", textButton308)
        local conn309 = textButton308.MouseButton1Click:Connect(function()
            textButton308.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton308.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton309 = Instance.new("TextButton", frame128)
        textButton309.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton309.Text = "Lav"
        textButton309.TextSize = 9
        textButton309.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton309.Font = Enum.Font.GothamBold
        local uICorner305 = Instance.new("UICorner", textButton309)
        local conn310 = textButton309.MouseButton1Click:Connect(function()
            textButton309.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton309.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn311 = textButton303.MouseButton1Click:Connect(function()
            frame128.Visible = true
        end)
        local conn312 = textButton304.MouseButton1Click:Connect(function()
            textButton304.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame129 = Instance.new("Frame", scrollingFrame7)
        frame129.Size = UDim2.new(1, 0, 0, 28)
        frame129.BackgroundTransparency = 1
        local textButton310 = Instance.new("TextButton", frame129)
        textButton310.Size = UDim2.new(0.72, 0, 1, 0)
        textButton310.BackgroundTransparency = 1
        textButton310.Text = "La Vacca Saturno Saturnita"
        textButton310.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton310.TextXAlignment = Enum.TextXAlignment.Left
        textButton310.Font = Enum.Font.Gotham
        textButton310.TextSize = 10
        local textButton311 = Instance.new("TextButton", frame129)
        textButton311.Size = UDim2.new(0, 16, 0, 16)
        textButton311.Position = UDim2.new(1, -20, 0.5, -8)
        textButton311.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton311.Text = ""
        local uICorner306 = Instance.new("UICorner", textButton311)
        uICorner306.CornerRadius = UDim.new(0, 3)
        local frame130 = Instance.new("Frame", scrollingFrame7)
        frame130.Size = UDim2.new(1, 0, 0, 26)
        frame130.BackgroundTransparency = 1
        frame130.Visible = false
        local uIGridLayout43 = Instance.new("UIGridLayout", frame130)
        uIGridLayout43.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout43.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton312 = Instance.new("TextButton", frame130)
        textButton312.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton312.Text = "Nor"
        textButton312.TextSize = 9
        textButton312.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton312.Font = Enum.Font.GothamBold
        local uICorner307 = Instance.new("UICorner", textButton312)
        local conn313 = textButton312.MouseButton1Click:Connect(function()
            textButton312.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton312.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton313 = Instance.new("TextButton", frame130)
        textButton313.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton313.Text = "Gol"
        textButton313.TextSize = 9
        textButton313.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton313.Font = Enum.Font.GothamBold
        local uICorner308 = Instance.new("UICorner", textButton313)
        local conn314 = textButton313.MouseButton1Click:Connect(function()
            textButton313.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton313.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton314 = Instance.new("TextButton", frame130)
        textButton314.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton314.Text = "Dia"
        textButton314.TextSize = 9
        textButton314.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton314.Font = Enum.Font.GothamBold
        local uICorner309 = Instance.new("UICorner", textButton314)
        local conn315 = textButton314.MouseButton1Click:Connect(function()
            textButton314.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton314.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton315 = Instance.new("TextButton", frame130)
        textButton315.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton315.Text = "Rai"
        textButton315.TextSize = 9
        textButton315.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton315.Font = Enum.Font.GothamBold
        local uICorner310 = Instance.new("UICorner", textButton315)
        local conn316 = textButton315.MouseButton1Click:Connect(function()
            textButton315.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton315.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton316 = Instance.new("TextButton", frame130)
        textButton316.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton316.Text = "Lav"
        textButton316.TextSize = 9
        textButton316.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton316.Font = Enum.Font.GothamBold
        local uICorner311 = Instance.new("UICorner", textButton316)
        local conn317 = textButton316.MouseButton1Click:Connect(function()
            textButton316.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton316.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn318 = textButton310.MouseButton1Click:Connect(function()
            frame130.Visible = true
        end)
        local conn319 = textButton311.MouseButton1Click:Connect(function()
            textButton311.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame131 = Instance.new("Frame", scrollingFrame7)
        frame131.Size = UDim2.new(1, 0, 0, 28)
        frame131.BackgroundTransparency = 1
        local textButton317 = Instance.new("TextButton", frame131)
        textButton317.Size = UDim2.new(0.72, 0, 1, 0)
        textButton317.BackgroundTransparency = 1
        textButton317.Text = "Esok Sekolah"
        textButton317.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton317.TextXAlignment = Enum.TextXAlignment.Left
        textButton317.Font = Enum.Font.Gotham
        textButton317.TextSize = 10
        local textButton318 = Instance.new("TextButton", frame131)
        textButton318.Size = UDim2.new(0, 16, 0, 16)
        textButton318.Position = UDim2.new(1, -20, 0.5, -8)
        textButton318.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton318.Text = ""
        local uICorner312 = Instance.new("UICorner", textButton318)
        uICorner312.CornerRadius = UDim.new(0, 3)
        local frame132 = Instance.new("Frame", scrollingFrame7)
        frame132.Size = UDim2.new(1, 0, 0, 26)
        frame132.BackgroundTransparency = 1
        frame132.Visible = false
        local uIGridLayout44 = Instance.new("UIGridLayout", frame132)
        uIGridLayout44.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout44.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton319 = Instance.new("TextButton", frame132)
        textButton319.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton319.Text = "Nor"
        textButton319.TextSize = 9
        textButton319.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton319.Font = Enum.Font.GothamBold
        local uICorner313 = Instance.new("UICorner", textButton319)
        local conn320 = textButton319.MouseButton1Click:Connect(function()
            textButton319.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton319.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton320 = Instance.new("TextButton", frame132)
        textButton320.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton320.Text = "Gol"
        textButton320.TextSize = 9
        textButton320.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton320.Font = Enum.Font.GothamBold
        local uICorner314 = Instance.new("UICorner", textButton320)
        local conn321 = textButton320.MouseButton1Click:Connect(function()
            textButton320.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton320.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton321 = Instance.new("TextButton", frame132)
        textButton321.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton321.Text = "Dia"
        textButton321.TextSize = 9
        textButton321.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton321.Font = Enum.Font.GothamBold
        local uICorner315 = Instance.new("UICorner", textButton321)
        local conn322 = textButton321.MouseButton1Click:Connect(function()
            textButton321.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton321.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton322 = Instance.new("TextButton", frame132)
        textButton322.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton322.Text = "Rai"
        textButton322.TextSize = 9
        textButton322.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton322.Font = Enum.Font.GothamBold
        local uICorner316 = Instance.new("UICorner", textButton322)
        local conn323 = textButton322.MouseButton1Click:Connect(function()
            textButton322.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton322.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton323 = Instance.new("TextButton", frame132)
        textButton323.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton323.Text = "Lav"
        textButton323.TextSize = 9
        textButton323.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton323.Font = Enum.Font.GothamBold
        local uICorner317 = Instance.new("UICorner", textButton323)
        local conn324 = textButton323.MouseButton1Click:Connect(function()
            textButton323.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton323.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn325 = textButton317.MouseButton1Click:Connect(function()
            frame132.Visible = true
        end)
        local conn326 = textButton318.MouseButton1Click:Connect(function()
            textButton318.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame133 = Instance.new("Frame", scrollingFrame7)
        frame133.Size = UDim2.new(1, 0, 0, 28)
        frame133.BackgroundTransparency = 1
        local textButton324 = Instance.new("TextButton", frame133)
        textButton324.Size = UDim2.new(0.72, 0, 1, 0)
        textButton324.BackgroundTransparency = 1
        textButton324.Text = "Tralaledon"
        textButton324.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton324.TextXAlignment = Enum.TextXAlignment.Left
        textButton324.Font = Enum.Font.Gotham
        textButton324.TextSize = 10
        local textButton325 = Instance.new("TextButton", frame133)
        textButton325.Size = UDim2.new(0, 16, 0, 16)
        textButton325.Position = UDim2.new(1, -20, 0.5, -8)
        textButton325.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton325.Text = ""
        local uICorner318 = Instance.new("UICorner", textButton325)
        uICorner318.CornerRadius = UDim.new(0, 3)
        local frame134 = Instance.new("Frame", scrollingFrame7)
        frame134.Size = UDim2.new(1, 0, 0, 26)
        frame134.BackgroundTransparency = 1
        frame134.Visible = false
        local uIGridLayout45 = Instance.new("UIGridLayout", frame134)
        uIGridLayout45.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout45.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton326 = Instance.new("TextButton", frame134)
        textButton326.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton326.Text = "Nor"
        textButton326.TextSize = 9
        textButton326.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton326.Font = Enum.Font.GothamBold
        local uICorner319 = Instance.new("UICorner", textButton326)
        local conn327 = textButton326.MouseButton1Click:Connect(function()
            textButton326.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton326.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton327 = Instance.new("TextButton", frame134)
        textButton327.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton327.Text = "Gol"
        textButton327.TextSize = 9
        textButton327.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton327.Font = Enum.Font.GothamBold
        local uICorner320 = Instance.new("UICorner", textButton327)
        local conn328 = textButton327.MouseButton1Click:Connect(function()
            textButton327.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton327.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton328 = Instance.new("TextButton", frame134)
        textButton328.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton328.Text = "Dia"
        textButton328.TextSize = 9
        textButton328.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton328.Font = Enum.Font.GothamBold
        local uICorner321 = Instance.new("UICorner", textButton328)
        local conn329 = textButton328.MouseButton1Click:Connect(function()
            textButton328.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton328.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton329 = Instance.new("TextButton", frame134)
        textButton329.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton329.Text = "Rai"
        textButton329.TextSize = 9
        textButton329.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton329.Font = Enum.Font.GothamBold
        local uICorner322 = Instance.new("UICorner", textButton329)
        local conn330 = textButton329.MouseButton1Click:Connect(function()
            textButton329.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton329.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton330 = Instance.new("TextButton", frame134)
        textButton330.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton330.Text = "Lav"
        textButton330.TextSize = 9
        textButton330.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton330.Font = Enum.Font.GothamBold
        local uICorner323 = Instance.new("UICorner", textButton330)
        local conn331 = textButton330.MouseButton1Click:Connect(function()
            textButton330.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton330.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn332 = textButton324.MouseButton1Click:Connect(function()
            frame134.Visible = true
        end)
        local conn333 = textButton325.MouseButton1Click:Connect(function()
            textButton325.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame135 = Instance.new("Frame", scrollingFrame7)
        frame135.Size = UDim2.new(1, 0, 0, 28)
        frame135.BackgroundTransparency = 1
        local textButton331 = Instance.new("TextButton", frame135)
        textButton331.Size = UDim2.new(0.72, 0, 1, 0)
        textButton331.BackgroundTransparency = 1
        textButton331.Text = "Tralalero Tralala"
        textButton331.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton331.TextXAlignment = Enum.TextXAlignment.Left
        textButton331.Font = Enum.Font.Gotham
        textButton331.TextSize = 10
        local textButton332 = Instance.new("TextButton", frame135)
        textButton332.Size = UDim2.new(0, 16, 0, 16)
        textButton332.Position = UDim2.new(1, -20, 0.5, -8)
        textButton332.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton332.Text = ""
        local uICorner324 = Instance.new("UICorner", textButton332)
        uICorner324.CornerRadius = UDim.new(0, 3)
        local frame136 = Instance.new("Frame", scrollingFrame7)
        frame136.Size = UDim2.new(1, 0, 0, 26)
        frame136.BackgroundTransparency = 1
        frame136.Visible = false
        local uIGridLayout46 = Instance.new("UIGridLayout", frame136)
        uIGridLayout46.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout46.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton333 = Instance.new("TextButton", frame136)
        textButton333.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton333.Text = "Nor"
        textButton333.TextSize = 9
        textButton333.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton333.Font = Enum.Font.GothamBold
        local uICorner325 = Instance.new("UICorner", textButton333)
        local conn334 = textButton333.MouseButton1Click:Connect(function()
            textButton333.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton333.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton334 = Instance.new("TextButton", frame136)
        textButton334.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton334.Text = "Gol"
        textButton334.TextSize = 9
        textButton334.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton334.Font = Enum.Font.GothamBold
        local uICorner326 = Instance.new("UICorner", textButton334)
        local conn335 = textButton334.MouseButton1Click:Connect(function()
            textButton334.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton334.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton335 = Instance.new("TextButton", frame136)
        textButton335.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton335.Text = "Dia"
        textButton335.TextSize = 9
        textButton335.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton335.Font = Enum.Font.GothamBold
        local uICorner327 = Instance.new("UICorner", textButton335)
        local conn336 = textButton335.MouseButton1Click:Connect(function()
            textButton335.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton335.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton336 = Instance.new("TextButton", frame136)
        textButton336.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton336.Text = "Rai"
        textButton336.TextSize = 9
        textButton336.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton336.Font = Enum.Font.GothamBold
        local uICorner328 = Instance.new("UICorner", textButton336)
        local conn337 = textButton336.MouseButton1Click:Connect(function()
            textButton336.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton336.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton337 = Instance.new("TextButton", frame136)
        textButton337.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton337.Text = "Lav"
        textButton337.TextSize = 9
        textButton337.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton337.Font = Enum.Font.GothamBold
        local uICorner329 = Instance.new("UICorner", textButton337)
        local conn338 = textButton337.MouseButton1Click:Connect(function()
            textButton337.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton337.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn339 = textButton331.MouseButton1Click:Connect(function()
            frame136.Visible = true
        end)
        local conn340 = textButton332.MouseButton1Click:Connect(function()
            textButton332.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame137 = Instance.new("Frame", scrollingFrame7)
        frame137.Size = UDim2.new(1, 0, 0, 28)
        frame137.BackgroundTransparency = 1
        local textButton338 = Instance.new("TextButton", frame137)
        textButton338.Size = UDim2.new(0.72, 0, 1, 0)
        textButton338.BackgroundTransparency = 1
        textButton338.Text = "Chicleteira Bicicleteira"
        textButton338.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton338.TextXAlignment = Enum.TextXAlignment.Left
        textButton338.Font = Enum.Font.Gotham
        textButton338.TextSize = 10
        local textButton339 = Instance.new("TextButton", frame137)
        textButton339.Size = UDim2.new(0, 16, 0, 16)
        textButton339.Position = UDim2.new(1, -20, 0.5, -8)
        textButton339.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton339.Text = ""
        local uICorner330 = Instance.new("UICorner", textButton339)
        uICorner330.CornerRadius = UDim.new(0, 3)
        local frame138 = Instance.new("Frame", scrollingFrame7)
        frame138.Size = UDim2.new(1, 0, 0, 26)
        frame138.BackgroundTransparency = 1
        frame138.Visible = false
        local uIGridLayout47 = Instance.new("UIGridLayout", frame138)
        uIGridLayout47.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout47.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton340 = Instance.new("TextButton", frame138)
        textButton340.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton340.Text = "Nor"
        textButton340.TextSize = 9
        textButton340.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton340.Font = Enum.Font.GothamBold
        local uICorner331 = Instance.new("UICorner", textButton340)
        local conn341 = textButton340.MouseButton1Click:Connect(function()
            textButton340.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton340.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton341 = Instance.new("TextButton", frame138)
        textButton341.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton341.Text = "Gol"
        textButton341.TextSize = 9
        textButton341.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton341.Font = Enum.Font.GothamBold
        local uICorner332 = Instance.new("UICorner", textButton341)
        local conn342 = textButton341.MouseButton1Click:Connect(function()
            textButton341.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton341.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton342 = Instance.new("TextButton", frame138)
        textButton342.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton342.Text = "Dia"
        textButton342.TextSize = 9
        textButton342.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton342.Font = Enum.Font.GothamBold
        local uICorner333 = Instance.new("UICorner", textButton342)
        local conn343 = textButton342.MouseButton1Click:Connect(function()
            textButton342.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton342.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton343 = Instance.new("TextButton", frame138)
        textButton343.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton343.Text = "Rai"
        textButton343.TextSize = 9
        textButton343.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton343.Font = Enum.Font.GothamBold
        local uICorner334 = Instance.new("UICorner", textButton343)
        local conn344 = textButton343.MouseButton1Click:Connect(function()
            textButton343.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton343.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton344 = Instance.new("TextButton", frame138)
        textButton344.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton344.Text = "Lav"
        textButton344.TextSize = 9
        textButton344.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton344.Font = Enum.Font.GothamBold
        local uICorner335 = Instance.new("UICorner", textButton344)
        local conn345 = textButton344.MouseButton1Click:Connect(function()
            textButton344.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton344.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn346 = textButton338.MouseButton1Click:Connect(function()
            frame138.Visible = true
        end)
        local conn347 = textButton339.MouseButton1Click:Connect(function()
            textButton339.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame139 = Instance.new("Frame", scrollingFrame7)
        frame139.Size = UDim2.new(1, 0, 0, 28)
        frame139.BackgroundTransparency = 1
        local textButton345 = Instance.new("TextButton", frame139)
        textButton345.Size = UDim2.new(0.72, 0, 1, 0)
        textButton345.BackgroundTransparency = 1
        textButton345.Text = "Torrtuginni Dragonfrutini"
        textButton345.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton345.TextXAlignment = Enum.TextXAlignment.Left
        textButton345.Font = Enum.Font.Gotham
        textButton345.TextSize = 10
        local textButton346 = Instance.new("TextButton", frame139)
        textButton346.Size = UDim2.new(0, 16, 0, 16)
        textButton346.Position = UDim2.new(1, -20, 0.5, -8)
        textButton346.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton346.Text = ""
        local uICorner336 = Instance.new("UICorner", textButton346)
        uICorner336.CornerRadius = UDim.new(0, 3)
        local frame140 = Instance.new("Frame", scrollingFrame7)
        frame140.Size = UDim2.new(1, 0, 0, 26)
        frame140.BackgroundTransparency = 1
        frame140.Visible = false
        local uIGridLayout48 = Instance.new("UIGridLayout", frame140)
        uIGridLayout48.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout48.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton347 = Instance.new("TextButton", frame140)
        textButton347.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton347.Text = "Nor"
        textButton347.TextSize = 9
        textButton347.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton347.Font = Enum.Font.GothamBold
        local uICorner337 = Instance.new("UICorner", textButton347)
        local conn348 = textButton347.MouseButton1Click:Connect(function()
            textButton347.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton347.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton348 = Instance.new("TextButton", frame140)
        textButton348.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton348.Text = "Gol"
        textButton348.TextSize = 9
        textButton348.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton348.Font = Enum.Font.GothamBold
        local uICorner338 = Instance.new("UICorner", textButton348)
        local conn349 = textButton348.MouseButton1Click:Connect(function()
            textButton348.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton348.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton349 = Instance.new("TextButton", frame140)
        textButton349.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton349.Text = "Dia"
        textButton349.TextSize = 9
        textButton349.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton349.Font = Enum.Font.GothamBold
        local uICorner339 = Instance.new("UICorner", textButton349)
        local conn350 = textButton349.MouseButton1Click:Connect(function()
            textButton349.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton349.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton350 = Instance.new("TextButton", frame140)
        textButton350.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton350.Text = "Rai"
        textButton350.TextSize = 9
        textButton350.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton350.Font = Enum.Font.GothamBold
        local uICorner340 = Instance.new("UICorner", textButton350)
        local conn351 = textButton350.MouseButton1Click:Connect(function()
            textButton350.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton350.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton351 = Instance.new("TextButton", frame140)
        textButton351.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton351.Text = "Lav"
        textButton351.TextSize = 9
        textButton351.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton351.Font = Enum.Font.GothamBold
        local uICorner341 = Instance.new("UICorner", textButton351)
        local conn352 = textButton351.MouseButton1Click:Connect(function()
            textButton351.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton351.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn353 = textButton345.MouseButton1Click:Connect(function()
            frame140.Visible = true
        end)
        local conn354 = textButton346.MouseButton1Click:Connect(function()
            textButton346.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame141 = Instance.new("Frame", scrollingFrame7)
        frame141.Size = UDim2.new(1, 0, 0, 28)
        frame141.BackgroundTransparency = 1
        local textButton352 = Instance.new("TextButton", frame141)
        textButton352.Size = UDim2.new(0.72, 0, 1, 0)
        textButton352.BackgroundTransparency = 1
        textButton352.Text = "Nuclearo Dinosauru"
        textButton352.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton352.TextXAlignment = Enum.TextXAlignment.Left
        textButton352.Font = Enum.Font.Gotham
        textButton352.TextSize = 10
        local textButton353 = Instance.new("TextButton", frame141)
        textButton353.Size = UDim2.new(0, 16, 0, 16)
        textButton353.Position = UDim2.new(1, -20, 0.5, -8)
        textButton353.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton353.Text = ""
        local uICorner342 = Instance.new("UICorner", textButton353)
        uICorner342.CornerRadius = UDim.new(0, 3)
        local frame142 = Instance.new("Frame", scrollingFrame7)
        frame142.Size = UDim2.new(1, 0, 0, 26)
        frame142.BackgroundTransparency = 1
        frame142.Visible = false
        local uIGridLayout49 = Instance.new("UIGridLayout", frame142)
        uIGridLayout49.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout49.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton354 = Instance.new("TextButton", frame142)
        textButton354.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton354.Text = "Nor"
        textButton354.TextSize = 9
        textButton354.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton354.Font = Enum.Font.GothamBold
        local uICorner343 = Instance.new("UICorner", textButton354)
        local conn355 = textButton354.MouseButton1Click:Connect(function()
            textButton354.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton354.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton355 = Instance.new("TextButton", frame142)
        textButton355.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton355.Text = "Gol"
        textButton355.TextSize = 9
        textButton355.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton355.Font = Enum.Font.GothamBold
        local uICorner344 = Instance.new("UICorner", textButton355)
        local conn356 = textButton355.MouseButton1Click:Connect(function()
            textButton355.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton355.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton356 = Instance.new("TextButton", frame142)
        textButton356.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton356.Text = "Dia"
        textButton356.TextSize = 9
        textButton356.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton356.Font = Enum.Font.GothamBold
        local uICorner345 = Instance.new("UICorner", textButton356)
        local conn357 = textButton356.MouseButton1Click:Connect(function()
            textButton356.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton356.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton357 = Instance.new("TextButton", frame142)
        textButton357.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton357.Text = "Rai"
        textButton357.TextSize = 9
        textButton357.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton357.Font = Enum.Font.GothamBold
        local uICorner346 = Instance.new("UICorner", textButton357)
        local conn358 = textButton357.MouseButton1Click:Connect(function()
            textButton357.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton357.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton358 = Instance.new("TextButton", frame142)
        textButton358.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton358.Text = "Lav"
        textButton358.TextSize = 9
        textButton358.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton358.Font = Enum.Font.GothamBold
        local uICorner347 = Instance.new("UICorner", textButton358)
        local conn359 = textButton358.MouseButton1Click:Connect(function()
            textButton358.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton358.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn360 = textButton352.MouseButton1Click:Connect(function()
            frame142.Visible = true
        end)
        local conn361 = textButton353.MouseButton1Click:Connect(function()
            textButton353.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame143 = Instance.new("Frame", scrollingFrame7)
        frame143.Size = UDim2.new(1, 0, 0, 28)
        frame143.BackgroundTransparency = 1
        local textButton359 = Instance.new("TextButton", frame143)
        textButton359.Size = UDim2.new(0.72, 0, 1, 0)
        textButton359.BackgroundTransparency = 1
        textButton359.Text = "Quesadilla Crocodila"
        textButton359.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton359.TextXAlignment = Enum.TextXAlignment.Left
        textButton359.Font = Enum.Font.Gotham
        textButton359.TextSize = 10
        local textButton360 = Instance.new("TextButton", frame143)
        textButton360.Size = UDim2.new(0, 16, 0, 16)
        textButton360.Position = UDim2.new(1, -20, 0.5, -8)
        textButton360.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton360.Text = ""
        local uICorner348 = Instance.new("UICorner", textButton360)
        uICorner348.CornerRadius = UDim.new(0, 3)
        local frame144 = Instance.new("Frame", scrollingFrame7)
        frame144.Size = UDim2.new(1, 0, 0, 26)
        frame144.BackgroundTransparency = 1
        frame144.Visible = false
        local uIGridLayout50 = Instance.new("UIGridLayout", frame144)
        uIGridLayout50.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout50.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton361 = Instance.new("TextButton", frame144)
        textButton361.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton361.Text = "Nor"
        textButton361.TextSize = 9
        textButton361.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton361.Font = Enum.Font.GothamBold
        local uICorner349 = Instance.new("UICorner", textButton361)
        local conn362 = textButton361.MouseButton1Click:Connect(function()
            textButton361.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton361.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton362 = Instance.new("TextButton", frame144)
        textButton362.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton362.Text = "Gol"
        textButton362.TextSize = 9
        textButton362.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton362.Font = Enum.Font.GothamBold
        local uICorner350 = Instance.new("UICorner", textButton362)
        local conn363 = textButton362.MouseButton1Click:Connect(function()
            textButton362.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton362.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton363 = Instance.new("TextButton", frame144)
        textButton363.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton363.Text = "Dia"
        textButton363.TextSize = 9
        textButton363.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton363.Font = Enum.Font.GothamBold
        local uICorner351 = Instance.new("UICorner", textButton363)
        local conn364 = textButton363.MouseButton1Click:Connect(function()
            textButton363.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton363.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton364 = Instance.new("TextButton", frame144)
        textButton364.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton364.Text = "Rai"
        textButton364.TextSize = 9
        textButton364.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton364.Font = Enum.Font.GothamBold
        local uICorner352 = Instance.new("UICorner", textButton364)
        local conn365 = textButton364.MouseButton1Click:Connect(function()
            textButton364.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton364.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton365 = Instance.new("TextButton", frame144)
        textButton365.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton365.Text = "Lav"
        textButton365.TextSize = 9
        textButton365.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton365.Font = Enum.Font.GothamBold
        local uICorner353 = Instance.new("UICorner", textButton365)
        local conn366 = textButton365.MouseButton1Click:Connect(function()
            textButton365.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton365.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn367 = textButton359.MouseButton1Click:Connect(function()
            frame144.Visible = true
        end)
        local conn368 = textButton360.MouseButton1Click:Connect(function()
            textButton360.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame145 = Instance.new("Frame", scrollingFrame7)
        frame145.Size = UDim2.new(1, 0, 0, 28)
        frame145.BackgroundTransparency = 1
        local textButton366 = Instance.new("TextButton", frame145)
        textButton366.Size = UDim2.new(0.72, 0, 1, 0)
        textButton366.BackgroundTransparency = 1
        textButton366.Text = "Graipussi Medussi"
        textButton366.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton366.TextXAlignment = Enum.TextXAlignment.Left
        textButton366.Font = Enum.Font.Gotham
        textButton366.TextSize = 10
        local textButton367 = Instance.new("TextButton", frame145)
        textButton367.Size = UDim2.new(0, 16, 0, 16)
        textButton367.Position = UDim2.new(1, -20, 0.5, -8)
        textButton367.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton367.Text = ""
        local uICorner354 = Instance.new("UICorner", textButton367)
        uICorner354.CornerRadius = UDim.new(0, 3)
        local frame146 = Instance.new("Frame", scrollingFrame7)
        frame146.Size = UDim2.new(1, 0, 0, 26)
        frame146.BackgroundTransparency = 1
        frame146.Visible = false
        local uIGridLayout51 = Instance.new("UIGridLayout", frame146)
        uIGridLayout51.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout51.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton368 = Instance.new("TextButton", frame146)
        textButton368.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton368.Text = "Nor"
        textButton368.TextSize = 9
        textButton368.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton368.Font = Enum.Font.GothamBold
        local uICorner355 = Instance.new("UICorner", textButton368)
        local conn369 = textButton368.MouseButton1Click:Connect(function()
            textButton368.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton368.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton369 = Instance.new("TextButton", frame146)
        textButton369.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton369.Text = "Gol"
        textButton369.TextSize = 9
        textButton369.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton369.Font = Enum.Font.GothamBold
        local uICorner356 = Instance.new("UICorner", textButton369)
        local conn370 = textButton369.MouseButton1Click:Connect(function()
            textButton369.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton369.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton370 = Instance.new("TextButton", frame146)
        textButton370.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton370.Text = "Dia"
        textButton370.TextSize = 9
        textButton370.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton370.Font = Enum.Font.GothamBold
        local uICorner357 = Instance.new("UICorner", textButton370)
        local conn371 = textButton370.MouseButton1Click:Connect(function()
            textButton370.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton370.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton371 = Instance.new("TextButton", frame146)
        textButton371.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton371.Text = "Rai"
        textButton371.TextSize = 9
        textButton371.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton371.Font = Enum.Font.GothamBold
        local uICorner358 = Instance.new("UICorner", textButton371)
        local conn372 = textButton371.MouseButton1Click:Connect(function()
            textButton371.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton371.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton372 = Instance.new("TextButton", frame146)
        textButton372.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton372.Text = "Lav"
        textButton372.TextSize = 9
        textButton372.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton372.Font = Enum.Font.GothamBold
        local uICorner359 = Instance.new("UICorner", textButton372)
        local conn373 = textButton372.MouseButton1Click:Connect(function()
            textButton372.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton372.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn374 = textButton366.MouseButton1Click:Connect(function()
            frame146.Visible = true
        end)
        local conn375 = textButton367.MouseButton1Click:Connect(function()
            textButton367.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame147 = Instance.new("Frame", scrollingFrame7)
        frame147.Size = UDim2.new(1, 0, 0, 28)
        frame147.BackgroundTransparency = 1
        local textButton373 = Instance.new("TextButton", frame147)
        textButton373.Size = UDim2.new(0.72, 0, 1, 0)
        textButton373.BackgroundTransparency = 1
        textButton373.Text = "Caramelini Brasilini"
        textButton373.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton373.TextXAlignment = Enum.TextXAlignment.Left
        textButton373.Font = Enum.Font.Gotham
        textButton373.TextSize = 10
        local textButton374 = Instance.new("TextButton", frame147)
        textButton374.Size = UDim2.new(0, 16, 0, 16)
        textButton374.Position = UDim2.new(1, -20, 0.5, -8)
        textButton374.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton374.Text = ""
        local uICorner360 = Instance.new("UICorner", textButton374)
        uICorner360.CornerRadius = UDim.new(0, 3)
        local frame148 = Instance.new("Frame", scrollingFrame7)
        frame148.Size = UDim2.new(1, 0, 0, 26)
        frame148.BackgroundTransparency = 1
        frame148.Visible = false
        local uIGridLayout52 = Instance.new("UIGridLayout", frame148)
        uIGridLayout52.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout52.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton375 = Instance.new("TextButton", frame148)
        textButton375.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton375.Text = "Nor"
        textButton375.TextSize = 9
        textButton375.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton375.Font = Enum.Font.GothamBold
        local uICorner361 = Instance.new("UICorner", textButton375)
        local conn376 = textButton375.MouseButton1Click:Connect(function()
            textButton375.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton375.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton376 = Instance.new("TextButton", frame148)
        textButton376.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton376.Text = "Gol"
        textButton376.TextSize = 9
        textButton376.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton376.Font = Enum.Font.GothamBold
        local uICorner362 = Instance.new("UICorner", textButton376)
        local conn377 = textButton376.MouseButton1Click:Connect(function()
            textButton376.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton376.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton377 = Instance.new("TextButton", frame148)
        textButton377.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton377.Text = "Dia"
        textButton377.TextSize = 9
        textButton377.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton377.Font = Enum.Font.GothamBold
        local uICorner363 = Instance.new("UICorner", textButton377)
        local conn378 = textButton377.MouseButton1Click:Connect(function()
            textButton377.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton377.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton378 = Instance.new("TextButton", frame148)
        textButton378.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton378.Text = "Rai"
        textButton378.TextSize = 9
        textButton378.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton378.Font = Enum.Font.GothamBold
        local uICorner364 = Instance.new("UICorner", textButton378)
        local conn379 = textButton378.MouseButton1Click:Connect(function()
            textButton378.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton378.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton379 = Instance.new("TextButton", frame148)
        textButton379.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton379.Text = "Lav"
        textButton379.TextSize = 9
        textButton379.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton379.Font = Enum.Font.GothamBold
        local uICorner365 = Instance.new("UICorner", textButton379)
        local conn380 = textButton379.MouseButton1Click:Connect(function()
            textButton379.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton379.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn381 = textButton373.MouseButton1Click:Connect(function()
            frame148.Visible = true
        end)
        local conn382 = textButton374.MouseButton1Click:Connect(function()
            textButton374.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame149 = Instance.new("Frame", scrollingFrame7)
        frame149.Size = UDim2.new(1, 0, 0, 28)
        frame149.BackgroundTransparency = 1
        local textButton380 = Instance.new("TextButton", frame149)
        textButton380.Size = UDim2.new(0.72, 0, 1, 0)
        textButton380.BackgroundTransparency = 1
        textButton380.Text = "Garama and Madundung"
        textButton380.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton380.TextXAlignment = Enum.TextXAlignment.Left
        textButton380.Font = Enum.Font.Gotham
        textButton380.TextSize = 10
        local textButton381 = Instance.new("TextButton", frame149)
        textButton381.Size = UDim2.new(0, 16, 0, 16)
        textButton381.Position = UDim2.new(1, -20, 0.5, -8)
        textButton381.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton381.Text = ""
        local uICorner366 = Instance.new("UICorner", textButton381)
        uICorner366.CornerRadius = UDim.new(0, 3)
        local frame150 = Instance.new("Frame", scrollingFrame7)
        frame150.Size = UDim2.new(1, 0, 0, 26)
        frame150.BackgroundTransparency = 1
        frame150.Visible = false
        local uIGridLayout53 = Instance.new("UIGridLayout", frame150)
        uIGridLayout53.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout53.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton382 = Instance.new("TextButton", frame150)
        textButton382.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton382.Text = "Nor"
        textButton382.TextSize = 9
        textButton382.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton382.Font = Enum.Font.GothamBold
        local uICorner367 = Instance.new("UICorner", textButton382)
        local conn383 = textButton382.MouseButton1Click:Connect(function()
            textButton382.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton382.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton383 = Instance.new("TextButton", frame150)
        textButton383.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton383.Text = "Gol"
        textButton383.TextSize = 9
        textButton383.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton383.Font = Enum.Font.GothamBold
        local uICorner368 = Instance.new("UICorner", textButton383)
        local conn384 = textButton383.MouseButton1Click:Connect(function()
            textButton383.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton383.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton384 = Instance.new("TextButton", frame150)
        textButton384.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton384.Text = "Dia"
        textButton384.TextSize = 9
        textButton384.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton384.Font = Enum.Font.GothamBold
        local uICorner369 = Instance.new("UICorner", textButton384)
        local conn385 = textButton384.MouseButton1Click:Connect(function()
            textButton384.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton384.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton385 = Instance.new("TextButton", frame150)
        textButton385.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton385.Text = "Rai"
        textButton385.TextSize = 9
        textButton385.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton385.Font = Enum.Font.GothamBold
        local uICorner370 = Instance.new("UICorner", textButton385)
        local conn386 = textButton385.MouseButton1Click:Connect(function()
            textButton385.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton385.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton386 = Instance.new("TextButton", frame150)
        textButton386.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton386.Text = "Lav"
        textButton386.TextSize = 9
        textButton386.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton386.Font = Enum.Font.GothamBold
        local uICorner371 = Instance.new("UICorner", textButton386)
        local conn387 = textButton386.MouseButton1Click:Connect(function()
            textButton386.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton386.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn388 = textButton380.MouseButton1Click:Connect(function()
            frame150.Visible = true
        end)
        local conn389 = textButton381.MouseButton1Click:Connect(function()
            textButton381.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame151 = Instance.new("Frame", scrollingFrame7)
        frame151.Size = UDim2.new(1, 0, 0, 28)
        frame151.BackgroundTransparency = 1
        local textButton387 = Instance.new("TextButton", frame151)
        textButton387.Size = UDim2.new(0.72, 0, 1, 0)
        textButton387.BackgroundTransparency = 1
        textButton387.Text = "Meowl"
        textButton387.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton387.TextXAlignment = Enum.TextXAlignment.Left
        textButton387.Font = Enum.Font.Gotham
        textButton387.TextSize = 10
        local textButton388 = Instance.new("TextButton", frame151)
        textButton388.Size = UDim2.new(0, 16, 0, 16)
        textButton388.Position = UDim2.new(1, -20, 0.5, -8)
        textButton388.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton388.Text = ""
        local uICorner372 = Instance.new("UICorner", textButton388)
        uICorner372.CornerRadius = UDim.new(0, 3)
        local frame152 = Instance.new("Frame", scrollingFrame7)
        frame152.Size = UDim2.new(1, 0, 0, 26)
        frame152.BackgroundTransparency = 1
        frame152.Visible = false
        local uIGridLayout54 = Instance.new("UIGridLayout", frame152)
        uIGridLayout54.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout54.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton389 = Instance.new("TextButton", frame152)
        textButton389.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton389.Text = "Nor"
        textButton389.TextSize = 9
        textButton389.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton389.Font = Enum.Font.GothamBold
        local uICorner373 = Instance.new("UICorner", textButton389)
        local conn390 = textButton389.MouseButton1Click:Connect(function()
            textButton389.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton389.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton390 = Instance.new("TextButton", frame152)
        textButton390.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton390.Text = "Gol"
        textButton390.TextSize = 9
        textButton390.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton390.Font = Enum.Font.GothamBold
        local uICorner374 = Instance.new("UICorner", textButton390)
        local conn391 = textButton390.MouseButton1Click:Connect(function()
            textButton390.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton390.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton391 = Instance.new("TextButton", frame152)
        textButton391.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton391.Text = "Dia"
        textButton391.TextSize = 9
        textButton391.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton391.Font = Enum.Font.GothamBold
        local uICorner375 = Instance.new("UICorner", textButton391)
        local conn392 = textButton391.MouseButton1Click:Connect(function()
            textButton391.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton391.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton392 = Instance.new("TextButton", frame152)
        textButton392.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton392.Text = "Rai"
        textButton392.TextSize = 9
        textButton392.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton392.Font = Enum.Font.GothamBold
        local uICorner376 = Instance.new("UICorner", textButton392)
        local conn393 = textButton392.MouseButton1Click:Connect(function()
            textButton392.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton392.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton393 = Instance.new("TextButton", frame152)
        textButton393.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton393.Text = "Lav"
        textButton393.TextSize = 9
        textButton393.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton393.Font = Enum.Font.GothamBold
        local uICorner377 = Instance.new("UICorner", textButton393)
        local conn394 = textButton393.MouseButton1Click:Connect(function()
            textButton393.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton393.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn395 = textButton387.MouseButton1Click:Connect(function()
            frame152.Visible = true
        end)
        local conn396 = textButton388.MouseButton1Click:Connect(function()
            textButton388.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame153 = Instance.new("Frame", scrollingFrame7)
        frame153.Size = UDim2.new(1, 0, 0, 28)
        frame153.BackgroundTransparency = 1
        local textButton394 = Instance.new("TextButton", frame153)
        textButton394.Size = UDim2.new(0.72, 0, 1, 0)
        textButton394.BackgroundTransparency = 1
        textButton394.Text = "Smurf Cat"
        textButton394.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton394.TextXAlignment = Enum.TextXAlignment.Left
        textButton394.Font = Enum.Font.Gotham
        textButton394.TextSize = 10
        local textButton395 = Instance.new("TextButton", frame153)
        textButton395.Size = UDim2.new(0, 16, 0, 16)
        textButton395.Position = UDim2.new(1, -20, 0.5, -8)
        textButton395.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton395.Text = ""
        local uICorner378 = Instance.new("UICorner", textButton395)
        uICorner378.CornerRadius = UDim.new(0, 3)
        local frame154 = Instance.new("Frame", scrollingFrame7)
        frame154.Size = UDim2.new(1, 0, 0, 26)
        frame154.BackgroundTransparency = 1
        frame154.Visible = false
        local uIGridLayout55 = Instance.new("UIGridLayout", frame154)
        uIGridLayout55.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout55.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton396 = Instance.new("TextButton", frame154)
        textButton396.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton396.Text = "Nor"
        textButton396.TextSize = 9
        textButton396.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton396.Font = Enum.Font.GothamBold
        local uICorner379 = Instance.new("UICorner", textButton396)
        local conn397 = textButton396.MouseButton1Click:Connect(function()
            textButton396.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton396.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton397 = Instance.new("TextButton", frame154)
        textButton397.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton397.Text = "Gol"
        textButton397.TextSize = 9
        textButton397.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton397.Font = Enum.Font.GothamBold
        local uICorner380 = Instance.new("UICorner", textButton397)
        local conn398 = textButton397.MouseButton1Click:Connect(function()
            textButton397.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton397.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton398 = Instance.new("TextButton", frame154)
        textButton398.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton398.Text = "Dia"
        textButton398.TextSize = 9
        textButton398.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton398.Font = Enum.Font.GothamBold
        local uICorner381 = Instance.new("UICorner", textButton398)
        local conn399 = textButton398.MouseButton1Click:Connect(function()
            textButton398.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton398.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton399 = Instance.new("TextButton", frame154)
        textButton399.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton399.Text = "Rai"
        textButton399.TextSize = 9
        textButton399.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton399.Font = Enum.Font.GothamBold
        local uICorner382 = Instance.new("UICorner", textButton399)
        local conn400 = textButton399.MouseButton1Click:Connect(function()
            textButton399.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton399.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton400 = Instance.new("TextButton", frame154)
        textButton400.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton400.Text = "Lav"
        textButton400.TextSize = 9
        textButton400.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton400.Font = Enum.Font.GothamBold
        local uICorner383 = Instance.new("UICorner", textButton400)
        local conn401 = textButton400.MouseButton1Click:Connect(function()
            textButton400.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton400.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn402 = textButton394.MouseButton1Click:Connect(function()
            frame154.Visible = true
        end)
        local conn403 = textButton395.MouseButton1Click:Connect(function()
            textButton395.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame155 = Instance.new("Frame", scrollingFrame7)
        frame155.Size = UDim2.new(1, 0, 0, 28)
        frame155.BackgroundTransparency = 1
        local textButton401 = Instance.new("TextButton", frame155)
        textButton401.Size = UDim2.new(0.72, 0, 1, 0)
        textButton401.BackgroundTransparency = 1
        textButton401.Text = "Capitano Clash Warnini"
        textButton401.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton401.TextXAlignment = Enum.TextXAlignment.Left
        textButton401.Font = Enum.Font.Gotham
        textButton401.TextSize = 10
        local textButton402 = Instance.new("TextButton", frame155)
        textButton402.Size = UDim2.new(0, 16, 0, 16)
        textButton402.Position = UDim2.new(1, -20, 0.5, -8)
        textButton402.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton402.Text = ""
        local uICorner384 = Instance.new("UICorner", textButton402)
        uICorner384.CornerRadius = UDim.new(0, 3)
        local frame156 = Instance.new("Frame", scrollingFrame7)
        frame156.Size = UDim2.new(1, 0, 0, 26)
        frame156.BackgroundTransparency = 1
        frame156.Visible = false
        local uIGridLayout56 = Instance.new("UIGridLayout", frame156)
        uIGridLayout56.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout56.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton403 = Instance.new("TextButton", frame156)
        textButton403.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton403.Text = "Nor"
        textButton403.TextSize = 9
        textButton403.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton403.Font = Enum.Font.GothamBold
        local uICorner385 = Instance.new("UICorner", textButton403)
        local conn404 = textButton403.MouseButton1Click:Connect(function()
            textButton403.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton403.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton404 = Instance.new("TextButton", frame156)
        textButton404.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton404.Text = "Gol"
        textButton404.TextSize = 9
        textButton404.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton404.Font = Enum.Font.GothamBold
        local uICorner386 = Instance.new("UICorner", textButton404)
        local conn405 = textButton404.MouseButton1Click:Connect(function()
            textButton404.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton404.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton405 = Instance.new("TextButton", frame156)
        textButton405.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton405.Text = "Dia"
        textButton405.TextSize = 9
        textButton405.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton405.Font = Enum.Font.GothamBold
        local uICorner387 = Instance.new("UICorner", textButton405)
        local conn406 = textButton405.MouseButton1Click:Connect(function()
            textButton405.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton405.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton406 = Instance.new("TextButton", frame156)
        textButton406.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton406.Text = "Rai"
        textButton406.TextSize = 9
        textButton406.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton406.Font = Enum.Font.GothamBold
        local uICorner388 = Instance.new("UICorner", textButton406)
        local conn407 = textButton406.MouseButton1Click:Connect(function()
            textButton406.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton406.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton407 = Instance.new("TextButton", frame156)
        textButton407.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton407.Text = "Lav"
        textButton407.TextSize = 9
        textButton407.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton407.Font = Enum.Font.GothamBold
        local uICorner389 = Instance.new("UICorner", textButton407)
        local conn408 = textButton407.MouseButton1Click:Connect(function()
            textButton407.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton407.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn409 = textButton401.MouseButton1Click:Connect(function()
            frame156.Visible = true
        end)
        local conn410 = textButton402.MouseButton1Click:Connect(function()
            textButton402.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame157 = Instance.new("Frame", scrollingFrame7)
        frame157.Size = UDim2.new(1, 0, 0, 28)
        frame157.BackgroundTransparency = 1
        local textButton408 = Instance.new("TextButton", frame157)
        textButton408.Size = UDim2.new(0.72, 0, 1, 0)
        textButton408.BackgroundTransparency = 1
        textButton408.Text = "Strawberry Elephant"
        textButton408.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton408.TextXAlignment = Enum.TextXAlignment.Left
        textButton408.Font = Enum.Font.Gotham
        textButton408.TextSize = 10
        local textButton409 = Instance.new("TextButton", frame157)
        textButton409.Size = UDim2.new(0, 16, 0, 16)
        textButton409.Position = UDim2.new(1, -20, 0.5, -8)
        textButton409.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton409.Text = ""
        local uICorner390 = Instance.new("UICorner", textButton409)
        uICorner390.CornerRadius = UDim.new(0, 3)
        local frame158 = Instance.new("Frame", scrollingFrame7)
        frame158.Size = UDim2.new(1, 0, 0, 26)
        frame158.BackgroundTransparency = 1
        frame158.Visible = false
        local uIGridLayout57 = Instance.new("UIGridLayout", frame158)
        uIGridLayout57.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout57.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton410 = Instance.new("TextButton", frame158)
        textButton410.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton410.Text = "Nor"
        textButton410.TextSize = 9
        textButton410.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton410.Font = Enum.Font.GothamBold
        local uICorner391 = Instance.new("UICorner", textButton410)
        local conn411 = textButton410.MouseButton1Click:Connect(function()
            textButton410.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton410.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton411 = Instance.new("TextButton", frame158)
        textButton411.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton411.Text = "Gol"
        textButton411.TextSize = 9
        textButton411.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton411.Font = Enum.Font.GothamBold
        local uICorner392 = Instance.new("UICorner", textButton411)
        local conn412 = textButton411.MouseButton1Click:Connect(function()
            textButton411.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton411.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton412 = Instance.new("TextButton", frame158)
        textButton412.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton412.Text = "Dia"
        textButton412.TextSize = 9
        textButton412.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton412.Font = Enum.Font.GothamBold
        local uICorner393 = Instance.new("UICorner", textButton412)
        local conn413 = textButton412.MouseButton1Click:Connect(function()
            textButton412.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton412.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton413 = Instance.new("TextButton", frame158)
        textButton413.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton413.Text = "Rai"
        textButton413.TextSize = 9
        textButton413.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton413.Font = Enum.Font.GothamBold
        local uICorner394 = Instance.new("UICorner", textButton413)
        local conn414 = textButton413.MouseButton1Click:Connect(function()
            textButton413.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton413.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton414 = Instance.new("TextButton", frame158)
        textButton414.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton414.Text = "Lav"
        textButton414.TextSize = 9
        textButton414.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton414.Font = Enum.Font.GothamBold
        local uICorner395 = Instance.new("UICorner", textButton414)
        local conn415 = textButton414.MouseButton1Click:Connect(function()
            textButton414.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton414.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn416 = textButton408.MouseButton1Click:Connect(function()
            frame158.Visible = true
        end)
        local conn417 = textButton409.MouseButton1Click:Connect(function()
            textButton409.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame159 = Instance.new("Frame", frame5)
        frame159.Size = UDim2.new(0.96, 0, 0, 32)
        frame159.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner396 = Instance.new("UICorner", frame159)
        local uIStroke30 = Instance.new("UIStroke", frame159)
        uIStroke30.Color = Color3.fromRGB(255, 220, 50)
        uIStroke30.Thickness = 1.5
        local textLabel43 = Instance.new("TextLabel", frame159)
        textLabel43.Text = "Auto Ice Emblem"
        textLabel43.Size = UDim2.new(1, -50, 1, 0)
        textLabel43.Position = UDim2.new(0, 10, 0, 0)
        textLabel43.TextColor3 = Color3.new(1, 1, 1)
        textLabel43.BackgroundTransparency = 1
        textLabel43.Font = Enum.Font.GothamBold
        textLabel43.TextXAlignment = Enum.TextXAlignment.Left
        textLabel43.TextSize = 9
        local textButton415 = Instance.new("TextButton", frame159)
        textButton415.Size = UDim2.new(0, 30, 0, 14)
        textButton415.Position = UDim2.new(1, -38, 0.5, -7)
        textButton415.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton415.Text = ""
        local uICorner397 = Instance.new("UICorner", textButton415)
        uICorner397.CornerRadius = UDim.new(1, 0)
        local frame160 = Instance.new("Frame", textButton415)
        frame160.Size = UDim2.new(0, 10, 0, 10)
        frame160.Position = UDim2.new(0, 2, 0.5, -5)
        frame160.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner398 = Instance.new("UICorner", frame160)
        uICorner398.CornerRadius = UDim.new(1, 0)
        local conn418 = textButton415.MouseButton1Click:Connect(function()
            local tween19 = TweenService:Create(frame160, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween19:Play()
            local tween20 = TweenService:Create(textButton415, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween20:Play()
            local frame161 = Instance.new("Frame", screenGui)
            frame161.Size = UDim2.new(0, 220, 0, 60)
            frame161.Position = UDim2.new(1, 20, 1, -80)
            frame161.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner399 = Instance.new("UICorner", frame161)
            local uIStroke31 = Instance.new("UIStroke", frame161)
            uIStroke31.Color = Color3.fromRGB(255, 220, 50)
            uIStroke31.Thickness = 1.5
            local textLabel44 = Instance.new("TextLabel", frame161)
            textLabel44.Size = UDim2.new(1, -16, 0, 20)
            textLabel44.Position = UDim2.new(0, 8, 0, 10)
            textLabel44.Text = "Auto Ice Emblem"
            textLabel44.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel44.Font = Enum.Font.GothamBlack
            textLabel44.TextSize = 13
            textLabel44.BackgroundTransparency = 1
            textLabel44.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel45 = Instance.new("TextLabel", frame161)
            textLabel45.Size = UDim2.new(1, -16, 0, 18)
            textLabel45.Position = UDim2.new(0, 8, 0, 30)
            textLabel45.Text = "Ativado"
            textLabel45.TextColor3 = Color3.new(1, 1, 1)
            textLabel45.Font = Enum.Font.GothamBold
            textLabel45.TextSize = 11
            textLabel45.BackgroundTransparency = 1
            textLabel45.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition33 = frame161:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition34 = frame161:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame161:Destroy()
            end)
        end)
        task.spawn(function()
            local frame162 = Instance.new("Frame", screenGui)
            frame162.Size = UDim2.new(0, 220, 0, 60)
            frame162.Position = UDim2.new(1, 20, 1, -80)
            frame162.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner400 = Instance.new("UICorner", frame162)
            local uIStroke32 = Instance.new("UIStroke", frame162)
            uIStroke32.Color = Color3.fromRGB(255, 220, 50)
            uIStroke32.Thickness = 1.5
            local textLabel46 = Instance.new("TextLabel", frame162)
            textLabel46.Size = UDim2.new(1, -16, 0, 20)
            textLabel46.Position = UDim2.new(0, 8, 0, 10)
            textLabel46.Text = "Auto Ice Emblem"
            textLabel46.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel46.Font = Enum.Font.GothamBlack
            textLabel46.TextSize = 13
            textLabel46.BackgroundTransparency = 1
            textLabel46.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel47 = Instance.new("TextLabel", frame162)
            textLabel47.Size = UDim2.new(1, -16, 0, 18)
            textLabel47.Position = UDim2.new(0, 8, 0, 30)
            textLabel47.Text = "Ativado"
            textLabel47.TextColor3 = Color3.new(1, 1, 1)
            textLabel47.Font = Enum.Font.GothamBold
            textLabel47.TextSize = 11
            textLabel47.BackgroundTransparency = 1
            textLabel47.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition35 = frame162:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition36 = frame162:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame162:Destroy()
            end)
        end)
        local frame163 = Instance.new("Frame", frame5)
        frame163.Size = UDim2.new(0.96, 0, 0, 32)
        frame163.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner401 = Instance.new("UICorner", frame163)
        local uIStroke33 = Instance.new("UIStroke", frame163)
        uIStroke33.Color = Color3.fromRGB(255, 220, 50)
        uIStroke33.Thickness = 1.5
        local textLabel48 = Instance.new("TextLabel", frame163)
        textLabel48.Text = "Auto Victrola"
        textLabel48.Size = UDim2.new(1, -50, 1, 0)
        textLabel48.Position = UDim2.new(0, 10, 0, 0)
        textLabel48.TextColor3 = Color3.new(1, 1, 1)
        textLabel48.BackgroundTransparency = 1
        textLabel48.Font = Enum.Font.GothamBold
        textLabel48.TextXAlignment = Enum.TextXAlignment.Left
        textLabel48.TextSize = 9
        local textButton416 = Instance.new("TextButton", frame163)
        textButton416.Size = UDim2.new(0, 30, 0, 14)
        textButton416.Position = UDim2.new(1, -38, 0.5, -7)
        textButton416.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton416.Text = ""
        local uICorner402 = Instance.new("UICorner", textButton416)
        uICorner402.CornerRadius = UDim.new(1, 0)
        local frame164 = Instance.new("Frame", textButton416)
        frame164.Size = UDim2.new(0, 10, 0, 10)
        frame164.Position = UDim2.new(0, 2, 0.5, -5)
        frame164.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner403 = Instance.new("UICorner", frame164)
        uICorner403.CornerRadius = UDim.new(1, 0)
        local conn419 = textButton416.MouseButton1Click:Connect(function()
            local tween21 = TweenService:Create(frame164, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween21:Play()
            local tween22 = TweenService:Create(textButton416, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween22:Play()
            local frame165 = Instance.new("Frame", screenGui)
            frame165.Size = UDim2.new(0, 220, 0, 60)
            frame165.Position = UDim2.new(1, 20, 1, -80)
            frame165.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner404 = Instance.new("UICorner", frame165)
            local uIStroke34 = Instance.new("UIStroke", frame165)
            uIStroke34.Color = Color3.fromRGB(255, 220, 50)
            uIStroke34.Thickness = 1.5
            local textLabel49 = Instance.new("TextLabel", frame165)
            textLabel49.Size = UDim2.new(1, -16, 0, 20)
            textLabel49.Position = UDim2.new(0, 8, 0, 10)
            textLabel49.Text = "Auto Victrola"
            textLabel49.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel49.Font = Enum.Font.GothamBlack
            textLabel49.TextSize = 13
            textLabel49.BackgroundTransparency = 1
            textLabel49.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel50 = Instance.new("TextLabel", frame165)
            textLabel50.Size = UDim2.new(1, -16, 0, 18)
            textLabel50.Position = UDim2.new(0, 8, 0, 30)
            textLabel50.Text = "Ativado"
            textLabel50.TextColor3 = Color3.new(1, 1, 1)
            textLabel50.Font = Enum.Font.GothamBold
            textLabel50.TextSize = 11
            textLabel50.BackgroundTransparency = 1
            textLabel50.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition37 = frame165:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition38 = frame165:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame165:Destroy()
            end)
        end)
        task.spawn(function()
            local frame166 = Instance.new("Frame", screenGui)
            frame166.Size = UDim2.new(0, 220, 0, 60)
            frame166.Position = UDim2.new(1, 20, 1, -80)
            frame166.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner405 = Instance.new("UICorner", frame166)
            local uIStroke35 = Instance.new("UIStroke", frame166)
            uIStroke35.Color = Color3.fromRGB(255, 220, 50)
            uIStroke35.Thickness = 1.5
            local textLabel51 = Instance.new("TextLabel", frame166)
            textLabel51.Size = UDim2.new(1, -16, 0, 20)
            textLabel51.Position = UDim2.new(0, 8, 0, 10)
            textLabel51.Text = "Auto Victrola"
            textLabel51.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel51.Font = Enum.Font.GothamBlack
            textLabel51.TextSize = 13
            textLabel51.BackgroundTransparency = 1
            textLabel51.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel52 = Instance.new("TextLabel", frame166)
            textLabel52.Size = UDim2.new(1, -16, 0, 18)
            textLabel52.Position = UDim2.new(0, 8, 0, 30)
            textLabel52.Text = "Ativado"
            textLabel52.TextColor3 = Color3.new(1, 1, 1)
            textLabel52.Font = Enum.Font.GothamBold
            textLabel52.TextSize = 11
            textLabel52.BackgroundTransparency = 1
            textLabel52.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition39 = frame166:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition40 = frame166:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame166:Destroy()
            end)
        end)
        local frame167 = Instance.new("Frame", frame5)
        frame167.Size = UDim2.new(0.96, 0, 0, 32)
        frame167.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner406 = Instance.new("UICorner", frame167)
        local uIStroke36 = Instance.new("UIStroke", frame167)
        uIStroke36.Color = Color3.fromRGB(255, 220, 50)
        uIStroke36.Thickness = 1.5
        local textLabel53 = Instance.new("TextLabel", frame167)
        textLabel53.Text = "Auto Star"
        textLabel53.Size = UDim2.new(1, -50, 1, 0)
        textLabel53.Position = UDim2.new(0, 10, 0, 0)
        textLabel53.TextColor3 = Color3.new(1, 1, 1)
        textLabel53.BackgroundTransparency = 1
        textLabel53.Font = Enum.Font.GothamBold
        textLabel53.TextXAlignment = Enum.TextXAlignment.Left
        textLabel53.TextSize = 9
        local textButton417 = Instance.new("TextButton", frame167)
        textButton417.Size = UDim2.new(0, 30, 0, 14)
        textButton417.Position = UDim2.new(1, -38, 0.5, -7)
        textButton417.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton417.Text = ""
        local uICorner407 = Instance.new("UICorner", textButton417)
        uICorner407.CornerRadius = UDim.new(1, 0)
        local frame168 = Instance.new("Frame", textButton417)
        frame168.Size = UDim2.new(0, 10, 0, 10)
        frame168.Position = UDim2.new(0, 2, 0.5, -5)
        frame168.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner408 = Instance.new("UICorner", frame168)
        uICorner408.CornerRadius = UDim.new(1, 0)
        local conn420 = textButton417.MouseButton1Click:Connect(function()
            local tween23 = TweenService:Create(frame168, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween23:Play()
            local tween24 = TweenService:Create(textButton417, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween24:Play()
            local frame169 = Instance.new("Frame", screenGui)
            frame169.Size = UDim2.new(0, 220, 0, 60)
            frame169.Position = UDim2.new(1, 20, 1, -80)
            frame169.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner409 = Instance.new("UICorner", frame169)
            local uIStroke37 = Instance.new("UIStroke", frame169)
            uIStroke37.Color = Color3.fromRGB(255, 220, 50)
            uIStroke37.Thickness = 1.5
            local textLabel54 = Instance.new("TextLabel", frame169)
            textLabel54.Size = UDim2.new(1, -16, 0, 20)
            textLabel54.Position = UDim2.new(0, 8, 0, 10)
            textLabel54.Text = "Auto Star"
            textLabel54.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel54.Font = Enum.Font.GothamBlack
            textLabel54.TextSize = 13
            textLabel54.BackgroundTransparency = 1
            textLabel54.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel55 = Instance.new("TextLabel", frame169)
            textLabel55.Size = UDim2.new(1, -16, 0, 18)
            textLabel55.Position = UDim2.new(0, 8, 0, 30)
            textLabel55.Text = "Ativado"
            textLabel55.TextColor3 = Color3.new(1, 1, 1)
            textLabel55.Font = Enum.Font.GothamBold
            textLabel55.TextSize = 11
            textLabel55.BackgroundTransparency = 1
            textLabel55.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition41 = frame169:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition42 = frame169:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame169:Destroy()
            end)
        end)
        task.spawn(function()
            local frame170 = Instance.new("Frame", screenGui)
            frame170.Size = UDim2.new(0, 220, 0, 60)
            frame170.Position = UDim2.new(1, 20, 1, -80)
            frame170.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner410 = Instance.new("UICorner", frame170)
            local uIStroke38 = Instance.new("UIStroke", frame170)
            uIStroke38.Color = Color3.fromRGB(255, 220, 50)
            uIStroke38.Thickness = 1.5
            local textLabel56 = Instance.new("TextLabel", frame170)
            textLabel56.Size = UDim2.new(1, -16, 0, 20)
            textLabel56.Position = UDim2.new(0, 8, 0, 10)
            textLabel56.Text = "Auto Star"
            textLabel56.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel56.Font = Enum.Font.GothamBlack
            textLabel56.TextSize = 13
            textLabel56.BackgroundTransparency = 1
            textLabel56.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel57 = Instance.new("TextLabel", frame170)
            textLabel57.Size = UDim2.new(1, -16, 0, 18)
            textLabel57.Position = UDim2.new(0, 8, 0, 30)
            textLabel57.Text = "Ativado"
            textLabel57.TextColor3 = Color3.new(1, 1, 1)
            textLabel57.Font = Enum.Font.GothamBold
            textLabel57.TextSize = 11
            textLabel57.BackgroundTransparency = 1
            textLabel57.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition43 = frame170:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition44 = frame170:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame170:Destroy()
            end)
        end)
        local frame171 = Instance.new("Frame", frame5)
        frame171.Size = UDim2.new(0.96, 0, 0, 32)
        frame171.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner411 = Instance.new("UICorner", frame171)
        local uIStroke39 = Instance.new("UIStroke", frame171)
        uIStroke39.Color = Color3.fromRGB(255, 220, 50)
        uIStroke39.Thickness = 1.5
        local textLabel58 = Instance.new("TextLabel", frame171)
        textLabel58.Text = "Auto Flower"
        textLabel58.Size = UDim2.new(1, -50, 1, 0)
        textLabel58.Position = UDim2.new(0, 10, 0, 0)
        textLabel58.TextColor3 = Color3.new(1, 1, 1)
        textLabel58.BackgroundTransparency = 1
        textLabel58.Font = Enum.Font.GothamBold
        textLabel58.TextXAlignment = Enum.TextXAlignment.Left
        textLabel58.TextSize = 9
        local textButton418 = Instance.new("TextButton", frame171)
        textButton418.Size = UDim2.new(0, 30, 0, 14)
        textButton418.Position = UDim2.new(1, -38, 0.5, -7)
        textButton418.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton418.Text = ""
        local uICorner412 = Instance.new("UICorner", textButton418)
        uICorner412.CornerRadius = UDim.new(1, 0)
        local frame172 = Instance.new("Frame", textButton418)
        frame172.Size = UDim2.new(0, 10, 0, 10)
        frame172.Position = UDim2.new(0, 2, 0.5, -5)
        frame172.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner413 = Instance.new("UICorner", frame172)
        uICorner413.CornerRadius = UDim.new(1, 0)
        local conn421 = textButton418.MouseButton1Click:Connect(function()
            local tween25 = TweenService:Create(frame172, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween25:Play()
            local tween26 = TweenService:Create(textButton418, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween26:Play()
            local frame173 = Instance.new("Frame", screenGui)
            frame173.Size = UDim2.new(0, 220, 0, 60)
            frame173.Position = UDim2.new(1, 20, 1, -80)
            frame173.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner414 = Instance.new("UICorner", frame173)
            local uIStroke40 = Instance.new("UIStroke", frame173)
            uIStroke40.Color = Color3.fromRGB(255, 220, 50)
            uIStroke40.Thickness = 1.5
            local textLabel59 = Instance.new("TextLabel", frame173)
            textLabel59.Size = UDim2.new(1, -16, 0, 20)
            textLabel59.Position = UDim2.new(0, 8, 0, 10)
            textLabel59.Text = "Auto Flower"
            textLabel59.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel59.Font = Enum.Font.GothamBlack
            textLabel59.TextSize = 13
            textLabel59.BackgroundTransparency = 1
            textLabel59.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel60 = Instance.new("TextLabel", frame173)
            textLabel60.Size = UDim2.new(1, -16, 0, 18)
            textLabel60.Position = UDim2.new(0, 8, 0, 30)
            textLabel60.Text = "Ativado"
            textLabel60.TextColor3 = Color3.new(1, 1, 1)
            textLabel60.Font = Enum.Font.GothamBold
            textLabel60.TextSize = 11
            textLabel60.BackgroundTransparency = 1
            textLabel60.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition45 = frame173:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition46 = frame173:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame173:Destroy()
            end)
        end)
        task.spawn(function()
            local frame174 = Instance.new("Frame", screenGui)
            frame174.Size = UDim2.new(0, 220, 0, 60)
            frame174.Position = UDim2.new(1, 20, 1, -80)
            frame174.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner415 = Instance.new("UICorner", frame174)
            local uIStroke41 = Instance.new("UIStroke", frame174)
            uIStroke41.Color = Color3.fromRGB(255, 220, 50)
            uIStroke41.Thickness = 1.5
            local textLabel61 = Instance.new("TextLabel", frame174)
            textLabel61.Size = UDim2.new(1, -16, 0, 20)
            textLabel61.Position = UDim2.new(0, 8, 0, 10)
            textLabel61.Text = "Auto Flower"
            textLabel61.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel61.Font = Enum.Font.GothamBlack
            textLabel61.TextSize = 13
            textLabel61.BackgroundTransparency = 1
            textLabel61.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel62 = Instance.new("TextLabel", frame174)
            textLabel62.Size = UDim2.new(1, -16, 0, 18)
            textLabel62.Position = UDim2.new(0, 8, 0, 30)
            textLabel62.Text = "Ativado"
            textLabel62.TextColor3 = Color3.new(1, 1, 1)
            textLabel62.Font = Enum.Font.GothamBold
            textLabel62.TextSize = 11
            textLabel62.BackgroundTransparency = 1
            textLabel62.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition47 = frame174:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition48 = frame174:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame174:Destroy()
            end)
        end)
        local frame175 = Instance.new("Frame", frame5)
        frame175.Size = UDim2.new(0.96, 0, 0, 32)
        frame175.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner416 = Instance.new("UICorner", frame175)
        local uIStroke42 = Instance.new("UIStroke", frame175)
        uIStroke42.Color = Color3.fromRGB(255, 220, 50)
        uIStroke42.Thickness = 1.5
        local textLabel63 = Instance.new("TextLabel", frame175)
        textLabel63.Text = "Auto Phone"
        textLabel63.Size = UDim2.new(1, -50, 1, 0)
        textLabel63.Position = UDim2.new(0, 10, 0, 0)
        textLabel63.TextColor3 = Color3.new(1, 1, 1)
        textLabel63.BackgroundTransparency = 1
        textLabel63.Font = Enum.Font.GothamBold
        textLabel63.TextXAlignment = Enum.TextXAlignment.Left
        textLabel63.TextSize = 9
        local textButton419 = Instance.new("TextButton", frame175)
        textButton419.Size = UDim2.new(0, 30, 0, 14)
        textButton419.Position = UDim2.new(1, -38, 0.5, -7)
        textButton419.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton419.Text = ""
        local uICorner417 = Instance.new("UICorner", textButton419)
        uICorner417.CornerRadius = UDim.new(1, 0)
        local frame176 = Instance.new("Frame", textButton419)
        frame176.Size = UDim2.new(0, 10, 0, 10)
        frame176.Position = UDim2.new(0, 2, 0.5, -5)
        frame176.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner418 = Instance.new("UICorner", frame176)
        uICorner418.CornerRadius = UDim.new(1, 0)
        local conn422 = textButton419.MouseButton1Click:Connect(function()
            local tween27 = TweenService:Create(frame176, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween27:Play()
            local tween28 = TweenService:Create(textButton419, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween28:Play()
            local frame177 = Instance.new("Frame", screenGui)
            frame177.Size = UDim2.new(0, 220, 0, 60)
            frame177.Position = UDim2.new(1, 20, 1, -80)
            frame177.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner419 = Instance.new("UICorner", frame177)
            local uIStroke43 = Instance.new("UIStroke", frame177)
            uIStroke43.Color = Color3.fromRGB(255, 220, 50)
            uIStroke43.Thickness = 1.5
            local textLabel64 = Instance.new("TextLabel", frame177)
            textLabel64.Size = UDim2.new(1, -16, 0, 20)
            textLabel64.Position = UDim2.new(0, 8, 0, 10)
            textLabel64.Text = "Auto Phone"
            textLabel64.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel64.Font = Enum.Font.GothamBlack
            textLabel64.TextSize = 13
            textLabel64.BackgroundTransparency = 1
            textLabel64.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel65 = Instance.new("TextLabel", frame177)
            textLabel65.Size = UDim2.new(1, -16, 0, 18)
            textLabel65.Position = UDim2.new(0, 8, 0, 30)
            textLabel65.Text = "Ativado"
            textLabel65.TextColor3 = Color3.new(1, 1, 1)
            textLabel65.Font = Enum.Font.GothamBold
            textLabel65.TextSize = 11
            textLabel65.BackgroundTransparency = 1
            textLabel65.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition49 = frame177:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition50 = frame177:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame177:Destroy()
            end)
        end)
        task.spawn(function()
            local frame178 = Instance.new("Frame", screenGui)
            frame178.Size = UDim2.new(0, 220, 0, 60)
            frame178.Position = UDim2.new(1, 20, 1, -80)
            frame178.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner420 = Instance.new("UICorner", frame178)
            local uIStroke44 = Instance.new("UIStroke", frame178)
            uIStroke44.Color = Color3.fromRGB(255, 220, 50)
            uIStroke44.Thickness = 1.5
            local textLabel66 = Instance.new("TextLabel", frame178)
            textLabel66.Size = UDim2.new(1, -16, 0, 20)
            textLabel66.Position = UDim2.new(0, 8, 0, 10)
            textLabel66.Text = "Auto Phone"
            textLabel66.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel66.Font = Enum.Font.GothamBlack
            textLabel66.TextSize = 13
            textLabel66.BackgroundTransparency = 1
            textLabel66.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel67 = Instance.new("TextLabel", frame178)
            textLabel67.Size = UDim2.new(1, -16, 0, 18)
            textLabel67.Position = UDim2.new(0, 8, 0, 30)
            textLabel67.Text = "Ativado"
            textLabel67.TextColor3 = Color3.new(1, 1, 1)
            textLabel67.Font = Enum.Font.GothamBold
            textLabel67.TextSize = 11
            textLabel67.BackgroundTransparency = 1
            textLabel67.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition51 = frame178:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition52 = frame178:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame178:Destroy()
            end)
        end)
        local frame179 = Instance.new("Frame", frame5)
        frame179.Size = UDim2.new(0.96, 0, 0, 32)
        frame179.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner421 = Instance.new("UICorner", frame179)
        local uIStroke45 = Instance.new("UIStroke", frame179)
        uIStroke45.Color = Color3.fromRGB(255, 220, 50)
        uIStroke45.Thickness = 1.5
        local textLabel68 = Instance.new("TextLabel", frame179)
        textLabel68.Text = "Auto Taco"
        textLabel68.Size = UDim2.new(1, -50, 1, 0)
        textLabel68.Position = UDim2.new(0, 10, 0, 0)
        textLabel68.TextColor3 = Color3.new(1, 1, 1)
        textLabel68.BackgroundTransparency = 1
        textLabel68.Font = Enum.Font.GothamBold
        textLabel68.TextXAlignment = Enum.TextXAlignment.Left
        textLabel68.TextSize = 9
        local textButton420 = Instance.new("TextButton", frame179)
        textButton420.Size = UDim2.new(0, 30, 0, 14)
        textButton420.Position = UDim2.new(1, -38, 0.5, -7)
        textButton420.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton420.Text = ""
        local uICorner422 = Instance.new("UICorner", textButton420)
        uICorner422.CornerRadius = UDim.new(1, 0)
        local frame180 = Instance.new("Frame", textButton420)
        frame180.Size = UDim2.new(0, 10, 0, 10)
        frame180.Position = UDim2.new(0, 2, 0.5, -5)
        frame180.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner423 = Instance.new("UICorner", frame180)
        uICorner423.CornerRadius = UDim.new(1, 0)
        local conn423 = textButton420.MouseButton1Click:Connect(function()
            local tween29 = TweenService:Create(frame180, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween29:Play()
            local tween30 = TweenService:Create(textButton420, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween30:Play()
            local frame181 = Instance.new("Frame", screenGui)
            frame181.Size = UDim2.new(0, 220, 0, 60)
            frame181.Position = UDim2.new(1, 20, 1, -80)
            frame181.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner424 = Instance.new("UICorner", frame181)
            local uIStroke46 = Instance.new("UIStroke", frame181)
            uIStroke46.Color = Color3.fromRGB(255, 220, 50)
            uIStroke46.Thickness = 1.5
            local textLabel69 = Instance.new("TextLabel", frame181)
            textLabel69.Size = UDim2.new(1, -16, 0, 20)
            textLabel69.Position = UDim2.new(0, 8, 0, 10)
            textLabel69.Text = "Auto Taco"
            textLabel69.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel69.Font = Enum.Font.GothamBlack
            textLabel69.TextSize = 13
            textLabel69.BackgroundTransparency = 1
            textLabel69.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel70 = Instance.new("TextLabel", frame181)
            textLabel70.Size = UDim2.new(1, -16, 0, 18)
            textLabel70.Position = UDim2.new(0, 8, 0, 30)
            textLabel70.Text = "Ativado"
            textLabel70.TextColor3 = Color3.new(1, 1, 1)
            textLabel70.Font = Enum.Font.GothamBold
            textLabel70.TextSize = 11
            textLabel70.BackgroundTransparency = 1
            textLabel70.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition53 = frame181:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition54 = frame181:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame181:Destroy()
            end)
        end)
        task.spawn(function()
            local frame182 = Instance.new("Frame", screenGui)
            frame182.Size = UDim2.new(0, 220, 0, 60)
            frame182.Position = UDim2.new(1, 20, 1, -80)
            frame182.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner425 = Instance.new("UICorner", frame182)
            local uIStroke47 = Instance.new("UIStroke", frame182)
            uIStroke47.Color = Color3.fromRGB(255, 220, 50)
            uIStroke47.Thickness = 1.5
            local textLabel71 = Instance.new("TextLabel", frame182)
            textLabel71.Size = UDim2.new(1, -16, 0, 20)
            textLabel71.Position = UDim2.new(0, 8, 0, 10)
            textLabel71.Text = "Auto Taco"
            textLabel71.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel71.Font = Enum.Font.GothamBlack
            textLabel71.TextSize = 13
            textLabel71.BackgroundTransparency = 1
            textLabel71.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel72 = Instance.new("TextLabel", frame182)
            textLabel72.Size = UDim2.new(1, -16, 0, 18)
            textLabel72.Position = UDim2.new(0, 8, 0, 30)
            textLabel72.Text = "Ativado"
            textLabel72.TextColor3 = Color3.new(1, 1, 1)
            textLabel72.Font = Enum.Font.GothamBold
            textLabel72.TextSize = 11
            textLabel72.BackgroundTransparency = 1
            textLabel72.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition55 = frame182:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition56 = frame182:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame182:Destroy()
            end)
        end)
        local frame183 = Instance.new("Frame", frame5)
        frame183.Size = UDim2.new(0.96, 0, 0, 32)
        frame183.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner426 = Instance.new("UICorner", frame183)
        local uIStroke48 = Instance.new("UIStroke", frame183)
        uIStroke48.Color = Color3.fromRGB(255, 220, 50)
        uIStroke48.Thickness = 1.5
        local textLabel73 = Instance.new("TextLabel", frame183)
        textLabel73.Text = "Auto Lighter"
        textLabel73.Size = UDim2.new(1, -50, 1, 0)
        textLabel73.Position = UDim2.new(0, 10, 0, 0)
        textLabel73.TextColor3 = Color3.new(1, 1, 1)
        textLabel73.BackgroundTransparency = 1
        textLabel73.Font = Enum.Font.GothamBold
        textLabel73.TextXAlignment = Enum.TextXAlignment.Left
        textLabel73.TextSize = 9
        local textButton421 = Instance.new("TextButton", frame183)
        textButton421.Size = UDim2.new(0, 30, 0, 14)
        textButton421.Position = UDim2.new(1, -38, 0.5, -7)
        textButton421.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton421.Text = ""
        local uICorner427 = Instance.new("UICorner", textButton421)
        uICorner427.CornerRadius = UDim.new(1, 0)
        local frame184 = Instance.new("Frame", textButton421)
        frame184.Size = UDim2.new(0, 10, 0, 10)
        frame184.Position = UDim2.new(0, 2, 0.5, -5)
        frame184.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner428 = Instance.new("UICorner", frame184)
        uICorner428.CornerRadius = UDim.new(1, 0)
        local conn424 = textButton421.MouseButton1Click:Connect(function()
            local tween31 = TweenService:Create(frame184, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween31:Play()
            local tween32 = TweenService:Create(textButton421, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween32:Play()
            local frame185 = Instance.new("Frame", screenGui)
            frame185.Size = UDim2.new(0, 220, 0, 60)
            frame185.Position = UDim2.new(1, 20, 1, -80)
            frame185.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner429 = Instance.new("UICorner", frame185)
            local uIStroke49 = Instance.new("UIStroke", frame185)
            uIStroke49.Color = Color3.fromRGB(255, 220, 50)
            uIStroke49.Thickness = 1.5
            local textLabel74 = Instance.new("TextLabel", frame185)
            textLabel74.Size = UDim2.new(1, -16, 0, 20)
            textLabel74.Position = UDim2.new(0, 8, 0, 10)
            textLabel74.Text = "Auto Lighter"
            textLabel74.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel74.Font = Enum.Font.GothamBlack
            textLabel74.TextSize = 13
            textLabel74.BackgroundTransparency = 1
            textLabel74.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel75 = Instance.new("TextLabel", frame185)
            textLabel75.Size = UDim2.new(1, -16, 0, 18)
            textLabel75.Position = UDim2.new(0, 8, 0, 30)
            textLabel75.Text = "Ativado"
            textLabel75.TextColor3 = Color3.new(1, 1, 1)
            textLabel75.Font = Enum.Font.GothamBold
            textLabel75.TextSize = 11
            textLabel75.BackgroundTransparency = 1
            textLabel75.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition57 = frame185:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition58 = frame185:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame185:Destroy()
            end)
        end)
        task.spawn(function()
            local frame186 = Instance.new("Frame", screenGui)
            frame186.Size = UDim2.new(0, 220, 0, 60)
            frame186.Position = UDim2.new(1, 20, 1, -80)
            frame186.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner430 = Instance.new("UICorner", frame186)
            local uIStroke50 = Instance.new("UIStroke", frame186)
            uIStroke50.Color = Color3.fromRGB(255, 220, 50)
            uIStroke50.Thickness = 1.5
            local textLabel76 = Instance.new("TextLabel", frame186)
            textLabel76.Size = UDim2.new(1, -16, 0, 20)
            textLabel76.Position = UDim2.new(0, 8, 0, 10)
            textLabel76.Text = "Auto Lighter"
            textLabel76.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel76.Font = Enum.Font.GothamBlack
            textLabel76.TextSize = 13
            textLabel76.BackgroundTransparency = 1
            textLabel76.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel77 = Instance.new("TextLabel", frame186)
            textLabel77.Size = UDim2.new(1, -16, 0, 18)
            textLabel77.Position = UDim2.new(0, 8, 0, 30)
            textLabel77.Text = "Ativado"
            textLabel77.TextColor3 = Color3.new(1, 1, 1)
            textLabel77.Font = Enum.Font.GothamBold
            textLabel77.TextSize = 11
            textLabel77.BackgroundTransparency = 1
            textLabel77.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition59 = frame186:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition60 = frame186:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame186:Destroy()
            end)
        end)
        local frame187 = Instance.new("Frame", frame5)
        frame187.Size = UDim2.new(0.96, 0, 0, 32)
        frame187.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner431 = Instance.new("UICorner", frame187)
        local uIStroke51 = Instance.new("UIStroke", frame187)
        uIStroke51.Color = Color3.fromRGB(255, 220, 50)
        uIStroke51.Thickness = 1.5
        local textLabel78 = Instance.new("TextLabel", frame187)
        textLabel78.Text = "Auto Spin"
        textLabel78.Size = UDim2.new(1, -50, 1, 0)
        textLabel78.Position = UDim2.new(0, 10, 0, 0)
        textLabel78.TextColor3 = Color3.new(1, 1, 1)
        textLabel78.BackgroundTransparency = 1
        textLabel78.Font = Enum.Font.GothamBold
        textLabel78.TextXAlignment = Enum.TextXAlignment.Left
        textLabel78.TextSize = 9
        local textButton422 = Instance.new("TextButton", frame187)
        textButton422.Size = UDim2.new(0, 30, 0, 14)
        textButton422.Position = UDim2.new(1, -38, 0.5, -7)
        textButton422.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton422.Text = ""
        local uICorner432 = Instance.new("UICorner", textButton422)
        uICorner432.CornerRadius = UDim.new(1, 0)
        local frame188 = Instance.new("Frame", textButton422)
        frame188.Size = UDim2.new(0, 10, 0, 10)
        frame188.Position = UDim2.new(0, 2, 0.5, -5)
        frame188.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner433 = Instance.new("UICorner", frame188)
        uICorner433.CornerRadius = UDim.new(1, 0)
        local conn425 = textButton422.MouseButton1Click:Connect(function()
            local tween33 = TweenService:Create(frame188, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween33:Play()
            local tween34 = TweenService:Create(textButton422, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween34:Play()
            local frame189 = Instance.new("Frame", screenGui)
            frame189.Size = UDim2.new(0, 220, 0, 60)
            frame189.Position = UDim2.new(1, 20, 1, -80)
            frame189.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner434 = Instance.new("UICorner", frame189)
            local uIStroke52 = Instance.new("UIStroke", frame189)
            uIStroke52.Color = Color3.fromRGB(255, 220, 50)
            uIStroke52.Thickness = 1.5
            local textLabel79 = Instance.new("TextLabel", frame189)
            textLabel79.Size = UDim2.new(1, -16, 0, 20)
            textLabel79.Position = UDim2.new(0, 8, 0, 10)
            textLabel79.Text = "Auto Spin"
            textLabel79.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel79.Font = Enum.Font.GothamBlack
            textLabel79.TextSize = 13
            textLabel79.BackgroundTransparency = 1
            textLabel79.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel80 = Instance.new("TextLabel", frame189)
            textLabel80.Size = UDim2.new(1, -16, 0, 18)
            textLabel80.Position = UDim2.new(0, 8, 0, 30)
            textLabel80.Text = "Ativado"
            textLabel80.TextColor3 = Color3.new(1, 1, 1)
            textLabel80.Font = Enum.Font.GothamBold
            textLabel80.TextSize = 11
            textLabel80.BackgroundTransparency = 1
            textLabel80.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition61 = frame189:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition62 = frame189:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame189:Destroy()
            end)
        end)
        task.spawn(function()
            local frame190 = Instance.new("Frame", screenGui)
            frame190.Size = UDim2.new(0, 220, 0, 60)
            frame190.Position = UDim2.new(1, 20, 1, -80)
            frame190.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner435 = Instance.new("UICorner", frame190)
            local uIStroke53 = Instance.new("UIStroke", frame190)
            uIStroke53.Color = Color3.fromRGB(255, 220, 50)
            uIStroke53.Thickness = 1.5
            local textLabel81 = Instance.new("TextLabel", frame190)
            textLabel81.Size = UDim2.new(1, -16, 0, 20)
            textLabel81.Position = UDim2.new(0, 8, 0, 10)
            textLabel81.Text = "Auto Spin"
            textLabel81.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel81.Font = Enum.Font.GothamBlack
            textLabel81.TextSize = 13
            textLabel81.BackgroundTransparency = 1
            textLabel81.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel82 = Instance.new("TextLabel", frame190)
            textLabel82.Size = UDim2.new(1, -16, 0, 18)
            textLabel82.Position = UDim2.new(0, 8, 0, 30)
            textLabel82.Text = "Ativado"
            textLabel82.TextColor3 = Color3.new(1, 1, 1)
            textLabel82.Font = Enum.Font.GothamBold
            textLabel82.TextSize = 11
            textLabel82.BackgroundTransparency = 1
            textLabel82.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition63 = frame190:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition64 = frame190:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame190:Destroy()
            end)
        end)
        local frame191 = Instance.new("Frame", frame6)
        frame191.Size = UDim2.new(0.96, 0, 0, 32)
        frame191.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner436 = Instance.new("UICorner", frame191)
        local uIStroke54 = Instance.new("UIStroke", frame191)
        uIStroke54.Color = Color3.fromRGB(255, 220, 50)
        uIStroke54.Thickness = 1.5
        local textLabel83 = Instance.new("TextLabel", frame191)
        textLabel83.Text = "Auto Epic"
        textLabel83.Size = UDim2.new(1, -50, 1, 0)
        textLabel83.Position = UDim2.new(0, 10, 0, 0)
        textLabel83.TextColor3 = Color3.new(1, 1, 1)
        textLabel83.BackgroundTransparency = 1
        textLabel83.Font = Enum.Font.GothamBold
        textLabel83.TextXAlignment = Enum.TextXAlignment.Left
        textLabel83.TextSize = 9
        local textButton423 = Instance.new("TextButton", frame191)
        textButton423.Size = UDim2.new(0, 30, 0, 14)
        textButton423.Position = UDim2.new(1, -38, 0.5, -7)
        textButton423.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton423.Text = ""
        local uICorner437 = Instance.new("UICorner", textButton423)
        uICorner437.CornerRadius = UDim.new(1, 0)
        local frame192 = Instance.new("Frame", textButton423)
        frame192.Size = UDim2.new(0, 10, 0, 10)
        frame192.Position = UDim2.new(0, 2, 0.5, -5)
        frame192.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner438 = Instance.new("UICorner", frame192)
        uICorner438.CornerRadius = UDim.new(1, 0)
        local conn426 = textButton423.MouseButton1Click:Connect(function()
            local tween35 = TweenService:Create(frame192, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween35:Play()
            local tween36 = TweenService:Create(textButton423, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween36:Play()
            local frame193 = Instance.new("Frame", screenGui)
            frame193.Size = UDim2.new(0, 220, 0, 60)
            frame193.Position = UDim2.new(1, 20, 1, -80)
            frame193.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner439 = Instance.new("UICorner", frame193)
            local uIStroke55 = Instance.new("UIStroke", frame193)
            uIStroke55.Color = Color3.fromRGB(255, 220, 50)
            uIStroke55.Thickness = 1.5
            local textLabel84 = Instance.new("TextLabel", frame193)
            textLabel84.Size = UDim2.new(1, -16, 0, 20)
            textLabel84.Position = UDim2.new(0, 8, 0, 10)
            textLabel84.Text = "Auto Epic"
            textLabel84.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel84.Font = Enum.Font.GothamBlack
            textLabel84.TextSize = 13
            textLabel84.BackgroundTransparency = 1
            textLabel84.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel85 = Instance.new("TextLabel", frame193)
            textLabel85.Size = UDim2.new(1, -16, 0, 18)
            textLabel85.Position = UDim2.new(0, 8, 0, 30)
            textLabel85.Text = "Ativado"
            textLabel85.TextColor3 = Color3.new(1, 1, 1)
            textLabel85.Font = Enum.Font.GothamBold
            textLabel85.TextSize = 11
            textLabel85.BackgroundTransparency = 1
            textLabel85.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition65 = frame193:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition66 = frame193:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame193:Destroy()
            end)
        end)
        task.spawn(function()
            local frame194 = Instance.new("Frame", screenGui)
            frame194.Size = UDim2.new(0, 220, 0, 60)
            frame194.Position = UDim2.new(1, 20, 1, -80)
            frame194.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner440 = Instance.new("UICorner", frame194)
            local uIStroke56 = Instance.new("UIStroke", frame194)
            uIStroke56.Color = Color3.fromRGB(255, 220, 50)
            uIStroke56.Thickness = 1.5
            local textLabel86 = Instance.new("TextLabel", frame194)
            textLabel86.Size = UDim2.new(1, -16, 0, 20)
            textLabel86.Position = UDim2.new(0, 8, 0, 10)
            textLabel86.Text = "Auto Epic"
            textLabel86.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel86.Font = Enum.Font.GothamBlack
            textLabel86.TextSize = 13
            textLabel86.BackgroundTransparency = 1
            textLabel86.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel87 = Instance.new("TextLabel", frame194)
            textLabel87.Size = UDim2.new(1, -16, 0, 18)
            textLabel87.Position = UDim2.new(0, 8, 0, 30)
            textLabel87.Text = "Ativado"
            textLabel87.TextColor3 = Color3.new(1, 1, 1)
            textLabel87.Font = Enum.Font.GothamBold
            textLabel87.TextSize = 11
            textLabel87.BackgroundTransparency = 1
            textLabel87.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition67 = frame194:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition68 = frame194:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame194:Destroy()
            end)
        end)
        local frame195 = Instance.new("Frame", frame6)
        frame195.Size = UDim2.new(0.96, 0, 0, 32)
        frame195.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner441 = Instance.new("UICorner", frame195)
        local uIStroke57 = Instance.new("UIStroke", frame195)
        uIStroke57.Color = Color3.fromRGB(255, 220, 50)
        uIStroke57.Thickness = 1.5
        local textLabel88 = Instance.new("TextLabel", frame195)
        textLabel88.Text = "Auto Legendary"
        textLabel88.Size = UDim2.new(1, -50, 1, 0)
        textLabel88.Position = UDim2.new(0, 10, 0, 0)
        textLabel88.TextColor3 = Color3.new(1, 1, 1)
        textLabel88.BackgroundTransparency = 1
        textLabel88.Font = Enum.Font.GothamBold
        textLabel88.TextXAlignment = Enum.TextXAlignment.Left
        textLabel88.TextSize = 9
        local textButton424 = Instance.new("TextButton", frame195)
        textButton424.Size = UDim2.new(0, 30, 0, 14)
        textButton424.Position = UDim2.new(1, -38, 0.5, -7)
        textButton424.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton424.Text = ""
        local uICorner442 = Instance.new("UICorner", textButton424)
        uICorner442.CornerRadius = UDim.new(1, 0)
        local frame196 = Instance.new("Frame", textButton424)
        frame196.Size = UDim2.new(0, 10, 0, 10)
        frame196.Position = UDim2.new(0, 2, 0.5, -5)
        frame196.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner443 = Instance.new("UICorner", frame196)
        uICorner443.CornerRadius = UDim.new(1, 0)
        local conn427 = textButton424.MouseButton1Click:Connect(function()
            local tween37 = TweenService:Create(frame196, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween37:Play()
            local tween38 = TweenService:Create(textButton424, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween38:Play()
            local frame197 = Instance.new("Frame", screenGui)
            frame197.Size = UDim2.new(0, 220, 0, 60)
            frame197.Position = UDim2.new(1, 20, 1, -80)
            frame197.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner444 = Instance.new("UICorner", frame197)
            local uIStroke58 = Instance.new("UIStroke", frame197)
            uIStroke58.Color = Color3.fromRGB(255, 220, 50)
            uIStroke58.Thickness = 1.5
            local textLabel89 = Instance.new("TextLabel", frame197)
            textLabel89.Size = UDim2.new(1, -16, 0, 20)
            textLabel89.Position = UDim2.new(0, 8, 0, 10)
            textLabel89.Text = "Auto Legendary"
            textLabel89.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel89.Font = Enum.Font.GothamBlack
            textLabel89.TextSize = 13
            textLabel89.BackgroundTransparency = 1
            textLabel89.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel90 = Instance.new("TextLabel", frame197)
            textLabel90.Size = UDim2.new(1, -16, 0, 18)
            textLabel90.Position = UDim2.new(0, 8, 0, 30)
            textLabel90.Text = "Ativado"
            textLabel90.TextColor3 = Color3.new(1, 1, 1)
            textLabel90.Font = Enum.Font.GothamBold
            textLabel90.TextSize = 11
            textLabel90.BackgroundTransparency = 1
            textLabel90.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition69 = frame197:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition70 = frame197:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame197:Destroy()
            end)
        end)
        task.spawn(function()
            local frame198 = Instance.new("Frame", screenGui)
            frame198.Size = UDim2.new(0, 220, 0, 60)
            frame198.Position = UDim2.new(1, 20, 1, -80)
            frame198.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner445 = Instance.new("UICorner", frame198)
            local uIStroke59 = Instance.new("UIStroke", frame198)
            uIStroke59.Color = Color3.fromRGB(255, 220, 50)
            uIStroke59.Thickness = 1.5
            local textLabel91 = Instance.new("TextLabel", frame198)
            textLabel91.Size = UDim2.new(1, -16, 0, 20)
            textLabel91.Position = UDim2.new(0, 8, 0, 10)
            textLabel91.Text = "Auto Legendary"
            textLabel91.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel91.Font = Enum.Font.GothamBlack
            textLabel91.TextSize = 13
            textLabel91.BackgroundTransparency = 1
            textLabel91.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel92 = Instance.new("TextLabel", frame198)
            textLabel92.Size = UDim2.new(1, -16, 0, 18)
            textLabel92.Position = UDim2.new(0, 8, 0, 30)
            textLabel92.Text = "Ativado"
            textLabel92.TextColor3 = Color3.new(1, 1, 1)
            textLabel92.Font = Enum.Font.GothamBold
            textLabel92.TextSize = 11
            textLabel92.BackgroundTransparency = 1
            textLabel92.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition71 = frame198:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition72 = frame198:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame198:Destroy()
            end)
        end)
        local frame199 = Instance.new("Frame", frame6)
        frame199.Size = UDim2.new(0.96, 0, 0, 32)
        frame199.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner446 = Instance.new("UICorner", frame199)
        local uIStroke60 = Instance.new("UIStroke", frame199)
        uIStroke60.Color = Color3.fromRGB(255, 220, 50)
        uIStroke60.Thickness = 1.5
        local textLabel93 = Instance.new("TextLabel", frame199)
        textLabel93.Text = "Auto Mystic"
        textLabel93.Size = UDim2.new(1, -50, 1, 0)
        textLabel93.Position = UDim2.new(0, 10, 0, 0)
        textLabel93.TextColor3 = Color3.new(1, 1, 1)
        textLabel93.BackgroundTransparency = 1
        textLabel93.Font = Enum.Font.GothamBold
        textLabel93.TextXAlignment = Enum.TextXAlignment.Left
        textLabel93.TextSize = 9
        local textButton425 = Instance.new("TextButton", frame199)
        textButton425.Size = UDim2.new(0, 30, 0, 14)
        textButton425.Position = UDim2.new(1, -38, 0.5, -7)
        textButton425.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton425.Text = ""
        local uICorner447 = Instance.new("UICorner", textButton425)
        uICorner447.CornerRadius = UDim.new(1, 0)
        local frame200 = Instance.new("Frame", textButton425)
        frame200.Size = UDim2.new(0, 10, 0, 10)
        frame200.Position = UDim2.new(0, 2, 0.5, -5)
        frame200.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner448 = Instance.new("UICorner", frame200)
        uICorner448.CornerRadius = UDim.new(1, 0)
        local conn428 = textButton425.MouseButton1Click:Connect(function()
            local tween39 = TweenService:Create(frame200, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween39:Play()
            local tween40 = TweenService:Create(textButton425, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween40:Play()
            local frame201 = Instance.new("Frame", screenGui)
            frame201.Size = UDim2.new(0, 220, 0, 60)
            frame201.Position = UDim2.new(1, 20, 1, -80)
            frame201.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner449 = Instance.new("UICorner", frame201)
            local uIStroke61 = Instance.new("UIStroke", frame201)
            uIStroke61.Color = Color3.fromRGB(255, 220, 50)
            uIStroke61.Thickness = 1.5
            local textLabel94 = Instance.new("TextLabel", frame201)
            textLabel94.Size = UDim2.new(1, -16, 0, 20)
            textLabel94.Position = UDim2.new(0, 8, 0, 10)
            textLabel94.Text = "Auto Mystic"
            textLabel94.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel94.Font = Enum.Font.GothamBlack
            textLabel94.TextSize = 13
            textLabel94.BackgroundTransparency = 1
            textLabel94.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel95 = Instance.new("TextLabel", frame201)
            textLabel95.Size = UDim2.new(1, -16, 0, 18)
            textLabel95.Position = UDim2.new(0, 8, 0, 30)
            textLabel95.Text = "Ativado"
            textLabel95.TextColor3 = Color3.new(1, 1, 1)
            textLabel95.Font = Enum.Font.GothamBold
            textLabel95.TextSize = 11
            textLabel95.BackgroundTransparency = 1
            textLabel95.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition73 = frame201:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition74 = frame201:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame201:Destroy()
            end)
        end)
        task.spawn(function()
            local frame202 = Instance.new("Frame", screenGui)
            frame202.Size = UDim2.new(0, 220, 0, 60)
            frame202.Position = UDim2.new(1, 20, 1, -80)
            frame202.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner450 = Instance.new("UICorner", frame202)
            local uIStroke62 = Instance.new("UIStroke", frame202)
            uIStroke62.Color = Color3.fromRGB(255, 220, 50)
            uIStroke62.Thickness = 1.5
            local textLabel96 = Instance.new("TextLabel", frame202)
            textLabel96.Size = UDim2.new(1, -16, 0, 20)
            textLabel96.Position = UDim2.new(0, 8, 0, 10)
            textLabel96.Text = "Auto Mystic"
            textLabel96.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel96.Font = Enum.Font.GothamBlack
            textLabel96.TextSize = 13
            textLabel96.BackgroundTransparency = 1
            textLabel96.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel97 = Instance.new("TextLabel", frame202)
            textLabel97.Size = UDim2.new(1, -16, 0, 18)
            textLabel97.Position = UDim2.new(0, 8, 0, 30)
            textLabel97.Text = "Ativado"
            textLabel97.TextColor3 = Color3.new(1, 1, 1)
            textLabel97.Font = Enum.Font.GothamBold
            textLabel97.TextSize = 11
            textLabel97.BackgroundTransparency = 1
            textLabel97.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition75 = frame202:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition76 = frame202:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame202:Destroy()
            end)
        end)
        local frame203 = Instance.new("Frame", frame6)
        frame203.Size = UDim2.new(0.96, 0, 0, 32)
        frame203.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner451 = Instance.new("UICorner", frame203)
        local uIStroke63 = Instance.new("UIStroke", frame203)
        uIStroke63.Color = Color3.fromRGB(255, 220, 50)
        uIStroke63.Thickness = 1.5
        local textLabel98 = Instance.new("TextLabel", frame203)
        textLabel98.Text = "Auto Secret"
        textLabel98.Size = UDim2.new(1, -50, 1, 0)
        textLabel98.Position = UDim2.new(0, 10, 0, 0)
        textLabel98.TextColor3 = Color3.new(1, 1, 1)
        textLabel98.BackgroundTransparency = 1
        textLabel98.Font = Enum.Font.GothamBold
        textLabel98.TextXAlignment = Enum.TextXAlignment.Left
        textLabel98.TextSize = 9
        local textButton426 = Instance.new("TextButton", frame203)
        textButton426.Size = UDim2.new(0, 30, 0, 14)
        textButton426.Position = UDim2.new(1, -38, 0.5, -7)
        textButton426.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton426.Text = ""
        local uICorner452 = Instance.new("UICorner", textButton426)
        uICorner452.CornerRadius = UDim.new(1, 0)
        local frame204 = Instance.new("Frame", textButton426)
        frame204.Size = UDim2.new(0, 10, 0, 10)
        frame204.Position = UDim2.new(0, 2, 0.5, -5)
        frame204.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner453 = Instance.new("UICorner", frame204)
        uICorner453.CornerRadius = UDim.new(1, 0)
        local conn429 = textButton426.MouseButton1Click:Connect(function()
            local tween41 = TweenService:Create(frame204, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween41:Play()
            local tween42 = TweenService:Create(textButton426, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween42:Play()
            local frame205 = Instance.new("Frame", screenGui)
            frame205.Size = UDim2.new(0, 220, 0, 60)
            frame205.Position = UDim2.new(1, 20, 1, -80)
            frame205.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner454 = Instance.new("UICorner", frame205)
            local uIStroke64 = Instance.new("UIStroke", frame205)
            uIStroke64.Color = Color3.fromRGB(255, 220, 50)
            uIStroke64.Thickness = 1.5
            local textLabel99 = Instance.new("TextLabel", frame205)
            textLabel99.Size = UDim2.new(1, -16, 0, 20)
            textLabel99.Position = UDim2.new(0, 8, 0, 10)
            textLabel99.Text = "Auto Secret"
            textLabel99.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel99.Font = Enum.Font.GothamBlack
            textLabel99.TextSize = 13
            textLabel99.BackgroundTransparency = 1
            textLabel99.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel100 = Instance.new("TextLabel", frame205)
            textLabel100.Size = UDim2.new(1, -16, 0, 18)
            textLabel100.Position = UDim2.new(0, 8, 0, 30)
            textLabel100.Text = "Ativado"
            textLabel100.TextColor3 = Color3.new(1, 1, 1)
            textLabel100.Font = Enum.Font.GothamBold
            textLabel100.TextSize = 11
            textLabel100.BackgroundTransparency = 1
            textLabel100.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition77 = frame205:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition78 = frame205:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame205:Destroy()
            end)
        end)
        task.spawn(function()
            local frame206 = Instance.new("Frame", screenGui)
            frame206.Size = UDim2.new(0, 220, 0, 60)
            frame206.Position = UDim2.new(1, 20, 1, -80)
            frame206.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner455 = Instance.new("UICorner", frame206)
            local uIStroke65 = Instance.new("UIStroke", frame206)
            uIStroke65.Color = Color3.fromRGB(255, 220, 50)
            uIStroke65.Thickness = 1.5
            local textLabel101 = Instance.new("TextLabel", frame206)
            textLabel101.Size = UDim2.new(1, -16, 0, 20)
            textLabel101.Position = UDim2.new(0, 8, 0, 10)
            textLabel101.Text = "Auto Secret"
            textLabel101.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel101.Font = Enum.Font.GothamBlack
            textLabel101.TextSize = 13
            textLabel101.BackgroundTransparency = 1
            textLabel101.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel102 = Instance.new("TextLabel", frame206)
            textLabel102.Size = UDim2.new(1, -16, 0, 18)
            textLabel102.Position = UDim2.new(0, 8, 0, 30)
            textLabel102.Text = "Ativado"
            textLabel102.TextColor3 = Color3.new(1, 1, 1)
            textLabel102.Font = Enum.Font.GothamBold
            textLabel102.TextSize = 11
            textLabel102.BackgroundTransparency = 1
            textLabel102.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition79 = frame206:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition80 = frame206:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame206:Destroy()
            end)
        end)
        local frame207 = Instance.new("Frame", frame6)
        frame207.Size = UDim2.new(0.96, 0, 0, 32)
        frame207.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner456 = Instance.new("UICorner", frame207)
        local uIStroke66 = Instance.new("UIStroke", frame207)
        uIStroke66.Color = Color3.fromRGB(255, 220, 50)
        uIStroke66.Thickness = 1.5
        local textLabel103 = Instance.new("TextLabel", frame207)
        textLabel103.Text = "Auto Stellar"
        textLabel103.Size = UDim2.new(1, -50, 1, 0)
        textLabel103.Position = UDim2.new(0, 10, 0, 0)
        textLabel103.TextColor3 = Color3.new(1, 1, 1)
        textLabel103.BackgroundTransparency = 1
        textLabel103.Font = Enum.Font.GothamBold
        textLabel103.TextXAlignment = Enum.TextXAlignment.Left
        textLabel103.TextSize = 9
        local textButton427 = Instance.new("TextButton", frame207)
        textButton427.Size = UDim2.new(0, 30, 0, 14)
        textButton427.Position = UDim2.new(1, -38, 0.5, -7)
        textButton427.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton427.Text = ""
        local uICorner457 = Instance.new("UICorner", textButton427)
        uICorner457.CornerRadius = UDim.new(1, 0)
        local frame208 = Instance.new("Frame", textButton427)
        frame208.Size = UDim2.new(0, 10, 0, 10)
        frame208.Position = UDim2.new(0, 2, 0.5, -5)
        frame208.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner458 = Instance.new("UICorner", frame208)
        uICorner458.CornerRadius = UDim.new(1, 0)
        local conn430 = textButton427.MouseButton1Click:Connect(function()
            local tween43 = TweenService:Create(frame208, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween43:Play()
            local tween44 = TweenService:Create(textButton427, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween44:Play()
            local frame209 = Instance.new("Frame", screenGui)
            frame209.Size = UDim2.new(0, 220, 0, 60)
            frame209.Position = UDim2.new(1, 20, 1, -80)
            frame209.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner459 = Instance.new("UICorner", frame209)
            local uIStroke67 = Instance.new("UIStroke", frame209)
            uIStroke67.Color = Color3.fromRGB(255, 220, 50)
            uIStroke67.Thickness = 1.5
            local textLabel104 = Instance.new("TextLabel", frame209)
            textLabel104.Size = UDim2.new(1, -16, 0, 20)
            textLabel104.Position = UDim2.new(0, 8, 0, 10)
            textLabel104.Text = "Auto Stellar"
            textLabel104.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel104.Font = Enum.Font.GothamBlack
            textLabel104.TextSize = 13
            textLabel104.BackgroundTransparency = 1
            textLabel104.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel105 = Instance.new("TextLabel", frame209)
            textLabel105.Size = UDim2.new(1, -16, 0, 18)
            textLabel105.Position = UDim2.new(0, 8, 0, 30)
            textLabel105.Text = "Ativado"
            textLabel105.TextColor3 = Color3.new(1, 1, 1)
            textLabel105.Font = Enum.Font.GothamBold
            textLabel105.TextSize = 11
            textLabel105.BackgroundTransparency = 1
            textLabel105.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition81 = frame209:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition82 = frame209:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame209:Destroy()
            end)
        end)
        task.spawn(function()
            local frame210 = Instance.new("Frame", screenGui)
            frame210.Size = UDim2.new(0, 220, 0, 60)
            frame210.Position = UDim2.new(1, 20, 1, -80)
            frame210.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner460 = Instance.new("UICorner", frame210)
            local uIStroke68 = Instance.new("UIStroke", frame210)
            uIStroke68.Color = Color3.fromRGB(255, 220, 50)
            uIStroke68.Thickness = 1.5
            local textLabel106 = Instance.new("TextLabel", frame210)
            textLabel106.Size = UDim2.new(1, -16, 0, 20)
            textLabel106.Position = UDim2.new(0, 8, 0, 10)
            textLabel106.Text = "Auto Stellar"
            textLabel106.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel106.Font = Enum.Font.GothamBlack
            textLabel106.TextSize = 13
            textLabel106.BackgroundTransparency = 1
            textLabel106.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel107 = Instance.new("TextLabel", frame210)
            textLabel107.Size = UDim2.new(1, -16, 0, 18)
            textLabel107.Position = UDim2.new(0, 8, 0, 30)
            textLabel107.Text = "Ativado"
            textLabel107.TextColor3 = Color3.new(1, 1, 1)
            textLabel107.Font = Enum.Font.GothamBold
            textLabel107.TextSize = 11
            textLabel107.BackgroundTransparency = 1
            textLabel107.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition83 = frame210:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition84 = frame210:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame210:Destroy()
            end)
        end)
        local frame211 = Instance.new("Frame", frame6)
        frame211.Size = UDim2.new(0.96, 0, 0, 32)
        frame211.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner461 = Instance.new("UICorner", frame211)
        local uIStroke69 = Instance.new("UIStroke", frame211)
        uIStroke69.Color = Color3.fromRGB(255, 220, 50)
        uIStroke69.Thickness = 1.5
        local textLabel108 = Instance.new("TextLabel", frame211)
        textLabel108.Text = "Auto Dig [Shovel]"
        textLabel108.Size = UDim2.new(1, -50, 1, 0)
        textLabel108.Position = UDim2.new(0, 10, 0, 0)
        textLabel108.TextColor3 = Color3.new(1, 1, 1)
        textLabel108.BackgroundTransparency = 1
        textLabel108.Font = Enum.Font.GothamBold
        textLabel108.TextXAlignment = Enum.TextXAlignment.Left
        textLabel108.TextSize = 9
        local textButton428 = Instance.new("TextButton", frame211)
        textButton428.Size = UDim2.new(0, 30, 0, 14)
        textButton428.Position = UDim2.new(1, -38, 0.5, -7)
        textButton428.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton428.Text = ""
        local uICorner462 = Instance.new("UICorner", textButton428)
        uICorner462.CornerRadius = UDim.new(1, 0)
        local frame212 = Instance.new("Frame", textButton428)
        frame212.Size = UDim2.new(0, 10, 0, 10)
        frame212.Position = UDim2.new(0, 2, 0.5, -5)
        frame212.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner463 = Instance.new("UICorner", frame212)
        uICorner463.CornerRadius = UDim.new(1, 0)
        local conn431 = textButton428.MouseButton1Click:Connect(function()
            local tween45 = TweenService:Create(frame212, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween45:Play()
            local tween46 = TweenService:Create(textButton428, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween46:Play()
            local frame213 = Instance.new("Frame", screenGui)
            frame213.Size = UDim2.new(0, 220, 0, 60)
            frame213.Position = UDim2.new(1, 20, 1, -80)
            frame213.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner464 = Instance.new("UICorner", frame213)
            local uIStroke70 = Instance.new("UIStroke", frame213)
            uIStroke70.Color = Color3.fromRGB(255, 220, 50)
            uIStroke70.Thickness = 1.5
            local textLabel109 = Instance.new("TextLabel", frame213)
            textLabel109.Size = UDim2.new(1, -16, 0, 20)
            textLabel109.Position = UDim2.new(0, 8, 0, 10)
            textLabel109.Text = "Auto Dig"
            textLabel109.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel109.Font = Enum.Font.GothamBlack
            textLabel109.TextSize = 13
            textLabel109.BackgroundTransparency = 1
            textLabel109.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel110 = Instance.new("TextLabel", frame213)
            textLabel110.Size = UDim2.new(1, -16, 0, 18)
            textLabel110.Position = UDim2.new(0, 8, 0, 30)
            textLabel110.Text = "Ativado"
            textLabel110.TextColor3 = Color3.new(1, 1, 1)
            textLabel110.Font = Enum.Font.GothamBold
            textLabel110.TextSize = 11
            textLabel110.BackgroundTransparency = 1
            textLabel110.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition85 = frame213:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition86 = frame213:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame213:Destroy()
            end)
        end)
        task.spawn(function()
            local frame214 = Instance.new("Frame", screenGui)
            frame214.Size = UDim2.new(0, 220, 0, 60)
            frame214.Position = UDim2.new(1, 20, 1, -80)
            frame214.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner465 = Instance.new("UICorner", frame214)
            local uIStroke71 = Instance.new("UIStroke", frame214)
            uIStroke71.Color = Color3.fromRGB(255, 220, 50)
            uIStroke71.Thickness = 1.5
            local textLabel111 = Instance.new("TextLabel", frame214)
            textLabel111.Size = UDim2.new(1, -16, 0, 20)
            textLabel111.Position = UDim2.new(0, 8, 0, 10)
            textLabel111.Text = "Auto Dig"
            textLabel111.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel111.Font = Enum.Font.GothamBlack
            textLabel111.TextSize = 13
            textLabel111.BackgroundTransparency = 1
            textLabel111.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel112 = Instance.new("TextLabel", frame214)
            textLabel112.Size = UDim2.new(1, -16, 0, 18)
            textLabel112.Position = UDim2.new(0, 8, 0, 30)
            textLabel112.Text = "Ativado"
            textLabel112.TextColor3 = Color3.new(1, 1, 1)
            textLabel112.Font = Enum.Font.GothamBold
            textLabel112.TextSize = 11
            textLabel112.BackgroundTransparency = 1
            textLabel112.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition87 = frame214:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition88 = frame214:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame214:Destroy()
            end)
        end)
        local frame215 = Instance.new("Frame", frame6)
        frame215.Size = UDim2.new(0.96, 0, 0, 36)
        frame215.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner466 = Instance.new("UICorner", frame215)
        local uIStroke72 = Instance.new("UIStroke", frame215)
        uIStroke72.Color = Color3.fromRGB(255, 220, 50)
        uIStroke72.Thickness = 1.5
        local textButton429 = Instance.new("TextButton", frame215)
        textButton429.Size = UDim2.new(1, -50, 1, 0)
        textButton429.Position = UDim2.new(0, 10, 0, 0)
        textButton429.BackgroundTransparency = 1
        textButton429.Text = "Auto Index Missing  [Click for Select]"
        textButton429.TextColor3 = Color3.new(1, 1, 1)
        textButton429.Font = Enum.Font.GothamBold
        textButton429.TextXAlignment = Enum.TextXAlignment.Left
        textButton429.TextSize = 10
        textButton429.ZIndex = 5
        local textButton430 = Instance.new("TextButton", frame215)
        textButton430.Size = UDim2.new(0, 30, 0, 14)
        textButton430.Position = UDim2.new(1, -38, 0.5, -7)
        textButton430.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton430.Text = ""
        textButton430.ZIndex = 10
        local uICorner467 = Instance.new("UICorner", textButton430)
        uICorner467.CornerRadius = UDim.new(1, 0)
        local frame216 = Instance.new("Frame", textButton430)
        frame216.Size = UDim2.new(0, 10, 0, 10)
        frame216.Position = UDim2.new(0, 2, 0.5, -5)
        frame216.BackgroundColor3 = Color3.new(1, 1, 1)
        frame216.ZIndex = 11
        local uICorner468 = Instance.new("UICorner", frame216)
        uICorner468.CornerRadius = UDim.new(1, 0)
        local conn432 = textButton430.MouseButton1Click:Connect(function()
            local tween47 = TweenService:Create(frame216, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween47:Play()
            local tween48 = TweenService:Create(textButton430, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween48:Play()
            local frame217 = Instance.new("Frame", screenGui)
            frame217.Size = UDim2.new(0, 220, 0, 60)
            frame217.Position = UDim2.new(1, 20, 1, -80)
            frame217.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner469 = Instance.new("UICorner", frame217)
            local uIStroke73 = Instance.new("UIStroke", frame217)
            uIStroke73.Color = Color3.fromRGB(255, 220, 50)
            uIStroke73.Thickness = 1.5
            local textLabel113 = Instance.new("TextLabel", frame217)
            textLabel113.Size = UDim2.new(1, -16, 0, 20)
            textLabel113.Position = UDim2.new(0, 8, 0, 10)
            textLabel113.Text = "Auto Index Missing"
            textLabel113.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel113.Font = Enum.Font.GothamBlack
            textLabel113.TextSize = 13
            textLabel113.BackgroundTransparency = 1
            textLabel113.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel114 = Instance.new("TextLabel", frame217)
            textLabel114.Size = UDim2.new(1, -16, 0, 18)
            textLabel114.Position = UDim2.new(0, 8, 0, 30)
            textLabel114.Text = "Ativado"
            textLabel114.TextColor3 = Color3.new(1, 1, 1)
            textLabel114.Font = Enum.Font.GothamBold
            textLabel114.TextSize = 11
            textLabel114.BackgroundTransparency = 1
            textLabel114.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition89 = frame217:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition90 = frame217:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame217:Destroy()
            end)
        end)
        local conn433 = textButton429.MouseButton1Click:Connect(function()
        end)
        local frame218 = Instance.new("Frame", frame6)
        frame218.Size = UDim2.new(0.96, 0, 0, 0)
        frame218.BackgroundColor3 = Color3.fromRGB(13, 13, 16)
        frame218.Visible = false
        frame218.ClipsDescendants = true
        local uICorner470 = Instance.new("UICorner", frame218)
        local uIStroke74 = Instance.new("UIStroke", frame218)
        uIStroke74.Color = Color3.fromRGB(255, 220, 50)
        local uIPadding8 = Instance.new("UIPadding", frame218)
        uIPadding8.PaddingTop = UDim.new(0, 5)
        uIPadding8.PaddingBottom = UDim.new(0, 5)
        uIPadding8.PaddingLeft = UDim.new(0, 6)
        uIPadding8.PaddingRight = UDim.new(0, 6)
        local uIListLayout8 = Instance.new("UIListLayout", frame218)
        uIListLayout8.SortOrder = 0
        uIListLayout8.Padding = UDim.new(0, 4)
        local textButton431 = Instance.new("TextButton", frame218)
        textButton431.Size = UDim2.new(1, 0, 0, 28)
        textButton431.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton431.Text = "Normal"
        textButton431.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton431.Font = Enum.Font.GothamBold
        textButton431.TextSize = 10
        local uICorner471 = Instance.new("UICorner", textButton431)
        local conn434 = textButton431.MouseButton1Click:Connect(function()
            textButton431.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
            textButton431.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton432 = Instance.new("TextButton", frame218)
        textButton432.Size = UDim2.new(1, 0, 0, 28)
        textButton432.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton432.Text = "Gold"
        textButton432.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton432.Font = Enum.Font.GothamBold
        textButton432.TextSize = 10
        local uICorner472 = Instance.new("UICorner", textButton432)
        local conn435 = textButton432.MouseButton1Click:Connect(function()
            textButton432.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
            textButton432.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton433 = Instance.new("TextButton", frame218)
        textButton433.Size = UDim2.new(1, 0, 0, 28)
        textButton433.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton433.Text = "Diamond"
        textButton433.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton433.Font = Enum.Font.GothamBold
        textButton433.TextSize = 10
        local uICorner473 = Instance.new("UICorner", textButton433)
        local conn436 = textButton433.MouseButton1Click:Connect(function()
            textButton433.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
            textButton433.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton434 = Instance.new("TextButton", frame218)
        textButton434.Size = UDim2.new(1, 0, 0, 28)
        textButton434.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton434.Text = "Rainbow"
        textButton434.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton434.Font = Enum.Font.GothamBold
        textButton434.TextSize = 10
        local uICorner474 = Instance.new("UICorner", textButton434)
        local conn437 = textButton434.MouseButton1Click:Connect(function()
            textButton434.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
            textButton434.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton435 = Instance.new("TextButton", frame218)
        textButton435.Size = UDim2.new(1, 0, 0, 28)
        textButton435.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton435.Text = "Lava"
        textButton435.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton435.Font = Enum.Font.GothamBold
        textButton435.TextSize = 10
        local uICorner475 = Instance.new("UICorner", textButton435)
        local conn438 = textButton435.MouseButton1Click:Connect(function()
            textButton435.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
            textButton435.TextColor3 = Color3.new(1, 1, 1)
        end)
        local frame219 = Instance.new("Frame", frame6)
        frame219.Size = UDim2.new(0.96, 0, 0, 36)
        frame219.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner476 = Instance.new("UICorner", frame219)
        local uIStroke75 = Instance.new("UIStroke", frame219)
        uIStroke75.Color = Color3.fromRGB(255, 220, 50)
        uIStroke75.Thickness = 1.5
        local textButton436 = Instance.new("TextButton", frame219)
        textButton436.Size = UDim2.new(1, -50, 1, 0)
        textButton436.Position = UDim2.new(0, 10, 0, 0)
        textButton436.BackgroundTransparency = 1
        textButton436.Text = "Rebirth Auto  [Click for Select]"
        textButton436.TextColor3 = Color3.new(1, 1, 1)
        textButton436.Font = Enum.Font.GothamBold
        textButton436.TextXAlignment = Enum.TextXAlignment.Left
        textButton436.TextSize = 10
        textButton436.ZIndex = 5
        local textButton437 = Instance.new("TextButton", frame219)
        textButton437.Size = UDim2.new(0, 30, 0, 14)
        textButton437.Position = UDim2.new(1, -38, 0.5, -7)
        textButton437.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton437.Text = ""
        textButton437.ZIndex = 10
        local uICorner477 = Instance.new("UICorner", textButton437)
        uICorner477.CornerRadius = UDim.new(1, 0)
        local frame220 = Instance.new("Frame", textButton437)
        frame220.Size = UDim2.new(0, 10, 0, 10)
        frame220.Position = UDim2.new(0, 2, 0.5, -5)
        frame220.BackgroundColor3 = Color3.new(1, 1, 1)
        frame220.ZIndex = 11
        local uICorner478 = Instance.new("UICorner", frame220)
        uICorner478.CornerRadius = UDim.new(1, 0)
        local conn439 = textButton437.MouseButton1Click:Connect(function()
            local frame221 = Instance.new("Frame", screenGui)
            frame221.Size = UDim2.new(0, 220, 0, 60)
            frame221.Position = UDim2.new(1, 20, 1, -80)
            frame221.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner479 = Instance.new("UICorner", frame221)
            local uIStroke76 = Instance.new("UIStroke", frame221)
            uIStroke76.Color = Color3.fromRGB(255, 220, 50)
            uIStroke76.Thickness = 1.5
            local textLabel115 = Instance.new("TextLabel", frame221)
            textLabel115.Size = UDim2.new(1, -16, 0, 20)
            textLabel115.Position = UDim2.new(0, 8, 0, 10)
            textLabel115.Text = "Rebirth Auto"
            textLabel115.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel115.Font = Enum.Font.GothamBlack
            textLabel115.TextSize = 13
            textLabel115.BackgroundTransparency = 1
            textLabel115.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel116 = Instance.new("TextLabel", frame221)
            textLabel116.Size = UDim2.new(1, -16, 0, 18)
            textLabel116.Position = UDim2.new(0, 8, 0, 30)
            textLabel116.Text = "Selecione um Rebirth primeiro!"
            textLabel116.TextColor3 = Color3.new(1, 1, 1)
            textLabel116.Font = Enum.Font.GothamBold
            textLabel116.TextSize = 11
            textLabel116.BackgroundTransparency = 1
            textLabel116.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition91 = frame221:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition92 = frame221:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame221:Destroy()
            end)
        end)
        local conn440 = textButton436.MouseButton1Click:Connect(function()
        end)
        local scrollingFrame8 = Instance.new("ScrollingFrame", frame6)
        scrollingFrame8.ScrollBarThickness = 3
        scrollingFrame8.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
        scrollingFrame8.AutomaticCanvasSize = 0
        scrollingFrame8.CanvasSize = UDim2.new(0, 0, 0, 0)
        scrollingFrame8.ScrollingDirection = 0
        scrollingFrame8.BorderSizePixel = 0
        scrollingFrame8.Size = UDim2.new(0.96, 0, 0, 0)
        scrollingFrame8.BackgroundColor3 = Color3.fromRGB(13, 13, 16)
        scrollingFrame8.Visible = false
        scrollingFrame8.ClipsDescendants = true
        local uICorner480 = Instance.new("UICorner", scrollingFrame8)
        local uIStroke77 = Instance.new("UIStroke", scrollingFrame8)
        uIStroke77.Color = Color3.fromRGB(255, 220, 50)
        local uIPadding9 = Instance.new("UIPadding", scrollingFrame8)
        uIPadding9.PaddingTop = UDim.new(0, 5)
        uIPadding9.PaddingBottom = UDim.new(0, 5)
        uIPadding9.PaddingLeft = UDim.new(0, 6)
        uIPadding9.PaddingRight = UDim.new(0, 6)
        local uIListLayout9 = Instance.new("UIListLayout", scrollingFrame8)
        uIListLayout9.SortOrder = 0
        uIListLayout9.Padding = UDim.new(0, 3)
        for _, child in textButton436:GetChildren() do
            local textButton438 = Instance.new("TextButton", scrollingFrame8)
            textButton438.Size = UDim2.new(1, 0, 0, 26)
            textButton438.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
            textButton438.Text = "Rebirth 1"
            textButton438.TextColor3 = Color3.new(1, 1, 1)
            textButton438.Font = Enum.Font.GothamBold
            textButton438.TextSize = 10
            local uICorner481 = Instance.new("UICorner", textButton438)
            local conn441 = textButton438.MouseButton1Click:Connect(function()
                local tween49 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                    Size = UDim2.new(0.96, 0, 0, 0)
                })
                tween49:Play()
                task.wait(0.15)
                scrollingFrame8.Visible = false
                local frame222 = Instance.new("Frame", screenGui)
                frame222.Size = UDim2.new(0, 220, 0, 60)
                frame222.Position = UDim2.new(1, 20, 1, -80)
                frame222.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
                local uICorner482 = Instance.new("UICorner", frame222)
                local uIStroke78 = Instance.new("UIStroke", frame222)
                uIStroke78.Color = Color3.fromRGB(255, 220, 50)
                uIStroke78.Thickness = 1.5
                local textLabel117 = Instance.new("TextLabel", frame222)
                textLabel117.Size = UDim2.new(1, -16, 0, 20)
                textLabel117.Position = UDim2.new(0, 8, 0, 10)
                textLabel117.Text = "Rebirth"
                textLabel117.TextColor3 = Color3.fromRGB(255, 220, 50)
                textLabel117.Font = Enum.Font.GothamBlack
                textLabel117.TextSize = 13
                textLabel117.BackgroundTransparency = 1
                textLabel117.TextXAlignment = Enum.TextXAlignment.Left
                local textLabel118 = Instance.new("TextLabel", frame222)
                textLabel118.Size = UDim2.new(1, -16, 0, 18)
                textLabel118.Position = UDim2.new(0, 8, 0, 30)
                textLabel118.Text = "Selecionado: Rebirth 1"
                textLabel118.TextColor3 = Color3.new(1, 1, 1)
                textLabel118.Font = Enum.Font.GothamBold
                textLabel118.TextSize = 11
                textLabel118.BackgroundTransparency = 1
                textLabel118.TextXAlignment = Enum.TextXAlignment.Left
                local tweenPosition93 = frame222:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
                task.delay(3, function()
                    local tweenPosition94 = frame222:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                    task.wait(0.5)
                    frame222:Destroy()
                end
            end)
        end)
        local textButton439 = Instance.new("TextButton", scrollingFrame8)
        textButton439.Size = UDim2.new(1, 0, 0, 26)
        textButton439.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton439.Text = "Rebirth 2"
        textButton439.TextColor3 = Color3.new(1, 1, 1)
        textButton439.Font = Enum.Font.GothamBold
        textButton439.TextSize = 10
        local uICorner483 = Instance.new("UICorner", textButton439)
        local conn442 = textButton439.MouseButton1Click:Connect(function()
            local tween50 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween50:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame223 = Instance.new("Frame", screenGui)
            frame223.Size = UDim2.new(0, 220, 0, 60)
            frame223.Position = UDim2.new(1, 20, 1, -80)
            frame223.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner484 = Instance.new("UICorner", frame223)
            local uIStroke79 = Instance.new("UIStroke", frame223)
            uIStroke79.Color = Color3.fromRGB(255, 220, 50)
            uIStroke79.Thickness = 1.5
            local textLabel119 = Instance.new("TextLabel", frame223)
            textLabel119.Size = UDim2.new(1, -16, 0, 20)
            textLabel119.Position = UDim2.new(0, 8, 0, 10)
            textLabel119.Text = "Rebirth"
            textLabel119.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel119.Font = Enum.Font.GothamBlack
            textLabel119.TextSize = 13
            textLabel119.BackgroundTransparency = 1
            textLabel119.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel120 = Instance.new("TextLabel", frame223)
            textLabel120.Size = UDim2.new(1, -16, 0, 18)
            textLabel120.Position = UDim2.new(0, 8, 0, 30)
            textLabel120.Text = "Selecionado: Rebirth 2"
            textLabel120.TextColor3 = Color3.new(1, 1, 1)
            textLabel120.Font = Enum.Font.GothamBold
            textLabel120.TextSize = 11
            textLabel120.BackgroundTransparency = 1
            textLabel120.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition95 = frame223:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition96 = frame223:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame223:Destroy()
            end)
        end)
        local textButton440 = Instance.new("TextButton", scrollingFrame8)
        textButton440.Size = UDim2.new(1, 0, 0, 26)
        textButton440.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton440.Text = "Rebirth 3"
        textButton440.TextColor3 = Color3.new(1, 1, 1)
        textButton440.Font = Enum.Font.GothamBold
        textButton440.TextSize = 10
        local uICorner485 = Instance.new("UICorner", textButton440)
        local conn443 = textButton440.MouseButton1Click:Connect(function()
            local tween51 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween51:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame224 = Instance.new("Frame", screenGui)
            frame224.Size = UDim2.new(0, 220, 0, 60)
            frame224.Position = UDim2.new(1, 20, 1, -80)
            frame224.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner486 = Instance.new("UICorner", frame224)
            local uIStroke80 = Instance.new("UIStroke", frame224)
            uIStroke80.Color = Color3.fromRGB(255, 220, 50)
            uIStroke80.Thickness = 1.5
            local textLabel121 = Instance.new("TextLabel", frame224)
            textLabel121.Size = UDim2.new(1, -16, 0, 20)
            textLabel121.Position = UDim2.new(0, 8, 0, 10)
            textLabel121.Text = "Rebirth"
            textLabel121.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel121.Font = Enum.Font.GothamBlack
            textLabel121.TextSize = 13
            textLabel121.BackgroundTransparency = 1
            textLabel121.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel122 = Instance.new("TextLabel", frame224)
            textLabel122.Size = UDim2.new(1, -16, 0, 18)
            textLabel122.Position = UDim2.new(0, 8, 0, 30)
            textLabel122.Text = "Selecionado: Rebirth 3"
            textLabel122.TextColor3 = Color3.new(1, 1, 1)
            textLabel122.Font = Enum.Font.GothamBold
            textLabel122.TextSize = 11
            textLabel122.BackgroundTransparency = 1
            textLabel122.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition97 = frame224:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition98 = frame224:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame224:Destroy()
            end)
        end)
        local textButton441 = Instance.new("TextButton", scrollingFrame8)
        textButton441.Size = UDim2.new(1, 0, 0, 26)
        textButton441.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton441.Text = "Rebirth 4"
        textButton441.TextColor3 = Color3.new(1, 1, 1)
        textButton441.Font = Enum.Font.GothamBold
        textButton441.TextSize = 10
        local uICorner487 = Instance.new("UICorner", textButton441)
        local conn444 = textButton441.MouseButton1Click:Connect(function()
            local tween52 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween52:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame225 = Instance.new("Frame", screenGui)
            frame225.Size = UDim2.new(0, 220, 0, 60)
            frame225.Position = UDim2.new(1, 20, 1, -80)
            frame225.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner488 = Instance.new("UICorner", frame225)
            local uIStroke81 = Instance.new("UIStroke", frame225)
            uIStroke81.Color = Color3.fromRGB(255, 220, 50)
            uIStroke81.Thickness = 1.5
            local textLabel123 = Instance.new("TextLabel", frame225)
            textLabel123.Size = UDim2.new(1, -16, 0, 20)
            textLabel123.Position = UDim2.new(0, 8, 0, 10)
            textLabel123.Text = "Rebirth"
            textLabel123.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel123.Font = Enum.Font.GothamBlack
            textLabel123.TextSize = 13
            textLabel123.BackgroundTransparency = 1
            textLabel123.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel124 = Instance.new("TextLabel", frame225)
            textLabel124.Size = UDim2.new(1, -16, 0, 18)
            textLabel124.Position = UDim2.new(0, 8, 0, 30)
            textLabel124.Text = "Selecionado: Rebirth 4"
            textLabel124.TextColor3 = Color3.new(1, 1, 1)
            textLabel124.Font = Enum.Font.GothamBold
            textLabel124.TextSize = 11
            textLabel124.BackgroundTransparency = 1
            textLabel124.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition99 = frame225:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition100 = frame225:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame225:Destroy()
            end)
        end)
        local textButton442 = Instance.new("TextButton", scrollingFrame8)
        textButton442.Size = UDim2.new(1, 0, 0, 26)
        textButton442.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton442.Text = "Rebirth 5"
        textButton442.TextColor3 = Color3.new(1, 1, 1)
        textButton442.Font = Enum.Font.GothamBold
        textButton442.TextSize = 10
        local uICorner489 = Instance.new("UICorner", textButton442)
        local conn445 = textButton442.MouseButton1Click:Connect(function()
            local tween53 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween53:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame226 = Instance.new("Frame", screenGui)
            frame226.Size = UDim2.new(0, 220, 0, 60)
            frame226.Position = UDim2.new(1, 20, 1, -80)
            frame226.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner490 = Instance.new("UICorner", frame226)
            local uIStroke82 = Instance.new("UIStroke", frame226)
            uIStroke82.Color = Color3.fromRGB(255, 220, 50)
            uIStroke82.Thickness = 1.5
            local textLabel125 = Instance.new("TextLabel", frame226)
            textLabel125.Size = UDim2.new(1, -16, 0, 20)
            textLabel125.Position = UDim2.new(0, 8, 0, 10)
            textLabel125.Text = "Rebirth"
            textLabel125.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel125.Font = Enum.Font.GothamBlack
            textLabel125.TextSize = 13
            textLabel125.BackgroundTransparency = 1
            textLabel125.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel126 = Instance.new("TextLabel", frame226)
            textLabel126.Size = UDim2.new(1, -16, 0, 18)
            textLabel126.Position = UDim2.new(0, 8, 0, 30)
            textLabel126.Text = "Selecionado: Rebirth 5"
            textLabel126.TextColor3 = Color3.new(1, 1, 1)
            textLabel126.Font = Enum.Font.GothamBold
            textLabel126.TextSize = 11
            textLabel126.BackgroundTransparency = 1
            textLabel126.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition101 = frame226:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition102 = frame226:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame226:Destroy()
            end)
        end)
        local textButton443 = Instance.new("TextButton", scrollingFrame8)
        textButton443.Size = UDim2.new(1, 0, 0, 26)
        textButton443.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton443.Text = "Rebirth 6"
        textButton443.TextColor3 = Color3.new(1, 1, 1)
        textButton443.Font = Enum.Font.GothamBold
        textButton443.TextSize = 10
        local uICorner491 = Instance.new("UICorner", textButton443)
        local conn446 = textButton443.MouseButton1Click:Connect(function()
            local tween54 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween54:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame227 = Instance.new("Frame", screenGui)
            frame227.Size = UDim2.new(0, 220, 0, 60)
            frame227.Position = UDim2.new(1, 20, 1, -80)
            frame227.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner492 = Instance.new("UICorner", frame227)
            local uIStroke83 = Instance.new("UIStroke", frame227)
            uIStroke83.Color = Color3.fromRGB(255, 220, 50)
            uIStroke83.Thickness = 1.5
            local textLabel127 = Instance.new("TextLabel", frame227)
            textLabel127.Size = UDim2.new(1, -16, 0, 20)
            textLabel127.Position = UDim2.new(0, 8, 0, 10)
            textLabel127.Text = "Rebirth"
            textLabel127.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel127.Font = Enum.Font.GothamBlack
            textLabel127.TextSize = 13
            textLabel127.BackgroundTransparency = 1
            textLabel127.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel128 = Instance.new("TextLabel", frame227)
            textLabel128.Size = UDim2.new(1, -16, 0, 18)
            textLabel128.Position = UDim2.new(0, 8, 0, 30)
            textLabel128.Text = "Selecionado: Rebirth 6"
            textLabel128.TextColor3 = Color3.new(1, 1, 1)
            textLabel128.Font = Enum.Font.GothamBold
            textLabel128.TextSize = 11
            textLabel128.BackgroundTransparency = 1
            textLabel128.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition103 = frame227:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition104 = frame227:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame227:Destroy()
            end)
        end)
        local textButton444 = Instance.new("TextButton", scrollingFrame8)
        textButton444.Size = UDim2.new(1, 0, 0, 26)
        textButton444.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton444.Text = "Rebirth 7"
        textButton444.TextColor3 = Color3.new(1, 1, 1)
        textButton444.Font = Enum.Font.GothamBold
        textButton444.TextSize = 10
        local uICorner493 = Instance.new("UICorner", textButton444)
        local conn447 = textButton444.MouseButton1Click:Connect(function()
            local tween55 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween55:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame228 = Instance.new("Frame", screenGui)
            frame228.Size = UDim2.new(0, 220, 0, 60)
            frame228.Position = UDim2.new(1, 20, 1, -80)
            frame228.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner494 = Instance.new("UICorner", frame228)
            local uIStroke84 = Instance.new("UIStroke", frame228)
            uIStroke84.Color = Color3.fromRGB(255, 220, 50)
            uIStroke84.Thickness = 1.5
            local textLabel129 = Instance.new("TextLabel", frame228)
            textLabel129.Size = UDim2.new(1, -16, 0, 20)
            textLabel129.Position = UDim2.new(0, 8, 0, 10)
            textLabel129.Text = "Rebirth"
            textLabel129.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel129.Font = Enum.Font.GothamBlack
            textLabel129.TextSize = 13
            textLabel129.BackgroundTransparency = 1
            textLabel129.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel130 = Instance.new("TextLabel", frame228)
            textLabel130.Size = UDim2.new(1, -16, 0, 18)
            textLabel130.Position = UDim2.new(0, 8, 0, 30)
            textLabel130.Text = "Selecionado: Rebirth 7"
            textLabel130.TextColor3 = Color3.new(1, 1, 1)
            textLabel130.Font = Enum.Font.GothamBold
            textLabel130.TextSize = 11
            textLabel130.BackgroundTransparency = 1
            textLabel130.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition105 = frame228:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition106 = frame228:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame228:Destroy()
            end)
        end)
        local textButton445 = Instance.new("TextButton", scrollingFrame8)
        textButton445.Size = UDim2.new(1, 0, 0, 26)
        textButton445.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton445.Text = "Rebirth 8"
        textButton445.TextColor3 = Color3.new(1, 1, 1)
        textButton445.Font = Enum.Font.GothamBold
        textButton445.TextSize = 10
        local uICorner495 = Instance.new("UICorner", textButton445)
        local conn448 = textButton445.MouseButton1Click:Connect(function()
            local tween56 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween56:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame229 = Instance.new("Frame", screenGui)
            frame229.Size = UDim2.new(0, 220, 0, 60)
            frame229.Position = UDim2.new(1, 20, 1, -80)
            frame229.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner496 = Instance.new("UICorner", frame229)
            local uIStroke85 = Instance.new("UIStroke", frame229)
            uIStroke85.Color = Color3.fromRGB(255, 220, 50)
            uIStroke85.Thickness = 1.5
            local textLabel131 = Instance.new("TextLabel", frame229)
            textLabel131.Size = UDim2.new(1, -16, 0, 20)
            textLabel131.Position = UDim2.new(0, 8, 0, 10)
            textLabel131.Text = "Rebirth"
            textLabel131.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel131.Font = Enum.Font.GothamBlack
            textLabel131.TextSize = 13
            textLabel131.BackgroundTransparency = 1
            textLabel131.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel132 = Instance.new("TextLabel", frame229)
            textLabel132.Size = UDim2.new(1, -16, 0, 18)
            textLabel132.Position = UDim2.new(0, 8, 0, 30)
            textLabel132.Text = "Selecionado: Rebirth 8"
            textLabel132.TextColor3 = Color3.new(1, 1, 1)
            textLabel132.Font = Enum.Font.GothamBold
            textLabel132.TextSize = 11
            textLabel132.BackgroundTransparency = 1
            textLabel132.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition107 = frame229:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition108 = frame229:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame229:Destroy()
            end)
        end)
        local textButton446 = Instance.new("TextButton", scrollingFrame8)
        textButton446.Size = UDim2.new(1, 0, 0, 26)
        textButton446.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton446.Text = "Rebirth 9"
        textButton446.TextColor3 = Color3.new(1, 1, 1)
        textButton446.Font = Enum.Font.GothamBold
        textButton446.TextSize = 10
        local uICorner497 = Instance.new("UICorner", textButton446)
        local conn449 = textButton446.MouseButton1Click:Connect(function()
            local tween57 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween57:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame230 = Instance.new("Frame", screenGui)
            frame230.Size = UDim2.new(0, 220, 0, 60)
            frame230.Position = UDim2.new(1, 20, 1, -80)
            frame230.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner498 = Instance.new("UICorner", frame230)
            local uIStroke86 = Instance.new("UIStroke", frame230)
            uIStroke86.Color = Color3.fromRGB(255, 220, 50)
            uIStroke86.Thickness = 1.5
            local textLabel133 = Instance.new("TextLabel", frame230)
            textLabel133.Size = UDim2.new(1, -16, 0, 20)
            textLabel133.Position = UDim2.new(0, 8, 0, 10)
            textLabel133.Text = "Rebirth"
            textLabel133.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel133.Font = Enum.Font.GothamBlack
            textLabel133.TextSize = 13
            textLabel133.BackgroundTransparency = 1
            textLabel133.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel134 = Instance.new("TextLabel", frame230)
            textLabel134.Size = UDim2.new(1, -16, 0, 18)
            textLabel134.Position = UDim2.new(0, 8, 0, 30)
            textLabel134.Text = "Selecionado: Rebirth 9"
            textLabel134.TextColor3 = Color3.new(1, 1, 1)
            textLabel134.Font = Enum.Font.GothamBold
            textLabel134.TextSize = 11
            textLabel134.BackgroundTransparency = 1
            textLabel134.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition109 = frame230:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition110 = frame230:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame230:Destroy()
            end)
        end)
        local textButton447 = Instance.new("TextButton", scrollingFrame8)
        textButton447.Size = UDim2.new(1, 0, 0, 26)
        textButton447.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton447.Text = "Rebirth 10"
        textButton447.TextColor3 = Color3.new(1, 1, 1)
        textButton447.Font = Enum.Font.GothamBold
        textButton447.TextSize = 10
        local uICorner499 = Instance.new("UICorner", textButton447)
        local conn450 = textButton447.MouseButton1Click:Connect(function()
            local tween58 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween58:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame231 = Instance.new("Frame", screenGui)
            frame231.Size = UDim2.new(0, 220, 0, 60)
            frame231.Position = UDim2.new(1, 20, 1, -80)
            frame231.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner500 = Instance.new("UICorner", frame231)
            local uIStroke87 = Instance.new("UIStroke", frame231)
            uIStroke87.Color = Color3.fromRGB(255, 220, 50)
            uIStroke87.Thickness = 1.5
            local textLabel135 = Instance.new("TextLabel", frame231)
            textLabel135.Size = UDim2.new(1, -16, 0, 20)
            textLabel135.Position = UDim2.new(0, 8, 0, 10)
            textLabel135.Text = "Rebirth"
            textLabel135.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel135.Font = Enum.Font.GothamBlack
            textLabel135.TextSize = 13
            textLabel135.BackgroundTransparency = 1
            textLabel135.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel136 = Instance.new("TextLabel", frame231)
            textLabel136.Size = UDim2.new(1, -16, 0, 18)
            textLabel136.Position = UDim2.new(0, 8, 0, 30)
            textLabel136.Text = "Selecionado: Rebirth 10"
            textLabel136.TextColor3 = Color3.new(1, 1, 1)
            textLabel136.Font = Enum.Font.GothamBold
            textLabel136.TextSize = 11
            textLabel136.BackgroundTransparency = 1
            textLabel136.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition111 = frame231:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition112 = frame231:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame231:Destroy()
            end)
        end)
        local textButton448 = Instance.new("TextButton", scrollingFrame8)
        textButton448.Size = UDim2.new(1, 0, 0, 26)
        textButton448.BackgroundColor3 = Color3.fromRGB(20, 20, 20)
        textButton448.Text = "Rebirth 11"
        textButton448.TextColor3 = Color3.new(1, 1, 1)
        textButton448.Font = Enum.Font.GothamBold
        textButton448.TextSize = 10
        local uICorner501 = Instance.new("UICorner", textButton448)
        local conn451 = textButton448.MouseButton1Click:Connect(function()
            local tween59 = TweenService:Create(scrollingFrame8, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Size = UDim2.new(0.96, 0, 0, 0)
            })
            tween59:Play()
            task.wait(0.15)
            scrollingFrame8.Visible = false
            local frame232 = Instance.new("Frame", screenGui)
            frame232.Size = UDim2.new(0, 220, 0, 60)
            frame232.Position = UDim2.new(1, 20, 1, -80)
            frame232.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner502 = Instance.new("UICorner", frame232)
            local uIStroke88 = Instance.new("UIStroke", frame232)
            uIStroke88.Color = Color3.fromRGB(255, 220, 50)
            uIStroke88.Thickness = 1.5
            local textLabel137 = Instance.new("TextLabel", frame232)
            textLabel137.Size = UDim2.new(1, -16, 0, 20)
            textLabel137.Position = UDim2.new(0, 8, 0, 10)
            textLabel137.Text = "Rebirth"
            textLabel137.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel137.Font = Enum.Font.GothamBlack
            textLabel137.TextSize = 13
            textLabel137.BackgroundTransparency = 1
            textLabel137.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel138 = Instance.new("TextLabel", frame232)
            textLabel138.Size = UDim2.new(1, -16, 0, 18)
            textLabel138.Position = UDim2.new(0, 8, 0, 30)
            textLabel138.Text = "Selecionado: Rebirth 11"
            textLabel138.TextColor3 = Color3.new(1, 1, 1)
            textLabel138.Font = Enum.Font.GothamBold
            textLabel138.TextSize = 11
            textLabel138.BackgroundTransparency = 1
            textLabel138.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition113 = frame232:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition114 = frame232:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame232:Destroy()
            end)
        end)
        local frame233 = Instance.new("Frame", frame6)
        frame233.Size = UDim2.new(0.96, 0, 0, 36)
        frame233.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner503 = Instance.new("UICorner", frame233)
        local uIStroke89 = Instance.new("UIStroke", frame233)
        uIStroke89.Color = Color3.fromRGB(255, 220, 50)
        uIStroke89.Thickness = 1.5
        local textButton449 = Instance.new("TextButton", frame233)
        textButton449.Size = UDim2.new(1, -50, 1, 0)
        textButton449.Position = UDim2.new(0, 10, 0, 0)
        textButton449.BackgroundTransparency = 1
        textButton449.Text = "Auto Specific  [Click for Select]"
        textButton449.TextColor3 = Color3.new(1, 1, 1)
        textButton449.Font = Enum.Font.GothamBold
        textButton449.TextXAlignment = Enum.TextXAlignment.Left
        textButton449.TextSize = 10
        textButton449.ZIndex = 5
        local textButton450 = Instance.new("TextButton", frame233)
        textButton450.Size = UDim2.new(0, 30, 0, 14)
        textButton450.Position = UDim2.new(1, -38, 0.5, -7)
        textButton450.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton450.Text = ""
        textButton450.ZIndex = 10
        local uICorner504 = Instance.new("UICorner", textButton450)
        uICorner504.CornerRadius = UDim.new(1, 0)
        local frame234 = Instance.new("Frame", textButton450)
        frame234.Size = UDim2.new(0, 10, 0, 10)
        frame234.Position = UDim2.new(0, 2, 0.5, -5)
        frame234.BackgroundColor3 = Color3.new(1, 1, 1)
        frame234.ZIndex = 11
        local uICorner505 = Instance.new("UICorner", frame234)
        uICorner505.CornerRadius = UDim.new(1, 0)
        local conn452 = textButton450.MouseButton1Click:Connect(function()
            local tween60 = TweenService:Create(frame234, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween60:Play()
            local tween61 = TweenService:Create(textButton450, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween61:Play()
            local frame235 = Instance.new("Frame", screenGui)
            frame235.Size = UDim2.new(0, 220, 0, 60)
            frame235.Position = UDim2.new(1, 20, 1, -80)
            frame235.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner506 = Instance.new("UICorner", frame235)
            local uIStroke90 = Instance.new("UIStroke", frame235)
            uIStroke90.Color = Color3.fromRGB(255, 220, 50)
            uIStroke90.Thickness = 1.5
            local textLabel139 = Instance.new("TextLabel", frame235)
            textLabel139.Size = UDim2.new(1, -16, 0, 20)
            textLabel139.Position = UDim2.new(0, 8, 0, 10)
            textLabel139.Text = "Auto Specific"
            textLabel139.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel139.Font = Enum.Font.GothamBlack
            textLabel139.TextSize = 13
            textLabel139.BackgroundTransparency = 1
            textLabel139.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel140 = Instance.new("TextLabel", frame235)
            textLabel140.Size = UDim2.new(1, -16, 0, 18)
            textLabel140.Position = UDim2.new(0, 8, 0, 30)
            textLabel140.Text = "Ativado"
            textLabel140.TextColor3 = Color3.new(1, 1, 1)
            textLabel140.Font = Enum.Font.GothamBold
            textLabel140.TextSize = 11
            textLabel140.BackgroundTransparency = 1
            textLabel140.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition115 = frame235:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition116 = frame235:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame235:Destroy()
            end)
        end)
        local conn453 = textButton449.MouseButton1Click:Connect(function()
        end)
        local frame236 = Instance.new("Frame", frame6)
        frame236.Size = UDim2.new(0.96, 0, 0, 200)
        frame236.BackgroundColor3 = Color3.fromRGB(12, 12, 15)
        frame236.Visible = false
        frame236.ClipsDescendants = true
        local uICorner507 = Instance.new("UICorner", frame236)
        local uIStroke91 = Instance.new("UIStroke", frame236)
        uIStroke91.Color = Color3.fromRGB(255, 220, 50)
        local scrollingFrame9 = Instance.new("ScrollingFrame", frame236)
        scrollingFrame9.Size = UDim2.new(1, 0, 1, 0)
        scrollingFrame9.BackgroundTransparency = 1
        scrollingFrame9.ScrollBarThickness = 3
        scrollingFrame9.ScrollBarImageColor3 = Color3.fromRGB(255, 220, 50)
        scrollingFrame9.AutomaticCanvasSize = 0
        scrollingFrame9.CanvasSize = UDim2.new(0, 0, 0, 0)
        local uIListLayout10 = Instance.new("UIListLayout", scrollingFrame9)
        uIListLayout10.Padding = UDim.new(0, 2)
        uIListLayout10.SortOrder = 0
        local uIPadding10 = Instance.new("UIPadding", scrollingFrame9)
        uIPadding10.PaddingTop = UDim.new(0, 4)
        uIPadding10.PaddingBottom = UDim.new(0, 4)
        uIPadding10.PaddingLeft = UDim.new(0, 4)
        uIPadding10.PaddingRight = UDim.new(0, 4)
        local frame237 = Instance.new("Frame", scrollingFrame9)
        frame237.Size = UDim2.new(1, 0, 0, 28)
        frame237.BackgroundTransparency = 1
        local textButton451 = Instance.new("TextButton", frame237)
        textButton451.Size = UDim2.new(0.72, 0, 1, 0)
        textButton451.BackgroundTransparency = 1
        textButton451.Text = "Noobini Pizzanini"
        textButton451.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton451.TextXAlignment = Enum.TextXAlignment.Left
        textButton451.Font = Enum.Font.Gotham
        textButton451.TextSize = 10
        local textButton452 = Instance.new("TextButton", frame237)
        textButton452.Size = UDim2.new(0, 16, 0, 16)
        textButton452.Position = UDim2.new(1, -20, 0.5, -8)
        textButton452.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton452.Text = ""
        local uICorner508 = Instance.new("UICorner", textButton452)
        uICorner508.CornerRadius = UDim.new(0, 3)
        local frame238 = Instance.new("Frame", scrollingFrame9)
        frame238.Size = UDim2.new(1, 0, 0, 26)
        frame238.BackgroundTransparency = 1
        frame238.Visible = false
        local uIGridLayout58 = Instance.new("UIGridLayout", frame238)
        uIGridLayout58.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout58.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton453 = Instance.new("TextButton", frame238)
        textButton453.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton453.Text = "Nor"
        textButton453.TextSize = 9
        textButton453.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton453.Font = Enum.Font.GothamBold
        local uICorner509 = Instance.new("UICorner", textButton453)
        local conn454 = textButton453.MouseButton1Click:Connect(function()
            textButton453.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton453.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton454 = Instance.new("TextButton", frame238)
        textButton454.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton454.Text = "Gol"
        textButton454.TextSize = 9
        textButton454.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton454.Font = Enum.Font.GothamBold
        local uICorner510 = Instance.new("UICorner", textButton454)
        local conn455 = textButton454.MouseButton1Click:Connect(function()
            textButton454.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton454.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton455 = Instance.new("TextButton", frame238)
        textButton455.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton455.Text = "Dia"
        textButton455.TextSize = 9
        textButton455.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton455.Font = Enum.Font.GothamBold
        local uICorner511 = Instance.new("UICorner", textButton455)
        local conn456 = textButton455.MouseButton1Click:Connect(function()
            textButton455.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton455.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton456 = Instance.new("TextButton", frame238)
        textButton456.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton456.Text = "Rai"
        textButton456.TextSize = 9
        textButton456.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton456.Font = Enum.Font.GothamBold
        local uICorner512 = Instance.new("UICorner", textButton456)
        local conn457 = textButton456.MouseButton1Click:Connect(function()
            textButton456.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton456.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton457 = Instance.new("TextButton", frame238)
        textButton457.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton457.Text = "Lav"
        textButton457.TextSize = 9
        textButton457.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton457.Font = Enum.Font.GothamBold
        local uICorner513 = Instance.new("UICorner", textButton457)
        local conn458 = textButton457.MouseButton1Click:Connect(function()
            textButton457.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton457.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn459 = textButton451.MouseButton1Click:Connect(function()
            frame238.Visible = true
        end)
        local conn460 = textButton452.MouseButton1Click:Connect(function()
            textButton452.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame239 = Instance.new("Frame", scrollingFrame9)
        frame239.Size = UDim2.new(1, 0, 0, 28)
        frame239.BackgroundTransparency = 1
        local textButton458 = Instance.new("TextButton", frame239)
        textButton458.Size = UDim2.new(0.72, 0, 1, 0)
        textButton458.BackgroundTransparency = 1
        textButton458.Text = "LiriliLarila"
        textButton458.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton458.TextXAlignment = Enum.TextXAlignment.Left
        textButton458.Font = Enum.Font.Gotham
        textButton458.TextSize = 10
        local textButton459 = Instance.new("TextButton", frame239)
        textButton459.Size = UDim2.new(0, 16, 0, 16)
        textButton459.Position = UDim2.new(1, -20, 0.5, -8)
        textButton459.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton459.Text = ""
        local uICorner514 = Instance.new("UICorner", textButton459)
        uICorner514.CornerRadius = UDim.new(0, 3)
        local frame240 = Instance.new("Frame", scrollingFrame9)
        frame240.Size = UDim2.new(1, 0, 0, 26)
        frame240.BackgroundTransparency = 1
        frame240.Visible = false
        local uIGridLayout59 = Instance.new("UIGridLayout", frame240)
        uIGridLayout59.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout59.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton460 = Instance.new("TextButton", frame240)
        textButton460.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton460.Text = "Nor"
        textButton460.TextSize = 9
        textButton460.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton460.Font = Enum.Font.GothamBold
        local uICorner515 = Instance.new("UICorner", textButton460)
        local conn461 = textButton460.MouseButton1Click:Connect(function()
            textButton460.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton460.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton461 = Instance.new("TextButton", frame240)
        textButton461.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton461.Text = "Gol"
        textButton461.TextSize = 9
        textButton461.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton461.Font = Enum.Font.GothamBold
        local uICorner516 = Instance.new("UICorner", textButton461)
        local conn462 = textButton461.MouseButton1Click:Connect(function()
            textButton461.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton461.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton462 = Instance.new("TextButton", frame240)
        textButton462.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton462.Text = "Dia"
        textButton462.TextSize = 9
        textButton462.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton462.Font = Enum.Font.GothamBold
        local uICorner517 = Instance.new("UICorner", textButton462)
        local conn463 = textButton462.MouseButton1Click:Connect(function()
            textButton462.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton462.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton463 = Instance.new("TextButton", frame240)
        textButton463.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton463.Text = "Rai"
        textButton463.TextSize = 9
        textButton463.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton463.Font = Enum.Font.GothamBold
        local uICorner518 = Instance.new("UICorner", textButton463)
        local conn464 = textButton463.MouseButton1Click:Connect(function()
            textButton463.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton463.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton464 = Instance.new("TextButton", frame240)
        textButton464.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton464.Text = "Lav"
        textButton464.TextSize = 9
        textButton464.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton464.Font = Enum.Font.GothamBold
        local uICorner519 = Instance.new("UICorner", textButton464)
        local conn465 = textButton464.MouseButton1Click:Connect(function()
            textButton464.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton464.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn466 = textButton458.MouseButton1Click:Connect(function()
            frame240.Visible = true
        end)
        local conn467 = textButton459.MouseButton1Click:Connect(function()
            textButton459.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame241 = Instance.new("Frame", scrollingFrame9)
        frame241.Size = UDim2.new(1, 0, 0, 28)
        frame241.BackgroundTransparency = 1
        local textButton465 = Instance.new("TextButton", frame241)
        textButton465.Size = UDim2.new(0.72, 0, 1, 0)
        textButton465.BackgroundTransparency = 1
        textButton465.Text = "Fluri Flura"
        textButton465.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton465.TextXAlignment = Enum.TextXAlignment.Left
        textButton465.Font = Enum.Font.Gotham
        textButton465.TextSize = 10
        local textButton466 = Instance.new("TextButton", frame241)
        textButton466.Size = UDim2.new(0, 16, 0, 16)
        textButton466.Position = UDim2.new(1, -20, 0.5, -8)
        textButton466.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton466.Text = ""
        local uICorner520 = Instance.new("UICorner", textButton466)
        uICorner520.CornerRadius = UDim.new(0, 3)
        local frame242 = Instance.new("Frame", scrollingFrame9)
        frame242.Size = UDim2.new(1, 0, 0, 26)
        frame242.BackgroundTransparency = 1
        frame242.Visible = false
        local uIGridLayout60 = Instance.new("UIGridLayout", frame242)
        uIGridLayout60.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout60.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton467 = Instance.new("TextButton", frame242)
        textButton467.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton467.Text = "Nor"
        textButton467.TextSize = 9
        textButton467.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton467.Font = Enum.Font.GothamBold
        local uICorner521 = Instance.new("UICorner", textButton467)
        local conn468 = textButton467.MouseButton1Click:Connect(function()
            textButton467.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton467.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton468 = Instance.new("TextButton", frame242)
        textButton468.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton468.Text = "Gol"
        textButton468.TextSize = 9
        textButton468.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton468.Font = Enum.Font.GothamBold
        local uICorner522 = Instance.new("UICorner", textButton468)
        local conn469 = textButton468.MouseButton1Click:Connect(function()
            textButton468.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton468.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton469 = Instance.new("TextButton", frame242)
        textButton469.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton469.Text = "Dia"
        textButton469.TextSize = 9
        textButton469.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton469.Font = Enum.Font.GothamBold
        local uICorner523 = Instance.new("UICorner", textButton469)
        local conn470 = textButton469.MouseButton1Click:Connect(function()
            textButton469.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton469.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton470 = Instance.new("TextButton", frame242)
        textButton470.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton470.Text = "Rai"
        textButton470.TextSize = 9
        textButton470.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton470.Font = Enum.Font.GothamBold
        local uICorner524 = Instance.new("UICorner", textButton470)
        local conn471 = textButton470.MouseButton1Click:Connect(function()
            textButton470.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton470.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton471 = Instance.new("TextButton", frame242)
        textButton471.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton471.Text = "Lav"
        textButton471.TextSize = 9
        textButton471.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton471.Font = Enum.Font.GothamBold
        local uICorner525 = Instance.new("UICorner", textButton471)
        local conn472 = textButton471.MouseButton1Click:Connect(function()
            textButton471.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton471.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn473 = textButton465.MouseButton1Click:Connect(function()
            frame242.Visible = true
        end)
        local conn474 = textButton466.MouseButton1Click:Connect(function()
            textButton466.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame243 = Instance.new("Frame", scrollingFrame9)
        frame243.Size = UDim2.new(1, 0, 0, 28)
        frame243.BackgroundTransparency = 1
        local textButton472 = Instance.new("TextButton", frame243)
        textButton472.Size = UDim2.new(0.72, 0, 1, 0)
        textButton472.BackgroundTransparency = 1
        textButton472.Text = "Cacto Hipopotamo"
        textButton472.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton472.TextXAlignment = Enum.TextXAlignment.Left
        textButton472.Font = Enum.Font.Gotham
        textButton472.TextSize = 10
        local textButton473 = Instance.new("TextButton", frame243)
        textButton473.Size = UDim2.new(0, 16, 0, 16)
        textButton473.Position = UDim2.new(1, -20, 0.5, -8)
        textButton473.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton473.Text = ""
        local uICorner526 = Instance.new("UICorner", textButton473)
        uICorner526.CornerRadius = UDim.new(0, 3)
        local frame244 = Instance.new("Frame", scrollingFrame9)
        frame244.Size = UDim2.new(1, 0, 0, 26)
        frame244.BackgroundTransparency = 1
        frame244.Visible = false
        local uIGridLayout61 = Instance.new("UIGridLayout", frame244)
        uIGridLayout61.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout61.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton474 = Instance.new("TextButton", frame244)
        textButton474.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton474.Text = "Nor"
        textButton474.TextSize = 9
        textButton474.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton474.Font = Enum.Font.GothamBold
        local uICorner527 = Instance.new("UICorner", textButton474)
        local conn475 = textButton474.MouseButton1Click:Connect(function()
            textButton474.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton474.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton475 = Instance.new("TextButton", frame244)
        textButton475.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton475.Text = "Gol"
        textButton475.TextSize = 9
        textButton475.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton475.Font = Enum.Font.GothamBold
        local uICorner528 = Instance.new("UICorner", textButton475)
        local conn476 = textButton475.MouseButton1Click:Connect(function()
            textButton475.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton475.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton476 = Instance.new("TextButton", frame244)
        textButton476.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton476.Text = "Dia"
        textButton476.TextSize = 9
        textButton476.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton476.Font = Enum.Font.GothamBold
        local uICorner529 = Instance.new("UICorner", textButton476)
        local conn477 = textButton476.MouseButton1Click:Connect(function()
            textButton476.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton476.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton477 = Instance.new("TextButton", frame244)
        textButton477.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton477.Text = "Rai"
        textButton477.TextSize = 9
        textButton477.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton477.Font = Enum.Font.GothamBold
        local uICorner530 = Instance.new("UICorner", textButton477)
        local conn478 = textButton477.MouseButton1Click:Connect(function()
            textButton477.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton477.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton478 = Instance.new("TextButton", frame244)
        textButton478.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton478.Text = "Lav"
        textButton478.TextSize = 9
        textButton478.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton478.Font = Enum.Font.GothamBold
        local uICorner531 = Instance.new("UICorner", textButton478)
        local conn479 = textButton478.MouseButton1Click:Connect(function()
            textButton478.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton478.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn480 = textButton472.MouseButton1Click:Connect(function()
            frame244.Visible = true
        end)
        local conn481 = textButton473.MouseButton1Click:Connect(function()
            textButton473.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame245 = Instance.new("Frame", scrollingFrame9)
        frame245.Size = UDim2.new(1, 0, 0, 28)
        frame245.BackgroundTransparency = 1
        local textButton479 = Instance.new("TextButton", frame245)
        textButton479.Size = UDim2.new(0.72, 0, 1, 0)
        textButton479.BackgroundTransparency = 1
        textButton479.Text = "Pipi Potato"
        textButton479.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton479.TextXAlignment = Enum.TextXAlignment.Left
        textButton479.Font = Enum.Font.Gotham
        textButton479.TextSize = 10
        local textButton480 = Instance.new("TextButton", frame245)
        textButton480.Size = UDim2.new(0, 16, 0, 16)
        textButton480.Position = UDim2.new(1, -20, 0.5, -8)
        textButton480.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton480.Text = ""
        local uICorner532 = Instance.new("UICorner", textButton480)
        uICorner532.CornerRadius = UDim.new(0, 3)
        local frame246 = Instance.new("Frame", scrollingFrame9)
        frame246.Size = UDim2.new(1, 0, 0, 26)
        frame246.BackgroundTransparency = 1
        frame246.Visible = false
        local uIGridLayout62 = Instance.new("UIGridLayout", frame246)
        uIGridLayout62.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout62.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton481 = Instance.new("TextButton", frame246)
        textButton481.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton481.Text = "Nor"
        textButton481.TextSize = 9
        textButton481.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton481.Font = Enum.Font.GothamBold
        local uICorner533 = Instance.new("UICorner", textButton481)
        local conn482 = textButton481.MouseButton1Click:Connect(function()
            textButton481.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton481.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton482 = Instance.new("TextButton", frame246)
        textButton482.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton482.Text = "Gol"
        textButton482.TextSize = 9
        textButton482.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton482.Font = Enum.Font.GothamBold
        local uICorner534 = Instance.new("UICorner", textButton482)
        local conn483 = textButton482.MouseButton1Click:Connect(function()
            textButton482.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton482.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton483 = Instance.new("TextButton", frame246)
        textButton483.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton483.Text = "Dia"
        textButton483.TextSize = 9
        textButton483.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton483.Font = Enum.Font.GothamBold
        local uICorner535 = Instance.new("UICorner", textButton483)
        local conn484 = textButton483.MouseButton1Click:Connect(function()
            textButton483.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton483.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton484 = Instance.new("TextButton", frame246)
        textButton484.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton484.Text = "Rai"
        textButton484.TextSize = 9
        textButton484.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton484.Font = Enum.Font.GothamBold
        local uICorner536 = Instance.new("UICorner", textButton484)
        local conn485 = textButton484.MouseButton1Click:Connect(function()
            textButton484.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton484.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton485 = Instance.new("TextButton", frame246)
        textButton485.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton485.Text = "Lav"
        textButton485.TextSize = 9
        textButton485.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton485.Font = Enum.Font.GothamBold
        local uICorner537 = Instance.new("UICorner", textButton485)
        local conn486 = textButton485.MouseButton1Click:Connect(function()
            textButton485.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton485.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn487 = textButton479.MouseButton1Click:Connect(function()
            frame246.Visible = true
        end)
        local conn488 = textButton480.MouseButton1Click:Connect(function()
            textButton480.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame247 = Instance.new("Frame", scrollingFrame9)
        frame247.Size = UDim2.new(1, 0, 0, 28)
        frame247.BackgroundTransparency = 1
        local textButton486 = Instance.new("TextButton", frame247)
        textButton486.Size = UDim2.new(0.72, 0, 1, 0)
        textButton486.BackgroundTransparency = 1
        textButton486.Text = "Tric Trac Barabum"
        textButton486.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton486.TextXAlignment = Enum.TextXAlignment.Left
        textButton486.Font = Enum.Font.Gotham
        textButton486.TextSize = 10
        local textButton487 = Instance.new("TextButton", frame247)
        textButton487.Size = UDim2.new(0, 16, 0, 16)
        textButton487.Position = UDim2.new(1, -20, 0.5, -8)
        textButton487.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton487.Text = ""
        local uICorner538 = Instance.new("UICorner", textButton487)
        uICorner538.CornerRadius = UDim.new(0, 3)
        local frame248 = Instance.new("Frame", scrollingFrame9)
        frame248.Size = UDim2.new(1, 0, 0, 26)
        frame248.BackgroundTransparency = 1
        frame248.Visible = false
        local uIGridLayout63 = Instance.new("UIGridLayout", frame248)
        uIGridLayout63.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout63.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton488 = Instance.new("TextButton", frame248)
        textButton488.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton488.Text = "Nor"
        textButton488.TextSize = 9
        textButton488.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton488.Font = Enum.Font.GothamBold
        local uICorner539 = Instance.new("UICorner", textButton488)
        local conn489 = textButton488.MouseButton1Click:Connect(function()
            textButton488.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton488.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton489 = Instance.new("TextButton", frame248)
        textButton489.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton489.Text = "Gol"
        textButton489.TextSize = 9
        textButton489.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton489.Font = Enum.Font.GothamBold
        local uICorner540 = Instance.new("UICorner", textButton489)
        local conn490 = textButton489.MouseButton1Click:Connect(function()
            textButton489.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton489.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton490 = Instance.new("TextButton", frame248)
        textButton490.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton490.Text = "Dia"
        textButton490.TextSize = 9
        textButton490.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton490.Font = Enum.Font.GothamBold
        local uICorner541 = Instance.new("UICorner", textButton490)
        local conn491 = textButton490.MouseButton1Click:Connect(function()
            textButton490.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton490.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton491 = Instance.new("TextButton", frame248)
        textButton491.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton491.Text = "Rai"
        textButton491.TextSize = 9
        textButton491.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton491.Font = Enum.Font.GothamBold
        local uICorner542 = Instance.new("UICorner", textButton491)
        local conn492 = textButton491.MouseButton1Click:Connect(function()
            textButton491.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton491.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton492 = Instance.new("TextButton", frame248)
        textButton492.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton492.Text = "Lav"
        textButton492.TextSize = 9
        textButton492.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton492.Font = Enum.Font.GothamBold
        local uICorner543 = Instance.new("UICorner", textButton492)
        local conn493 = textButton492.MouseButton1Click:Connect(function()
            textButton492.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton492.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn494 = textButton486.MouseButton1Click:Connect(function()
            frame248.Visible = true
        end)
        local conn495 = textButton487.MouseButton1Click:Connect(function()
            textButton487.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame249 = Instance.new("Frame", scrollingFrame9)
        frame249.Size = UDim2.new(1, 0, 0, 28)
        frame249.BackgroundTransparency = 1
        local textButton493 = Instance.new("TextButton", frame249)
        textButton493.Size = UDim2.new(0.72, 0, 1, 0)
        textButton493.BackgroundTransparency = 1
        textButton493.Text = "Burbaloni Loliloli"
        textButton493.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton493.TextXAlignment = Enum.TextXAlignment.Left
        textButton493.Font = Enum.Font.Gotham
        textButton493.TextSize = 10
        local textButton494 = Instance.new("TextButton", frame249)
        textButton494.Size = UDim2.new(0, 16, 0, 16)
        textButton494.Position = UDim2.new(1, -20, 0.5, -8)
        textButton494.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton494.Text = ""
        local uICorner544 = Instance.new("UICorner", textButton494)
        uICorner544.CornerRadius = UDim.new(0, 3)
        local frame250 = Instance.new("Frame", scrollingFrame9)
        frame250.Size = UDim2.new(1, 0, 0, 26)
        frame250.BackgroundTransparency = 1
        frame250.Visible = false
        local uIGridLayout64 = Instance.new("UIGridLayout", frame250)
        uIGridLayout64.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout64.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton495 = Instance.new("TextButton", frame250)
        textButton495.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton495.Text = "Nor"
        textButton495.TextSize = 9
        textButton495.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton495.Font = Enum.Font.GothamBold
        local uICorner545 = Instance.new("UICorner", textButton495)
        local conn496 = textButton495.MouseButton1Click:Connect(function()
            textButton495.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton495.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton496 = Instance.new("TextButton", frame250)
        textButton496.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton496.Text = "Gol"
        textButton496.TextSize = 9
        textButton496.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton496.Font = Enum.Font.GothamBold
        local uICorner546 = Instance.new("UICorner", textButton496)
        local conn497 = textButton496.MouseButton1Click:Connect(function()
            textButton496.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton496.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton497 = Instance.new("TextButton", frame250)
        textButton497.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton497.Text = "Dia"
        textButton497.TextSize = 9
        textButton497.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton497.Font = Enum.Font.GothamBold
        local uICorner547 = Instance.new("UICorner", textButton497)
        local conn498 = textButton497.MouseButton1Click:Connect(function()
            textButton497.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton497.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton498 = Instance.new("TextButton", frame250)
        textButton498.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton498.Text = "Rai"
        textButton498.TextSize = 9
        textButton498.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton498.Font = Enum.Font.GothamBold
        local uICorner548 = Instance.new("UICorner", textButton498)
        local conn499 = textButton498.MouseButton1Click:Connect(function()
            textButton498.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton498.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton499 = Instance.new("TextButton", frame250)
        textButton499.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton499.Text = "Lav"
        textButton499.TextSize = 9
        textButton499.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton499.Font = Enum.Font.GothamBold
        local uICorner549 = Instance.new("UICorner", textButton499)
        local conn500 = textButton499.MouseButton1Click:Connect(function()
            textButton499.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton499.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn501 = textButton493.MouseButton1Click:Connect(function()
            frame250.Visible = true
        end)
        local conn502 = textButton494.MouseButton1Click:Connect(function()
            textButton494.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame251 = Instance.new("Frame", scrollingFrame9)
        frame251.Size = UDim2.new(1, 0, 0, 28)
        frame251.BackgroundTransparency = 1
        local textButton500 = Instance.new("TextButton", frame251)
        textButton500.Size = UDim2.new(0.72, 0, 1, 0)
        textButton500.BackgroundTransparency = 1
        textButton500.Text = "Boneca Ambalabu"
        textButton500.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton500.TextXAlignment = Enum.TextXAlignment.Left
        textButton500.Font = Enum.Font.Gotham
        textButton500.TextSize = 10
        local textButton501 = Instance.new("TextButton", frame251)
        textButton501.Size = UDim2.new(0, 16, 0, 16)
        textButton501.Position = UDim2.new(1, -20, 0.5, -8)
        textButton501.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton501.Text = ""
        local uICorner550 = Instance.new("UICorner", textButton501)
        uICorner550.CornerRadius = UDim.new(0, 3)
        local frame252 = Instance.new("Frame", scrollingFrame9)
        frame252.Size = UDim2.new(1, 0, 0, 26)
        frame252.BackgroundTransparency = 1
        frame252.Visible = false
        local uIGridLayout65 = Instance.new("UIGridLayout", frame252)
        uIGridLayout65.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout65.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton502 = Instance.new("TextButton", frame252)
        textButton502.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton502.Text = "Nor"
        textButton502.TextSize = 9
        textButton502.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton502.Font = Enum.Font.GothamBold
        local uICorner551 = Instance.new("UICorner", textButton502)
        local conn503 = textButton502.MouseButton1Click:Connect(function()
            textButton502.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton502.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton503 = Instance.new("TextButton", frame252)
        textButton503.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton503.Text = "Gol"
        textButton503.TextSize = 9
        textButton503.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton503.Font = Enum.Font.GothamBold
        local uICorner552 = Instance.new("UICorner", textButton503)
        local conn504 = textButton503.MouseButton1Click:Connect(function()
            textButton503.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton503.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton504 = Instance.new("TextButton", frame252)
        textButton504.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton504.Text = "Dia"
        textButton504.TextSize = 9
        textButton504.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton504.Font = Enum.Font.GothamBold
        local uICorner553 = Instance.new("UICorner", textButton504)
        local conn505 = textButton504.MouseButton1Click:Connect(function()
            textButton504.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton504.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton505 = Instance.new("TextButton", frame252)
        textButton505.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton505.Text = "Rai"
        textButton505.TextSize = 9
        textButton505.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton505.Font = Enum.Font.GothamBold
        local uICorner554 = Instance.new("UICorner", textButton505)
        local conn506 = textButton505.MouseButton1Click:Connect(function()
            textButton505.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton505.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton506 = Instance.new("TextButton", frame252)
        textButton506.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton506.Text = "Lav"
        textButton506.TextSize = 9
        textButton506.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton506.Font = Enum.Font.GothamBold
        local uICorner555 = Instance.new("UICorner", textButton506)
        local conn507 = textButton506.MouseButton1Click:Connect(function()
            textButton506.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton506.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn508 = textButton500.MouseButton1Click:Connect(function()
            frame252.Visible = true
        end)
        local conn509 = textButton501.MouseButton1Click:Connect(function()
            textButton501.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame253 = Instance.new("Frame", scrollingFrame9)
        frame253.Size = UDim2.new(1, 0, 0, 28)
        frame253.BackgroundTransparency = 1
        local textButton507 = Instance.new("TextButton", frame253)
        textButton507.Size = UDim2.new(0.72, 0, 1, 0)
        textButton507.BackgroundTransparency = 1
        textButton507.Text = "Trippi Troppi"
        textButton507.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton507.TextXAlignment = Enum.TextXAlignment.Left
        textButton507.Font = Enum.Font.Gotham
        textButton507.TextSize = 10
        local textButton508 = Instance.new("TextButton", frame253)
        textButton508.Size = UDim2.new(0, 16, 0, 16)
        textButton508.Position = UDim2.new(1, -20, 0.5, -8)
        textButton508.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton508.Text = ""
        local uICorner556 = Instance.new("UICorner", textButton508)
        uICorner556.CornerRadius = UDim.new(0, 3)
        local frame254 = Instance.new("Frame", scrollingFrame9)
        frame254.Size = UDim2.new(1, 0, 0, 26)
        frame254.BackgroundTransparency = 1
        frame254.Visible = false
        local uIGridLayout66 = Instance.new("UIGridLayout", frame254)
        uIGridLayout66.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout66.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton509 = Instance.new("TextButton", frame254)
        textButton509.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton509.Text = "Nor"
        textButton509.TextSize = 9
        textButton509.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton509.Font = Enum.Font.GothamBold
        local uICorner557 = Instance.new("UICorner", textButton509)
        local conn510 = textButton509.MouseButton1Click:Connect(function()
            textButton509.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton509.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton510 = Instance.new("TextButton", frame254)
        textButton510.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton510.Text = "Gol"
        textButton510.TextSize = 9
        textButton510.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton510.Font = Enum.Font.GothamBold
        local uICorner558 = Instance.new("UICorner", textButton510)
        local conn511 = textButton510.MouseButton1Click:Connect(function()
            textButton510.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton510.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton511 = Instance.new("TextButton", frame254)
        textButton511.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton511.Text = "Dia"
        textButton511.TextSize = 9
        textButton511.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton511.Font = Enum.Font.GothamBold
        local uICorner559 = Instance.new("UICorner", textButton511)
        local conn512 = textButton511.MouseButton1Click:Connect(function()
            textButton511.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton511.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton512 = Instance.new("TextButton", frame254)
        textButton512.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton512.Text = "Rai"
        textButton512.TextSize = 9
        textButton512.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton512.Font = Enum.Font.GothamBold
        local uICorner560 = Instance.new("UICorner", textButton512)
        local conn513 = textButton512.MouseButton1Click:Connect(function()
            textButton512.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton512.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton513 = Instance.new("TextButton", frame254)
        textButton513.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton513.Text = "Lav"
        textButton513.TextSize = 9
        textButton513.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton513.Font = Enum.Font.GothamBold
        local uICorner561 = Instance.new("UICorner", textButton513)
        local conn514 = textButton513.MouseButton1Click:Connect(function()
            textButton513.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton513.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn515 = textButton507.MouseButton1Click:Connect(function()
            frame254.Visible = true
        end)
        local conn516 = textButton508.MouseButton1Click:Connect(function()
            textButton508.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame255 = Instance.new("Frame", scrollingFrame9)
        frame255.Size = UDim2.new(1, 0, 0, 28)
        frame255.BackgroundTransparency = 1
        local textButton514 = Instance.new("TextButton", frame255)
        textButton514.Size = UDim2.new(0.72, 0, 1, 0)
        textButton514.BackgroundTransparency = 1
        textButton514.Text = "Svinina Bombardino"
        textButton514.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton514.TextXAlignment = Enum.TextXAlignment.Left
        textButton514.Font = Enum.Font.Gotham
        textButton514.TextSize = 10
        local textButton515 = Instance.new("TextButton", frame255)
        textButton515.Size = UDim2.new(0, 16, 0, 16)
        textButton515.Position = UDim2.new(1, -20, 0.5, -8)
        textButton515.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton515.Text = ""
        local uICorner562 = Instance.new("UICorner", textButton515)
        uICorner562.CornerRadius = UDim.new(0, 3)
        local frame256 = Instance.new("Frame", scrollingFrame9)
        frame256.Size = UDim2.new(1, 0, 0, 26)
        frame256.BackgroundTransparency = 1
        frame256.Visible = false
        local uIGridLayout67 = Instance.new("UIGridLayout", frame256)
        uIGridLayout67.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout67.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton516 = Instance.new("TextButton", frame256)
        textButton516.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton516.Text = "Nor"
        textButton516.TextSize = 9
        textButton516.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton516.Font = Enum.Font.GothamBold
        local uICorner563 = Instance.new("UICorner", textButton516)
        local conn517 = textButton516.MouseButton1Click:Connect(function()
            textButton516.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton516.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton517 = Instance.new("TextButton", frame256)
        textButton517.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton517.Text = "Gol"
        textButton517.TextSize = 9
        textButton517.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton517.Font = Enum.Font.GothamBold
        local uICorner564 = Instance.new("UICorner", textButton517)
        local conn518 = textButton517.MouseButton1Click:Connect(function()
            textButton517.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton517.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton518 = Instance.new("TextButton", frame256)
        textButton518.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton518.Text = "Dia"
        textButton518.TextSize = 9
        textButton518.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton518.Font = Enum.Font.GothamBold
        local uICorner565 = Instance.new("UICorner", textButton518)
        local conn519 = textButton518.MouseButton1Click:Connect(function()
            textButton518.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton518.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton519 = Instance.new("TextButton", frame256)
        textButton519.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton519.Text = "Rai"
        textButton519.TextSize = 9
        textButton519.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton519.Font = Enum.Font.GothamBold
        local uICorner566 = Instance.new("UICorner", textButton519)
        local conn520 = textButton519.MouseButton1Click:Connect(function()
            textButton519.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton519.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton520 = Instance.new("TextButton", frame256)
        textButton520.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton520.Text = "Lav"
        textButton520.TextSize = 9
        textButton520.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton520.Font = Enum.Font.GothamBold
        local uICorner567 = Instance.new("UICorner", textButton520)
        local conn521 = textButton520.MouseButton1Click:Connect(function()
            textButton520.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton520.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn522 = textButton514.MouseButton1Click:Connect(function()
            frame256.Visible = true
        end)
        local conn523 = textButton515.MouseButton1Click:Connect(function()
            textButton515.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame257 = Instance.new("Frame", scrollingFrame9)
        frame257.Size = UDim2.new(1, 0, 0, 28)
        frame257.BackgroundTransparency = 1
        local textButton521 = Instance.new("TextButton", frame257)
        textButton521.Size = UDim2.new(0.72, 0, 1, 0)
        textButton521.BackgroundTransparency = 1
        textButton521.Text = "Bambini Crostini"
        textButton521.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton521.TextXAlignment = Enum.TextXAlignment.Left
        textButton521.Font = Enum.Font.Gotham
        textButton521.TextSize = 10
        local textButton522 = Instance.new("TextButton", frame257)
        textButton522.Size = UDim2.new(0, 16, 0, 16)
        textButton522.Position = UDim2.new(1, -20, 0.5, -8)
        textButton522.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton522.Text = ""
        local uICorner568 = Instance.new("UICorner", textButton522)
        uICorner568.CornerRadius = UDim.new(0, 3)
        local frame258 = Instance.new("Frame", scrollingFrame9)
        frame258.Size = UDim2.new(1, 0, 0, 26)
        frame258.BackgroundTransparency = 1
        frame258.Visible = false
        local uIGridLayout68 = Instance.new("UIGridLayout", frame258)
        uIGridLayout68.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout68.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton523 = Instance.new("TextButton", frame258)
        textButton523.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton523.Text = "Nor"
        textButton523.TextSize = 9
        textButton523.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton523.Font = Enum.Font.GothamBold
        local uICorner569 = Instance.new("UICorner", textButton523)
        local conn524 = textButton523.MouseButton1Click:Connect(function()
            textButton523.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton523.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton524 = Instance.new("TextButton", frame258)
        textButton524.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton524.Text = "Gol"
        textButton524.TextSize = 9
        textButton524.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton524.Font = Enum.Font.GothamBold
        local uICorner570 = Instance.new("UICorner", textButton524)
        local conn525 = textButton524.MouseButton1Click:Connect(function()
            textButton524.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton524.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton525 = Instance.new("TextButton", frame258)
        textButton525.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton525.Text = "Dia"
        textButton525.TextSize = 9
        textButton525.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton525.Font = Enum.Font.GothamBold
        local uICorner571 = Instance.new("UICorner", textButton525)
        local conn526 = textButton525.MouseButton1Click:Connect(function()
            textButton525.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton525.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton526 = Instance.new("TextButton", frame258)
        textButton526.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton526.Text = "Rai"
        textButton526.TextSize = 9
        textButton526.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton526.Font = Enum.Font.GothamBold
        local uICorner572 = Instance.new("UICorner", textButton526)
        local conn527 = textButton526.MouseButton1Click:Connect(function()
            textButton526.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton526.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton527 = Instance.new("TextButton", frame258)
        textButton527.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton527.Text = "Lav"
        textButton527.TextSize = 9
        textButton527.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton527.Font = Enum.Font.GothamBold
        local uICorner573 = Instance.new("UICorner", textButton527)
        local conn528 = textButton527.MouseButton1Click:Connect(function()
            textButton527.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton527.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn529 = textButton521.MouseButton1Click:Connect(function()
            frame258.Visible = true
        end)
        local conn530 = textButton522.MouseButton1Click:Connect(function()
            textButton522.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame259 = Instance.new("Frame", scrollingFrame9)
        frame259.Size = UDim2.new(1, 0, 0, 28)
        frame259.BackgroundTransparency = 1
        local textButton528 = Instance.new("TextButton", frame259)
        textButton528.Size = UDim2.new(0.72, 0, 1, 0)
        textButton528.BackgroundTransparency = 1
        textButton528.Text = "Avocadini Guffo"
        textButton528.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton528.TextXAlignment = Enum.TextXAlignment.Left
        textButton528.Font = Enum.Font.Gotham
        textButton528.TextSize = 10
        local textButton529 = Instance.new("TextButton", frame259)
        textButton529.Size = UDim2.new(0, 16, 0, 16)
        textButton529.Position = UDim2.new(1, -20, 0.5, -8)
        textButton529.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton529.Text = ""
        local uICorner574 = Instance.new("UICorner", textButton529)
        uICorner574.CornerRadius = UDim.new(0, 3)
        local frame260 = Instance.new("Frame", scrollingFrame9)
        frame260.Size = UDim2.new(1, 0, 0, 26)
        frame260.BackgroundTransparency = 1
        frame260.Visible = false
        local uIGridLayout69 = Instance.new("UIGridLayout", frame260)
        uIGridLayout69.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout69.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton530 = Instance.new("TextButton", frame260)
        textButton530.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton530.Text = "Nor"
        textButton530.TextSize = 9
        textButton530.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton530.Font = Enum.Font.GothamBold
        local uICorner575 = Instance.new("UICorner", textButton530)
        local conn531 = textButton530.MouseButton1Click:Connect(function()
            textButton530.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton530.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton531 = Instance.new("TextButton", frame260)
        textButton531.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton531.Text = "Gol"
        textButton531.TextSize = 9
        textButton531.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton531.Font = Enum.Font.GothamBold
        local uICorner576 = Instance.new("UICorner", textButton531)
        local conn532 = textButton531.MouseButton1Click:Connect(function()
            textButton531.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton531.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton532 = Instance.new("TextButton", frame260)
        textButton532.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton532.Text = "Dia"
        textButton532.TextSize = 9
        textButton532.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton532.Font = Enum.Font.GothamBold
        local uICorner577 = Instance.new("UICorner", textButton532)
        local conn533 = textButton532.MouseButton1Click:Connect(function()
            textButton532.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton532.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton533 = Instance.new("TextButton", frame260)
        textButton533.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton533.Text = "Rai"
        textButton533.TextSize = 9
        textButton533.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton533.Font = Enum.Font.GothamBold
        local uICorner578 = Instance.new("UICorner", textButton533)
        local conn534 = textButton533.MouseButton1Click:Connect(function()
            textButton533.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton533.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton534 = Instance.new("TextButton", frame260)
        textButton534.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton534.Text = "Lav"
        textButton534.TextSize = 9
        textButton534.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton534.Font = Enum.Font.GothamBold
        local uICorner579 = Instance.new("UICorner", textButton534)
        local conn535 = textButton534.MouseButton1Click:Connect(function()
            textButton534.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton534.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn536 = textButton528.MouseButton1Click:Connect(function()
            frame260.Visible = true
        end)
        local conn537 = textButton529.MouseButton1Click:Connect(function()
            textButton529.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame261 = Instance.new("Frame", scrollingFrame9)
        frame261.Size = UDim2.new(1, 0, 0, 28)
        frame261.BackgroundTransparency = 1
        local textButton535 = Instance.new("TextButton", frame261)
        textButton535.Size = UDim2.new(0.72, 0, 1, 0)
        textButton535.BackgroundTransparency = 1
        textButton535.Text = "Bandito Bobrito"
        textButton535.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton535.TextXAlignment = Enum.TextXAlignment.Left
        textButton535.Font = Enum.Font.Gotham
        textButton535.TextSize = 10
        local textButton536 = Instance.new("TextButton", frame261)
        textButton536.Size = UDim2.new(0, 16, 0, 16)
        textButton536.Position = UDim2.new(1, -20, 0.5, -8)
        textButton536.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton536.Text = ""
        local uICorner580 = Instance.new("UICorner", textButton536)
        uICorner580.CornerRadius = UDim.new(0, 3)
        local frame262 = Instance.new("Frame", scrollingFrame9)
        frame262.Size = UDim2.new(1, 0, 0, 26)
        frame262.BackgroundTransparency = 1
        frame262.Visible = false
        local uIGridLayout70 = Instance.new("UIGridLayout", frame262)
        uIGridLayout70.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout70.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton537 = Instance.new("TextButton", frame262)
        textButton537.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton537.Text = "Nor"
        textButton537.TextSize = 9
        textButton537.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton537.Font = Enum.Font.GothamBold
        local uICorner581 = Instance.new("UICorner", textButton537)
        local conn538 = textButton537.MouseButton1Click:Connect(function()
            textButton537.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton537.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton538 = Instance.new("TextButton", frame262)
        textButton538.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton538.Text = "Gol"
        textButton538.TextSize = 9
        textButton538.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton538.Font = Enum.Font.GothamBold
        local uICorner582 = Instance.new("UICorner", textButton538)
        local conn539 = textButton538.MouseButton1Click:Connect(function()
            textButton538.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton538.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton539 = Instance.new("TextButton", frame262)
        textButton539.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton539.Text = "Dia"
        textButton539.TextSize = 9
        textButton539.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton539.Font = Enum.Font.GothamBold
        local uICorner583 = Instance.new("UICorner", textButton539)
        local conn540 = textButton539.MouseButton1Click:Connect(function()
            textButton539.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton539.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton540 = Instance.new("TextButton", frame262)
        textButton540.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton540.Text = "Rai"
        textButton540.TextSize = 9
        textButton540.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton540.Font = Enum.Font.GothamBold
        local uICorner584 = Instance.new("UICorner", textButton540)
        local conn541 = textButton540.MouseButton1Click:Connect(function()
            textButton540.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton540.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton541 = Instance.new("TextButton", frame262)
        textButton541.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton541.Text = "Lav"
        textButton541.TextSize = 9
        textButton541.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton541.Font = Enum.Font.GothamBold
        local uICorner585 = Instance.new("UICorner", textButton541)
        local conn542 = textButton541.MouseButton1Click:Connect(function()
            textButton541.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton541.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn543 = textButton535.MouseButton1Click:Connect(function()
            frame262.Visible = true
        end)
        local conn544 = textButton536.MouseButton1Click:Connect(function()
            textButton536.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame263 = Instance.new("Frame", scrollingFrame9)
        frame263.Size = UDim2.new(1, 0, 0, 28)
        frame263.BackgroundTransparency = 1
        local textButton542 = Instance.new("TextButton", frame263)
        textButton542.Size = UDim2.new(0.72, 0, 1, 0)
        textButton542.BackgroundTransparency = 1
        textButton542.Text = "Tatatata Sahur"
        textButton542.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton542.TextXAlignment = Enum.TextXAlignment.Left
        textButton542.Font = Enum.Font.Gotham
        textButton542.TextSize = 10
        local textButton543 = Instance.new("TextButton", frame263)
        textButton543.Size = UDim2.new(0, 16, 0, 16)
        textButton543.Position = UDim2.new(1, -20, 0.5, -8)
        textButton543.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton543.Text = ""
        local uICorner586 = Instance.new("UICorner", textButton543)
        uICorner586.CornerRadius = UDim.new(0, 3)
        local frame264 = Instance.new("Frame", scrollingFrame9)
        frame264.Size = UDim2.new(1, 0, 0, 26)
        frame264.BackgroundTransparency = 1
        frame264.Visible = false
        local uIGridLayout71 = Instance.new("UIGridLayout", frame264)
        uIGridLayout71.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout71.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton544 = Instance.new("TextButton", frame264)
        textButton544.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton544.Text = "Nor"
        textButton544.TextSize = 9
        textButton544.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton544.Font = Enum.Font.GothamBold
        local uICorner587 = Instance.new("UICorner", textButton544)
        local conn545 = textButton544.MouseButton1Click:Connect(function()
            textButton544.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton544.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton545 = Instance.new("TextButton", frame264)
        textButton545.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton545.Text = "Gol"
        textButton545.TextSize = 9
        textButton545.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton545.Font = Enum.Font.GothamBold
        local uICorner588 = Instance.new("UICorner", textButton545)
        local conn546 = textButton545.MouseButton1Click:Connect(function()
            textButton545.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton545.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton546 = Instance.new("TextButton", frame264)
        textButton546.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton546.Text = "Dia"
        textButton546.TextSize = 9
        textButton546.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton546.Font = Enum.Font.GothamBold
        local uICorner589 = Instance.new("UICorner", textButton546)
        local conn547 = textButton546.MouseButton1Click:Connect(function()
            textButton546.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton546.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton547 = Instance.new("TextButton", frame264)
        textButton547.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton547.Text = "Rai"
        textButton547.TextSize = 9
        textButton547.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton547.Font = Enum.Font.GothamBold
        local uICorner590 = Instance.new("UICorner", textButton547)
        local conn548 = textButton547.MouseButton1Click:Connect(function()
            textButton547.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton547.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton548 = Instance.new("TextButton", frame264)
        textButton548.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton548.Text = "Lav"
        textButton548.TextSize = 9
        textButton548.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton548.Font = Enum.Font.GothamBold
        local uICorner591 = Instance.new("UICorner", textButton548)
        local conn549 = textButton548.MouseButton1Click:Connect(function()
            textButton548.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton548.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn550 = textButton542.MouseButton1Click:Connect(function()
            frame264.Visible = true
        end)
        local conn551 = textButton543.MouseButton1Click:Connect(function()
            textButton543.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame265 = Instance.new("Frame", scrollingFrame9)
        frame265.Size = UDim2.new(1, 0, 0, 28)
        frame265.BackgroundTransparency = 1
        local textButton549 = Instance.new("TextButton", frame265)
        textButton549.Size = UDim2.new(0.72, 0, 1, 0)
        textButton549.BackgroundTransparency = 1
        textButton549.Text = "Gangster Footera"
        textButton549.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton549.TextXAlignment = Enum.TextXAlignment.Left
        textButton549.Font = Enum.Font.Gotham
        textButton549.TextSize = 10
        local textButton550 = Instance.new("TextButton", frame265)
        textButton550.Size = UDim2.new(0, 16, 0, 16)
        textButton550.Position = UDim2.new(1, -20, 0.5, -8)
        textButton550.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton550.Text = ""
        local uICorner592 = Instance.new("UICorner", textButton550)
        uICorner592.CornerRadius = UDim.new(0, 3)
        local frame266 = Instance.new("Frame", scrollingFrame9)
        frame266.Size = UDim2.new(1, 0, 0, 26)
        frame266.BackgroundTransparency = 1
        frame266.Visible = false
        local uIGridLayout72 = Instance.new("UIGridLayout", frame266)
        uIGridLayout72.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout72.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton551 = Instance.new("TextButton", frame266)
        textButton551.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton551.Text = "Nor"
        textButton551.TextSize = 9
        textButton551.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton551.Font = Enum.Font.GothamBold
        local uICorner593 = Instance.new("UICorner", textButton551)
        local conn552 = textButton551.MouseButton1Click:Connect(function()
            textButton551.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton551.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton552 = Instance.new("TextButton", frame266)
        textButton552.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton552.Text = "Gol"
        textButton552.TextSize = 9
        textButton552.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton552.Font = Enum.Font.GothamBold
        local uICorner594 = Instance.new("UICorner", textButton552)
        local conn553 = textButton552.MouseButton1Click:Connect(function()
            textButton552.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton552.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton553 = Instance.new("TextButton", frame266)
        textButton553.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton553.Text = "Dia"
        textButton553.TextSize = 9
        textButton553.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton553.Font = Enum.Font.GothamBold
        local uICorner595 = Instance.new("UICorner", textButton553)
        local conn554 = textButton553.MouseButton1Click:Connect(function()
            textButton553.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton553.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton554 = Instance.new("TextButton", frame266)
        textButton554.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton554.Text = "Rai"
        textButton554.TextSize = 9
        textButton554.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton554.Font = Enum.Font.GothamBold
        local uICorner596 = Instance.new("UICorner", textButton554)
        local conn555 = textButton554.MouseButton1Click:Connect(function()
            textButton554.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton554.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton555 = Instance.new("TextButton", frame266)
        textButton555.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton555.Text = "Lav"
        textButton555.TextSize = 9
        textButton555.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton555.Font = Enum.Font.GothamBold
        local uICorner597 = Instance.new("UICorner", textButton555)
        local conn556 = textButton555.MouseButton1Click:Connect(function()
            textButton555.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton555.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn557 = textButton549.MouseButton1Click:Connect(function()
            frame266.Visible = true
        end)
        local conn558 = textButton550.MouseButton1Click:Connect(function()
            textButton550.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame267 = Instance.new("Frame", scrollingFrame9)
        frame267.Size = UDim2.new(1, 0, 0, 28)
        frame267.BackgroundTransparency = 1
        local textButton556 = Instance.new("TextButton", frame267)
        textButton556.Size = UDim2.new(0.72, 0, 1, 0)
        textButton556.BackgroundTransparency = 1
        textButton556.Text = "Tung Tung Sahur"
        textButton556.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton556.TextXAlignment = Enum.TextXAlignment.Left
        textButton556.Font = Enum.Font.Gotham
        textButton556.TextSize = 10
        local textButton557 = Instance.new("TextButton", frame267)
        textButton557.Size = UDim2.new(0, 16, 0, 16)
        textButton557.Position = UDim2.new(1, -20, 0.5, -8)
        textButton557.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton557.Text = ""
        local uICorner598 = Instance.new("UICorner", textButton557)
        uICorner598.CornerRadius = UDim.new(0, 3)
        local frame268 = Instance.new("Frame", scrollingFrame9)
        frame268.Size = UDim2.new(1, 0, 0, 26)
        frame268.BackgroundTransparency = 1
        frame268.Visible = false
        local uIGridLayout73 = Instance.new("UIGridLayout", frame268)
        uIGridLayout73.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout73.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton558 = Instance.new("TextButton", frame268)
        textButton558.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton558.Text = "Nor"
        textButton558.TextSize = 9
        textButton558.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton558.Font = Enum.Font.GothamBold
        local uICorner599 = Instance.new("UICorner", textButton558)
        local conn559 = textButton558.MouseButton1Click:Connect(function()
            textButton558.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton558.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton559 = Instance.new("TextButton", frame268)
        textButton559.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton559.Text = "Gol"
        textButton559.TextSize = 9
        textButton559.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton559.Font = Enum.Font.GothamBold
        local uICorner600 = Instance.new("UICorner", textButton559)
        local conn560 = textButton559.MouseButton1Click:Connect(function()
            textButton559.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton559.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton560 = Instance.new("TextButton", frame268)
        textButton560.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton560.Text = "Dia"
        textButton560.TextSize = 9
        textButton560.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton560.Font = Enum.Font.GothamBold
        local uICorner601 = Instance.new("UICorner", textButton560)
        local conn561 = textButton560.MouseButton1Click:Connect(function()
            textButton560.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton560.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton561 = Instance.new("TextButton", frame268)
        textButton561.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton561.Text = "Rai"
        textButton561.TextSize = 9
        textButton561.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton561.Font = Enum.Font.GothamBold
        local uICorner602 = Instance.new("UICorner", textButton561)
        local conn562 = textButton561.MouseButton1Click:Connect(function()
            textButton561.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton561.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton562 = Instance.new("TextButton", frame268)
        textButton562.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton562.Text = "Lav"
        textButton562.TextSize = 9
        textButton562.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton562.Font = Enum.Font.GothamBold
        local uICorner603 = Instance.new("UICorner", textButton562)
        local conn563 = textButton562.MouseButton1Click:Connect(function()
            textButton562.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton562.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn564 = textButton556.MouseButton1Click:Connect(function()
            frame268.Visible = true
        end)
        local conn565 = textButton557.MouseButton1Click:Connect(function()
            textButton557.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame269 = Instance.new("Frame", scrollingFrame9)
        frame269.Size = UDim2.new(1, 0, 0, 28)
        frame269.BackgroundTransparency = 1
        local textButton563 = Instance.new("TextButton", frame269)
        textButton563.Size = UDim2.new(0.72, 0, 1, 0)
        textButton563.BackgroundTransparency = 1
        textButton563.Text = "Cappuccino Assassino"
        textButton563.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton563.TextXAlignment = Enum.TextXAlignment.Left
        textButton563.Font = Enum.Font.Gotham
        textButton563.TextSize = 10
        local textButton564 = Instance.new("TextButton", frame269)
        textButton564.Size = UDim2.new(0, 16, 0, 16)
        textButton564.Position = UDim2.new(1, -20, 0.5, -8)
        textButton564.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton564.Text = ""
        local uICorner604 = Instance.new("UICorner", textButton564)
        uICorner604.CornerRadius = UDim.new(0, 3)
        local frame270 = Instance.new("Frame", scrollingFrame9)
        frame270.Size = UDim2.new(1, 0, 0, 26)
        frame270.BackgroundTransparency = 1
        frame270.Visible = false
        local uIGridLayout74 = Instance.new("UIGridLayout", frame270)
        uIGridLayout74.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout74.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton565 = Instance.new("TextButton", frame270)
        textButton565.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton565.Text = "Nor"
        textButton565.TextSize = 9
        textButton565.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton565.Font = Enum.Font.GothamBold
        local uICorner605 = Instance.new("UICorner", textButton565)
        local conn566 = textButton565.MouseButton1Click:Connect(function()
            textButton565.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton565.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton566 = Instance.new("TextButton", frame270)
        textButton566.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton566.Text = "Gol"
        textButton566.TextSize = 9
        textButton566.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton566.Font = Enum.Font.GothamBold
        local uICorner606 = Instance.new("UICorner", textButton566)
        local conn567 = textButton566.MouseButton1Click:Connect(function()
            textButton566.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton566.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton567 = Instance.new("TextButton", frame270)
        textButton567.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton567.Text = "Dia"
        textButton567.TextSize = 9
        textButton567.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton567.Font = Enum.Font.GothamBold
        local uICorner607 = Instance.new("UICorner", textButton567)
        local conn568 = textButton567.MouseButton1Click:Connect(function()
            textButton567.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton567.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton568 = Instance.new("TextButton", frame270)
        textButton568.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton568.Text = "Rai"
        textButton568.TextSize = 9
        textButton568.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton568.Font = Enum.Font.GothamBold
        local uICorner608 = Instance.new("UICorner", textButton568)
        local conn569 = textButton568.MouseButton1Click:Connect(function()
            textButton568.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton568.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton569 = Instance.new("TextButton", frame270)
        textButton569.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton569.Text = "Lav"
        textButton569.TextSize = 9
        textButton569.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton569.Font = Enum.Font.GothamBold
        local uICorner609 = Instance.new("UICorner", textButton569)
        local conn570 = textButton569.MouseButton1Click:Connect(function()
            textButton569.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton569.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn571 = textButton563.MouseButton1Click:Connect(function()
            frame270.Visible = true
        end)
        local conn572 = textButton564.MouseButton1Click:Connect(function()
            textButton564.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame271 = Instance.new("Frame", scrollingFrame9)
        frame271.Size = UDim2.new(1, 0, 0, 28)
        frame271.BackgroundTransparency = 1
        local textButton570 = Instance.new("TextButton", frame271)
        textButton570.Size = UDim2.new(0.72, 0, 1, 0)
        textButton570.BackgroundTransparency = 1
        textButton570.Text = "Pipi Kiwi"
        textButton570.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton570.TextXAlignment = Enum.TextXAlignment.Left
        textButton570.Font = Enum.Font.Gotham
        textButton570.TextSize = 10
        local textButton571 = Instance.new("TextButton", frame271)
        textButton571.Size = UDim2.new(0, 16, 0, 16)
        textButton571.Position = UDim2.new(1, -20, 0.5, -8)
        textButton571.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton571.Text = ""
        local uICorner610 = Instance.new("UICorner", textButton571)
        uICorner610.CornerRadius = UDim.new(0, 3)
        local frame272 = Instance.new("Frame", scrollingFrame9)
        frame272.Size = UDim2.new(1, 0, 0, 26)
        frame272.BackgroundTransparency = 1
        frame272.Visible = false
        local uIGridLayout75 = Instance.new("UIGridLayout", frame272)
        uIGridLayout75.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout75.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton572 = Instance.new("TextButton", frame272)
        textButton572.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton572.Text = "Nor"
        textButton572.TextSize = 9
        textButton572.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton572.Font = Enum.Font.GothamBold
        local uICorner611 = Instance.new("UICorner", textButton572)
        local conn573 = textButton572.MouseButton1Click:Connect(function()
            textButton572.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton572.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton573 = Instance.new("TextButton", frame272)
        textButton573.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton573.Text = "Gol"
        textButton573.TextSize = 9
        textButton573.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton573.Font = Enum.Font.GothamBold
        local uICorner612 = Instance.new("UICorner", textButton573)
        local conn574 = textButton573.MouseButton1Click:Connect(function()
            textButton573.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton573.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton574 = Instance.new("TextButton", frame272)
        textButton574.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton574.Text = "Dia"
        textButton574.TextSize = 9
        textButton574.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton574.Font = Enum.Font.GothamBold
        local uICorner613 = Instance.new("UICorner", textButton574)
        local conn575 = textButton574.MouseButton1Click:Connect(function()
            textButton574.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton574.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton575 = Instance.new("TextButton", frame272)
        textButton575.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton575.Text = "Rai"
        textButton575.TextSize = 9
        textButton575.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton575.Font = Enum.Font.GothamBold
        local uICorner614 = Instance.new("UICorner", textButton575)
        local conn576 = textButton575.MouseButton1Click:Connect(function()
            textButton575.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton575.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton576 = Instance.new("TextButton", frame272)
        textButton576.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton576.Text = "Lav"
        textButton576.TextSize = 9
        textButton576.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton576.Font = Enum.Font.GothamBold
        local uICorner615 = Instance.new("UICorner", textButton576)
        local conn577 = textButton576.MouseButton1Click:Connect(function()
            textButton576.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton576.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn578 = textButton570.MouseButton1Click:Connect(function()
            frame272.Visible = true
        end)
        local conn579 = textButton571.MouseButton1Click:Connect(function()
            textButton571.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame273 = Instance.new("Frame", scrollingFrame9)
        frame273.Size = UDim2.new(1, 0, 0, 28)
        frame273.BackgroundTransparency = 1
        local textButton577 = Instance.new("TextButton", frame273)
        textButton577.Size = UDim2.new(0.72, 0, 1, 0)
        textButton577.BackgroundTransparency = 1
        textButton577.Text = "Orangutini Ananassini"
        textButton577.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton577.TextXAlignment = Enum.TextXAlignment.Left
        textButton577.Font = Enum.Font.Gotham
        textButton577.TextSize = 10
        local textButton578 = Instance.new("TextButton", frame273)
        textButton578.Size = UDim2.new(0, 16, 0, 16)
        textButton578.Position = UDim2.new(1, -20, 0.5, -8)
        textButton578.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton578.Text = ""
        local uICorner616 = Instance.new("UICorner", textButton578)
        uICorner616.CornerRadius = UDim.new(0, 3)
        local frame274 = Instance.new("Frame", scrollingFrame9)
        frame274.Size = UDim2.new(1, 0, 0, 26)
        frame274.BackgroundTransparency = 1
        frame274.Visible = false
        local uIGridLayout76 = Instance.new("UIGridLayout", frame274)
        uIGridLayout76.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout76.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton579 = Instance.new("TextButton", frame274)
        textButton579.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton579.Text = "Nor"
        textButton579.TextSize = 9
        textButton579.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton579.Font = Enum.Font.GothamBold
        local uICorner617 = Instance.new("UICorner", textButton579)
        local conn580 = textButton579.MouseButton1Click:Connect(function()
            textButton579.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton579.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton580 = Instance.new("TextButton", frame274)
        textButton580.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton580.Text = "Gol"
        textButton580.TextSize = 9
        textButton580.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton580.Font = Enum.Font.GothamBold
        local uICorner618 = Instance.new("UICorner", textButton580)
        local conn581 = textButton580.MouseButton1Click:Connect(function()
            textButton580.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton580.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton581 = Instance.new("TextButton", frame274)
        textButton581.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton581.Text = "Dia"
        textButton581.TextSize = 9
        textButton581.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton581.Font = Enum.Font.GothamBold
        local uICorner619 = Instance.new("UICorner", textButton581)
        local conn582 = textButton581.MouseButton1Click:Connect(function()
            textButton581.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton581.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton582 = Instance.new("TextButton", frame274)
        textButton582.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton582.Text = "Rai"
        textButton582.TextSize = 9
        textButton582.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton582.Font = Enum.Font.GothamBold
        local uICorner620 = Instance.new("UICorner", textButton582)
        local conn583 = textButton582.MouseButton1Click:Connect(function()
            textButton582.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton582.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton583 = Instance.new("TextButton", frame274)
        textButton583.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton583.Text = "Lav"
        textButton583.TextSize = 9
        textButton583.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton583.Font = Enum.Font.GothamBold
        local uICorner621 = Instance.new("UICorner", textButton583)
        local conn584 = textButton583.MouseButton1Click:Connect(function()
            textButton583.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton583.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn585 = textButton577.MouseButton1Click:Connect(function()
            frame274.Visible = true
        end)
        local conn586 = textButton578.MouseButton1Click:Connect(function()
            textButton578.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame275 = Instance.new("Frame", scrollingFrame9)
        frame275.Size = UDim2.new(1, 0, 0, 28)
        frame275.BackgroundTransparency = 1
        local textButton584 = Instance.new("TextButton", frame275)
        textButton584.Size = UDim2.new(0.72, 0, 1, 0)
        textButton584.BackgroundTransparency = 1
        textButton584.Text = "Talpa Di Fero"
        textButton584.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton584.TextXAlignment = Enum.TextXAlignment.Left
        textButton584.Font = Enum.Font.Gotham
        textButton584.TextSize = 10
        local textButton585 = Instance.new("TextButton", frame275)
        textButton585.Size = UDim2.new(0, 16, 0, 16)
        textButton585.Position = UDim2.new(1, -20, 0.5, -8)
        textButton585.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton585.Text = ""
        local uICorner622 = Instance.new("UICorner", textButton585)
        uICorner622.CornerRadius = UDim.new(0, 3)
        local frame276 = Instance.new("Frame", scrollingFrame9)
        frame276.Size = UDim2.new(1, 0, 0, 26)
        frame276.BackgroundTransparency = 1
        frame276.Visible = false
        local uIGridLayout77 = Instance.new("UIGridLayout", frame276)
        uIGridLayout77.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout77.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton586 = Instance.new("TextButton", frame276)
        textButton586.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton586.Text = "Nor"
        textButton586.TextSize = 9
        textButton586.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton586.Font = Enum.Font.GothamBold
        local uICorner623 = Instance.new("UICorner", textButton586)
        local conn587 = textButton586.MouseButton1Click:Connect(function()
            textButton586.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton586.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton587 = Instance.new("TextButton", frame276)
        textButton587.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton587.Text = "Gol"
        textButton587.TextSize = 9
        textButton587.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton587.Font = Enum.Font.GothamBold
        local uICorner624 = Instance.new("UICorner", textButton587)
        local conn588 = textButton587.MouseButton1Click:Connect(function()
            textButton587.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton587.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton588 = Instance.new("TextButton", frame276)
        textButton588.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton588.Text = "Dia"
        textButton588.TextSize = 9
        textButton588.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton588.Font = Enum.Font.GothamBold
        local uICorner625 = Instance.new("UICorner", textButton588)
        local conn589 = textButton588.MouseButton1Click:Connect(function()
            textButton588.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton588.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton589 = Instance.new("TextButton", frame276)
        textButton589.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton589.Text = "Rai"
        textButton589.TextSize = 9
        textButton589.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton589.Font = Enum.Font.GothamBold
        local uICorner626 = Instance.new("UICorner", textButton589)
        local conn590 = textButton589.MouseButton1Click:Connect(function()
            textButton589.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton589.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton590 = Instance.new("TextButton", frame276)
        textButton590.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton590.Text = "Lav"
        textButton590.TextSize = 9
        textButton590.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton590.Font = Enum.Font.GothamBold
        local uICorner627 = Instance.new("UICorner", textButton590)
        local conn591 = textButton590.MouseButton1Click:Connect(function()
            textButton590.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton590.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn592 = textButton584.MouseButton1Click:Connect(function()
            frame276.Visible = true
        end)
        local conn593 = textButton585.MouseButton1Click:Connect(function()
            textButton585.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame277 = Instance.new("Frame", scrollingFrame9)
        frame277.Size = UDim2.new(1, 0, 0, 28)
        frame277.BackgroundTransparency = 1
        local textButton591 = Instance.new("TextButton", frame277)
        textButton591.Size = UDim2.new(0.72, 0, 1, 0)
        textButton591.BackgroundTransparency = 1
        textButton591.Text = "Espresso Signora"
        textButton591.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton591.TextXAlignment = Enum.TextXAlignment.Left
        textButton591.Font = Enum.Font.Gotham
        textButton591.TextSize = 10
        local textButton592 = Instance.new("TextButton", frame277)
        textButton592.Size = UDim2.new(0, 16, 0, 16)
        textButton592.Position = UDim2.new(1, -20, 0.5, -8)
        textButton592.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton592.Text = ""
        local uICorner628 = Instance.new("UICorner", textButton592)
        uICorner628.CornerRadius = UDim.new(0, 3)
        local frame278 = Instance.new("Frame", scrollingFrame9)
        frame278.Size = UDim2.new(1, 0, 0, 26)
        frame278.BackgroundTransparency = 1
        frame278.Visible = false
        local uIGridLayout78 = Instance.new("UIGridLayout", frame278)
        uIGridLayout78.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout78.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton593 = Instance.new("TextButton", frame278)
        textButton593.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton593.Text = "Nor"
        textButton593.TextSize = 9
        textButton593.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton593.Font = Enum.Font.GothamBold
        local uICorner629 = Instance.new("UICorner", textButton593)
        local conn594 = textButton593.MouseButton1Click:Connect(function()
            textButton593.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton593.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton594 = Instance.new("TextButton", frame278)
        textButton594.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton594.Text = "Gol"
        textButton594.TextSize = 9
        textButton594.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton594.Font = Enum.Font.GothamBold
        local uICorner630 = Instance.new("UICorner", textButton594)
        local conn595 = textButton594.MouseButton1Click:Connect(function()
            textButton594.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton594.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton595 = Instance.new("TextButton", frame278)
        textButton595.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton595.Text = "Dia"
        textButton595.TextSize = 9
        textButton595.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton595.Font = Enum.Font.GothamBold
        local uICorner631 = Instance.new("UICorner", textButton595)
        local conn596 = textButton595.MouseButton1Click:Connect(function()
            textButton595.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton595.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton596 = Instance.new("TextButton", frame278)
        textButton596.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton596.Text = "Rai"
        textButton596.TextSize = 9
        textButton596.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton596.Font = Enum.Font.GothamBold
        local uICorner632 = Instance.new("UICorner", textButton596)
        local conn597 = textButton596.MouseButton1Click:Connect(function()
            textButton596.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton596.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton597 = Instance.new("TextButton", frame278)
        textButton597.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton597.Text = "Lav"
        textButton597.TextSize = 9
        textButton597.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton597.Font = Enum.Font.GothamBold
        local uICorner633 = Instance.new("UICorner", textButton597)
        local conn598 = textButton597.MouseButton1Click:Connect(function()
            textButton597.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton597.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn599 = textButton591.MouseButton1Click:Connect(function()
            frame278.Visible = true
        end)
        local conn600 = textButton592.MouseButton1Click:Connect(function()
            textButton592.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame279 = Instance.new("Frame", scrollingFrame9)
        frame279.Size = UDim2.new(1, 0, 0, 28)
        frame279.BackgroundTransparency = 1
        local textButton598 = Instance.new("TextButton", frame279)
        textButton598.Size = UDim2.new(0.72, 0, 1, 0)
        textButton598.BackgroundTransparency = 1
        textButton598.Text = "Brr Brr Patapim"
        textButton598.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton598.TextXAlignment = Enum.TextXAlignment.Left
        textButton598.Font = Enum.Font.Gotham
        textButton598.TextSize = 10
        local textButton599 = Instance.new("TextButton", frame279)
        textButton599.Size = UDim2.new(0, 16, 0, 16)
        textButton599.Position = UDim2.new(1, -20, 0.5, -8)
        textButton599.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton599.Text = ""
        local uICorner634 = Instance.new("UICorner", textButton599)
        uICorner634.CornerRadius = UDim.new(0, 3)
        local frame280 = Instance.new("Frame", scrollingFrame9)
        frame280.Size = UDim2.new(1, 0, 0, 26)
        frame280.BackgroundTransparency = 1
        frame280.Visible = false
        local uIGridLayout79 = Instance.new("UIGridLayout", frame280)
        uIGridLayout79.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout79.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton600 = Instance.new("TextButton", frame280)
        textButton600.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton600.Text = "Nor"
        textButton600.TextSize = 9
        textButton600.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton600.Font = Enum.Font.GothamBold
        local uICorner635 = Instance.new("UICorner", textButton600)
        local conn601 = textButton600.MouseButton1Click:Connect(function()
            textButton600.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton600.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton601 = Instance.new("TextButton", frame280)
        textButton601.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton601.Text = "Gol"
        textButton601.TextSize = 9
        textButton601.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton601.Font = Enum.Font.GothamBold
        local uICorner636 = Instance.new("UICorner", textButton601)
        local conn602 = textButton601.MouseButton1Click:Connect(function()
            textButton601.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton601.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton602 = Instance.new("TextButton", frame280)
        textButton602.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton602.Text = "Dia"
        textButton602.TextSize = 9
        textButton602.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton602.Font = Enum.Font.GothamBold
        local uICorner637 = Instance.new("UICorner", textButton602)
        local conn603 = textButton602.MouseButton1Click:Connect(function()
            textButton602.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton602.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton603 = Instance.new("TextButton", frame280)
        textButton603.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton603.Text = "Rai"
        textButton603.TextSize = 9
        textButton603.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton603.Font = Enum.Font.GothamBold
        local uICorner638 = Instance.new("UICorner", textButton603)
        local conn604 = textButton603.MouseButton1Click:Connect(function()
            textButton603.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton603.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton604 = Instance.new("TextButton", frame280)
        textButton604.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton604.Text = "Lav"
        textButton604.TextSize = 9
        textButton604.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton604.Font = Enum.Font.GothamBold
        local uICorner639 = Instance.new("UICorner", textButton604)
        local conn605 = textButton604.MouseButton1Click:Connect(function()
            textButton604.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton604.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn606 = textButton598.MouseButton1Click:Connect(function()
            frame280.Visible = true
        end)
        local conn607 = textButton599.MouseButton1Click:Connect(function()
            textButton599.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame281 = Instance.new("Frame", scrollingFrame9)
        frame281.Size = UDim2.new(1, 0, 0, 28)
        frame281.BackgroundTransparency = 1
        local textButton605 = Instance.new("TextButton", frame281)
        textButton605.Size = UDim2.new(0.72, 0, 1, 0)
        textButton605.BackgroundTransparency = 1
        textButton605.Text = "Rhino Toasterino"
        textButton605.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton605.TextXAlignment = Enum.TextXAlignment.Left
        textButton605.Font = Enum.Font.Gotham
        textButton605.TextSize = 10
        local textButton606 = Instance.new("TextButton", frame281)
        textButton606.Size = UDim2.new(0, 16, 0, 16)
        textButton606.Position = UDim2.new(1, -20, 0.5, -8)
        textButton606.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton606.Text = ""
        local uICorner640 = Instance.new("UICorner", textButton606)
        uICorner640.CornerRadius = UDim.new(0, 3)
        local frame282 = Instance.new("Frame", scrollingFrame9)
        frame282.Size = UDim2.new(1, 0, 0, 26)
        frame282.BackgroundTransparency = 1
        frame282.Visible = false
        local uIGridLayout80 = Instance.new("UIGridLayout", frame282)
        uIGridLayout80.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout80.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton607 = Instance.new("TextButton", frame282)
        textButton607.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton607.Text = "Nor"
        textButton607.TextSize = 9
        textButton607.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton607.Font = Enum.Font.GothamBold
        local uICorner641 = Instance.new("UICorner", textButton607)
        local conn608 = textButton607.MouseButton1Click:Connect(function()
            textButton607.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton607.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton608 = Instance.new("TextButton", frame282)
        textButton608.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton608.Text = "Gol"
        textButton608.TextSize = 9
        textButton608.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton608.Font = Enum.Font.GothamBold
        local uICorner642 = Instance.new("UICorner", textButton608)
        local conn609 = textButton608.MouseButton1Click:Connect(function()
            textButton608.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton608.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton609 = Instance.new("TextButton", frame282)
        textButton609.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton609.Text = "Dia"
        textButton609.TextSize = 9
        textButton609.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton609.Font = Enum.Font.GothamBold
        local uICorner643 = Instance.new("UICorner", textButton609)
        local conn610 = textButton609.MouseButton1Click:Connect(function()
            textButton609.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton609.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton610 = Instance.new("TextButton", frame282)
        textButton610.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton610.Text = "Rai"
        textButton610.TextSize = 9
        textButton610.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton610.Font = Enum.Font.GothamBold
        local uICorner644 = Instance.new("UICorner", textButton610)
        local conn611 = textButton610.MouseButton1Click:Connect(function()
            textButton610.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton610.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton611 = Instance.new("TextButton", frame282)
        textButton611.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton611.Text = "Lav"
        textButton611.TextSize = 9
        textButton611.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton611.Font = Enum.Font.GothamBold
        local uICorner645 = Instance.new("UICorner", textButton611)
        local conn612 = textButton611.MouseButton1Click:Connect(function()
            textButton611.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton611.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn613 = textButton605.MouseButton1Click:Connect(function()
            frame282.Visible = true
        end)
        local conn614 = textButton606.MouseButton1Click:Connect(function()
            textButton606.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame283 = Instance.new("Frame", scrollingFrame9)
        frame283.Size = UDim2.new(1, 0, 0, 28)
        frame283.BackgroundTransparency = 1
        local textButton612 = Instance.new("TextButton", frame283)
        textButton612.Size = UDim2.new(0.72, 0, 1, 0)
        textButton612.BackgroundTransparency = 1
        textButton612.Text = "Brr Bicus Dicus"
        textButton612.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton612.TextXAlignment = Enum.TextXAlignment.Left
        textButton612.Font = Enum.Font.Gotham
        textButton612.TextSize = 10
        local textButton613 = Instance.new("TextButton", frame283)
        textButton613.Size = UDim2.new(0, 16, 0, 16)
        textButton613.Position = UDim2.new(1, -20, 0.5, -8)
        textButton613.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton613.Text = ""
        local uICorner646 = Instance.new("UICorner", textButton613)
        uICorner646.CornerRadius = UDim.new(0, 3)
        local frame284 = Instance.new("Frame", scrollingFrame9)
        frame284.Size = UDim2.new(1, 0, 0, 26)
        frame284.BackgroundTransparency = 1
        frame284.Visible = false
        local uIGridLayout81 = Instance.new("UIGridLayout", frame284)
        uIGridLayout81.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout81.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton614 = Instance.new("TextButton", frame284)
        textButton614.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton614.Text = "Nor"
        textButton614.TextSize = 9
        textButton614.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton614.Font = Enum.Font.GothamBold
        local uICorner647 = Instance.new("UICorner", textButton614)
        local conn615 = textButton614.MouseButton1Click:Connect(function()
            textButton614.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton614.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton615 = Instance.new("TextButton", frame284)
        textButton615.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton615.Text = "Gol"
        textButton615.TextSize = 9
        textButton615.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton615.Font = Enum.Font.GothamBold
        local uICorner648 = Instance.new("UICorner", textButton615)
        local conn616 = textButton615.MouseButton1Click:Connect(function()
            textButton615.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton615.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton616 = Instance.new("TextButton", frame284)
        textButton616.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton616.Text = "Dia"
        textButton616.TextSize = 9
        textButton616.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton616.Font = Enum.Font.GothamBold
        local uICorner649 = Instance.new("UICorner", textButton616)
        local conn617 = textButton616.MouseButton1Click:Connect(function()
            textButton616.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton616.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton617 = Instance.new("TextButton", frame284)
        textButton617.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton617.Text = "Rai"
        textButton617.TextSize = 9
        textButton617.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton617.Font = Enum.Font.GothamBold
        local uICorner650 = Instance.new("UICorner", textButton617)
        local conn618 = textButton617.MouseButton1Click:Connect(function()
            textButton617.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton617.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton618 = Instance.new("TextButton", frame284)
        textButton618.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton618.Text = "Lav"
        textButton618.TextSize = 9
        textButton618.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton618.Font = Enum.Font.GothamBold
        local uICorner651 = Instance.new("UICorner", textButton618)
        local conn619 = textButton618.MouseButton1Click:Connect(function()
            textButton618.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton618.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn620 = textButton612.MouseButton1Click:Connect(function()
            frame284.Visible = true
        end)
        local conn621 = textButton613.MouseButton1Click:Connect(function()
            textButton613.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame285 = Instance.new("Frame", scrollingFrame9)
        frame285.Size = UDim2.new(1, 0, 0, 28)
        frame285.BackgroundTransparency = 1
        local textButton619 = Instance.new("TextButton", frame285)
        textButton619.Size = UDim2.new(0.72, 0, 1, 0)
        textButton619.BackgroundTransparency = 1
        textButton619.Text = "Strawberrelli Flamingelli"
        textButton619.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton619.TextXAlignment = Enum.TextXAlignment.Left
        textButton619.Font = Enum.Font.Gotham
        textButton619.TextSize = 10
        local textButton620 = Instance.new("TextButton", frame285)
        textButton620.Size = UDim2.new(0, 16, 0, 16)
        textButton620.Position = UDim2.new(1, -20, 0.5, -8)
        textButton620.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton620.Text = ""
        local uICorner652 = Instance.new("UICorner", textButton620)
        uICorner652.CornerRadius = UDim.new(0, 3)
        local frame286 = Instance.new("Frame", scrollingFrame9)
        frame286.Size = UDim2.new(1, 0, 0, 26)
        frame286.BackgroundTransparency = 1
        frame286.Visible = false
        local uIGridLayout82 = Instance.new("UIGridLayout", frame286)
        uIGridLayout82.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout82.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton621 = Instance.new("TextButton", frame286)
        textButton621.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton621.Text = "Nor"
        textButton621.TextSize = 9
        textButton621.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton621.Font = Enum.Font.GothamBold
        local uICorner653 = Instance.new("UICorner", textButton621)
        local conn622 = textButton621.MouseButton1Click:Connect(function()
            textButton621.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton621.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton622 = Instance.new("TextButton", frame286)
        textButton622.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton622.Text = "Gol"
        textButton622.TextSize = 9
        textButton622.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton622.Font = Enum.Font.GothamBold
        local uICorner654 = Instance.new("UICorner", textButton622)
        local conn623 = textButton622.MouseButton1Click:Connect(function()
            textButton622.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton622.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton623 = Instance.new("TextButton", frame286)
        textButton623.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton623.Text = "Dia"
        textButton623.TextSize = 9
        textButton623.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton623.Font = Enum.Font.GothamBold
        local uICorner655 = Instance.new("UICorner", textButton623)
        local conn624 = textButton623.MouseButton1Click:Connect(function()
            textButton623.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton623.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton624 = Instance.new("TextButton", frame286)
        textButton624.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton624.Text = "Rai"
        textButton624.TextSize = 9
        textButton624.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton624.Font = Enum.Font.GothamBold
        local uICorner656 = Instance.new("UICorner", textButton624)
        local conn625 = textButton624.MouseButton1Click:Connect(function()
            textButton624.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton624.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton625 = Instance.new("TextButton", frame286)
        textButton625.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton625.Text = "Lav"
        textButton625.TextSize = 9
        textButton625.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton625.Font = Enum.Font.GothamBold
        local uICorner657 = Instance.new("UICorner", textButton625)
        local conn626 = textButton625.MouseButton1Click:Connect(function()
            textButton625.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton625.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn627 = textButton619.MouseButton1Click:Connect(function()
            frame286.Visible = true
        end)
        local conn628 = textButton620.MouseButton1Click:Connect(function()
            textButton620.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame287 = Instance.new("Frame", scrollingFrame9)
        frame287.Size = UDim2.new(1, 0, 0, 28)
        frame287.BackgroundTransparency = 1
        local textButton626 = Instance.new("TextButton", frame287)
        textButton626.Size = UDim2.new(0.72, 0, 1, 0)
        textButton626.BackgroundTransparency = 1
        textButton626.Text = "Bananito Delfinito"
        textButton626.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton626.TextXAlignment = Enum.TextXAlignment.Left
        textButton626.Font = Enum.Font.Gotham
        textButton626.TextSize = 10
        local textButton627 = Instance.new("TextButton", frame287)
        textButton627.Size = UDim2.new(0, 16, 0, 16)
        textButton627.Position = UDim2.new(1, -20, 0.5, -8)
        textButton627.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton627.Text = ""
        local uICorner658 = Instance.new("UICorner", textButton627)
        uICorner658.CornerRadius = UDim.new(0, 3)
        local frame288 = Instance.new("Frame", scrollingFrame9)
        frame288.Size = UDim2.new(1, 0, 0, 26)
        frame288.BackgroundTransparency = 1
        frame288.Visible = false
        local uIGridLayout83 = Instance.new("UIGridLayout", frame288)
        uIGridLayout83.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout83.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton628 = Instance.new("TextButton", frame288)
        textButton628.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton628.Text = "Nor"
        textButton628.TextSize = 9
        textButton628.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton628.Font = Enum.Font.GothamBold
        local uICorner659 = Instance.new("UICorner", textButton628)
        local conn629 = textButton628.MouseButton1Click:Connect(function()
            textButton628.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton628.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton629 = Instance.new("TextButton", frame288)
        textButton629.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton629.Text = "Gol"
        textButton629.TextSize = 9
        textButton629.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton629.Font = Enum.Font.GothamBold
        local uICorner660 = Instance.new("UICorner", textButton629)
        local conn630 = textButton629.MouseButton1Click:Connect(function()
            textButton629.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton629.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton630 = Instance.new("TextButton", frame288)
        textButton630.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton630.Text = "Dia"
        textButton630.TextSize = 9
        textButton630.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton630.Font = Enum.Font.GothamBold
        local uICorner661 = Instance.new("UICorner", textButton630)
        local conn631 = textButton630.MouseButton1Click:Connect(function()
            textButton630.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton630.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton631 = Instance.new("TextButton", frame288)
        textButton631.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton631.Text = "Rai"
        textButton631.TextSize = 9
        textButton631.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton631.Font = Enum.Font.GothamBold
        local uICorner662 = Instance.new("UICorner", textButton631)
        local conn632 = textButton631.MouseButton1Click:Connect(function()
            textButton631.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton631.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton632 = Instance.new("TextButton", frame288)
        textButton632.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton632.Text = "Lav"
        textButton632.TextSize = 9
        textButton632.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton632.Font = Enum.Font.GothamBold
        local uICorner663 = Instance.new("UICorner", textButton632)
        local conn633 = textButton632.MouseButton1Click:Connect(function()
            textButton632.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton632.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn634 = textButton626.MouseButton1Click:Connect(function()
            frame288.Visible = true
        end)
        local conn635 = textButton627.MouseButton1Click:Connect(function()
            textButton627.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame289 = Instance.new("Frame", scrollingFrame9)
        frame289.Size = UDim2.new(1, 0, 0, 28)
        frame289.BackgroundTransparency = 1
        local textButton633 = Instance.new("TextButton", frame289)
        textButton633.Size = UDim2.new(0.72, 0, 1, 0)
        textButton633.BackgroundTransparency = 1
        textButton633.Text = "Balerina Capucina"
        textButton633.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton633.TextXAlignment = Enum.TextXAlignment.Left
        textButton633.Font = Enum.Font.Gotham
        textButton633.TextSize = 10
        local textButton634 = Instance.new("TextButton", frame289)
        textButton634.Size = UDim2.new(0, 16, 0, 16)
        textButton634.Position = UDim2.new(1, -20, 0.5, -8)
        textButton634.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton634.Text = ""
        local uICorner664 = Instance.new("UICorner", textButton634)
        uICorner664.CornerRadius = UDim.new(0, 3)
        local frame290 = Instance.new("Frame", scrollingFrame9)
        frame290.Size = UDim2.new(1, 0, 0, 26)
        frame290.BackgroundTransparency = 1
        frame290.Visible = false
        local uIGridLayout84 = Instance.new("UIGridLayout", frame290)
        uIGridLayout84.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout84.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton635 = Instance.new("TextButton", frame290)
        textButton635.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton635.Text = "Nor"
        textButton635.TextSize = 9
        textButton635.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton635.Font = Enum.Font.GothamBold
        local uICorner665 = Instance.new("UICorner", textButton635)
        local conn636 = textButton635.MouseButton1Click:Connect(function()
            textButton635.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton635.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton636 = Instance.new("TextButton", frame290)
        textButton636.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton636.Text = "Gol"
        textButton636.TextSize = 9
        textButton636.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton636.Font = Enum.Font.GothamBold
        local uICorner666 = Instance.new("UICorner", textButton636)
        local conn637 = textButton636.MouseButton1Click:Connect(function()
            textButton636.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton636.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton637 = Instance.new("TextButton", frame290)
        textButton637.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton637.Text = "Dia"
        textButton637.TextSize = 9
        textButton637.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton637.Font = Enum.Font.GothamBold
        local uICorner667 = Instance.new("UICorner", textButton637)
        local conn638 = textButton637.MouseButton1Click:Connect(function()
            textButton637.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton637.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton638 = Instance.new("TextButton", frame290)
        textButton638.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton638.Text = "Rai"
        textButton638.TextSize = 9
        textButton638.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton638.Font = Enum.Font.GothamBold
        local uICorner668 = Instance.new("UICorner", textButton638)
        local conn639 = textButton638.MouseButton1Click:Connect(function()
            textButton638.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton638.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton639 = Instance.new("TextButton", frame290)
        textButton639.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton639.Text = "Lav"
        textButton639.TextSize = 9
        textButton639.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton639.Font = Enum.Font.GothamBold
        local uICorner669 = Instance.new("UICorner", textButton639)
        local conn640 = textButton639.MouseButton1Click:Connect(function()
            textButton639.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton639.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn641 = textButton633.MouseButton1Click:Connect(function()
            frame290.Visible = true
        end)
        local conn642 = textButton634.MouseButton1Click:Connect(function()
            textButton634.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame291 = Instance.new("Frame", scrollingFrame9)
        frame291.Size = UDim2.new(1, 0, 0, 28)
        frame291.BackgroundTransparency = 1
        local textButton640 = Instance.new("TextButton", frame291)
        textButton640.Size = UDim2.new(0.72, 0, 1, 0)
        textButton640.BackgroundTransparency = 1
        textButton640.Text = "Glorbo Fruttodrillo"
        textButton640.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton640.TextXAlignment = Enum.TextXAlignment.Left
        textButton640.Font = Enum.Font.Gotham
        textButton640.TextSize = 10
        local textButton641 = Instance.new("TextButton", frame291)
        textButton641.Size = UDim2.new(0, 16, 0, 16)
        textButton641.Position = UDim2.new(1, -20, 0.5, -8)
        textButton641.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton641.Text = ""
        local uICorner670 = Instance.new("UICorner", textButton641)
        uICorner670.CornerRadius = UDim.new(0, 3)
        local frame292 = Instance.new("Frame", scrollingFrame9)
        frame292.Size = UDim2.new(1, 0, 0, 26)
        frame292.BackgroundTransparency = 1
        frame292.Visible = false
        local uIGridLayout85 = Instance.new("UIGridLayout", frame292)
        uIGridLayout85.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout85.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton642 = Instance.new("TextButton", frame292)
        textButton642.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton642.Text = "Nor"
        textButton642.TextSize = 9
        textButton642.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton642.Font = Enum.Font.GothamBold
        local uICorner671 = Instance.new("UICorner", textButton642)
        local conn643 = textButton642.MouseButton1Click:Connect(function()
            textButton642.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton642.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton643 = Instance.new("TextButton", frame292)
        textButton643.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton643.Text = "Gol"
        textButton643.TextSize = 9
        textButton643.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton643.Font = Enum.Font.GothamBold
        local uICorner672 = Instance.new("UICorner", textButton643)
        local conn644 = textButton643.MouseButton1Click:Connect(function()
            textButton643.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton643.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton644 = Instance.new("TextButton", frame292)
        textButton644.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton644.Text = "Dia"
        textButton644.TextSize = 9
        textButton644.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton644.Font = Enum.Font.GothamBold
        local uICorner673 = Instance.new("UICorner", textButton644)
        local conn645 = textButton644.MouseButton1Click:Connect(function()
            textButton644.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton644.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton645 = Instance.new("TextButton", frame292)
        textButton645.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton645.Text = "Rai"
        textButton645.TextSize = 9
        textButton645.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton645.Font = Enum.Font.GothamBold
        local uICorner674 = Instance.new("UICorner", textButton645)
        local conn646 = textButton645.MouseButton1Click:Connect(function()
            textButton645.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton645.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton646 = Instance.new("TextButton", frame292)
        textButton646.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton646.Text = "Lav"
        textButton646.TextSize = 9
        textButton646.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton646.Font = Enum.Font.GothamBold
        local uICorner675 = Instance.new("UICorner", textButton646)
        local conn647 = textButton646.MouseButton1Click:Connect(function()
            textButton646.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton646.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn648 = textButton640.MouseButton1Click:Connect(function()
            frame292.Visible = true
        end)
        local conn649 = textButton641.MouseButton1Click:Connect(function()
            textButton641.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame293 = Instance.new("Frame", scrollingFrame9)
        frame293.Size = UDim2.new(1, 0, 0, 28)
        frame293.BackgroundTransparency = 1
        local textButton647 = Instance.new("TextButton", frame293)
        textButton647.Size = UDim2.new(0.72, 0, 1, 0)
        textButton647.BackgroundTransparency = 1
        textButton647.Text = "Blueberrinni Octopusini"
        textButton647.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton647.TextXAlignment = Enum.TextXAlignment.Left
        textButton647.Font = Enum.Font.Gotham
        textButton647.TextSize = 10
        local textButton648 = Instance.new("TextButton", frame293)
        textButton648.Size = UDim2.new(0, 16, 0, 16)
        textButton648.Position = UDim2.new(1, -20, 0.5, -8)
        textButton648.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton648.Text = ""
        local uICorner676 = Instance.new("UICorner", textButton648)
        uICorner676.CornerRadius = UDim.new(0, 3)
        local frame294 = Instance.new("Frame", scrollingFrame9)
        frame294.Size = UDim2.new(1, 0, 0, 26)
        frame294.BackgroundTransparency = 1
        frame294.Visible = false
        local uIGridLayout86 = Instance.new("UIGridLayout", frame294)
        uIGridLayout86.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout86.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton649 = Instance.new("TextButton", frame294)
        textButton649.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton649.Text = "Nor"
        textButton649.TextSize = 9
        textButton649.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton649.Font = Enum.Font.GothamBold
        local uICorner677 = Instance.new("UICorner", textButton649)
        local conn650 = textButton649.MouseButton1Click:Connect(function()
            textButton649.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton649.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton650 = Instance.new("TextButton", frame294)
        textButton650.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton650.Text = "Gol"
        textButton650.TextSize = 9
        textButton650.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton650.Font = Enum.Font.GothamBold
        local uICorner678 = Instance.new("UICorner", textButton650)
        local conn651 = textButton650.MouseButton1Click:Connect(function()
            textButton650.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton650.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton651 = Instance.new("TextButton", frame294)
        textButton651.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton651.Text = "Dia"
        textButton651.TextSize = 9
        textButton651.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton651.Font = Enum.Font.GothamBold
        local uICorner679 = Instance.new("UICorner", textButton651)
        local conn652 = textButton651.MouseButton1Click:Connect(function()
            textButton651.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton651.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton652 = Instance.new("TextButton", frame294)
        textButton652.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton652.Text = "Rai"
        textButton652.TextSize = 9
        textButton652.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton652.Font = Enum.Font.GothamBold
        local uICorner680 = Instance.new("UICorner", textButton652)
        local conn653 = textButton652.MouseButton1Click:Connect(function()
            textButton652.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton652.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton653 = Instance.new("TextButton", frame294)
        textButton653.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton653.Text = "Lav"
        textButton653.TextSize = 9
        textButton653.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton653.Font = Enum.Font.GothamBold
        local uICorner681 = Instance.new("UICorner", textButton653)
        local conn654 = textButton653.MouseButton1Click:Connect(function()
            textButton653.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton653.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn655 = textButton647.MouseButton1Click:Connect(function()
            frame294.Visible = true
        end)
        local conn656 = textButton648.MouseButton1Click:Connect(function()
            textButton648.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame295 = Instance.new("Frame", scrollingFrame9)
        frame295.Size = UDim2.new(1, 0, 0, 28)
        frame295.BackgroundTransparency = 1
        local textButton654 = Instance.new("TextButton", frame295)
        textButton654.Size = UDim2.new(0.72, 0, 1, 0)
        textButton654.BackgroundTransparency = 1
        textButton654.Text = "Chimpanzini Bananini"
        textButton654.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton654.TextXAlignment = Enum.TextXAlignment.Left
        textButton654.Font = Enum.Font.Gotham
        textButton654.TextSize = 10
        local textButton655 = Instance.new("TextButton", frame295)
        textButton655.Size = UDim2.new(0, 16, 0, 16)
        textButton655.Position = UDim2.new(1, -20, 0.5, -8)
        textButton655.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton655.Text = ""
        local uICorner682 = Instance.new("UICorner", textButton655)
        uICorner682.CornerRadius = UDim.new(0, 3)
        local frame296 = Instance.new("Frame", scrollingFrame9)
        frame296.Size = UDim2.new(1, 0, 0, 26)
        frame296.BackgroundTransparency = 1
        frame296.Visible = false
        local uIGridLayout87 = Instance.new("UIGridLayout", frame296)
        uIGridLayout87.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout87.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton656 = Instance.new("TextButton", frame296)
        textButton656.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton656.Text = "Nor"
        textButton656.TextSize = 9
        textButton656.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton656.Font = Enum.Font.GothamBold
        local uICorner683 = Instance.new("UICorner", textButton656)
        local conn657 = textButton656.MouseButton1Click:Connect(function()
            textButton656.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton656.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton657 = Instance.new("TextButton", frame296)
        textButton657.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton657.Text = "Gol"
        textButton657.TextSize = 9
        textButton657.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton657.Font = Enum.Font.GothamBold
        local uICorner684 = Instance.new("UICorner", textButton657)
        local conn658 = textButton657.MouseButton1Click:Connect(function()
            textButton657.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton657.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton658 = Instance.new("TextButton", frame296)
        textButton658.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton658.Text = "Dia"
        textButton658.TextSize = 9
        textButton658.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton658.Font = Enum.Font.GothamBold
        local uICorner685 = Instance.new("UICorner", textButton658)
        local conn659 = textButton658.MouseButton1Click:Connect(function()
            textButton658.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton658.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton659 = Instance.new("TextButton", frame296)
        textButton659.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton659.Text = "Rai"
        textButton659.TextSize = 9
        textButton659.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton659.Font = Enum.Font.GothamBold
        local uICorner686 = Instance.new("UICorner", textButton659)
        local conn660 = textButton659.MouseButton1Click:Connect(function()
            textButton659.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton659.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton660 = Instance.new("TextButton", frame296)
        textButton660.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton660.Text = "Lav"
        textButton660.TextSize = 9
        textButton660.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton660.Font = Enum.Font.GothamBold
        local uICorner687 = Instance.new("UICorner", textButton660)
        local conn661 = textButton660.MouseButton1Click:Connect(function()
            textButton660.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton660.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn662 = textButton654.MouseButton1Click:Connect(function()
            frame296.Visible = true
        end)
        local conn663 = textButton655.MouseButton1Click:Connect(function()
            textButton655.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame297 = Instance.new("Frame", scrollingFrame9)
        frame297.Size = UDim2.new(1, 0, 0, 28)
        frame297.BackgroundTransparency = 1
        local textButton661 = Instance.new("TextButton", frame297)
        textButton661.Size = UDim2.new(0.72, 0, 1, 0)
        textButton661.BackgroundTransparency = 1
        textButton661.Text = "Bombardiro Crocodilo"
        textButton661.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton661.TextXAlignment = Enum.TextXAlignment.Left
        textButton661.Font = Enum.Font.Gotham
        textButton661.TextSize = 10
        local textButton662 = Instance.new("TextButton", frame297)
        textButton662.Size = UDim2.new(0, 16, 0, 16)
        textButton662.Position = UDim2.new(1, -20, 0.5, -8)
        textButton662.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton662.Text = ""
        local uICorner688 = Instance.new("UICorner", textButton662)
        uICorner688.CornerRadius = UDim.new(0, 3)
        local frame298 = Instance.new("Frame", scrollingFrame9)
        frame298.Size = UDim2.new(1, 0, 0, 26)
        frame298.BackgroundTransparency = 1
        frame298.Visible = false
        local uIGridLayout88 = Instance.new("UIGridLayout", frame298)
        uIGridLayout88.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout88.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton663 = Instance.new("TextButton", frame298)
        textButton663.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton663.Text = "Nor"
        textButton663.TextSize = 9
        textButton663.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton663.Font = Enum.Font.GothamBold
        local uICorner689 = Instance.new("UICorner", textButton663)
        local conn664 = textButton663.MouseButton1Click:Connect(function()
            textButton663.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton663.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton664 = Instance.new("TextButton", frame298)
        textButton664.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton664.Text = "Gol"
        textButton664.TextSize = 9
        textButton664.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton664.Font = Enum.Font.GothamBold
        local uICorner690 = Instance.new("UICorner", textButton664)
        local conn665 = textButton664.MouseButton1Click:Connect(function()
            textButton664.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton664.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton665 = Instance.new("TextButton", frame298)
        textButton665.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton665.Text = "Dia"
        textButton665.TextSize = 9
        textButton665.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton665.Font = Enum.Font.GothamBold
        local uICorner691 = Instance.new("UICorner", textButton665)
        local conn666 = textButton665.MouseButton1Click:Connect(function()
            textButton665.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton665.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton666 = Instance.new("TextButton", frame298)
        textButton666.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton666.Text = "Rai"
        textButton666.TextSize = 9
        textButton666.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton666.Font = Enum.Font.GothamBold
        local uICorner692 = Instance.new("UICorner", textButton666)
        local conn667 = textButton666.MouseButton1Click:Connect(function()
            textButton666.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton666.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton667 = Instance.new("TextButton", frame298)
        textButton667.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton667.Text = "Lav"
        textButton667.TextSize = 9
        textButton667.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton667.Font = Enum.Font.GothamBold
        local uICorner693 = Instance.new("UICorner", textButton667)
        local conn668 = textButton667.MouseButton1Click:Connect(function()
            textButton667.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton667.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn669 = textButton661.MouseButton1Click:Connect(function()
            frame298.Visible = true
        end)
        local conn670 = textButton662.MouseButton1Click:Connect(function()
            textButton662.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame299 = Instance.new("Frame", scrollingFrame9)
        frame299.Size = UDim2.new(1, 0, 0, 28)
        frame299.BackgroundTransparency = 1
        local textButton668 = Instance.new("TextButton", frame299)
        textButton668.Size = UDim2.new(0.72, 0, 1, 0)
        textButton668.BackgroundTransparency = 1
        textButton668.Text = "Elefanto Cocofanto"
        textButton668.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton668.TextXAlignment = Enum.TextXAlignment.Left
        textButton668.Font = Enum.Font.Gotham
        textButton668.TextSize = 10
        local textButton669 = Instance.new("TextButton", frame299)
        textButton669.Size = UDim2.new(0, 16, 0, 16)
        textButton669.Position = UDim2.new(1, -20, 0.5, -8)
        textButton669.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton669.Text = ""
        local uICorner694 = Instance.new("UICorner", textButton669)
        uICorner694.CornerRadius = UDim.new(0, 3)
        local frame300 = Instance.new("Frame", scrollingFrame9)
        frame300.Size = UDim2.new(1, 0, 0, 26)
        frame300.BackgroundTransparency = 1
        frame300.Visible = false
        local uIGridLayout89 = Instance.new("UIGridLayout", frame300)
        uIGridLayout89.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout89.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton670 = Instance.new("TextButton", frame300)
        textButton670.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton670.Text = "Nor"
        textButton670.TextSize = 9
        textButton670.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton670.Font = Enum.Font.GothamBold
        local uICorner695 = Instance.new("UICorner", textButton670)
        local conn671 = textButton670.MouseButton1Click:Connect(function()
            textButton670.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton670.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton671 = Instance.new("TextButton", frame300)
        textButton671.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton671.Text = "Gol"
        textButton671.TextSize = 9
        textButton671.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton671.Font = Enum.Font.GothamBold
        local uICorner696 = Instance.new("UICorner", textButton671)
        local conn672 = textButton671.MouseButton1Click:Connect(function()
            textButton671.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton671.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton672 = Instance.new("TextButton", frame300)
        textButton672.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton672.Text = "Dia"
        textButton672.TextSize = 9
        textButton672.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton672.Font = Enum.Font.GothamBold
        local uICorner697 = Instance.new("UICorner", textButton672)
        local conn673 = textButton672.MouseButton1Click:Connect(function()
            textButton672.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton672.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton673 = Instance.new("TextButton", frame300)
        textButton673.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton673.Text = "Rai"
        textButton673.TextSize = 9
        textButton673.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton673.Font = Enum.Font.GothamBold
        local uICorner698 = Instance.new("UICorner", textButton673)
        local conn674 = textButton673.MouseButton1Click:Connect(function()
            textButton673.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton673.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton674 = Instance.new("TextButton", frame300)
        textButton674.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton674.Text = "Lav"
        textButton674.TextSize = 9
        textButton674.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton674.Font = Enum.Font.GothamBold
        local uICorner699 = Instance.new("UICorner", textButton674)
        local conn675 = textButton674.MouseButton1Click:Connect(function()
            textButton674.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton674.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn676 = textButton668.MouseButton1Click:Connect(function()
            frame300.Visible = true
        end)
        local conn677 = textButton669.MouseButton1Click:Connect(function()
            textButton669.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame301 = Instance.new("Frame", scrollingFrame9)
        frame301.Size = UDim2.new(1, 0, 0, 28)
        frame301.BackgroundTransparency = 1
        local textButton675 = Instance.new("TextButton", frame301)
        textButton675.Size = UDim2.new(0.72, 0, 1, 0)
        textButton675.BackgroundTransparency = 1
        textButton675.Text = "Bombombini Gusini"
        textButton675.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton675.TextXAlignment = Enum.TextXAlignment.Left
        textButton675.Font = Enum.Font.Gotham
        textButton675.TextSize = 10
        local textButton676 = Instance.new("TextButton", frame301)
        textButton676.Size = UDim2.new(0, 16, 0, 16)
        textButton676.Position = UDim2.new(1, -20, 0.5, -8)
        textButton676.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton676.Text = ""
        local uICorner700 = Instance.new("UICorner", textButton676)
        uICorner700.CornerRadius = UDim.new(0, 3)
        local frame302 = Instance.new("Frame", scrollingFrame9)
        frame302.Size = UDim2.new(1, 0, 0, 26)
        frame302.BackgroundTransparency = 1
        frame302.Visible = false
        local uIGridLayout90 = Instance.new("UIGridLayout", frame302)
        uIGridLayout90.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout90.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton677 = Instance.new("TextButton", frame302)
        textButton677.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton677.Text = "Nor"
        textButton677.TextSize = 9
        textButton677.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton677.Font = Enum.Font.GothamBold
        local uICorner701 = Instance.new("UICorner", textButton677)
        local conn678 = textButton677.MouseButton1Click:Connect(function()
            textButton677.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton677.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton678 = Instance.new("TextButton", frame302)
        textButton678.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton678.Text = "Gol"
        textButton678.TextSize = 9
        textButton678.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton678.Font = Enum.Font.GothamBold
        local uICorner702 = Instance.new("UICorner", textButton678)
        local conn679 = textButton678.MouseButton1Click:Connect(function()
            textButton678.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton678.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton679 = Instance.new("TextButton", frame302)
        textButton679.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton679.Text = "Dia"
        textButton679.TextSize = 9
        textButton679.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton679.Font = Enum.Font.GothamBold
        local uICorner703 = Instance.new("UICorner", textButton679)
        local conn680 = textButton679.MouseButton1Click:Connect(function()
            textButton679.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton679.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton680 = Instance.new("TextButton", frame302)
        textButton680.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton680.Text = "Rai"
        textButton680.TextSize = 9
        textButton680.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton680.Font = Enum.Font.GothamBold
        local uICorner704 = Instance.new("UICorner", textButton680)
        local conn681 = textButton680.MouseButton1Click:Connect(function()
            textButton680.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton680.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton681 = Instance.new("TextButton", frame302)
        textButton681.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton681.Text = "Lav"
        textButton681.TextSize = 9
        textButton681.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton681.Font = Enum.Font.GothamBold
        local uICorner705 = Instance.new("UICorner", textButton681)
        local conn682 = textButton681.MouseButton1Click:Connect(function()
            textButton681.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton681.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn683 = textButton675.MouseButton1Click:Connect(function()
            frame302.Visible = true
        end)
        local conn684 = textButton676.MouseButton1Click:Connect(function()
            textButton676.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame303 = Instance.new("Frame", scrollingFrame9)
        frame303.Size = UDim2.new(1, 0, 0, 28)
        frame303.BackgroundTransparency = 1
        local textButton682 = Instance.new("TextButton", frame303)
        textButton682.Size = UDim2.new(0.72, 0, 1, 0)
        textButton682.BackgroundTransparency = 1
        textButton682.Text = "Pandaccini Bananini"
        textButton682.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton682.TextXAlignment = Enum.TextXAlignment.Left
        textButton682.Font = Enum.Font.Gotham
        textButton682.TextSize = 10
        local textButton683 = Instance.new("TextButton", frame303)
        textButton683.Size = UDim2.new(0, 16, 0, 16)
        textButton683.Position = UDim2.new(1, -20, 0.5, -8)
        textButton683.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton683.Text = ""
        local uICorner706 = Instance.new("UICorner", textButton683)
        uICorner706.CornerRadius = UDim.new(0, 3)
        local frame304 = Instance.new("Frame", scrollingFrame9)
        frame304.Size = UDim2.new(1, 0, 0, 26)
        frame304.BackgroundTransparency = 1
        frame304.Visible = false
        local uIGridLayout91 = Instance.new("UIGridLayout", frame304)
        uIGridLayout91.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout91.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton684 = Instance.new("TextButton", frame304)
        textButton684.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton684.Text = "Nor"
        textButton684.TextSize = 9
        textButton684.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton684.Font = Enum.Font.GothamBold
        local uICorner707 = Instance.new("UICorner", textButton684)
        local conn685 = textButton684.MouseButton1Click:Connect(function()
            textButton684.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton684.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton685 = Instance.new("TextButton", frame304)
        textButton685.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton685.Text = "Gol"
        textButton685.TextSize = 9
        textButton685.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton685.Font = Enum.Font.GothamBold
        local uICorner708 = Instance.new("UICorner", textButton685)
        local conn686 = textButton685.MouseButton1Click:Connect(function()
            textButton685.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton685.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton686 = Instance.new("TextButton", frame304)
        textButton686.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton686.Text = "Dia"
        textButton686.TextSize = 9
        textButton686.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton686.Font = Enum.Font.GothamBold
        local uICorner709 = Instance.new("UICorner", textButton686)
        local conn687 = textButton686.MouseButton1Click:Connect(function()
            textButton686.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton686.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton687 = Instance.new("TextButton", frame304)
        textButton687.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton687.Text = "Rai"
        textButton687.TextSize = 9
        textButton687.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton687.Font = Enum.Font.GothamBold
        local uICorner710 = Instance.new("UICorner", textButton687)
        local conn688 = textButton687.MouseButton1Click:Connect(function()
            textButton687.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton687.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton688 = Instance.new("TextButton", frame304)
        textButton688.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton688.Text = "Lav"
        textButton688.TextSize = 9
        textButton688.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton688.Font = Enum.Font.GothamBold
        local uICorner711 = Instance.new("UICorner", textButton688)
        local conn689 = textButton688.MouseButton1Click:Connect(function()
            textButton688.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton688.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn690 = textButton682.MouseButton1Click:Connect(function()
            frame304.Visible = true
        end)
        local conn691 = textButton683.MouseButton1Click:Connect(function()
            textButton683.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame305 = Instance.new("Frame", scrollingFrame9)
        frame305.Size = UDim2.new(1, 0, 0, 28)
        frame305.BackgroundTransparency = 1
        local textButton689 = Instance.new("TextButton", frame305)
        textButton689.Size = UDim2.new(0.72, 0, 1, 0)
        textButton689.BackgroundTransparency = 1
        textButton689.Text = "Chef Crabracadabra"
        textButton689.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton689.TextXAlignment = Enum.TextXAlignment.Left
        textButton689.Font = Enum.Font.Gotham
        textButton689.TextSize = 10
        local textButton690 = Instance.new("TextButton", frame305)
        textButton690.Size = UDim2.new(0, 16, 0, 16)
        textButton690.Position = UDim2.new(1, -20, 0.5, -8)
        textButton690.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton690.Text = ""
        local uICorner712 = Instance.new("UICorner", textButton690)
        uICorner712.CornerRadius = UDim.new(0, 3)
        local frame306 = Instance.new("Frame", scrollingFrame9)
        frame306.Size = UDim2.new(1, 0, 0, 26)
        frame306.BackgroundTransparency = 1
        frame306.Visible = false
        local uIGridLayout92 = Instance.new("UIGridLayout", frame306)
        uIGridLayout92.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout92.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton691 = Instance.new("TextButton", frame306)
        textButton691.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton691.Text = "Nor"
        textButton691.TextSize = 9
        textButton691.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton691.Font = Enum.Font.GothamBold
        local uICorner713 = Instance.new("UICorner", textButton691)
        local conn692 = textButton691.MouseButton1Click:Connect(function()
            textButton691.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton691.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton692 = Instance.new("TextButton", frame306)
        textButton692.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton692.Text = "Gol"
        textButton692.TextSize = 9
        textButton692.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton692.Font = Enum.Font.GothamBold
        local uICorner714 = Instance.new("UICorner", textButton692)
        local conn693 = textButton692.MouseButton1Click:Connect(function()
            textButton692.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton692.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton693 = Instance.new("TextButton", frame306)
        textButton693.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton693.Text = "Dia"
        textButton693.TextSize = 9
        textButton693.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton693.Font = Enum.Font.GothamBold
        local uICorner715 = Instance.new("UICorner", textButton693)
        local conn694 = textButton693.MouseButton1Click:Connect(function()
            textButton693.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton693.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton694 = Instance.new("TextButton", frame306)
        textButton694.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton694.Text = "Rai"
        textButton694.TextSize = 9
        textButton694.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton694.Font = Enum.Font.GothamBold
        local uICorner716 = Instance.new("UICorner", textButton694)
        local conn695 = textButton694.MouseButton1Click:Connect(function()
            textButton694.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton694.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton695 = Instance.new("TextButton", frame306)
        textButton695.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton695.Text = "Lav"
        textButton695.TextSize = 9
        textButton695.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton695.Font = Enum.Font.GothamBold
        local uICorner717 = Instance.new("UICorner", textButton695)
        local conn696 = textButton695.MouseButton1Click:Connect(function()
            textButton695.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton695.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn697 = textButton689.MouseButton1Click:Connect(function()
            frame306.Visible = true
        end)
        local conn698 = textButton690.MouseButton1Click:Connect(function()
            textButton690.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame307 = Instance.new("Frame", scrollingFrame9)
        frame307.Size = UDim2.new(1, 0, 0, 28)
        frame307.BackgroundTransparency = 1
        local textButton696 = Instance.new("TextButton", frame307)
        textButton696.Size = UDim2.new(0.72, 0, 1, 0)
        textButton696.BackgroundTransparency = 1
        textButton696.Text = "Gorillo Watermelondrillo"
        textButton696.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton696.TextXAlignment = Enum.TextXAlignment.Left
        textButton696.Font = Enum.Font.Gotham
        textButton696.TextSize = 10
        local textButton697 = Instance.new("TextButton", frame307)
        textButton697.Size = UDim2.new(0, 16, 0, 16)
        textButton697.Position = UDim2.new(1, -20, 0.5, -8)
        textButton697.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton697.Text = ""
        local uICorner718 = Instance.new("UICorner", textButton697)
        uICorner718.CornerRadius = UDim.new(0, 3)
        local frame308 = Instance.new("Frame", scrollingFrame9)
        frame308.Size = UDim2.new(1, 0, 0, 26)
        frame308.BackgroundTransparency = 1
        frame308.Visible = false
        local uIGridLayout93 = Instance.new("UIGridLayout", frame308)
        uIGridLayout93.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout93.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton698 = Instance.new("TextButton", frame308)
        textButton698.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton698.Text = "Nor"
        textButton698.TextSize = 9
        textButton698.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton698.Font = Enum.Font.GothamBold
        local uICorner719 = Instance.new("UICorner", textButton698)
        local conn699 = textButton698.MouseButton1Click:Connect(function()
            textButton698.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton698.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton699 = Instance.new("TextButton", frame308)
        textButton699.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton699.Text = "Gol"
        textButton699.TextSize = 9
        textButton699.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton699.Font = Enum.Font.GothamBold
        local uICorner720 = Instance.new("UICorner", textButton699)
        local conn700 = textButton699.MouseButton1Click:Connect(function()
            textButton699.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton699.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton700 = Instance.new("TextButton", frame308)
        textButton700.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton700.Text = "Dia"
        textButton700.TextSize = 9
        textButton700.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton700.Font = Enum.Font.GothamBold
        local uICorner721 = Instance.new("UICorner", textButton700)
        local conn701 = textButton700.MouseButton1Click:Connect(function()
            textButton700.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton700.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton701 = Instance.new("TextButton", frame308)
        textButton701.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton701.Text = "Rai"
        textButton701.TextSize = 9
        textButton701.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton701.Font = Enum.Font.GothamBold
        local uICorner722 = Instance.new("UICorner", textButton701)
        local conn702 = textButton701.MouseButton1Click:Connect(function()
            textButton701.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton701.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton702 = Instance.new("TextButton", frame308)
        textButton702.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton702.Text = "Lav"
        textButton702.TextSize = 9
        textButton702.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton702.Font = Enum.Font.GothamBold
        local uICorner723 = Instance.new("UICorner", textButton702)
        local conn703 = textButton702.MouseButton1Click:Connect(function()
            textButton702.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton702.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn704 = textButton696.MouseButton1Click:Connect(function()
            frame308.Visible = true
        end)
        local conn705 = textButton697.MouseButton1Click:Connect(function()
            textButton697.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame309 = Instance.new("Frame", scrollingFrame9)
        frame309.Size = UDim2.new(1, 0, 0, 28)
        frame309.BackgroundTransparency = 1
        local textButton703 = Instance.new("TextButton", frame309)
        textButton703.Size = UDim2.new(0.72, 0, 1, 0)
        textButton703.BackgroundTransparency = 1
        textButton703.Text = "Frigo Camelo"
        textButton703.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton703.TextXAlignment = Enum.TextXAlignment.Left
        textButton703.Font = Enum.Font.Gotham
        textButton703.TextSize = 10
        local textButton704 = Instance.new("TextButton", frame309)
        textButton704.Size = UDim2.new(0, 16, 0, 16)
        textButton704.Position = UDim2.new(1, -20, 0.5, -8)
        textButton704.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton704.Text = ""
        local uICorner724 = Instance.new("UICorner", textButton704)
        uICorner724.CornerRadius = UDim.new(0, 3)
        local frame310 = Instance.new("Frame", scrollingFrame9)
        frame310.Size = UDim2.new(1, 0, 0, 26)
        frame310.BackgroundTransparency = 1
        frame310.Visible = false
        local uIGridLayout94 = Instance.new("UIGridLayout", frame310)
        uIGridLayout94.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout94.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton705 = Instance.new("TextButton", frame310)
        textButton705.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton705.Text = "Nor"
        textButton705.TextSize = 9
        textButton705.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton705.Font = Enum.Font.GothamBold
        local uICorner725 = Instance.new("UICorner", textButton705)
        local conn706 = textButton705.MouseButton1Click:Connect(function()
            textButton705.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton705.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton706 = Instance.new("TextButton", frame310)
        textButton706.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton706.Text = "Gol"
        textButton706.TextSize = 9
        textButton706.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton706.Font = Enum.Font.GothamBold
        local uICorner726 = Instance.new("UICorner", textButton706)
        local conn707 = textButton706.MouseButton1Click:Connect(function()
            textButton706.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton706.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton707 = Instance.new("TextButton", frame310)
        textButton707.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton707.Text = "Dia"
        textButton707.TextSize = 9
        textButton707.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton707.Font = Enum.Font.GothamBold
        local uICorner727 = Instance.new("UICorner", textButton707)
        local conn708 = textButton707.MouseButton1Click:Connect(function()
            textButton707.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton707.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton708 = Instance.new("TextButton", frame310)
        textButton708.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton708.Text = "Rai"
        textButton708.TextSize = 9
        textButton708.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton708.Font = Enum.Font.GothamBold
        local uICorner728 = Instance.new("UICorner", textButton708)
        local conn709 = textButton708.MouseButton1Click:Connect(function()
            textButton708.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton708.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton709 = Instance.new("TextButton", frame310)
        textButton709.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton709.Text = "Lav"
        textButton709.TextSize = 9
        textButton709.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton709.Font = Enum.Font.GothamBold
        local uICorner729 = Instance.new("UICorner", textButton709)
        local conn710 = textButton709.MouseButton1Click:Connect(function()
            textButton709.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton709.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn711 = textButton703.MouseButton1Click:Connect(function()
            frame310.Visible = true
        end)
        local conn712 = textButton704.MouseButton1Click:Connect(function()
            textButton704.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame311 = Instance.new("Frame", scrollingFrame9)
        frame311.Size = UDim2.new(1, 0, 0, 28)
        frame311.BackgroundTransparency = 1
        local textButton710 = Instance.new("TextButton", frame311)
        textButton710.Size = UDim2.new(0.72, 0, 1, 0)
        textButton710.BackgroundTransparency = 1
        textButton710.Text = "Girafa Celestre"
        textButton710.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton710.TextXAlignment = Enum.TextXAlignment.Left
        textButton710.Font = Enum.Font.Gotham
        textButton710.TextSize = 10
        local textButton711 = Instance.new("TextButton", frame311)
        textButton711.Size = UDim2.new(0, 16, 0, 16)
        textButton711.Position = UDim2.new(1, -20, 0.5, -8)
        textButton711.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton711.Text = ""
        local uICorner730 = Instance.new("UICorner", textButton711)
        uICorner730.CornerRadius = UDim.new(0, 3)
        local frame312 = Instance.new("Frame", scrollingFrame9)
        frame312.Size = UDim2.new(1, 0, 0, 26)
        frame312.BackgroundTransparency = 1
        frame312.Visible = false
        local uIGridLayout95 = Instance.new("UIGridLayout", frame312)
        uIGridLayout95.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout95.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton712 = Instance.new("TextButton", frame312)
        textButton712.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton712.Text = "Nor"
        textButton712.TextSize = 9
        textButton712.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton712.Font = Enum.Font.GothamBold
        local uICorner731 = Instance.new("UICorner", textButton712)
        local conn713 = textButton712.MouseButton1Click:Connect(function()
            textButton712.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton712.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton713 = Instance.new("TextButton", frame312)
        textButton713.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton713.Text = "Gol"
        textButton713.TextSize = 9
        textButton713.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton713.Font = Enum.Font.GothamBold
        local uICorner732 = Instance.new("UICorner", textButton713)
        local conn714 = textButton713.MouseButton1Click:Connect(function()
            textButton713.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton713.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton714 = Instance.new("TextButton", frame312)
        textButton714.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton714.Text = "Dia"
        textButton714.TextSize = 9
        textButton714.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton714.Font = Enum.Font.GothamBold
        local uICorner733 = Instance.new("UICorner", textButton714)
        local conn715 = textButton714.MouseButton1Click:Connect(function()
            textButton714.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton714.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton715 = Instance.new("TextButton", frame312)
        textButton715.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton715.Text = "Rai"
        textButton715.TextSize = 9
        textButton715.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton715.Font = Enum.Font.GothamBold
        local uICorner734 = Instance.new("UICorner", textButton715)
        local conn716 = textButton715.MouseButton1Click:Connect(function()
            textButton715.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton715.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton716 = Instance.new("TextButton", frame312)
        textButton716.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton716.Text = "Lav"
        textButton716.TextSize = 9
        textButton716.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton716.Font = Enum.Font.GothamBold
        local uICorner735 = Instance.new("UICorner", textButton716)
        local conn717 = textButton716.MouseButton1Click:Connect(function()
            textButton716.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton716.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn718 = textButton710.MouseButton1Click:Connect(function()
            frame312.Visible = true
        end)
        local conn719 = textButton711.MouseButton1Click:Connect(function()
            textButton711.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame313 = Instance.new("Frame", scrollingFrame9)
        frame313.Size = UDim2.new(1, 0, 0, 28)
        frame313.BackgroundTransparency = 1
        local textButton717 = Instance.new("TextButton", frame313)
        textButton717.Size = UDim2.new(0.72, 0, 1, 0)
        textButton717.BackgroundTransparency = 1
        textButton717.Text = "Ganganzelli Trulala"
        textButton717.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton717.TextXAlignment = Enum.TextXAlignment.Left
        textButton717.Font = Enum.Font.Gotham
        textButton717.TextSize = 10
        local textButton718 = Instance.new("TextButton", frame313)
        textButton718.Size = UDim2.new(0, 16, 0, 16)
        textButton718.Position = UDim2.new(1, -20, 0.5, -8)
        textButton718.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton718.Text = ""
        local uICorner736 = Instance.new("UICorner", textButton718)
        uICorner736.CornerRadius = UDim.new(0, 3)
        local frame314 = Instance.new("Frame", scrollingFrame9)
        frame314.Size = UDim2.new(1, 0, 0, 26)
        frame314.BackgroundTransparency = 1
        frame314.Visible = false
        local uIGridLayout96 = Instance.new("UIGridLayout", frame314)
        uIGridLayout96.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout96.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton719 = Instance.new("TextButton", frame314)
        textButton719.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton719.Text = "Nor"
        textButton719.TextSize = 9
        textButton719.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton719.Font = Enum.Font.GothamBold
        local uICorner737 = Instance.new("UICorner", textButton719)
        local conn720 = textButton719.MouseButton1Click:Connect(function()
            textButton719.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton719.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton720 = Instance.new("TextButton", frame314)
        textButton720.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton720.Text = "Gol"
        textButton720.TextSize = 9
        textButton720.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton720.Font = Enum.Font.GothamBold
        local uICorner738 = Instance.new("UICorner", textButton720)
        local conn721 = textButton720.MouseButton1Click:Connect(function()
            textButton720.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton720.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton721 = Instance.new("TextButton", frame314)
        textButton721.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton721.Text = "Dia"
        textButton721.TextSize = 9
        textButton721.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton721.Font = Enum.Font.GothamBold
        local uICorner739 = Instance.new("UICorner", textButton721)
        local conn722 = textButton721.MouseButton1Click:Connect(function()
            textButton721.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton721.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton722 = Instance.new("TextButton", frame314)
        textButton722.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton722.Text = "Rai"
        textButton722.TextSize = 9
        textButton722.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton722.Font = Enum.Font.GothamBold
        local uICorner740 = Instance.new("UICorner", textButton722)
        local conn723 = textButton722.MouseButton1Click:Connect(function()
            textButton722.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton722.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton723 = Instance.new("TextButton", frame314)
        textButton723.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton723.Text = "Lav"
        textButton723.TextSize = 9
        textButton723.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton723.Font = Enum.Font.GothamBold
        local uICorner741 = Instance.new("UICorner", textButton723)
        local conn724 = textButton723.MouseButton1Click:Connect(function()
            textButton723.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton723.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn725 = textButton717.MouseButton1Click:Connect(function()
            frame314.Visible = true
        end)
        local conn726 = textButton718.MouseButton1Click:Connect(function()
            textButton718.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame315 = Instance.new("Frame", scrollingFrame9)
        frame315.Size = UDim2.new(1, 0, 0, 28)
        frame315.BackgroundTransparency = 1
        local textButton724 = Instance.new("TextButton", frame315)
        textButton724.Size = UDim2.new(0.72, 0, 1, 0)
        textButton724.BackgroundTransparency = 1
        textButton724.Text = "Tigroligre Frutonni"
        textButton724.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton724.TextXAlignment = Enum.TextXAlignment.Left
        textButton724.Font = Enum.Font.Gotham
        textButton724.TextSize = 10
        local textButton725 = Instance.new("TextButton", frame315)
        textButton725.Size = UDim2.new(0, 16, 0, 16)
        textButton725.Position = UDim2.new(1, -20, 0.5, -8)
        textButton725.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton725.Text = ""
        local uICorner742 = Instance.new("UICorner", textButton725)
        uICorner742.CornerRadius = UDim.new(0, 3)
        local frame316 = Instance.new("Frame", scrollingFrame9)
        frame316.Size = UDim2.new(1, 0, 0, 26)
        frame316.BackgroundTransparency = 1
        frame316.Visible = false
        local uIGridLayout97 = Instance.new("UIGridLayout", frame316)
        uIGridLayout97.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout97.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton726 = Instance.new("TextButton", frame316)
        textButton726.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton726.Text = "Nor"
        textButton726.TextSize = 9
        textButton726.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton726.Font = Enum.Font.GothamBold
        local uICorner743 = Instance.new("UICorner", textButton726)
        local conn727 = textButton726.MouseButton1Click:Connect(function()
            textButton726.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton726.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton727 = Instance.new("TextButton", frame316)
        textButton727.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton727.Text = "Gol"
        textButton727.TextSize = 9
        textButton727.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton727.Font = Enum.Font.GothamBold
        local uICorner744 = Instance.new("UICorner", textButton727)
        local conn728 = textButton727.MouseButton1Click:Connect(function()
            textButton727.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton727.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton728 = Instance.new("TextButton", frame316)
        textButton728.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton728.Text = "Dia"
        textButton728.TextSize = 9
        textButton728.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton728.Font = Enum.Font.GothamBold
        local uICorner745 = Instance.new("UICorner", textButton728)
        local conn729 = textButton728.MouseButton1Click:Connect(function()
            textButton728.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton728.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton729 = Instance.new("TextButton", frame316)
        textButton729.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton729.Text = "Rai"
        textButton729.TextSize = 9
        textButton729.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton729.Font = Enum.Font.GothamBold
        local uICorner746 = Instance.new("UICorner", textButton729)
        local conn730 = textButton729.MouseButton1Click:Connect(function()
            textButton729.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton729.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton730 = Instance.new("TextButton", frame316)
        textButton730.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton730.Text = "Lav"
        textButton730.TextSize = 9
        textButton730.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton730.Font = Enum.Font.GothamBold
        local uICorner747 = Instance.new("UICorner", textButton730)
        local conn731 = textButton730.MouseButton1Click:Connect(function()
            textButton730.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton730.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn732 = textButton724.MouseButton1Click:Connect(function()
            frame316.Visible = true
        end)
        local conn733 = textButton725.MouseButton1Click:Connect(function()
            textButton725.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame317 = Instance.new("Frame", scrollingFrame9)
        frame317.Size = UDim2.new(1, 0, 0, 28)
        frame317.BackgroundTransparency = 1
        local textButton731 = Instance.new("TextButton", frame317)
        textButton731.Size = UDim2.new(0.72, 0, 1, 0)
        textButton731.BackgroundTransparency = 1
        textButton731.Text = "Matteo"
        textButton731.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton731.TextXAlignment = Enum.TextXAlignment.Left
        textButton731.Font = Enum.Font.Gotham
        textButton731.TextSize = 10
        local textButton732 = Instance.new("TextButton", frame317)
        textButton732.Size = UDim2.new(0, 16, 0, 16)
        textButton732.Position = UDim2.new(1, -20, 0.5, -8)
        textButton732.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton732.Text = ""
        local uICorner748 = Instance.new("UICorner", textButton732)
        uICorner748.CornerRadius = UDim.new(0, 3)
        local frame318 = Instance.new("Frame", scrollingFrame9)
        frame318.Size = UDim2.new(1, 0, 0, 26)
        frame318.BackgroundTransparency = 1
        frame318.Visible = false
        local uIGridLayout98 = Instance.new("UIGridLayout", frame318)
        uIGridLayout98.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout98.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton733 = Instance.new("TextButton", frame318)
        textButton733.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton733.Text = "Nor"
        textButton733.TextSize = 9
        textButton733.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton733.Font = Enum.Font.GothamBold
        local uICorner749 = Instance.new("UICorner", textButton733)
        local conn734 = textButton733.MouseButton1Click:Connect(function()
            textButton733.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton733.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton734 = Instance.new("TextButton", frame318)
        textButton734.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton734.Text = "Gol"
        textButton734.TextSize = 9
        textButton734.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton734.Font = Enum.Font.GothamBold
        local uICorner750 = Instance.new("UICorner", textButton734)
        local conn735 = textButton734.MouseButton1Click:Connect(function()
            textButton734.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton734.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton735 = Instance.new("TextButton", frame318)
        textButton735.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton735.Text = "Dia"
        textButton735.TextSize = 9
        textButton735.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton735.Font = Enum.Font.GothamBold
        local uICorner751 = Instance.new("UICorner", textButton735)
        local conn736 = textButton735.MouseButton1Click:Connect(function()
            textButton735.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton735.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton736 = Instance.new("TextButton", frame318)
        textButton736.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton736.Text = "Rai"
        textButton736.TextSize = 9
        textButton736.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton736.Font = Enum.Font.GothamBold
        local uICorner752 = Instance.new("UICorner", textButton736)
        local conn737 = textButton736.MouseButton1Click:Connect(function()
            textButton736.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton736.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton737 = Instance.new("TextButton", frame318)
        textButton737.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton737.Text = "Lav"
        textButton737.TextSize = 9
        textButton737.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton737.Font = Enum.Font.GothamBold
        local uICorner753 = Instance.new("UICorner", textButton737)
        local conn738 = textButton737.MouseButton1Click:Connect(function()
            textButton737.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton737.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn739 = textButton731.MouseButton1Click:Connect(function()
            frame318.Visible = true
        end)
        local conn740 = textButton732.MouseButton1Click:Connect(function()
            textButton732.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame319 = Instance.new("Frame", scrollingFrame9)
        frame319.Size = UDim2.new(1, 0, 0, 28)
        frame319.BackgroundTransparency = 1
        local textButton738 = Instance.new("TextButton", frame319)
        textButton738.Size = UDim2.new(0.72, 0, 1, 0)
        textButton738.BackgroundTransparency = 1
        textButton738.Text = "Cavallo Virtuoso"
        textButton738.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton738.TextXAlignment = Enum.TextXAlignment.Left
        textButton738.Font = Enum.Font.Gotham
        textButton738.TextSize = 10
        local textButton739 = Instance.new("TextButton", frame319)
        textButton739.Size = UDim2.new(0, 16, 0, 16)
        textButton739.Position = UDim2.new(1, -20, 0.5, -8)
        textButton739.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton739.Text = ""
        local uICorner754 = Instance.new("UICorner", textButton739)
        uICorner754.CornerRadius = UDim.new(0, 3)
        local frame320 = Instance.new("Frame", scrollingFrame9)
        frame320.Size = UDim2.new(1, 0, 0, 26)
        frame320.BackgroundTransparency = 1
        frame320.Visible = false
        local uIGridLayout99 = Instance.new("UIGridLayout", frame320)
        uIGridLayout99.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout99.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton740 = Instance.new("TextButton", frame320)
        textButton740.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton740.Text = "Nor"
        textButton740.TextSize = 9
        textButton740.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton740.Font = Enum.Font.GothamBold
        local uICorner755 = Instance.new("UICorner", textButton740)
        local conn741 = textButton740.MouseButton1Click:Connect(function()
            textButton740.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton740.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton741 = Instance.new("TextButton", frame320)
        textButton741.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton741.Text = "Gol"
        textButton741.TextSize = 9
        textButton741.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton741.Font = Enum.Font.GothamBold
        local uICorner756 = Instance.new("UICorner", textButton741)
        local conn742 = textButton741.MouseButton1Click:Connect(function()
            textButton741.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton741.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton742 = Instance.new("TextButton", frame320)
        textButton742.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton742.Text = "Dia"
        textButton742.TextSize = 9
        textButton742.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton742.Font = Enum.Font.GothamBold
        local uICorner757 = Instance.new("UICorner", textButton742)
        local conn743 = textButton742.MouseButton1Click:Connect(function()
            textButton742.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton742.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton743 = Instance.new("TextButton", frame320)
        textButton743.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton743.Text = "Rai"
        textButton743.TextSize = 9
        textButton743.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton743.Font = Enum.Font.GothamBold
        local uICorner758 = Instance.new("UICorner", textButton743)
        local conn744 = textButton743.MouseButton1Click:Connect(function()
            textButton743.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton743.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton744 = Instance.new("TextButton", frame320)
        textButton744.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton744.Text = "Lav"
        textButton744.TextSize = 9
        textButton744.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton744.Font = Enum.Font.GothamBold
        local uICorner759 = Instance.new("UICorner", textButton744)
        local conn745 = textButton744.MouseButton1Click:Connect(function()
            textButton744.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton744.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn746 = textButton738.MouseButton1Click:Connect(function()
            frame320.Visible = true
        end)
        local conn747 = textButton739.MouseButton1Click:Connect(function()
            textButton739.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame321 = Instance.new("Frame", scrollingFrame9)
        frame321.Size = UDim2.new(1, 0, 0, 28)
        frame321.BackgroundTransparency = 1
        local textButton745 = Instance.new("TextButton", frame321)
        textButton745.Size = UDim2.new(0.72, 0, 1, 0)
        textButton745.BackgroundTransparency = 1
        textButton745.Text = "La Vacca Saturno Saturnita"
        textButton745.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton745.TextXAlignment = Enum.TextXAlignment.Left
        textButton745.Font = Enum.Font.Gotham
        textButton745.TextSize = 10
        local textButton746 = Instance.new("TextButton", frame321)
        textButton746.Size = UDim2.new(0, 16, 0, 16)
        textButton746.Position = UDim2.new(1, -20, 0.5, -8)
        textButton746.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton746.Text = ""
        local uICorner760 = Instance.new("UICorner", textButton746)
        uICorner760.CornerRadius = UDim.new(0, 3)
        local frame322 = Instance.new("Frame", scrollingFrame9)
        frame322.Size = UDim2.new(1, 0, 0, 26)
        frame322.BackgroundTransparency = 1
        frame322.Visible = false
        local uIGridLayout100 = Instance.new("UIGridLayout", frame322)
        uIGridLayout100.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout100.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton747 = Instance.new("TextButton", frame322)
        textButton747.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton747.Text = "Nor"
        textButton747.TextSize = 9
        textButton747.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton747.Font = Enum.Font.GothamBold
        local uICorner761 = Instance.new("UICorner", textButton747)
        local conn748 = textButton747.MouseButton1Click:Connect(function()
            textButton747.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton747.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton748 = Instance.new("TextButton", frame322)
        textButton748.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton748.Text = "Gol"
        textButton748.TextSize = 9
        textButton748.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton748.Font = Enum.Font.GothamBold
        local uICorner762 = Instance.new("UICorner", textButton748)
        local conn749 = textButton748.MouseButton1Click:Connect(function()
            textButton748.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton748.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton749 = Instance.new("TextButton", frame322)
        textButton749.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton749.Text = "Dia"
        textButton749.TextSize = 9
        textButton749.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton749.Font = Enum.Font.GothamBold
        local uICorner763 = Instance.new("UICorner", textButton749)
        local conn750 = textButton749.MouseButton1Click:Connect(function()
            textButton749.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton749.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton750 = Instance.new("TextButton", frame322)
        textButton750.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton750.Text = "Rai"
        textButton750.TextSize = 9
        textButton750.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton750.Font = Enum.Font.GothamBold
        local uICorner764 = Instance.new("UICorner", textButton750)
        local conn751 = textButton750.MouseButton1Click:Connect(function()
            textButton750.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton750.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton751 = Instance.new("TextButton", frame322)
        textButton751.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton751.Text = "Lav"
        textButton751.TextSize = 9
        textButton751.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton751.Font = Enum.Font.GothamBold
        local uICorner765 = Instance.new("UICorner", textButton751)
        local conn752 = textButton751.MouseButton1Click:Connect(function()
            textButton751.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton751.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn753 = textButton745.MouseButton1Click:Connect(function()
            frame322.Visible = true
        end)
        local conn754 = textButton746.MouseButton1Click:Connect(function()
            textButton746.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame323 = Instance.new("Frame", scrollingFrame9)
        frame323.Size = UDim2.new(1, 0, 0, 28)
        frame323.BackgroundTransparency = 1
        local textButton752 = Instance.new("TextButton", frame323)
        textButton752.Size = UDim2.new(0.72, 0, 1, 0)
        textButton752.BackgroundTransparency = 1
        textButton752.Text = "Esok Sekolah"
        textButton752.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton752.TextXAlignment = Enum.TextXAlignment.Left
        textButton752.Font = Enum.Font.Gotham
        textButton752.TextSize = 10
        local textButton753 = Instance.new("TextButton", frame323)
        textButton753.Size = UDim2.new(0, 16, 0, 16)
        textButton753.Position = UDim2.new(1, -20, 0.5, -8)
        textButton753.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton753.Text = ""
        local uICorner766 = Instance.new("UICorner", textButton753)
        uICorner766.CornerRadius = UDim.new(0, 3)
        local frame324 = Instance.new("Frame", scrollingFrame9)
        frame324.Size = UDim2.new(1, 0, 0, 26)
        frame324.BackgroundTransparency = 1
        frame324.Visible = false
        local uIGridLayout101 = Instance.new("UIGridLayout", frame324)
        uIGridLayout101.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout101.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton754 = Instance.new("TextButton", frame324)
        textButton754.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton754.Text = "Nor"
        textButton754.TextSize = 9
        textButton754.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton754.Font = Enum.Font.GothamBold
        local uICorner767 = Instance.new("UICorner", textButton754)
        local conn755 = textButton754.MouseButton1Click:Connect(function()
            textButton754.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton754.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton755 = Instance.new("TextButton", frame324)
        textButton755.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton755.Text = "Gol"
        textButton755.TextSize = 9
        textButton755.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton755.Font = Enum.Font.GothamBold
        local uICorner768 = Instance.new("UICorner", textButton755)
        local conn756 = textButton755.MouseButton1Click:Connect(function()
            textButton755.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton755.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton756 = Instance.new("TextButton", frame324)
        textButton756.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton756.Text = "Dia"
        textButton756.TextSize = 9
        textButton756.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton756.Font = Enum.Font.GothamBold
        local uICorner769 = Instance.new("UICorner", textButton756)
        local conn757 = textButton756.MouseButton1Click:Connect(function()
            textButton756.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton756.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton757 = Instance.new("TextButton", frame324)
        textButton757.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton757.Text = "Rai"
        textButton757.TextSize = 9
        textButton757.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton757.Font = Enum.Font.GothamBold
        local uICorner770 = Instance.new("UICorner", textButton757)
        local conn758 = textButton757.MouseButton1Click:Connect(function()
            textButton757.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton757.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton758 = Instance.new("TextButton", frame324)
        textButton758.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton758.Text = "Lav"
        textButton758.TextSize = 9
        textButton758.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton758.Font = Enum.Font.GothamBold
        local uICorner771 = Instance.new("UICorner", textButton758)
        local conn759 = textButton758.MouseButton1Click:Connect(function()
            textButton758.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton758.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn760 = textButton752.MouseButton1Click:Connect(function()
            frame324.Visible = true
        end)
        local conn761 = textButton753.MouseButton1Click:Connect(function()
            textButton753.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame325 = Instance.new("Frame", scrollingFrame9)
        frame325.Size = UDim2.new(1, 0, 0, 28)
        frame325.BackgroundTransparency = 1
        local textButton759 = Instance.new("TextButton", frame325)
        textButton759.Size = UDim2.new(0.72, 0, 1, 0)
        textButton759.BackgroundTransparency = 1
        textButton759.Text = "Tralaledon"
        textButton759.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton759.TextXAlignment = Enum.TextXAlignment.Left
        textButton759.Font = Enum.Font.Gotham
        textButton759.TextSize = 10
        local textButton760 = Instance.new("TextButton", frame325)
        textButton760.Size = UDim2.new(0, 16, 0, 16)
        textButton760.Position = UDim2.new(1, -20, 0.5, -8)
        textButton760.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton760.Text = ""
        local uICorner772 = Instance.new("UICorner", textButton760)
        uICorner772.CornerRadius = UDim.new(0, 3)
        local frame326 = Instance.new("Frame", scrollingFrame9)
        frame326.Size = UDim2.new(1, 0, 0, 26)
        frame326.BackgroundTransparency = 1
        frame326.Visible = false
        local uIGridLayout102 = Instance.new("UIGridLayout", frame326)
        uIGridLayout102.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout102.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton761 = Instance.new("TextButton", frame326)
        textButton761.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton761.Text = "Nor"
        textButton761.TextSize = 9
        textButton761.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton761.Font = Enum.Font.GothamBold
        local uICorner773 = Instance.new("UICorner", textButton761)
        local conn762 = textButton761.MouseButton1Click:Connect(function()
            textButton761.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton761.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton762 = Instance.new("TextButton", frame326)
        textButton762.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton762.Text = "Gol"
        textButton762.TextSize = 9
        textButton762.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton762.Font = Enum.Font.GothamBold
        local uICorner774 = Instance.new("UICorner", textButton762)
        local conn763 = textButton762.MouseButton1Click:Connect(function()
            textButton762.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton762.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton763 = Instance.new("TextButton", frame326)
        textButton763.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton763.Text = "Dia"
        textButton763.TextSize = 9
        textButton763.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton763.Font = Enum.Font.GothamBold
        local uICorner775 = Instance.new("UICorner", textButton763)
        local conn764 = textButton763.MouseButton1Click:Connect(function()
            textButton763.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton763.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton764 = Instance.new("TextButton", frame326)
        textButton764.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton764.Text = "Rai"
        textButton764.TextSize = 9
        textButton764.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton764.Font = Enum.Font.GothamBold
        local uICorner776 = Instance.new("UICorner", textButton764)
        local conn765 = textButton764.MouseButton1Click:Connect(function()
            textButton764.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton764.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton765 = Instance.new("TextButton", frame326)
        textButton765.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton765.Text = "Lav"
        textButton765.TextSize = 9
        textButton765.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton765.Font = Enum.Font.GothamBold
        local uICorner777 = Instance.new("UICorner", textButton765)
        local conn766 = textButton765.MouseButton1Click:Connect(function()
            textButton765.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton765.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn767 = textButton759.MouseButton1Click:Connect(function()
            frame326.Visible = true
        end)
        local conn768 = textButton760.MouseButton1Click:Connect(function()
            textButton760.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame327 = Instance.new("Frame", scrollingFrame9)
        frame327.Size = UDim2.new(1, 0, 0, 28)
        frame327.BackgroundTransparency = 1
        local textButton766 = Instance.new("TextButton", frame327)
        textButton766.Size = UDim2.new(0.72, 0, 1, 0)
        textButton766.BackgroundTransparency = 1
        textButton766.Text = "Tralalero Tralala"
        textButton766.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton766.TextXAlignment = Enum.TextXAlignment.Left
        textButton766.Font = Enum.Font.Gotham
        textButton766.TextSize = 10
        local textButton767 = Instance.new("TextButton", frame327)
        textButton767.Size = UDim2.new(0, 16, 0, 16)
        textButton767.Position = UDim2.new(1, -20, 0.5, -8)
        textButton767.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton767.Text = ""
        local uICorner778 = Instance.new("UICorner", textButton767)
        uICorner778.CornerRadius = UDim.new(0, 3)
        local frame328 = Instance.new("Frame", scrollingFrame9)
        frame328.Size = UDim2.new(1, 0, 0, 26)
        frame328.BackgroundTransparency = 1
        frame328.Visible = false
        local uIGridLayout103 = Instance.new("UIGridLayout", frame328)
        uIGridLayout103.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout103.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton768 = Instance.new("TextButton", frame328)
        textButton768.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton768.Text = "Nor"
        textButton768.TextSize = 9
        textButton768.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton768.Font = Enum.Font.GothamBold
        local uICorner779 = Instance.new("UICorner", textButton768)
        local conn769 = textButton768.MouseButton1Click:Connect(function()
            textButton768.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton768.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton769 = Instance.new("TextButton", frame328)
        textButton769.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton769.Text = "Gol"
        textButton769.TextSize = 9
        textButton769.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton769.Font = Enum.Font.GothamBold
        local uICorner780 = Instance.new("UICorner", textButton769)
        local conn770 = textButton769.MouseButton1Click:Connect(function()
            textButton769.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton769.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton770 = Instance.new("TextButton", frame328)
        textButton770.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton770.Text = "Dia"
        textButton770.TextSize = 9
        textButton770.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton770.Font = Enum.Font.GothamBold
        local uICorner781 = Instance.new("UICorner", textButton770)
        local conn771 = textButton770.MouseButton1Click:Connect(function()
            textButton770.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton770.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton771 = Instance.new("TextButton", frame328)
        textButton771.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton771.Text = "Rai"
        textButton771.TextSize = 9
        textButton771.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton771.Font = Enum.Font.GothamBold
        local uICorner782 = Instance.new("UICorner", textButton771)
        local conn772 = textButton771.MouseButton1Click:Connect(function()
            textButton771.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton771.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton772 = Instance.new("TextButton", frame328)
        textButton772.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton772.Text = "Lav"
        textButton772.TextSize = 9
        textButton772.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton772.Font = Enum.Font.GothamBold
        local uICorner783 = Instance.new("UICorner", textButton772)
        local conn773 = textButton772.MouseButton1Click:Connect(function()
            textButton772.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton772.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn774 = textButton766.MouseButton1Click:Connect(function()
            frame328.Visible = true
        end)
        local conn775 = textButton767.MouseButton1Click:Connect(function()
            textButton767.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame329 = Instance.new("Frame", scrollingFrame9)
        frame329.Size = UDim2.new(1, 0, 0, 28)
        frame329.BackgroundTransparency = 1
        local textButton773 = Instance.new("TextButton", frame329)
        textButton773.Size = UDim2.new(0.72, 0, 1, 0)
        textButton773.BackgroundTransparency = 1
        textButton773.Text = "Chicleteira Bicicleteira"
        textButton773.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton773.TextXAlignment = Enum.TextXAlignment.Left
        textButton773.Font = Enum.Font.Gotham
        textButton773.TextSize = 10
        local textButton774 = Instance.new("TextButton", frame329)
        textButton774.Size = UDim2.new(0, 16, 0, 16)
        textButton774.Position = UDim2.new(1, -20, 0.5, -8)
        textButton774.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton774.Text = ""
        local uICorner784 = Instance.new("UICorner", textButton774)
        uICorner784.CornerRadius = UDim.new(0, 3)
        local frame330 = Instance.new("Frame", scrollingFrame9)
        frame330.Size = UDim2.new(1, 0, 0, 26)
        frame330.BackgroundTransparency = 1
        frame330.Visible = false
        local uIGridLayout104 = Instance.new("UIGridLayout", frame330)
        uIGridLayout104.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout104.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton775 = Instance.new("TextButton", frame330)
        textButton775.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton775.Text = "Nor"
        textButton775.TextSize = 9
        textButton775.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton775.Font = Enum.Font.GothamBold
        local uICorner785 = Instance.new("UICorner", textButton775)
        local conn776 = textButton775.MouseButton1Click:Connect(function()
            textButton775.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton775.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton776 = Instance.new("TextButton", frame330)
        textButton776.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton776.Text = "Gol"
        textButton776.TextSize = 9
        textButton776.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton776.Font = Enum.Font.GothamBold
        local uICorner786 = Instance.new("UICorner", textButton776)
        local conn777 = textButton776.MouseButton1Click:Connect(function()
            textButton776.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton776.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton777 = Instance.new("TextButton", frame330)
        textButton777.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton777.Text = "Dia"
        textButton777.TextSize = 9
        textButton777.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton777.Font = Enum.Font.GothamBold
        local uICorner787 = Instance.new("UICorner", textButton777)
        local conn778 = textButton777.MouseButton1Click:Connect(function()
            textButton777.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton777.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton778 = Instance.new("TextButton", frame330)
        textButton778.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton778.Text = "Rai"
        textButton778.TextSize = 9
        textButton778.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton778.Font = Enum.Font.GothamBold
        local uICorner788 = Instance.new("UICorner", textButton778)
        local conn779 = textButton778.MouseButton1Click:Connect(function()
            textButton778.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton778.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton779 = Instance.new("TextButton", frame330)
        textButton779.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton779.Text = "Lav"
        textButton779.TextSize = 9
        textButton779.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton779.Font = Enum.Font.GothamBold
        local uICorner789 = Instance.new("UICorner", textButton779)
        local conn780 = textButton779.MouseButton1Click:Connect(function()
            textButton779.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton779.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn781 = textButton773.MouseButton1Click:Connect(function()
            frame330.Visible = true
        end)
        local conn782 = textButton774.MouseButton1Click:Connect(function()
            textButton774.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame331 = Instance.new("Frame", scrollingFrame9)
        frame331.Size = UDim2.new(1, 0, 0, 28)
        frame331.BackgroundTransparency = 1
        local textButton780 = Instance.new("TextButton", frame331)
        textButton780.Size = UDim2.new(0.72, 0, 1, 0)
        textButton780.BackgroundTransparency = 1
        textButton780.Text = "Torrtuginni Dragonfrutini"
        textButton780.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton780.TextXAlignment = Enum.TextXAlignment.Left
        textButton780.Font = Enum.Font.Gotham
        textButton780.TextSize = 10
        local textButton781 = Instance.new("TextButton", frame331)
        textButton781.Size = UDim2.new(0, 16, 0, 16)
        textButton781.Position = UDim2.new(1, -20, 0.5, -8)
        textButton781.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton781.Text = ""
        local uICorner790 = Instance.new("UICorner", textButton781)
        uICorner790.CornerRadius = UDim.new(0, 3)
        local frame332 = Instance.new("Frame", scrollingFrame9)
        frame332.Size = UDim2.new(1, 0, 0, 26)
        frame332.BackgroundTransparency = 1
        frame332.Visible = false
        local uIGridLayout105 = Instance.new("UIGridLayout", frame332)
        uIGridLayout105.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout105.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton782 = Instance.new("TextButton", frame332)
        textButton782.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton782.Text = "Nor"
        textButton782.TextSize = 9
        textButton782.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton782.Font = Enum.Font.GothamBold
        local uICorner791 = Instance.new("UICorner", textButton782)
        local conn783 = textButton782.MouseButton1Click:Connect(function()
            textButton782.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton782.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton783 = Instance.new("TextButton", frame332)
        textButton783.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton783.Text = "Gol"
        textButton783.TextSize = 9
        textButton783.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton783.Font = Enum.Font.GothamBold
        local uICorner792 = Instance.new("UICorner", textButton783)
        local conn784 = textButton783.MouseButton1Click:Connect(function()
            textButton783.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton783.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton784 = Instance.new("TextButton", frame332)
        textButton784.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton784.Text = "Dia"
        textButton784.TextSize = 9
        textButton784.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton784.Font = Enum.Font.GothamBold
        local uICorner793 = Instance.new("UICorner", textButton784)
        local conn785 = textButton784.MouseButton1Click:Connect(function()
            textButton784.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton784.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton785 = Instance.new("TextButton", frame332)
        textButton785.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton785.Text = "Rai"
        textButton785.TextSize = 9
        textButton785.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton785.Font = Enum.Font.GothamBold
        local uICorner794 = Instance.new("UICorner", textButton785)
        local conn786 = textButton785.MouseButton1Click:Connect(function()
            textButton785.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton785.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton786 = Instance.new("TextButton", frame332)
        textButton786.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton786.Text = "Lav"
        textButton786.TextSize = 9
        textButton786.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton786.Font = Enum.Font.GothamBold
        local uICorner795 = Instance.new("UICorner", textButton786)
        local conn787 = textButton786.MouseButton1Click:Connect(function()
            textButton786.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton786.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn788 = textButton780.MouseButton1Click:Connect(function()
            frame332.Visible = true
        end)
        local conn789 = textButton781.MouseButton1Click:Connect(function()
            textButton781.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame333 = Instance.new("Frame", scrollingFrame9)
        frame333.Size = UDim2.new(1, 0, 0, 28)
        frame333.BackgroundTransparency = 1
        local textButton787 = Instance.new("TextButton", frame333)
        textButton787.Size = UDim2.new(0.72, 0, 1, 0)
        textButton787.BackgroundTransparency = 1
        textButton787.Text = "Nuclearo Dinosauru"
        textButton787.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton787.TextXAlignment = Enum.TextXAlignment.Left
        textButton787.Font = Enum.Font.Gotham
        textButton787.TextSize = 10
        local textButton788 = Instance.new("TextButton", frame333)
        textButton788.Size = UDim2.new(0, 16, 0, 16)
        textButton788.Position = UDim2.new(1, -20, 0.5, -8)
        textButton788.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton788.Text = ""
        local uICorner796 = Instance.new("UICorner", textButton788)
        uICorner796.CornerRadius = UDim.new(0, 3)
        local frame334 = Instance.new("Frame", scrollingFrame9)
        frame334.Size = UDim2.new(1, 0, 0, 26)
        frame334.BackgroundTransparency = 1
        frame334.Visible = false
        local uIGridLayout106 = Instance.new("UIGridLayout", frame334)
        uIGridLayout106.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout106.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton789 = Instance.new("TextButton", frame334)
        textButton789.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton789.Text = "Nor"
        textButton789.TextSize = 9
        textButton789.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton789.Font = Enum.Font.GothamBold
        local uICorner797 = Instance.new("UICorner", textButton789)
        local conn790 = textButton789.MouseButton1Click:Connect(function()
            textButton789.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton789.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton790 = Instance.new("TextButton", frame334)
        textButton790.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton790.Text = "Gol"
        textButton790.TextSize = 9
        textButton790.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton790.Font = Enum.Font.GothamBold
        local uICorner798 = Instance.new("UICorner", textButton790)
        local conn791 = textButton790.MouseButton1Click:Connect(function()
            textButton790.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton790.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton791 = Instance.new("TextButton", frame334)
        textButton791.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton791.Text = "Dia"
        textButton791.TextSize = 9
        textButton791.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton791.Font = Enum.Font.GothamBold
        local uICorner799 = Instance.new("UICorner", textButton791)
        local conn792 = textButton791.MouseButton1Click:Connect(function()
            textButton791.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton791.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton792 = Instance.new("TextButton", frame334)
        textButton792.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton792.Text = "Rai"
        textButton792.TextSize = 9
        textButton792.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton792.Font = Enum.Font.GothamBold
        local uICorner800 = Instance.new("UICorner", textButton792)
        local conn793 = textButton792.MouseButton1Click:Connect(function()
            textButton792.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton792.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton793 = Instance.new("TextButton", frame334)
        textButton793.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton793.Text = "Lav"
        textButton793.TextSize = 9
        textButton793.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton793.Font = Enum.Font.GothamBold
        local uICorner801 = Instance.new("UICorner", textButton793)
        local conn794 = textButton793.MouseButton1Click:Connect(function()
            textButton793.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton793.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn795 = textButton787.MouseButton1Click:Connect(function()
            frame334.Visible = true
        end)
        local conn796 = textButton788.MouseButton1Click:Connect(function()
            textButton788.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame335 = Instance.new("Frame", scrollingFrame9)
        frame335.Size = UDim2.new(1, 0, 0, 28)
        frame335.BackgroundTransparency = 1
        local textButton794 = Instance.new("TextButton", frame335)
        textButton794.Size = UDim2.new(0.72, 0, 1, 0)
        textButton794.BackgroundTransparency = 1
        textButton794.Text = "Quesadilla Crocodila"
        textButton794.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton794.TextXAlignment = Enum.TextXAlignment.Left
        textButton794.Font = Enum.Font.Gotham
        textButton794.TextSize = 10
        local textButton795 = Instance.new("TextButton", frame335)
        textButton795.Size = UDim2.new(0, 16, 0, 16)
        textButton795.Position = UDim2.new(1, -20, 0.5, -8)
        textButton795.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton795.Text = ""
        local uICorner802 = Instance.new("UICorner", textButton795)
        uICorner802.CornerRadius = UDim.new(0, 3)
        local frame336 = Instance.new("Frame", scrollingFrame9)
        frame336.Size = UDim2.new(1, 0, 0, 26)
        frame336.BackgroundTransparency = 1
        frame336.Visible = false
        local uIGridLayout107 = Instance.new("UIGridLayout", frame336)
        uIGridLayout107.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout107.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton796 = Instance.new("TextButton", frame336)
        textButton796.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton796.Text = "Nor"
        textButton796.TextSize = 9
        textButton796.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton796.Font = Enum.Font.GothamBold
        local uICorner803 = Instance.new("UICorner", textButton796)
        local conn797 = textButton796.MouseButton1Click:Connect(function()
            textButton796.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton796.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton797 = Instance.new("TextButton", frame336)
        textButton797.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton797.Text = "Gol"
        textButton797.TextSize = 9
        textButton797.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton797.Font = Enum.Font.GothamBold
        local uICorner804 = Instance.new("UICorner", textButton797)
        local conn798 = textButton797.MouseButton1Click:Connect(function()
            textButton797.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton797.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton798 = Instance.new("TextButton", frame336)
        textButton798.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton798.Text = "Dia"
        textButton798.TextSize = 9
        textButton798.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton798.Font = Enum.Font.GothamBold
        local uICorner805 = Instance.new("UICorner", textButton798)
        local conn799 = textButton798.MouseButton1Click:Connect(function()
            textButton798.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton798.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton799 = Instance.new("TextButton", frame336)
        textButton799.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton799.Text = "Rai"
        textButton799.TextSize = 9
        textButton799.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton799.Font = Enum.Font.GothamBold
        local uICorner806 = Instance.new("UICorner", textButton799)
        local conn800 = textButton799.MouseButton1Click:Connect(function()
            textButton799.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton799.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton800 = Instance.new("TextButton", frame336)
        textButton800.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton800.Text = "Lav"
        textButton800.TextSize = 9
        textButton800.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton800.Font = Enum.Font.GothamBold
        local uICorner807 = Instance.new("UICorner", textButton800)
        local conn801 = textButton800.MouseButton1Click:Connect(function()
            textButton800.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton800.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn802 = textButton794.MouseButton1Click:Connect(function()
            frame336.Visible = true
        end)
        local conn803 = textButton795.MouseButton1Click:Connect(function()
            textButton795.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame337 = Instance.new("Frame", scrollingFrame9)
        frame337.Size = UDim2.new(1, 0, 0, 28)
        frame337.BackgroundTransparency = 1
        local textButton801 = Instance.new("TextButton", frame337)
        textButton801.Size = UDim2.new(0.72, 0, 1, 0)
        textButton801.BackgroundTransparency = 1
        textButton801.Text = "Graipussi Medussi"
        textButton801.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton801.TextXAlignment = Enum.TextXAlignment.Left
        textButton801.Font = Enum.Font.Gotham
        textButton801.TextSize = 10
        local textButton802 = Instance.new("TextButton", frame337)
        textButton802.Size = UDim2.new(0, 16, 0, 16)
        textButton802.Position = UDim2.new(1, -20, 0.5, -8)
        textButton802.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton802.Text = ""
        local uICorner808 = Instance.new("UICorner", textButton802)
        uICorner808.CornerRadius = UDim.new(0, 3)
        local frame338 = Instance.new("Frame", scrollingFrame9)
        frame338.Size = UDim2.new(1, 0, 0, 26)
        frame338.BackgroundTransparency = 1
        frame338.Visible = false
        local uIGridLayout108 = Instance.new("UIGridLayout", frame338)
        uIGridLayout108.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout108.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton803 = Instance.new("TextButton", frame338)
        textButton803.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton803.Text = "Nor"
        textButton803.TextSize = 9
        textButton803.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton803.Font = Enum.Font.GothamBold
        local uICorner809 = Instance.new("UICorner", textButton803)
        local conn804 = textButton803.MouseButton1Click:Connect(function()
            textButton803.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton803.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton804 = Instance.new("TextButton", frame338)
        textButton804.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton804.Text = "Gol"
        textButton804.TextSize = 9
        textButton804.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton804.Font = Enum.Font.GothamBold
        local uICorner810 = Instance.new("UICorner", textButton804)
        local conn805 = textButton804.MouseButton1Click:Connect(function()
            textButton804.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton804.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton805 = Instance.new("TextButton", frame338)
        textButton805.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton805.Text = "Dia"
        textButton805.TextSize = 9
        textButton805.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton805.Font = Enum.Font.GothamBold
        local uICorner811 = Instance.new("UICorner", textButton805)
        local conn806 = textButton805.MouseButton1Click:Connect(function()
            textButton805.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton805.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton806 = Instance.new("TextButton", frame338)
        textButton806.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton806.Text = "Rai"
        textButton806.TextSize = 9
        textButton806.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton806.Font = Enum.Font.GothamBold
        local uICorner812 = Instance.new("UICorner", textButton806)
        local conn807 = textButton806.MouseButton1Click:Connect(function()
            textButton806.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton806.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton807 = Instance.new("TextButton", frame338)
        textButton807.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton807.Text = "Lav"
        textButton807.TextSize = 9
        textButton807.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton807.Font = Enum.Font.GothamBold
        local uICorner813 = Instance.new("UICorner", textButton807)
        local conn808 = textButton807.MouseButton1Click:Connect(function()
            textButton807.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton807.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn809 = textButton801.MouseButton1Click:Connect(function()
            frame338.Visible = true
        end)
        local conn810 = textButton802.MouseButton1Click:Connect(function()
            textButton802.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame339 = Instance.new("Frame", scrollingFrame9)
        frame339.Size = UDim2.new(1, 0, 0, 28)
        frame339.BackgroundTransparency = 1
        local textButton808 = Instance.new("TextButton", frame339)
        textButton808.Size = UDim2.new(0.72, 0, 1, 0)
        textButton808.BackgroundTransparency = 1
        textButton808.Text = "Lucky Block"
        textButton808.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton808.TextXAlignment = Enum.TextXAlignment.Left
        textButton808.Font = Enum.Font.Gotham
        textButton808.TextSize = 10
        local textButton809 = Instance.new("TextButton", frame339)
        textButton809.Size = UDim2.new(0, 16, 0, 16)
        textButton809.Position = UDim2.new(1, -20, 0.5, -8)
        textButton809.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton809.Text = ""
        local uICorner814 = Instance.new("UICorner", textButton809)
        uICorner814.CornerRadius = UDim.new(0, 3)
        local frame340 = Instance.new("Frame", scrollingFrame9)
        frame340.Size = UDim2.new(1, 0, 0, 26)
        frame340.BackgroundTransparency = 1
        frame340.Visible = false
        local uIGridLayout109 = Instance.new("UIGridLayout", frame340)
        uIGridLayout109.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout109.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton810 = Instance.new("TextButton", frame340)
        textButton810.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton810.Text = "Nor"
        textButton810.TextSize = 9
        textButton810.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton810.Font = Enum.Font.GothamBold
        local uICorner815 = Instance.new("UICorner", textButton810)
        local conn811 = textButton810.MouseButton1Click:Connect(function()
            textButton810.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton810.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton811 = Instance.new("TextButton", frame340)
        textButton811.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton811.Text = "Gol"
        textButton811.TextSize = 9
        textButton811.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton811.Font = Enum.Font.GothamBold
        local uICorner816 = Instance.new("UICorner", textButton811)
        local conn812 = textButton811.MouseButton1Click:Connect(function()
            textButton811.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton811.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton812 = Instance.new("TextButton", frame340)
        textButton812.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton812.Text = "Dia"
        textButton812.TextSize = 9
        textButton812.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton812.Font = Enum.Font.GothamBold
        local uICorner817 = Instance.new("UICorner", textButton812)
        local conn813 = textButton812.MouseButton1Click:Connect(function()
            textButton812.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton812.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton813 = Instance.new("TextButton", frame340)
        textButton813.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton813.Text = "Rai"
        textButton813.TextSize = 9
        textButton813.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton813.Font = Enum.Font.GothamBold
        local uICorner818 = Instance.new("UICorner", textButton813)
        local conn814 = textButton813.MouseButton1Click:Connect(function()
            textButton813.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton813.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton814 = Instance.new("TextButton", frame340)
        textButton814.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton814.Text = "Lav"
        textButton814.TextSize = 9
        textButton814.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton814.Font = Enum.Font.GothamBold
        local uICorner819 = Instance.new("UICorner", textButton814)
        local conn815 = textButton814.MouseButton1Click:Connect(function()
            textButton814.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton814.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn816 = textButton808.MouseButton1Click:Connect(function()
            frame340.Visible = true
        end)
        local conn817 = textButton809.MouseButton1Click:Connect(function()
            textButton809.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame341 = Instance.new("Frame", scrollingFrame9)
        frame341.Size = UDim2.new(1, 0, 0, 28)
        frame341.BackgroundTransparency = 1
        local textButton815 = Instance.new("TextButton", frame341)
        textButton815.Size = UDim2.new(0.72, 0, 1, 0)
        textButton815.BackgroundTransparency = 1
        textButton815.Text = "Caramelini Brasilini"
        textButton815.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton815.TextXAlignment = Enum.TextXAlignment.Left
        textButton815.Font = Enum.Font.Gotham
        textButton815.TextSize = 10
        local textButton816 = Instance.new("TextButton", frame341)
        textButton816.Size = UDim2.new(0, 16, 0, 16)
        textButton816.Position = UDim2.new(1, -20, 0.5, -8)
        textButton816.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton816.Text = ""
        local uICorner820 = Instance.new("UICorner", textButton816)
        uICorner820.CornerRadius = UDim.new(0, 3)
        local frame342 = Instance.new("Frame", scrollingFrame9)
        frame342.Size = UDim2.new(1, 0, 0, 26)
        frame342.BackgroundTransparency = 1
        frame342.Visible = false
        local uIGridLayout110 = Instance.new("UIGridLayout", frame342)
        uIGridLayout110.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout110.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton817 = Instance.new("TextButton", frame342)
        textButton817.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton817.Text = "Nor"
        textButton817.TextSize = 9
        textButton817.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton817.Font = Enum.Font.GothamBold
        local uICorner821 = Instance.new("UICorner", textButton817)
        local conn818 = textButton817.MouseButton1Click:Connect(function()
            textButton817.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton817.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton818 = Instance.new("TextButton", frame342)
        textButton818.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton818.Text = "Gol"
        textButton818.TextSize = 9
        textButton818.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton818.Font = Enum.Font.GothamBold
        local uICorner822 = Instance.new("UICorner", textButton818)
        local conn819 = textButton818.MouseButton1Click:Connect(function()
            textButton818.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton818.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton819 = Instance.new("TextButton", frame342)
        textButton819.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton819.Text = "Dia"
        textButton819.TextSize = 9
        textButton819.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton819.Font = Enum.Font.GothamBold
        local uICorner823 = Instance.new("UICorner", textButton819)
        local conn820 = textButton819.MouseButton1Click:Connect(function()
            textButton819.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton819.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton820 = Instance.new("TextButton", frame342)
        textButton820.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton820.Text = "Rai"
        textButton820.TextSize = 9
        textButton820.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton820.Font = Enum.Font.GothamBold
        local uICorner824 = Instance.new("UICorner", textButton820)
        local conn821 = textButton820.MouseButton1Click:Connect(function()
            textButton820.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton820.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton821 = Instance.new("TextButton", frame342)
        textButton821.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton821.Text = "Lav"
        textButton821.TextSize = 9
        textButton821.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton821.Font = Enum.Font.GothamBold
        local uICorner825 = Instance.new("UICorner", textButton821)
        local conn822 = textButton821.MouseButton1Click:Connect(function()
            textButton821.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton821.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn823 = textButton815.MouseButton1Click:Connect(function()
            frame342.Visible = true
        end)
        local conn824 = textButton816.MouseButton1Click:Connect(function()
            textButton816.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame343 = Instance.new("Frame", scrollingFrame9)
        frame343.Size = UDim2.new(1, 0, 0, 28)
        frame343.BackgroundTransparency = 1
        local textButton822 = Instance.new("TextButton", frame343)
        textButton822.Size = UDim2.new(0.72, 0, 1, 0)
        textButton822.BackgroundTransparency = 1
        textButton822.Text = "Garama and Madundung"
        textButton822.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton822.TextXAlignment = Enum.TextXAlignment.Left
        textButton822.Font = Enum.Font.Gotham
        textButton822.TextSize = 10
        local textButton823 = Instance.new("TextButton", frame343)
        textButton823.Size = UDim2.new(0, 16, 0, 16)
        textButton823.Position = UDim2.new(1, -20, 0.5, -8)
        textButton823.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton823.Text = ""
        local uICorner826 = Instance.new("UICorner", textButton823)
        uICorner826.CornerRadius = UDim.new(0, 3)
        local frame344 = Instance.new("Frame", scrollingFrame9)
        frame344.Size = UDim2.new(1, 0, 0, 26)
        frame344.BackgroundTransparency = 1
        frame344.Visible = false
        local uIGridLayout111 = Instance.new("UIGridLayout", frame344)
        uIGridLayout111.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout111.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton824 = Instance.new("TextButton", frame344)
        textButton824.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton824.Text = "Nor"
        textButton824.TextSize = 9
        textButton824.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton824.Font = Enum.Font.GothamBold
        local uICorner827 = Instance.new("UICorner", textButton824)
        local conn825 = textButton824.MouseButton1Click:Connect(function()
            textButton824.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton824.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton825 = Instance.new("TextButton", frame344)
        textButton825.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton825.Text = "Gol"
        textButton825.TextSize = 9
        textButton825.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton825.Font = Enum.Font.GothamBold
        local uICorner828 = Instance.new("UICorner", textButton825)
        local conn826 = textButton825.MouseButton1Click:Connect(function()
            textButton825.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton825.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton826 = Instance.new("TextButton", frame344)
        textButton826.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton826.Text = "Dia"
        textButton826.TextSize = 9
        textButton826.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton826.Font = Enum.Font.GothamBold
        local uICorner829 = Instance.new("UICorner", textButton826)
        local conn827 = textButton826.MouseButton1Click:Connect(function()
            textButton826.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton826.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton827 = Instance.new("TextButton", frame344)
        textButton827.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton827.Text = "Rai"
        textButton827.TextSize = 9
        textButton827.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton827.Font = Enum.Font.GothamBold
        local uICorner830 = Instance.new("UICorner", textButton827)
        local conn828 = textButton827.MouseButton1Click:Connect(function()
            textButton827.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton827.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton828 = Instance.new("TextButton", frame344)
        textButton828.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton828.Text = "Lav"
        textButton828.TextSize = 9
        textButton828.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton828.Font = Enum.Font.GothamBold
        local uICorner831 = Instance.new("UICorner", textButton828)
        local conn829 = textButton828.MouseButton1Click:Connect(function()
            textButton828.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton828.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn830 = textButton822.MouseButton1Click:Connect(function()
            frame344.Visible = true
        end)
        local conn831 = textButton823.MouseButton1Click:Connect(function()
            textButton823.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame345 = Instance.new("Frame", scrollingFrame9)
        frame345.Size = UDim2.new(1, 0, 0, 28)
        frame345.BackgroundTransparency = 1
        local textButton829 = Instance.new("TextButton", frame345)
        textButton829.Size = UDim2.new(0.72, 0, 1, 0)
        textButton829.BackgroundTransparency = 1
        textButton829.Text = "Meowl"
        textButton829.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton829.TextXAlignment = Enum.TextXAlignment.Left
        textButton829.Font = Enum.Font.Gotham
        textButton829.TextSize = 10
        local textButton830 = Instance.new("TextButton", frame345)
        textButton830.Size = UDim2.new(0, 16, 0, 16)
        textButton830.Position = UDim2.new(1, -20, 0.5, -8)
        textButton830.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton830.Text = ""
        local uICorner832 = Instance.new("UICorner", textButton830)
        uICorner832.CornerRadius = UDim.new(0, 3)
        local frame346 = Instance.new("Frame", scrollingFrame9)
        frame346.Size = UDim2.new(1, 0, 0, 26)
        frame346.BackgroundTransparency = 1
        frame346.Visible = false
        local uIGridLayout112 = Instance.new("UIGridLayout", frame346)
        uIGridLayout112.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout112.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton831 = Instance.new("TextButton", frame346)
        textButton831.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton831.Text = "Nor"
        textButton831.TextSize = 9
        textButton831.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton831.Font = Enum.Font.GothamBold
        local uICorner833 = Instance.new("UICorner", textButton831)
        local conn832 = textButton831.MouseButton1Click:Connect(function()
            textButton831.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton831.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton832 = Instance.new("TextButton", frame346)
        textButton832.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton832.Text = "Gol"
        textButton832.TextSize = 9
        textButton832.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton832.Font = Enum.Font.GothamBold
        local uICorner834 = Instance.new("UICorner", textButton832)
        local conn833 = textButton832.MouseButton1Click:Connect(function()
            textButton832.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton832.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton833 = Instance.new("TextButton", frame346)
        textButton833.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton833.Text = "Dia"
        textButton833.TextSize = 9
        textButton833.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton833.Font = Enum.Font.GothamBold
        local uICorner835 = Instance.new("UICorner", textButton833)
        local conn834 = textButton833.MouseButton1Click:Connect(function()
            textButton833.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton833.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton834 = Instance.new("TextButton", frame346)
        textButton834.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton834.Text = "Rai"
        textButton834.TextSize = 9
        textButton834.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton834.Font = Enum.Font.GothamBold
        local uICorner836 = Instance.new("UICorner", textButton834)
        local conn835 = textButton834.MouseButton1Click:Connect(function()
            textButton834.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton834.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton835 = Instance.new("TextButton", frame346)
        textButton835.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton835.Text = "Lav"
        textButton835.TextSize = 9
        textButton835.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton835.Font = Enum.Font.GothamBold
        local uICorner837 = Instance.new("UICorner", textButton835)
        local conn836 = textButton835.MouseButton1Click:Connect(function()
            textButton835.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton835.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn837 = textButton829.MouseButton1Click:Connect(function()
            frame346.Visible = true
        end)
        local conn838 = textButton830.MouseButton1Click:Connect(function()
            textButton830.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame347 = Instance.new("Frame", scrollingFrame9)
        frame347.Size = UDim2.new(1, 0, 0, 28)
        frame347.BackgroundTransparency = 1
        local textButton836 = Instance.new("TextButton", frame347)
        textButton836.Size = UDim2.new(0.72, 0, 1, 0)
        textButton836.BackgroundTransparency = 1
        textButton836.Text = "Smurf Cat"
        textButton836.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton836.TextXAlignment = Enum.TextXAlignment.Left
        textButton836.Font = Enum.Font.Gotham
        textButton836.TextSize = 10
        local textButton837 = Instance.new("TextButton", frame347)
        textButton837.Size = UDim2.new(0, 16, 0, 16)
        textButton837.Position = UDim2.new(1, -20, 0.5, -8)
        textButton837.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton837.Text = ""
        local uICorner838 = Instance.new("UICorner", textButton837)
        uICorner838.CornerRadius = UDim.new(0, 3)
        local frame348 = Instance.new("Frame", scrollingFrame9)
        frame348.Size = UDim2.new(1, 0, 0, 26)
        frame348.BackgroundTransparency = 1
        frame348.Visible = false
        local uIGridLayout113 = Instance.new("UIGridLayout", frame348)
        uIGridLayout113.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout113.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton838 = Instance.new("TextButton", frame348)
        textButton838.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton838.Text = "Nor"
        textButton838.TextSize = 9
        textButton838.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton838.Font = Enum.Font.GothamBold
        local uICorner839 = Instance.new("UICorner", textButton838)
        local conn839 = textButton838.MouseButton1Click:Connect(function()
            textButton838.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton838.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton839 = Instance.new("TextButton", frame348)
        textButton839.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton839.Text = "Gol"
        textButton839.TextSize = 9
        textButton839.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton839.Font = Enum.Font.GothamBold
        local uICorner840 = Instance.new("UICorner", textButton839)
        local conn840 = textButton839.MouseButton1Click:Connect(function()
            textButton839.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton839.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton840 = Instance.new("TextButton", frame348)
        textButton840.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton840.Text = "Dia"
        textButton840.TextSize = 9
        textButton840.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton840.Font = Enum.Font.GothamBold
        local uICorner841 = Instance.new("UICorner", textButton840)
        local conn841 = textButton840.MouseButton1Click:Connect(function()
            textButton840.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton840.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton841 = Instance.new("TextButton", frame348)
        textButton841.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton841.Text = "Rai"
        textButton841.TextSize = 9
        textButton841.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton841.Font = Enum.Font.GothamBold
        local uICorner842 = Instance.new("UICorner", textButton841)
        local conn842 = textButton841.MouseButton1Click:Connect(function()
            textButton841.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton841.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton842 = Instance.new("TextButton", frame348)
        textButton842.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton842.Text = "Lav"
        textButton842.TextSize = 9
        textButton842.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton842.Font = Enum.Font.GothamBold
        local uICorner843 = Instance.new("UICorner", textButton842)
        local conn843 = textButton842.MouseButton1Click:Connect(function()
            textButton842.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton842.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn844 = textButton836.MouseButton1Click:Connect(function()
            frame348.Visible = true
        end)
        local conn845 = textButton837.MouseButton1Click:Connect(function()
            textButton837.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame349 = Instance.new("Frame", scrollingFrame9)
        frame349.Size = UDim2.new(1, 0, 0, 28)
        frame349.BackgroundTransparency = 1
        local textButton843 = Instance.new("TextButton", frame349)
        textButton843.Size = UDim2.new(0.72, 0, 1, 0)
        textButton843.BackgroundTransparency = 1
        textButton843.Text = "Capitano Clash Warnini"
        textButton843.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton843.TextXAlignment = Enum.TextXAlignment.Left
        textButton843.Font = Enum.Font.Gotham
        textButton843.TextSize = 10
        local textButton844 = Instance.new("TextButton", frame349)
        textButton844.Size = UDim2.new(0, 16, 0, 16)
        textButton844.Position = UDim2.new(1, -20, 0.5, -8)
        textButton844.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton844.Text = ""
        local uICorner844 = Instance.new("UICorner", textButton844)
        uICorner844.CornerRadius = UDim.new(0, 3)
        local frame350 = Instance.new("Frame", scrollingFrame9)
        frame350.Size = UDim2.new(1, 0, 0, 26)
        frame350.BackgroundTransparency = 1
        frame350.Visible = false
        local uIGridLayout114 = Instance.new("UIGridLayout", frame350)
        uIGridLayout114.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout114.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton845 = Instance.new("TextButton", frame350)
        textButton845.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton845.Text = "Nor"
        textButton845.TextSize = 9
        textButton845.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton845.Font = Enum.Font.GothamBold
        local uICorner845 = Instance.new("UICorner", textButton845)
        local conn846 = textButton845.MouseButton1Click:Connect(function()
            textButton845.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton845.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton846 = Instance.new("TextButton", frame350)
        textButton846.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton846.Text = "Gol"
        textButton846.TextSize = 9
        textButton846.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton846.Font = Enum.Font.GothamBold
        local uICorner846 = Instance.new("UICorner", textButton846)
        local conn847 = textButton846.MouseButton1Click:Connect(function()
            textButton846.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton846.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton847 = Instance.new("TextButton", frame350)
        textButton847.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton847.Text = "Dia"
        textButton847.TextSize = 9
        textButton847.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton847.Font = Enum.Font.GothamBold
        local uICorner847 = Instance.new("UICorner", textButton847)
        local conn848 = textButton847.MouseButton1Click:Connect(function()
            textButton847.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton847.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton848 = Instance.new("TextButton", frame350)
        textButton848.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton848.Text = "Rai"
        textButton848.TextSize = 9
        textButton848.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton848.Font = Enum.Font.GothamBold
        local uICorner848 = Instance.new("UICorner", textButton848)
        local conn849 = textButton848.MouseButton1Click:Connect(function()
            textButton848.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton848.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton849 = Instance.new("TextButton", frame350)
        textButton849.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton849.Text = "Lav"
        textButton849.TextSize = 9
        textButton849.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton849.Font = Enum.Font.GothamBold
        local uICorner849 = Instance.new("UICorner", textButton849)
        local conn850 = textButton849.MouseButton1Click:Connect(function()
            textButton849.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton849.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn851 = textButton843.MouseButton1Click:Connect(function()
            frame350.Visible = true
        end)
        local conn852 = textButton844.MouseButton1Click:Connect(function()
            textButton844.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame351 = Instance.new("Frame", scrollingFrame9)
        frame351.Size = UDim2.new(1, 0, 0, 28)
        frame351.BackgroundTransparency = 1
        local textButton850 = Instance.new("TextButton", frame351)
        textButton850.Size = UDim2.new(0.72, 0, 1, 0)
        textButton850.BackgroundTransparency = 1
        textButton850.Text = "Strawberry Elephant"
        textButton850.TextColor3 = Color3.fromRGB(220, 220, 220)
        textButton850.TextXAlignment = Enum.TextXAlignment.Left
        textButton850.Font = Enum.Font.Gotham
        textButton850.TextSize = 10
        local textButton851 = Instance.new("TextButton", frame351)
        textButton851.Size = UDim2.new(0, 16, 0, 16)
        textButton851.Position = UDim2.new(1, -20, 0.5, -8)
        textButton851.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton851.Text = ""
        local uICorner850 = Instance.new("UICorner", textButton851)
        uICorner850.CornerRadius = UDim.new(0, 3)
        local frame352 = Instance.new("Frame", scrollingFrame9)
        frame352.Size = UDim2.new(1, 0, 0, 26)
        frame352.BackgroundTransparency = 1
        frame352.Visible = false
        local uIGridLayout115 = Instance.new("UIGridLayout", frame352)
        uIGridLayout115.CellSize = UDim2.new(0, 46, 0, 20)
        uIGridLayout115.CellPadding = UDim2.new(0, 2, 0, 2)
        local textButton852 = Instance.new("TextButton", frame352)
        textButton852.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton852.Text = "Nor"
        textButton852.TextSize = 9
        textButton852.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton852.Font = Enum.Font.GothamBold
        local uICorner851 = Instance.new("UICorner", textButton852)
        local conn853 = textButton852.MouseButton1Click:Connect(function()
            textButton852.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton852.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton853 = Instance.new("TextButton", frame352)
        textButton853.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton853.Text = "Gol"
        textButton853.TextSize = 9
        textButton853.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton853.Font = Enum.Font.GothamBold
        local uICorner852 = Instance.new("UICorner", textButton853)
        local conn854 = textButton853.MouseButton1Click:Connect(function()
            textButton853.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton853.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton854 = Instance.new("TextButton", frame352)
        textButton854.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton854.Text = "Dia"
        textButton854.TextSize = 9
        textButton854.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton854.Font = Enum.Font.GothamBold
        local uICorner853 = Instance.new("UICorner", textButton854)
        local conn855 = textButton854.MouseButton1Click:Connect(function()
            textButton854.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton854.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton855 = Instance.new("TextButton", frame352)
        textButton855.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton855.Text = "Rai"
        textButton855.TextSize = 9
        textButton855.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton855.Font = Enum.Font.GothamBold
        local uICorner854 = Instance.new("UICorner", textButton855)
        local conn856 = textButton855.MouseButton1Click:Connect(function()
            textButton855.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton855.TextColor3 = Color3.new(1, 1, 1)
        end)
        local textButton856 = Instance.new("TextButton", frame352)
        textButton856.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton856.Text = "Lav"
        textButton856.TextSize = 9
        textButton856.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton856.Font = Enum.Font.GothamBold
        local uICorner855 = Instance.new("UICorner", textButton856)
        local conn857 = textButton856.MouseButton1Click:Connect(function()
            textButton856.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
            textButton856.TextColor3 = Color3.new(1, 1, 1)
        end)
        local conn858 = textButton850.MouseButton1Click:Connect(function()
            frame352.Visible = true
        end)
        local conn859 = textButton851.MouseButton1Click:Connect(function()
            textButton851.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        end)
        local frame353 = Instance.new("Frame", frame7)
        frame353.Size = UDim2.new(0.96, 0, 0, 32)
        frame353.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner856 = Instance.new("UICorner", frame353)
        local uIStroke92 = Instance.new("UIStroke", frame353)
        uIStroke92.Color = Color3.fromRGB(255, 220, 50)
        uIStroke92.Thickness = 1.5
        local textLabel141 = Instance.new("TextLabel", frame353)
        textLabel141.Text = "Infinite Jump"
        textLabel141.Size = UDim2.new(1, -50, 1, 0)
        textLabel141.Position = UDim2.new(0, 10, 0, 0)
        textLabel141.TextColor3 = Color3.new(1, 1, 1)
        textLabel141.BackgroundTransparency = 1
        textLabel141.Font = Enum.Font.GothamBold
        textLabel141.TextXAlignment = Enum.TextXAlignment.Left
        textLabel141.TextSize = 9
        local textButton857 = Instance.new("TextButton", frame353)
        textButton857.Size = UDim2.new(0, 30, 0, 14)
        textButton857.Position = UDim2.new(1, -38, 0.5, -7)
        textButton857.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton857.Text = ""
        local uICorner857 = Instance.new("UICorner", textButton857)
        uICorner857.CornerRadius = UDim.new(1, 0)
        local frame354 = Instance.new("Frame", textButton857)
        frame354.Size = UDim2.new(0, 10, 0, 10)
        frame354.Position = UDim2.new(0, 2, 0.5, -5)
        frame354.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner858 = Instance.new("UICorner", frame354)
        uICorner858.CornerRadius = UDim.new(1, 0)
        local conn860 = textButton857.MouseButton1Click:Connect(function()
            local tween62 = TweenService:Create(frame354, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween62:Play()
            local tween63 = TweenService:Create(textButton857, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween63:Play()
            local frame355 = Instance.new("Frame", screenGui)
            frame355.Size = UDim2.new(0, 220, 0, 60)
            frame355.Position = UDim2.new(1, 20, 1, -80)
            frame355.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner859 = Instance.new("UICorner", frame355)
            local uIStroke93 = Instance.new("UIStroke", frame355)
            uIStroke93.Color = Color3.fromRGB(255, 220, 50)
            uIStroke93.Thickness = 1.5
            local textLabel142 = Instance.new("TextLabel", frame355)
            textLabel142.Size = UDim2.new(1, -16, 0, 20)
            textLabel142.Position = UDim2.new(0, 8, 0, 10)
            textLabel142.Text = "Infinite Jump"
            textLabel142.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel142.Font = Enum.Font.GothamBlack
            textLabel142.TextSize = 13
            textLabel142.BackgroundTransparency = 1
            textLabel142.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel143 = Instance.new("TextLabel", frame355)
            textLabel143.Size = UDim2.new(1, -16, 0, 18)
            textLabel143.Position = UDim2.new(0, 8, 0, 30)
            textLabel143.Text = "Ativado"
            textLabel143.TextColor3 = Color3.new(1, 1, 1)
            textLabel143.Font = Enum.Font.GothamBold
            textLabel143.TextSize = 11
            textLabel143.BackgroundTransparency = 1
            textLabel143.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition117 = frame355:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition118 = frame355:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame355:Destroy()
            end)
        end)
        task.spawn(function()
            local frame356 = Instance.new("Frame", screenGui)
            frame356.Size = UDim2.new(0, 220, 0, 60)
            frame356.Position = UDim2.new(1, 20, 1, -80)
            frame356.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner860 = Instance.new("UICorner", frame356)
            local uIStroke94 = Instance.new("UIStroke", frame356)
            uIStroke94.Color = Color3.fromRGB(255, 220, 50)
            uIStroke94.Thickness = 1.5
            local textLabel144 = Instance.new("TextLabel", frame356)
            textLabel144.Size = UDim2.new(1, -16, 0, 20)
            textLabel144.Position = UDim2.new(0, 8, 0, 10)
            textLabel144.Text = "Infinite Jump"
            textLabel144.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel144.Font = Enum.Font.GothamBlack
            textLabel144.TextSize = 13
            textLabel144.BackgroundTransparency = 1
            textLabel144.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel145 = Instance.new("TextLabel", frame356)
            textLabel145.Size = UDim2.new(1, -16, 0, 18)
            textLabel145.Position = UDim2.new(0, 8, 0, 30)
            textLabel145.Text = "Ativado"
            textLabel145.TextColor3 = Color3.new(1, 1, 1)
            textLabel145.Font = Enum.Font.GothamBold
            textLabel145.TextSize = 11
            textLabel145.BackgroundTransparency = 1
            textLabel145.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition119 = frame356:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition120 = frame356:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame356:Destroy()
            end)
        end)
        local frame357 = Instance.new("Frame", frame7)
        frame357.Size = UDim2.new(0.96, 0, 0, 32)
        frame357.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner861 = Instance.new("UICorner", frame357)
        local uIStroke95 = Instance.new("UIStroke", frame357)
        uIStroke95.Color = Color3.fromRGB(255, 220, 50)
        uIStroke95.Thickness = 1.5
        local textLabel146 = Instance.new("TextLabel", frame357)
        textLabel146.Text = "Enable Speed"
        textLabel146.Size = UDim2.new(1, -50, 1, 0)
        textLabel146.Position = UDim2.new(0, 10, 0, 0)
        textLabel146.TextColor3 = Color3.new(1, 1, 1)
        textLabel146.BackgroundTransparency = 1
        textLabel146.Font = Enum.Font.GothamBold
        textLabel146.TextXAlignment = Enum.TextXAlignment.Left
        textLabel146.TextSize = 9
        local textButton858 = Instance.new("TextButton", frame357)
        textButton858.Size = UDim2.new(0, 30, 0, 14)
        textButton858.Position = UDim2.new(1, -38, 0.5, -7)
        textButton858.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton858.Text = ""
        local uICorner862 = Instance.new("UICorner", textButton858)
        uICorner862.CornerRadius = UDim.new(1, 0)
        local frame358 = Instance.new("Frame", textButton858)
        frame358.Size = UDim2.new(0, 10, 0, 10)
        frame358.Position = UDim2.new(0, 2, 0.5, -5)
        frame358.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner863 = Instance.new("UICorner", frame358)
        uICorner863.CornerRadius = UDim.new(1, 0)
        local conn861 = textButton858.MouseButton1Click:Connect(function()
            local tween64 = TweenService:Create(frame358, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween64:Play()
            local tween65 = TweenService:Create(textButton858, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween65:Play()
            local frame359 = Instance.new("Frame", screenGui)
            frame359.Size = UDim2.new(0, 220, 0, 60)
            frame359.Position = UDim2.new(1, 20, 1, -80)
            frame359.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner864 = Instance.new("UICorner", frame359)
            local uIStroke96 = Instance.new("UIStroke", frame359)
            uIStroke96.Color = Color3.fromRGB(255, 220, 50)
            uIStroke96.Thickness = 1.5
            local textLabel147 = Instance.new("TextLabel", frame359)
            textLabel147.Size = UDim2.new(1, -16, 0, 20)
            textLabel147.Position = UDim2.new(0, 8, 0, 10)
            textLabel147.Text = "Speed"
            textLabel147.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel147.Font = Enum.Font.GothamBlack
            textLabel147.TextSize = 13
            textLabel147.BackgroundTransparency = 1
            textLabel147.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel148 = Instance.new("TextLabel", frame359)
            textLabel148.Size = UDim2.new(1, -16, 0, 18)
            textLabel148.Position = UDim2.new(0, 8, 0, 30)
            textLabel148.Text = "Ativado"
            textLabel148.TextColor3 = Color3.new(1, 1, 1)
            textLabel148.Font = Enum.Font.GothamBold
            textLabel148.TextSize = 11
            textLabel148.BackgroundTransparency = 1
            textLabel148.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition121 = frame359:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition122 = frame359:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame359:Destroy()
            end)
        end)
        task.spawn(function()
            local frame360 = Instance.new("Frame", screenGui)
            frame360.Size = UDim2.new(0, 220, 0, 60)
            frame360.Position = UDim2.new(1, 20, 1, -80)
            frame360.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner865 = Instance.new("UICorner", frame360)
            local uIStroke97 = Instance.new("UIStroke", frame360)
            uIStroke97.Color = Color3.fromRGB(255, 220, 50)
            uIStroke97.Thickness = 1.5
            local textLabel149 = Instance.new("TextLabel", frame360)
            textLabel149.Size = UDim2.new(1, -16, 0, 20)
            textLabel149.Position = UDim2.new(0, 8, 0, 10)
            textLabel149.Text = "Speed"
            textLabel149.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel149.Font = Enum.Font.GothamBlack
            textLabel149.TextSize = 13
            textLabel149.BackgroundTransparency = 1
            textLabel149.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel150 = Instance.new("TextLabel", frame360)
            textLabel150.Size = UDim2.new(1, -16, 0, 18)
            textLabel150.Position = UDim2.new(0, 8, 0, 30)
            textLabel150.Text = "Ativado"
            textLabel150.TextColor3 = Color3.new(1, 1, 1)
            textLabel150.Font = Enum.Font.GothamBold
            textLabel150.TextSize = 11
            textLabel150.BackgroundTransparency = 1
            textLabel150.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition123 = frame360:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition124 = frame360:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame360:Destroy()
            end)
        end)
        local frame361 = Instance.new("Frame", frame7)
        frame361.Size = UDim2.new(0.96, 0, 0, 44)
        frame361.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner866 = Instance.new("UICorner", frame361)
        local uIStroke98 = Instance.new("UIStroke", frame361)
        uIStroke98.Color = Color3.fromRGB(255, 220, 50)
        uIStroke98.Thickness = 1.5
        local textLabel151 = Instance.new("TextLabel", frame361)
        textLabel151.Text = "Speed: 32"
        textLabel151.Size = UDim2.new(1, -10, 0, 20)
        textLabel151.Position = UDim2.new(0, 10, 0, 4)
        textLabel151.TextColor3 = Color3.new(1, 1, 1)
        textLabel151.BackgroundTransparency = 1
        textLabel151.Font = Enum.Font.GothamBold
        textLabel151.TextXAlignment = Enum.TextXAlignment.Left
        textLabel151.TextSize = 9
        local textButton859 = Instance.new("TextButton", frame361)
        textButton859.Size = UDim2.new(1, -20, 0, 6)
        textButton859.Position = UDim2.new(0, 10, 0, 32)
        textButton859.BackgroundColor3 = Color3.fromRGB(35, 35, 35)
        textButton859.Text = ""
        local uICorner867 = Instance.new("UICorner", textButton859)
        uICorner867.CornerRadius = UDim.new(1, 0)
        local frame362 = Instance.new("Frame", textButton859)
        frame362.Size = UDim2.new(0.103679, 0, 1, 0)
        frame362.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        local uICorner868 = Instance.new("UICorner", frame362)
        uICorner868.CornerRadius = UDim.new(1, 0)
        local frame363 = Instance.new("Frame", frame362)
        frame363.Size = UDim2.new(0, 12, 0, 12)
        frame363.Position = UDim2.new(1, -6, 0.5, -6)
        frame363.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner869 = Instance.new("UICorner", frame363)
        uICorner869.CornerRadius = UDim.new(1, 0)
        local conn862 = textButton859.InputBegan:Connect(function(input, gameProcessed)
        end)
        local conn863 = uIS.InputChanged:Connect(function(input, gameProcessed)
        end)
        local conn864 = uIS.InputEnded:Connect(function(input, gameProcessed)
        end)
        task.spawn(function()
        end)
        local frame364 = Instance.new("Frame", frame7)
        frame364.Size = UDim2.new(0.96, 0, 0, 32)
        frame364.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner870 = Instance.new("UICorner", frame364)
        local uIStroke99 = Instance.new("UIStroke", frame364)
        uIStroke99.Color = Color3.fromRGB(255, 220, 50)
        uIStroke99.Thickness = 1.5
        local textLabel152 = Instance.new("TextLabel", frame364)
        textLabel152.Text = "Auto Bat"
        textLabel152.Size = UDim2.new(1, -50, 1, 0)
        textLabel152.Position = UDim2.new(0, 10, 0, 0)
        textLabel152.TextColor3 = Color3.new(1, 1, 1)
        textLabel152.BackgroundTransparency = 1
        textLabel152.Font = Enum.Font.GothamBold
        textLabel152.TextXAlignment = Enum.TextXAlignment.Left
        textLabel152.TextSize = 9
        local textButton860 = Instance.new("TextButton", frame364)
        textButton860.Size = UDim2.new(0, 30, 0, 14)
        textButton860.Position = UDim2.new(1, -38, 0.5, -7)
        textButton860.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton860.Text = ""
        local uICorner871 = Instance.new("UICorner", textButton860)
        uICorner871.CornerRadius = UDim.new(1, 0)
        local frame365 = Instance.new("Frame", textButton860)
        frame365.Size = UDim2.new(0, 10, 0, 10)
        frame365.Position = UDim2.new(0, 2, 0.5, -5)
        frame365.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner872 = Instance.new("UICorner", frame365)
        uICorner872.CornerRadius = UDim.new(1, 0)
        local conn865 = textButton860.MouseButton1Click:Connect(function()
            local tween66 = TweenService:Create(frame365, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween66:Play()
            local tween67 = TweenService:Create(textButton860, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween67:Play()
            local frame366 = Instance.new("Frame", screenGui)
            frame366.Size = UDim2.new(0, 220, 0, 60)
            frame366.Position = UDim2.new(1, 20, 1, -80)
            frame366.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner873 = Instance.new("UICorner", frame366)
            local uIStroke100 = Instance.new("UIStroke", frame366)
            uIStroke100.Color = Color3.fromRGB(255, 220, 50)
            uIStroke100.Thickness = 1.5
            local textLabel153 = Instance.new("TextLabel", frame366)
            textLabel153.Size = UDim2.new(1, -16, 0, 20)
            textLabel153.Position = UDim2.new(0, 8, 0, 10)
            textLabel153.Text = "Auto Bat"
            textLabel153.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel153.Font = Enum.Font.GothamBlack
            textLabel153.TextSize = 13
            textLabel153.BackgroundTransparency = 1
            textLabel153.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel154 = Instance.new("TextLabel", frame366)
            textLabel154.Size = UDim2.new(1, -16, 0, 18)
            textLabel154.Position = UDim2.new(0, 8, 0, 30)
            textLabel154.Text = "Ativado"
            textLabel154.TextColor3 = Color3.new(1, 1, 1)
            textLabel154.Font = Enum.Font.GothamBold
            textLabel154.TextSize = 11
            textLabel154.BackgroundTransparency = 1
            textLabel154.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition125 = frame366:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition126 = frame366:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame366:Destroy()
            end)
        end)
        task.spawn(function()
            local frame367 = Instance.new("Frame", screenGui)
            frame367.Size = UDim2.new(0, 220, 0, 60)
            frame367.Position = UDim2.new(1, 20, 1, -80)
            frame367.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner874 = Instance.new("UICorner", frame367)
            local uIStroke101 = Instance.new("UIStroke", frame367)
            uIStroke101.Color = Color3.fromRGB(255, 220, 50)
            uIStroke101.Thickness = 1.5
            local textLabel155 = Instance.new("TextLabel", frame367)
            textLabel155.Size = UDim2.new(1, -16, 0, 20)
            textLabel155.Position = UDim2.new(0, 8, 0, 10)
            textLabel155.Text = "Auto Bat"
            textLabel155.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel155.Font = Enum.Font.GothamBlack
            textLabel155.TextSize = 13
            textLabel155.BackgroundTransparency = 1
            textLabel155.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel156 = Instance.new("TextLabel", frame367)
            textLabel156.Size = UDim2.new(1, -16, 0, 18)
            textLabel156.Position = UDim2.new(0, 8, 0, 30)
            textLabel156.Text = "Ativado"
            textLabel156.TextColor3 = Color3.new(1, 1, 1)
            textLabel156.Font = Enum.Font.GothamBold
            textLabel156.TextSize = 11
            textLabel156.BackgroundTransparency = 1
            textLabel156.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition127 = frame367:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition128 = frame367:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame367:Destroy()
            end)
        end)
        local frame368 = Instance.new("Frame", frame7)
        frame368.Size = UDim2.new(0.96, 0, 0, 32)
        frame368.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner875 = Instance.new("UICorner", frame368)
        local uIStroke102 = Instance.new("UIStroke", frame368)
        uIStroke102.Color = Color3.fromRGB(255, 220, 50)
        uIStroke102.Thickness = 1.5
        local textLabel157 = Instance.new("TextLabel", frame368)
        textLabel157.Text = "Anti AFK"
        textLabel157.Size = UDim2.new(1, -50, 1, 0)
        textLabel157.Position = UDim2.new(0, 10, 0, 0)
        textLabel157.TextColor3 = Color3.new(1, 1, 1)
        textLabel157.BackgroundTransparency = 1
        textLabel157.Font = Enum.Font.GothamBold
        textLabel157.TextXAlignment = Enum.TextXAlignment.Left
        textLabel157.TextSize = 9
        local textButton861 = Instance.new("TextButton", frame368)
        textButton861.Size = UDim2.new(0, 30, 0, 14)
        textButton861.Position = UDim2.new(1, -38, 0.5, -7)
        textButton861.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton861.Text = ""
        local uICorner876 = Instance.new("UICorner", textButton861)
        uICorner876.CornerRadius = UDim.new(1, 0)
        local frame369 = Instance.new("Frame", textButton861)
        frame369.Size = UDim2.new(0, 10, 0, 10)
        frame369.Position = UDim2.new(0, 2, 0.5, -5)
        frame369.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner877 = Instance.new("UICorner", frame369)
        uICorner877.CornerRadius = UDim.new(1, 0)
        local conn866 = textButton861.MouseButton1Click:Connect(function()
            local tween68 = TweenService:Create(frame369, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween68:Play()
            local tween69 = TweenService:Create(textButton861, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween69:Play()
            local frame370 = Instance.new("Frame", screenGui)
            frame370.Size = UDim2.new(0, 220, 0, 60)
            frame370.Position = UDim2.new(1, 20, 1, -80)
            frame370.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner878 = Instance.new("UICorner", frame370)
            local uIStroke103 = Instance.new("UIStroke", frame370)
            uIStroke103.Color = Color3.fromRGB(255, 220, 50)
            uIStroke103.Thickness = 1.5
            local textLabel158 = Instance.new("TextLabel", frame370)
            textLabel158.Size = UDim2.new(1, -16, 0, 20)
            textLabel158.Position = UDim2.new(0, 8, 0, 10)
            textLabel158.Text = "Anti AFK"
            textLabel158.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel158.Font = Enum.Font.GothamBlack
            textLabel158.TextSize = 13
            textLabel158.BackgroundTransparency = 1
            textLabel158.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel159 = Instance.new("TextLabel", frame370)
            textLabel159.Size = UDim2.new(1, -16, 0, 18)
            textLabel159.Position = UDim2.new(0, 8, 0, 30)
            textLabel159.Text = "Ativado"
            textLabel159.TextColor3 = Color3.new(1, 1, 1)
            textLabel159.Font = Enum.Font.GothamBold
            textLabel159.TextSize = 11
            textLabel159.BackgroundTransparency = 1
            textLabel159.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition129 = frame370:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition130 = frame370:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame370:Destroy()
            end)
        end)
        task.spawn(function()
            local frame371 = Instance.new("Frame", screenGui)
            frame371.Size = UDim2.new(0, 220, 0, 60)
            frame371.Position = UDim2.new(1, 20, 1, -80)
            frame371.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner879 = Instance.new("UICorner", frame371)
            local uIStroke104 = Instance.new("UIStroke", frame371)
            uIStroke104.Color = Color3.fromRGB(255, 220, 50)
            uIStroke104.Thickness = 1.5
            local textLabel160 = Instance.new("TextLabel", frame371)
            textLabel160.Size = UDim2.new(1, -16, 0, 20)
            textLabel160.Position = UDim2.new(0, 8, 0, 10)
            textLabel160.Text = "Anti AFK"
            textLabel160.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel160.Font = Enum.Font.GothamBlack
            textLabel160.TextSize = 13
            textLabel160.BackgroundTransparency = 1
            textLabel160.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel161 = Instance.new("TextLabel", frame371)
            textLabel161.Size = UDim2.new(1, -16, 0, 18)
            textLabel161.Position = UDim2.new(0, 8, 0, 30)
            textLabel161.Text = "Ativado"
            textLabel161.TextColor3 = Color3.new(1, 1, 1)
            textLabel161.Font = Enum.Font.GothamBold
            textLabel161.TextSize = 11
            textLabel161.BackgroundTransparency = 1
            textLabel161.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition131 = frame371:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition132 = frame371:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame371:Destroy()
            end)
        end)
        local frame372 = Instance.new("Frame", frame7)
        frame372.Size = UDim2.new(0.96, 0, 0, 32)
        frame372.BackgroundColor3 = Color3.fromRGB(15, 15, 15)
        local uICorner880 = Instance.new("UICorner", frame372)
        local uIStroke105 = Instance.new("UIStroke", frame372)
        uIStroke105.Color = Color3.fromRGB(255, 220, 50)
        uIStroke105.Thickness = 1.5
        local textLabel162 = Instance.new("TextLabel", frame372)
        textLabel162.Text = "Staff Detector"
        textLabel162.Size = UDim2.new(1, -50, 1, 0)
        textLabel162.Position = UDim2.new(0, 10, 0, 0)
        textLabel162.TextColor3 = Color3.new(1, 1, 1)
        textLabel162.BackgroundTransparency = 1
        textLabel162.Font = Enum.Font.GothamBold
        textLabel162.TextXAlignment = Enum.TextXAlignment.Left
        textLabel162.TextSize = 9
        local textButton862 = Instance.new("TextButton", frame372)
        textButton862.Size = UDim2.new(0, 30, 0, 14)
        textButton862.Position = UDim2.new(1, -38, 0.5, -7)
        textButton862.BackgroundColor3 = Color3.fromRGB(30, 30, 30)
        textButton862.Text = ""
        local uICorner881 = Instance.new("UICorner", textButton862)
        uICorner881.CornerRadius = UDim.new(1, 0)
        local frame373 = Instance.new("Frame", textButton862)
        frame373.Size = UDim2.new(0, 10, 0, 10)
        frame373.Position = UDim2.new(0, 2, 0.5, -5)
        frame373.BackgroundColor3 = Color3.new(1, 1, 1)
        local uICorner882 = Instance.new("UICorner", frame373)
        uICorner882.CornerRadius = UDim.new(1, 0)
        local conn867 = textButton862.MouseButton1Click:Connect(function()
            local tween70 = TweenService:Create(frame373, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                Position = UDim2.new(0, 18, 0.5, -5)
            })
            tween70:Play()
            local tween71 = TweenService:Create(textButton862, TweenInfo.new(0.15, Enum.EasingStyle.Quad), {
                BackgroundColor3 = Color3.fromRGB(255, 220, 50)
            })
            tween71:Play()
            local frame374 = Instance.new("Frame", screenGui)
            frame374.Size = UDim2.new(0, 220, 0, 60)
            frame374.Position = UDim2.new(1, 20, 1, -80)
            frame374.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner883 = Instance.new("UICorner", frame374)
            local uIStroke106 = Instance.new("UIStroke", frame374)
            uIStroke106.Color = Color3.fromRGB(255, 220, 50)
            uIStroke106.Thickness = 1.5
            local textLabel163 = Instance.new("TextLabel", frame374)
            textLabel163.Size = UDim2.new(1, -16, 0, 20)
            textLabel163.Position = UDim2.new(0, 8, 0, 10)
            textLabel163.Text = "Staff Detector"
            textLabel163.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel163.Font = Enum.Font.GothamBlack
            textLabel163.TextSize = 13
            textLabel163.BackgroundTransparency = 1
            textLabel163.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel164 = Instance.new("TextLabel", frame374)
            textLabel164.Size = UDim2.new(1, -16, 0, 18)
            textLabel164.Position = UDim2.new(0, 8, 0, 30)
            textLabel164.Text = "Ativado"
            textLabel164.TextColor3 = Color3.new(1, 1, 1)
            textLabel164.Font = Enum.Font.GothamBold
            textLabel164.TextSize = 11
            textLabel164.BackgroundTransparency = 1
            textLabel164.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition133 = frame374:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition134 = frame374:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame374:Destroy()
            end)
        end)
        task.spawn(function()
            local frame375 = Instance.new("Frame", screenGui)
            frame375.Size = UDim2.new(0, 220, 0, 60)
            frame375.Position = UDim2.new(1, 20, 1, -80)
            frame375.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner884 = Instance.new("UICorner", frame375)
            local uIStroke107 = Instance.new("UIStroke", frame375)
            uIStroke107.Color = Color3.fromRGB(255, 220, 50)
            uIStroke107.Thickness = 1.5
            local textLabel165 = Instance.new("TextLabel", frame375)
            textLabel165.Size = UDim2.new(1, -16, 0, 20)
            textLabel165.Position = UDim2.new(0, 8, 0, 10)
            textLabel165.Text = "Staff Detector"
            textLabel165.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel165.Font = Enum.Font.GothamBlack
            textLabel165.TextSize = 13
            textLabel165.BackgroundTransparency = 1
            textLabel165.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel166 = Instance.new("TextLabel", frame375)
            textLabel166.Size = UDim2.new(1, -16, 0, 18)
            textLabel166.Position = UDim2.new(0, 8, 0, 30)
            textLabel166.Text = "Ativado"
            textLabel166.TextColor3 = Color3.new(1, 1, 1)
            textLabel166.Font = Enum.Font.GothamBold
            textLabel166.TextSize = 11
            textLabel166.BackgroundTransparency = 1
            textLabel166.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition135 = frame375:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition136 = frame375:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame375:Destroy()
            end)
        end)
        local frame376 = Instance.new("Frame", frame8)
        frame376.Size = UDim2.new(0.96, 0, 0, 120)
        frame376.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
        local uICorner885 = Instance.new("UICorner", frame376)
        local uIStroke108 = Instance.new("UIStroke", frame376)
        uIStroke108.Color = Color3.fromRGB(255, 220, 50)
        uIStroke108.Thickness = 2
        local textLabel167 = Instance.new("TextLabel", frame376)
        textLabel167.Size = UDim2.new(1, 0, 0, 30)
        textLabel167.Position = UDim2.new(0, 0, 0, 10)
        textLabel167.Text = "Zenith Hub"
        textLabel167.TextColor3 = Color3.fromRGB(255, 220, 50)
        textLabel167.Font = Enum.Font.GothamBlack
        textLabel167.TextSize = 18
        textLabel167.BackgroundTransparency = 1
        textLabel167.TextXAlignment = Enum.TextXAlignment.Center
        local textLabel168 = Instance.new("TextLabel", frame376)
        textLabel168.Size = UDim2.new(1, 0, 0, 20)
        textLabel168.Position = UDim2.new(0, 0, 0, 42)
        textLabel168.Text = "By: Zenith"
        textLabel168.TextColor3 = Color3.new(1, 1, 1)
        textLabel168.Font = Enum.Font.GothamBold
        textLabel168.TextSize = 12
        textLabel168.BackgroundTransparency = 1
        textLabel168.TextXAlignment = Enum.TextXAlignment.Center
        local textButton863 = Instance.new("TextButton", frame376)
        textButton863.Size = UDim2.new(0.8, 0, 0, 30)
        textButton863.Position = UDim2.new(0.1, 0, 0, 78)
        textButton863.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton863.Text = "Copiar link do Discord"
        textButton863.TextColor3 = Color3.fromRGB(0, 0, 0)
        textButton863.Font = Enum.Font.GothamBold
        textButton863.TextSize = 11
        local uICorner886 = Instance.new("UICorner", textButton863)
        uICorner886.CornerRadius = UDim.new(0, 6)
        local conn868 = textButton863.MouseButton1Click:Connect(function()
            local frame377 = Instance.new("Frame", screenGui)
            frame377.Size = UDim2.new(0, 220, 0, 60)
            frame377.Position = UDim2.new(1, 20, 1, -80)
            frame377.BackgroundColor3 = Color3.fromRGB(10, 10, 10)
            local uICorner887 = Instance.new("UICorner", frame377)
            local uIStroke109 = Instance.new("UIStroke", frame377)
            uIStroke109.Color = Color3.fromRGB(255, 220, 50)
            uIStroke109.Thickness = 1.5
            local textLabel169 = Instance.new("TextLabel", frame377)
            textLabel169.Size = UDim2.new(1, -16, 0, 20)
            textLabel169.Position = UDim2.new(0, 8, 0, 10)
            textLabel169.Text = "Discord"
            textLabel169.TextColor3 = Color3.fromRGB(255, 220, 50)
            textLabel169.Font = Enum.Font.GothamBlack
            textLabel169.TextSize = 13
            textLabel169.BackgroundTransparency = 1
            textLabel169.TextXAlignment = Enum.TextXAlignment.Left
            local textLabel170 = Instance.new("TextLabel", frame377)
            textLabel170.Size = UDim2.new(1, -16, 0, 18)
            textLabel170.Position = UDim2.new(0, 8, 0, 30)
            textLabel170.Text = "Link copiado!"
            textLabel170.TextColor3 = Color3.new(1, 1, 1)
            textLabel170.Font = Enum.Font.GothamBold
            textLabel170.TextSize = 11
            textLabel170.BackgroundTransparency = 1
            textLabel170.TextXAlignment = Enum.TextXAlignment.Left
            local tweenPosition137 = frame377:TweenPosition(UDim2.new(1, -230, 1, -80), "Out", "Back", 0.5, true)
            task.delay(3, function()
                local tweenPosition138 = frame377:TweenPosition(UDim2.new(1, 20, 1, -80), "In", "Back", 0.5, true)
                task.wait(0.5)
                frame377:Destroy()
            end)
        end)
        textButton.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton.TextColor3 = Color3.fromRGB(0, 0, 0)
        scrollingFrame2.Visible = true
        local textButton864 = Instance.new("TextButton", screenGui)
        textButton864.Size = UDim2.new(0, 48, 0, 48)
        textButton864.Position = UDim2.new(0, 20, 0.5, -27)
        textButton864.BackgroundColor3 = Color3.fromRGB(255, 220, 50)
        textButton864.Text = ""
        textButton864.BorderSizePixel = 0
        local uICorner888 = Instance.new("UICorner", textButton864)
        uICorner888.CornerRadius = UDim.new(0, 12)
        local frame378 = Instance.new("Frame", textButton864)
        frame378.Size = UDim2.new(0, 42, 0, 42)
        frame378.Position = UDim2.new(0.5, -21, 0.5, -21)
        frame378.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
        frame378.BorderSizePixel = 0
        local uICorner889 = Instance.new("UICorner", frame378)
        uICorner889.CornerRadius = UDim.new(0, 10)
        local textLabel171 = Instance.new("TextLabel", frame378)
        textLabel171.Size = UDim2.new(1, 0, 1, 0)
        textLabel171.BackgroundTransparency = 1
        textLabel171.Text = "Z"
        textLabel171.TextColor3 = Color3.fromRGB(255, 220, 50)
        textLabel171.TextSize = 22
        textLabel171.Font = Enum.Font.GothamBlack
        local conn869 = textButton864.InputBegan:Connect(function(input, gameProcessed)
        end)
        local conn870 = uIS.InputChanged:Connect(function(input, gameProcessed)
        end)
        local conn871 = uIS.InputEnded:Connect(function(input, gameProcessed)
        end)
        local conn872 = textButton864.MouseButton1Click:Connect(function()
            frame.Visible = true
        end)
        local client = workspace:WaitForChild("Client", 10)
        local path = client:WaitForChild("Path", 5)
        local brainrots = path:WaitForChild("Brainrots", 5)
        local client2 = object:WaitForChild("Client")
        local main = client2:WaitForChild("Main")
        local module = require(main)
        local conn873 = RunService.Heartbeat:Connect(function(deltaTime)
            local humanoidRootPart3 = object:FindFirstChild("HumanoidRootPart")
            for _, child in brainrots:GetChildren() do
            end
        end)
        local conn874 = RunService.Heartbeat:Connect(function(deltaTime)
            local humanoid3 = object:FindFirstChild("Humanoid")
            humanoid3.WalkSpeed = 32
        end)
        local connect = uIS.JumpRequest:Connect(function(value)
            local humanoid4 = object:FindFirstChildOfClass("Humanoid")
            humanoid4:ChangeState(Enum.HumanoidStateType.Jumping)
        end)
        local conn875 = RunService.Heartbeat:Connect(function(deltaTime)
            local getPlayers = game.Players:GetPlayers()
        end)
        local connect2 = localPlayer.Idled:Connect(function(value)
            local captureController = virtualUser:CaptureController()
            local button = virtualUser:ClickButton2(Vector2.new())
        end)
        local connect3 = game.Players.PlayerAdded:Connect(function(value) end)
        -- hookmetamethod: hooked game.__namecall
        task.spawn(function()
            local remotes = ReplicatedStorage:WaitForChild("Remotes", 5)
            local bridge = remotes:WaitForChild("Bridge")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)
            bridge:FireServer("General", "Rebirth", "Use")
            task.wait(0.5)



            rbDrop = scrollingFrame8
            sellDrop = frame44
            specListFrame = frame236
            mutDrop = frame218