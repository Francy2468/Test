"""Unit tests for the Lua syntax-repair helper functions added to cat.py."""

import sys
import types
import unittest

# ---------------------------------------------------------------------------
# Minimal stubs so we can import cat.py without a live Discord/requests env.
# ---------------------------------------------------------------------------

def _make_stub(name):
    mod = types.ModuleType(name)
    sys.modules[name] = mod
    return mod


for module_name in ("discord", "discord.ext", "discord.ext.commands", "requests", "dotenv"):
    if module_name not in sys.modules:
        _make_stub(module_name)

# discord stubs
discord = sys.modules["discord"]

class _FakeIntents:
    def __init__(self):
        self.message_content = False
    @staticmethod
    def default():
        return _FakeIntents()

discord.Intents = _FakeIntents
discord.File = object
discord.Embed = object
discord.Interaction = object
discord.errors = type("errors", (), {
    "DiscordServerError": Exception,
    "HTTPException": Exception,
})
discord.Message = object

# Stubs for UI components used by the interactive .darklua command.
class _FakeSelectOption:
    def __init__(self, *, label="", value="", description="", emoji=None):
        self.label = label
        self.value = value
        self.description = description
        self.emoji = emoji

discord.SelectOption = _FakeSelectOption

class _FakeButtonStyle:
    primary = 1
    secondary = 2
    success = 3
    danger = 4

discord.ButtonStyle = _FakeButtonStyle

# Minimal discord.ui stub
_fake_ui = types.ModuleType("discord.ui")
sys.modules["discord.ui"] = _fake_ui

class _FakeView:
    def __init__(self, *, timeout=None):
        self.children = []
    def stop(self):
        pass
    @staticmethod
    def select(**kwargs):
        return lambda f: f
    @staticmethod
    def button(**kwargs):
        return lambda f: f

_fake_ui.View = _FakeView
_fake_ui.Select = object
_fake_ui.Button = object
_fake_ui.select = lambda **kwargs: (lambda f: f)
_fake_ui.button = lambda **kwargs: (lambda f: f)

# Attach ui to the discord stub so `discord.ui.View` etc. resolve correctly.
discord.ui = _fake_ui

discord_ext = sys.modules["discord.ext"]
discord_ext_commands = sys.modules["discord.ext.commands"]
_fake_bot = type("Bot", (), {
    "__init__": lambda self, **kw: None,
    "command": lambda self, **kw: (lambda f: f),
    "event": lambda self, f: f,
})
discord_ext_commands.Bot = _fake_bot

dotenv = sys.modules["dotenv"]
dotenv.load_dotenv = lambda: None

requests = sys.modules["requests"]
requests.post = None
requests.get = None

# Now import the module under test
import importlib
cat = importlib.import_module("cat")

_fix_extra_ends = cat._fix_extra_ends
_fix_connect_end_parens = cat._fix_connect_end_parens
_fix_ui_variable_shadowing = cat._fix_ui_variable_shadowing
_fix_lua_do_end = cat._fix_lua_do_end
_fix_for_missing_do = cat._fix_for_missing_do
_fix_local_missing_assign = cat._fix_local_missing_assign
_dedup_connections = cat._dedup_connections
_fix_lua_compat = cat._fix_lua_compat
extract_first_url = cat.extract_first_url
_fold_string_concat = cat._fold_string_concat
_strip_loop_markers = cat._strip_loop_markers


class TestFixExtraEnds(unittest.TestCase):

    def test_no_extra_ends_unchanged(self):
        code = "function foo()\n    return 1\nend"
        self.assertEqual(_fix_extra_ends(code), code)

    def test_single_extra_end_at_top_dropped(self):
        # An 'end' before any opener is extra.
        code = "end\nfunction foo()\n    return 1\nend"
        result = _fix_extra_ends(code)
        self.assertNotIn("end\nfunction", result)
        self.assertIn("function foo()", result)

    def test_extra_end_after_closed_function_dropped(self):
        code = "function foo()\nend\nend"
        result = _fix_extra_ends(code)
        # The first end closes foo; the second is extra.
        lines = [l for l in result.splitlines() if l.strip()]
        end_count = sum(1 for l in lines if l.strip() == "end")
        self.assertEqual(end_count, 1)

    def test_broken_connect_extra_end_dropped(self):
        """The problem-statement example: end\nend) should lose the bare end."""
        code = (
            "local conn = textBox.FocusLost:Connect(function(enterPressed)\n"
            "end\n"
            "end)"
        )
        result = _fix_extra_ends(code)
        # After fixing, only one end-style line should remain.
        end_lines = [l.strip() for l in result.splitlines() if l.strip().startswith("end")]
        self.assertEqual(len(end_lines), 1)

    def test_balanced_code_unchanged(self):
        code = "if true then\n    doSomething()\nend"
        self.assertEqual(_fix_extra_ends(code), code)

    def test_empty_string(self):
        self.assertEqual(_fix_extra_ends(""), "")

    def test_comments_preserved(self):
        code = "-- a comment\nfunction foo()\nend"
        result = _fix_extra_ends(code)
        self.assertIn("-- a comment", result)


# ---------------------------------------------------------------------------
# Tests for _fix_connect_end_parens
# ---------------------------------------------------------------------------

class TestFixConnectEndParens(unittest.TestCase):

    def test_missing_close_paren_added(self):
        code = (
            "button.MouseButton1Click:Connect(function()\n"
            "    doSomething()\n"
            "end"
        )
        result = _fix_connect_end_parens(code)
        self.assertIn("end)", result)
        self.assertNotIn("\nend\n", result + "\n")  # bare end gone

    def test_already_closed_unchanged(self):
        code = (
            "button.MouseButton1Click:Connect(function()\n"
            "    doSomething()\n"
            "end)"
        )
        result = _fix_connect_end_parens(code)
        self.assertEqual(result, code)

    def test_multiple_connect_blocks(self):
        code = (
            "a.Click:Connect(function()\n"
            "    x()\n"
            "end\n"
            "b.Click:Connect(function()\n"
            "    y()\n"
            "end"
        )
        result = _fix_connect_end_parens(code)
        # Both blocks should end with 'end)'
        end_lines = [l.strip() for l in result.splitlines() if l.strip().startswith("end")]
        self.assertTrue(all(l == "end)" for l in end_lines), end_lines)

    def test_no_connect_unchanged(self):
        code = "function foo()\n    return 1\nend"
        self.assertEqual(_fix_connect_end_parens(code), code)

    def test_empty_string(self):
        self.assertEqual(_fix_connect_end_parens(""), "")

    def test_indentation_preserved(self):
        code = (
            "    a.E:Connect(function()\n"
            "        x()\n"
            "    end"
        )
        result = _fix_connect_end_parens(code)
        fixed_line = [l for l in result.splitlines() if "end" in l][0]
        self.assertTrue(fixed_line.startswith("    "), repr(fixed_line))
        self.assertIn("end)", fixed_line)


# ---------------------------------------------------------------------------
# Tests for _fix_ui_variable_shadowing
# ---------------------------------------------------------------------------

class TestFixUiVariableShadowing(unittest.TestCase):

    def test_no_duplicate_unchanged(self):
        code = 'local frame = Instance.new("Frame")\nframe.Size = UDim2.new(1,0,1,0)'
        self.assertEqual(_fix_ui_variable_shadowing(code), code)

    def test_duplicate_gets_suffix(self):
        code = (
            'local frame = Instance.new("Frame")\n'
            'frame.Size = UDim2.new(1,0,1,0)\n'
            'local frame = Instance.new("Frame")\n'
            'frame.Size = UDim2.new(0,100,0,50)'
        )
        result = _fix_ui_variable_shadowing(code)
        self.assertIn("local frame_2", result)

    def test_second_block_uses_new_name(self):
        code = (
            'local btn = Instance.new("TextButton")\n'
            'btn.Text = "First"\n'
            'local btn = Instance.new("TextButton")\n'
            'btn.Text = "Second"'
        )
        result = _fix_ui_variable_shadowing(code)
        lines = result.splitlines()
        # The third line should declare btn_2
        self.assertIn("local btn_2", lines[2])
        # The fourth line should reference btn_2 (the most recent rename)
        self.assertIn("btn_2", lines[3])
        # The second line should still reference the original 'btn'
        self.assertIn("btn", lines[1])
        self.assertNotIn("btn_2", lines[1])

    def test_triple_duplicate(self):
        code = (
            'local x = Instance.new("Frame")\n'
            'local x = Instance.new("Frame")\n'
            'local x = Instance.new("Frame")'
        )
        result = _fix_ui_variable_shadowing(code)
        self.assertIn("local x_2", result)
        self.assertIn("local x_3", result)

    def test_empty_string(self):
        self.assertEqual(_fix_ui_variable_shadowing(""), "")

    def test_non_instance_local_unchanged(self):
        code = "local x = 42\nlocal x = 99"
        result = _fix_ui_variable_shadowing(code)
        # No Instance.new — nothing should change.
        self.assertEqual(result, code)

    def test_inline_references_on_redeclaration_line_renamed(self):
        """Inline property assignments on the same line as the re-declaration are renamed."""
        code = (
            'local B=Instance.new("TextButton")B.Text="First"B.Parent=game\n'
            'local B=Instance.new("TextButton")B.Text="Second"B.Parent=game\n'
        )
        result = _fix_ui_variable_shadowing(code)
        lines = result.splitlines()
        # Second declaration line should use B_2 throughout (not B)
        self.assertIn("local B_2=", lines[1])
        self.assertIn("B_2.Text=", lines[1])
        self.assertIn("B_2.Parent=", lines[1])

    def test_instance_type_string_not_renamed(self):
        """Instance.new('Folder') type string must not be mutated when renaming Folder variable."""
        code = (
            'local Folder=Instance.new("Folder")Folder.Name="First"\n'
            'local Folder=Instance.new("Folder")Folder.Name="Second"\n'
        )
        result = _fix_ui_variable_shadowing(code)
        # Both lines should still reference the original type string
        self.assertIn('Instance.new("Folder")', result)


# ---------------------------------------------------------------------------
# Integration: combined pipeline on the problem-statement example
# ---------------------------------------------------------------------------

class TestCombinedPipeline(unittest.TestCase):

    def test_problem_statement_example(self):
        """The broken snippet from the problem statement is fully repaired."""
        broken = (
            "local conn = textBox.FocusLost:Connect(function(enterPressed, inputObject)\n"
            "end\n"
            "end)"
        )
        # Step 1: fix Connect parens (adds ) to first end → end))
        after_connect = _fix_connect_end_parens(broken)
        # Step 2: remove the now-extra end)
        after_extra = _fix_extra_ends(after_connect)

        # Result should contain exactly one end-style line and it should be end)
        end_lines = [l.strip() for l in after_extra.splitlines() if l.strip().startswith("end")]
        self.assertEqual(len(end_lines), 1, after_extra)
        self.assertEqual(end_lines[0], "end)")

    def test_fix_lua_compat_operators(self):
        self.assertEqual(_fix_lua_compat("if a != b then"), "if a ~= b then")
        self.assertEqual(_fix_lua_compat("if a && b then"), "if a and b then")
        self.assertEqual(_fix_lua_compat("if a || b then"), "if a or b then")
        self.assertIn("nil", _fix_lua_compat("local x = null"))

    def test_fix_lua_compat_else_if_same_line(self):
        """else if on the same line is collapsed to elseif."""
        self.assertEqual(_fix_lua_compat("else if x then"), "elseif x then")
        self.assertEqual(_fix_lua_compat("else if(x) then"), "elseif(x) then")

    def test_fix_lua_compat_end_else_if_preserved(self):
        """'end else if' on the same line must NOT be collapsed to elseif.

        The WeAreDevs VM (and similar obfuscators) write genuine Lua
        nested-if-in-else blocks on a single line as:
          "end else if n<x then"
        where 'end' closes the then-clause and 'else if' opens a new
        if-block inside the else-clause.  Collapsing it to 'elseif'
        removes a required structural 'end', producing:
          'end' expected near 'elseif'
        """
        code = "n=1 end else if n<100 then n=2 end end"
        result = _fix_lua_compat(code)
        self.assertNotIn("elseif", result)
        self.assertIn("else if", result)
        # Verify multiple occurrences are all protected
        code2 = "end else if a then x() end end else if b then y() end end"
        result2 = _fix_lua_compat(code2)
        self.assertNotIn("elseif", result2)
        self.assertEqual(result2.count("else if"), 2)
        # Verify tab-separated and multi-space variants are also protected
        self.assertNotIn("elseif", _fix_lua_compat("end\telse\tif x then"))
        self.assertNotIn("elseif", _fix_lua_compat("end  else  if x then"))

    def test_fix_lua_compat_else_if_multiline_preserved(self):
        """else followed by if on the next line must NOT be collapsed to elseif.

        Collapsing across lines removes the structural 'end' required to close
        the inner if, which causes the Lua error:
        'end' expected near 'elseif' (issue: Obfuscated_Script).
        """
        code = "if a then\n    x()\nelse\n    if b then\n        y()\n    end\nend"
        result = _fix_lua_compat(code)
        # The 'else' and 'if' on separate lines must remain separate keywords.
        self.assertNotIn("elseif", result)
        self.assertIn("else", result)
        self.assertIn("if b then", result)

    def test_dedup_connections_removes_second(self):
        code = (
            "btn.Click:Connect(function()\n"
            "    a()\n"
            "end)\n"
            "btn.Click:Connect(function()\n"
            "    b()\n"
            "end)"
        )
        result = _dedup_connections(code)
        # Second binding should be gone
        self.assertEqual(result.count("btn.Click:Connect"), 1)
        self.assertIn("a()", result)
        self.assertNotIn("b()", result)

    def test_fix_lua_do_end_appends_missing(self):
        code = "function foo()\n    return 1"
        result = _fix_lua_do_end(code)
        self.assertTrue(result.rstrip().endswith("end"))


class TestExtractFirstUrl(unittest.TestCase):
    """extract_first_url strips surrounding quotes so quoted URLs don't cause
    discord.ext.commands.errors.UnexpectedQuoteError when passed to .l / .bf /
    .fix commands whose ``link`` parameter was changed to keyword-only."""

    def test_bare_url_returned(self):
        url = "https://example.com/file.lua"
        self.assertEqual(extract_first_url(url), url)

    def test_double_quoted_url_stripped(self):
        """A URL wrapped in double-quotes is extracted without the quotes."""
        self.assertEqual(
            extract_first_url('"https://example.com/file.lua"'),
            "https://example.com/file.lua",
        )

    def test_url_with_trailing_text(self):
        raw = "https://example.com/file.lua some extra text"
        self.assertEqual(extract_first_url(raw), "https://example.com/file.lua")

    def test_no_url_returns_none(self):
        self.assertIsNone(extract_first_url("no url here"))

    def test_empty_string_returns_none(self):
        self.assertIsNone(extract_first_url(""))


class TestGameClassNameGuardPattern(unittest.TestCase):
    """Regression tests for the game.ClassName=="DataModel" guard pattern.

    Roblox scripts commonly start with:
        repeat wait(.1) until type(game)=="userdata" and game.ClassName=="DataModel"

    Before the catlogger.lua fix, game.ClassName returned "game" (the instance
    name) instead of "DataModel", causing this guard loop to spin until timeout.
    These tests verify that the Python post-processing pipeline handles output
    from scripts that pass through such guards without distortion.
    """

    def test_fold_string_concat_leaves_classname_check_intact(self):
        """_fold_string_concat must not corrupt standalone string literals."""
        code = 'if game.ClassName == "DataModel" then\n    return true\nend'
        self.assertEqual(_fold_string_concat(code), code)

    def test_strip_loop_markers_does_not_strip_normal_comment(self):
        """_strip_loop_markers only removes '-- Detected loops N' lines."""
        code = (
            'repeat task.wait(0.1) until game.ClassName == "DataModel"\n'
            '-- this comment is preserved\n'
            'local x = 1'
        )
        result = _strip_loop_markers(code)
        self.assertIn('-- this comment is preserved', result)
        self.assertIn('repeat task.wait(0.1)', result)

    def test_strip_loop_markers_removes_detected_loops_annotation(self):
        """'-- Detected loops N' lines injected by the dumper are stripped."""
        code = (
            'local x = 1\n'
            '-- Detected loops 500\n'
            'local y = 2'
        )
        result = _strip_loop_markers(code)
        self.assertNotIn('Detected loops', result)
        self.assertIn('local x = 1', result)
        self.assertIn('local y = 2', result)


_is_generic_var_for_type = cat._is_generic_var_for_type
_smart_rename_variables = cat._smart_rename_variables
_ai_rename_variables = cat._ai_rename_variables
_fold_string_concat = cat._fold_string_concat
_collapse_loop_unrolls = cat._collapse_loop_unrolls
_collapse_blank_lines = cat._collapse_blank_lines
_remove_trailing_whitespace = cat._remove_trailing_whitespace


class TestIsGenericVarForType(unittest.TestCase):

    def test_exact_prefix_is_generic(self):
        self.assertTrue(_is_generic_var_for_type("frame", "Frame"))
        self.assertTrue(_is_generic_var_for_type("button", "TextButton"))
        self.assertTrue(_is_generic_var_for_type("label", "TextLabel"))
        self.assertTrue(_is_generic_var_for_type("scroll", "ScrollingFrame"))
        self.assertTrue(_is_generic_var_for_type("gui", "ScreenGui"))

    def test_underscore_suffix_is_generic(self):
        self.assertTrue(_is_generic_var_for_type("frame_", "Frame"))
        self.assertTrue(_is_generic_var_for_type("frame__", "Frame"))
        self.assertTrue(_is_generic_var_for_type("button_", "TextButton"))

    def test_digit_suffix_is_generic(self):
        self.assertTrue(_is_generic_var_for_type("frame2", "Frame"))
        self.assertTrue(_is_generic_var_for_type("frame3", "Frame"))
        self.assertTrue(_is_generic_var_for_type("button2", "TextButton"))

    def test_letter_suffix_is_generic(self):
        self.assertTrue(_is_generic_var_for_type("frame_a", "Frame"))
        self.assertTrue(_is_generic_var_for_type("frame_b", "Frame"))
        self.assertTrue(_is_generic_var_for_type("button_a", "TextButton"))

    def test_type_camel_is_generic(self):
        # textButton / textButton_ / textButton__ as produced by dumpers
        self.assertTrue(_is_generic_var_for_type("textButton", "TextButton"))
        self.assertTrue(_is_generic_var_for_type("textButton_", "TextButton"))
        self.assertTrue(_is_generic_var_for_type("textLabel2", "TextLabel"))

    def test_descriptive_name_is_not_generic(self):
        self.assertFalse(_is_generic_var_for_type("mainFrame", "Frame"))
        self.assertFalse(_is_generic_var_for_type("closeButton", "TextButton"))
        self.assertFalse(_is_generic_var_for_type("searchBox", "TextBox"))
        self.assertFalse(_is_generic_var_for_type("copyAllButton", "TextButton"))

    def test_wrong_type_prefix_is_not_generic(self):
        # "frame" is not generic for type TextButton
        self.assertFalse(_is_generic_var_for_type("frame", "TextButton"))

    def test_short_name_is_always_generic(self):
        # Single- or double-character names are treated as abbreviated auto-generated names.
        self.assertTrue(_is_generic_var_for_type("B", "TextButton"))
        self.assertTrue(_is_generic_var_for_type("F", "Frame"))
        self.assertTrue(_is_generic_var_for_type("Gb", "TextButton"))
        self.assertTrue(_is_generic_var_for_type("x", "Frame"))

    def test_three_char_name_not_auto_generic(self):
        # Three-character names that don't match the type prefix are NOT generic.
        self.assertFalse(_is_generic_var_for_type("Foo", "Frame"))
        self.assertFalse(_is_generic_var_for_type("Bar", "TextButton"))


class TestSmartRenameVariables(unittest.TestCase):

    def test_name_property_used(self):
        code = (
            'local frame = Instance.new("Frame")\n'
            'frame.Name = "ClosePanel"\n'
        )
        result = _smart_rename_variables(code)
        self.assertIn("closePanel", result)
        self.assertNotIn("local frame ", result)

    def test_text_property_used_for_button(self):
        code = (
            'local textButton = Instance.new("TextButton")\n'
            'textButton.Text = "Fire All"\n'
        )
        result = _smart_rename_variables(code)
        self.assertIn("fireAll", result)

    def test_type_prefix_fallback(self):
        code = (
            'local frame = Instance.new("Frame")\n'
            'local frame_ = Instance.new("Frame")\n'
            'local frame__ = Instance.new("Frame")\n'
        )
        result = _smart_rename_variables(code)
        # Three frames → frame, frame2, frame3
        self.assertIn("frame", result)
        self.assertIn("frame2", result)
        self.assertIn("frame3", result)
        # Generic suffixed names should be gone
        self.assertNotIn("frame_ ", result)
        self.assertNotIn("frame__", result)

    def test_descriptive_name_unchanged(self):
        code = (
            'local mainFrame = Instance.new("Frame")\n'
            'mainFrame.Size = UDim2.new(1,0,1,0)\n'
        )
        result = _smart_rename_variables(code)
        self.assertIn("mainFrame", result)

    def test_connection_renamed(self):
        code = (
            'local button = Instance.new("TextButton")\n'
            'button.Name = "Close"\n'
            'local conn = button.MouseButton1Click:Connect(function()\n'
            'end)\n'
        )
        result = _smart_rename_variables(code)
        self.assertNotIn("local conn ", result)
        self.assertIn("Conn", result)

    def test_no_instance_code_unchanged(self):
        code = "local x = 42\nlocal y = x + 1\n"
        self.assertEqual(_smart_rename_variables(code), code)

    def test_name_priority_over_text(self):
        code = (
            'local textButton = Instance.new("TextButton")\n'
            'textButton.Name = "ActionBtn"\n'
            'textButton.Text = "Click Me"\n'
        )
        result = _smart_rename_variables(code)
        # .Name wins over .Text
        self.assertIn("actionBtn", result)
        self.assertNotIn("clickMe", result)

    def test_no_rename_without_key_falls_back(self):
        """_ai_rename_variables falls back to _smart_rename_variables when
        no DeepSeek client is available (key not set in this test env)."""
        code = (
            'local frame = Instance.new("Frame")\n'
            'local frame_ = Instance.new("Frame")\n'
        )
        # In the test environment DEEPSEEK_API_KEY may not be set.
        # The function must still return valid renamed code.
        result = _ai_rename_variables(code)
        self.assertIsInstance(result, str)
        self.assertIn("frame", result)

    def test_inline_name_property_detected(self):
        """Inline .Name assignment on the same line as Instance.new() is used for renaming."""
        code = 'local Gui=Instance.new("ScreenGui")Gui.Name="XGUI"Gui.Parent=game\n'
        result = _smart_rename_variables(code)
        self.assertIn("xGUI", result)
        self.assertNotIn("local Gui=", result)

    def test_inline_text_property_detected(self):
        """Inline .Text assignment on the same line as Instance.new() is used for renaming."""
        code = 'local B=Instance.new("TextButton")B.Text="ClickMe"B.Parent=game\n'
        result = _smart_rename_variables(code)
        self.assertIn("clickMe", result)
        self.assertNotIn("local B=", result)


class TestFixForMissingDo(unittest.TestCase):
    """_fix_for_missing_do inserts 'do' into for-loop headers that lack it."""

    def test_numeric_for_missing_do_inserted(self):
        code = 'for i=1,3 print("Count "..i)end'
        result = _fix_for_missing_do(code)
        self.assertIn("for i=1,3 do", result)

    def test_numeric_for_with_step_missing_do_inserted(self):
        code = 'for i=1,10,2 print(i)end'
        result = _fix_for_missing_do(code)
        self.assertIn("do", result)

    def test_numeric_for_already_has_do_unchanged(self):
        code = 'for i=1,3 do print("Count "..i)end'
        result = _fix_for_missing_do(code)
        # Should remain unchanged — exactly one 'do' between 'for' and body
        self.assertIn("for i=1,3 do", result)
        self.assertEqual(result.count("do"), 1)

    def test_generic_for_missing_do_inserted(self):
        code = 'for k,v in pairs(t) print(k,v)end'
        result = _fix_for_missing_do(code)
        self.assertIn("do", result)
        self.assertIn("pairs(t)", result)

    def test_generic_for_already_has_do_unchanged(self):
        code = 'for k,v in pairs(t) do print(k,v)end'
        result = _fix_for_missing_do(code)
        self.assertEqual(result.count("do"), 1)

    def test_two_for_loops_one_missing_do(self):
        """Only the loop without 'do' is modified."""
        code = 'for i=1,3 do print(i)end for i=1,3 print("nodo")end'
        result = _fix_for_missing_do(code)
        self.assertIn('for i=1,3 do print(i)end', result)
        self.assertIn('for i=1,3 do print("nodo")end', result)

    def test_non_for_code_unchanged(self):
        code = 'local x = 10\nprint(x)\n'
        self.assertEqual(_fix_for_missing_do(code), code)


class TestFixLocalMissingAssign(unittest.TestCase):
    """_fix_local_missing_assign corrects 'local var N' → 'local var = N'."""

    def test_integer_literal_fixed(self):
        code = 'local y 20'
        result = _fix_local_missing_assign(code)
        self.assertEqual(result, 'local y = 20')

    def test_negative_integer_fixed(self):
        code = 'local y -5'
        result = _fix_local_missing_assign(code)
        self.assertEqual(result, 'local y = -5')

    def test_decimal_literal_fixed(self):
        code = 'local pi 3.14'
        result = _fix_local_missing_assign(code)
        self.assertEqual(result, 'local pi = 3.14')

    def test_correct_assignment_unchanged(self):
        code = 'local y = 20'
        self.assertEqual(_fix_local_missing_assign(code), code)

    def test_multi_statement_line_fixed(self):
        code = 'local x=10 local y 20 local z = 30'
        result = _fix_local_missing_assign(code)
        self.assertIn('local y = 20', result)
        self.assertIn('local x=10', result)
        self.assertIn('local z = 30', result)

    def test_string_value_unchanged(self):
        code = 'local s = "hello"'
        self.assertEqual(_fix_local_missing_assign(code), code)


class TestFoldStringConcat(unittest.TestCase):

    def test_adjacent_literals_folded(self):
        code = '"Hello" .. " " .. "World"'
        result = _fold_string_concat(code)
        self.assertIn('"Hello World"', result)
        self.assertNotIn('..', result)

    def test_single_literal_unchanged(self):
        code = '"Hello"'
        self.assertEqual(_fold_string_concat(code), code)

    def test_non_adjacent_unchanged(self):
        code = '"a" .. x .. "b"'
        result = _fold_string_concat(code)
        # x is a variable, not a literal, so no full fold
        self.assertIn('"a"', result)
        self.assertIn('"b"', result)

    def test_empty_string(self):
        self.assertEqual(_fold_string_concat(""), "")


class TestCollapseLoopUnrolls(unittest.TestCase):

    def test_repeated_blocks_collapsed(self):
        # Four identical single-line blocks — first 3 kept, rest collapsed.
        code = (
            'tween1:Play()\n'
            'tween2:Play()\n'
            'tween3:Play()\n'
            'tween4:Play()\n'
            'tween5:Play()\n'
        )
        result = _collapse_loop_unrolls(code)
        self.assertIn('omitted', result.lower())

    def test_unique_lines_unchanged(self):
        code = 'local a = 1\nlocal b = 2\nlocal c = 3\n'
        result = _collapse_loop_unrolls(code)
        self.assertIn('local a = 1', result)
        self.assertIn('local b = 2', result)
        self.assertIn('local c = 3', result)

    def test_empty_string(self):
        self.assertEqual(_collapse_loop_unrolls(""), "")


class TestCollapseBlankLines(unittest.TestCase):

    def test_three_blanks_collapsed_to_two(self):
        code = "a\n\n\n\nb"
        result = _collapse_blank_lines(code)
        self.assertNotIn("\n\n\n", result)
        self.assertIn("a", result)
        self.assertIn("b", result)

    def test_two_blanks_collapsed_to_one(self):
        # "a\n\n\nb" has three newlines (two blank lines) → collapsed to two newlines (one blank line).
        code = "a\n\n\nb"
        result = _collapse_blank_lines(code)
        self.assertNotIn("\n\n\n", result)

    def test_no_extra_blanks_unchanged(self):
        code = "a\n\nb"
        self.assertEqual(_collapse_blank_lines(code), code)

    def test_empty_string(self):
        self.assertEqual(_collapse_blank_lines(""), "")


class TestRemoveTrailingWhitespace(unittest.TestCase):

    def test_trailing_spaces_stripped(self):
        code = "local x = 1   \nlocal y = 2  "
        result = _remove_trailing_whitespace(code)
        for line in result.splitlines():
            self.assertEqual(line, line.rstrip())

    def test_no_trailing_whitespace_unchanged(self):
        code = "local x = 1\nlocal y = 2"
        self.assertEqual(_remove_trailing_whitespace(code), code)

    def test_empty_string(self):
        self.assertEqual(_remove_trailing_whitespace(""), "")


class TestFixPipelineIntegration(unittest.TestCase):
    """Integration tests for improvements added to the .fix pipeline:
    smart renaming, string folding, loop collapse, and formatting cleanup."""

    def test_smart_rename_replaces_generic_frame(self):
        """_smart_rename_variables renames a generic 'frame' var using .Name."""
        code = (
            'local frame = Instance.new("Frame")\n'
            'frame.Name = "Dashboard"\n'
        )
        result = _smart_rename_variables(code)
        self.assertIn("dashboard", result)
        self.assertNotIn("local frame ", result)

    def test_smart_rename_uses_text_for_button(self):
        """_smart_rename_variables renames a generic button using .Text."""
        code = (
            'local button = Instance.new("TextButton")\n'
            'button.Text = "Submit"\n'
        )
        result = _smart_rename_variables(code)
        self.assertIn("submit", result)

    def test_fold_and_collapse_pipeline(self):
        """_fold_string_concat and _collapse_loop_unrolls work sequentially."""
        code = (
            'local msg = "Hello" .. " World"\n'
            'item1:Do()\n'
            'item2:Do()\n'
            'item3:Do()\n'
            'item4:Do()\n'
        )
        code = _fold_string_concat(code)
        self.assertIn('"Hello World"', code)
        code = _collapse_loop_unrolls(code)
        self.assertIn('omitted', code.lower())

    def test_formatting_cleanup(self):
        """_collapse_blank_lines and _remove_trailing_whitespace work together."""
        code = "local x = 1   \n\n\n\nlocal y = 2  "
        code = _collapse_blank_lines(code)
        code = _remove_trailing_whitespace(code)
        self.assertNotIn("\n\n\n", code)
        for line in code.splitlines():
            self.assertEqual(line, line.rstrip())


_run_heuristic_fix_pipeline = cat._run_heuristic_fix_pipeline
_ai_fix_lua = cat._ai_fix_lua


class TestFixLuaCompatExclamationMark(unittest.TestCase):
    """The '!' → 'not' replacement must not corrupt string literals."""

    def test_logical_not_identifier_replaced(self):
        self.assertEqual(_fix_lua_compat("if !isEnabled then"), "if not isEnabled then")

    def test_logical_not_paren_replaced(self):
        self.assertEqual(_fix_lua_compat("if !(a and b) then"), "if not (a and b) then")

    def test_exclamation_in_string_preserved(self):
        """'!' inside a string literal must NOT become 'not'."""
        code = 'print("hello!")'
        self.assertEqual(_fix_lua_compat(code), code)

    def test_exclamation_at_end_of_string_preserved(self):
        code = 'local msg = "done!"'
        self.assertEqual(_fix_lua_compat(code), code)

    def test_exclamation_punctuation_only_preserved(self):
        """Bare '!' not followed by identifier/paren must not be replaced."""
        code = 'local x = "!" .. "?"'
        self.assertEqual(_fix_lua_compat(code), code)

    def test_mixed_not_and_string(self):
        """Only the operator '!' is replaced, string '!' is left alone."""
        code = 'if !isEnabled then print("ok!") end'
        result = _fix_lua_compat(code)
        self.assertIn("not isEnabled", result)
        self.assertIn('"ok!"', result)


class TestRunHeuristicFixPipeline(unittest.TestCase):
    """_run_heuristic_fix_pipeline is a module-level function available as fallback."""

    def test_returns_string(self):
        code = 'local frame = Instance.new("Frame")\nframe.Name = "Panel"\n'
        result = _run_heuristic_fix_pipeline(code)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_renames_instance_variable(self):
        code = 'local frame = Instance.new("Frame")\nframe.Name = "Dashboard"\n'
        result = _run_heuristic_fix_pipeline(code)
        self.assertIn("dashboard", result)

    def test_fixes_lua_compat(self):
        code = "if a != b then\n    return nil\nend\n"
        result = _run_heuristic_fix_pipeline(code)
        self.assertIn("~=", result)
        self.assertNotIn("!=", result)

    def test_empty_string(self):
        self.assertEqual(_run_heuristic_fix_pipeline(""), "")


class TestAiFixLuaFallback(unittest.TestCase):
    """_ai_fix_lua falls back to heuristic pipeline when no DeepSeek key is set."""

    def test_returns_string_without_key(self):
        """Without DEEPSEEK_API_KEY the function must still return valid code."""
        code = 'local frame = Instance.new("Frame")\nframe.Name = "Panel"\n'
        result = _ai_fix_lua(code)
        self.assertIsInstance(result, str)
        self.assertTrue(len(result) > 0)

    def test_fallback_renames_instance(self):
        code = 'local frame = Instance.new("Frame")\nframe.Name = "Backdrop"\n'
        result = _ai_fix_lua(code)
        # Should at least apply heuristic renaming
        self.assertIn("backdrop", result)

    def test_fallback_fixes_compat(self):
        code = "if a != b then\n    return nil\nend\n"
        result = _ai_fix_lua(code)
        self.assertNotIn("!=", result)
        self.assertIn("~=", result)


if __name__ == "__main__":
    unittest.main()

