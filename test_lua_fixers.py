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
discord.errors = type("errors", (), {
    "DiscordServerError": Exception,
    "HTTPException": Exception,
})
discord.Message = object

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
_dedup_connections = cat._dedup_connections
_fix_lua_compat = cat._fix_lua_compat


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



if __name__ == "__main__":
    unittest.main()

