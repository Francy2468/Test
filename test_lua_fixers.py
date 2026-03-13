"""Unit tests for the Lua syntax-repair helper functions added to cat.py."""

import struct as _struct
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
decompile_luac = cat.decompile_luac
_luac_version   = cat._luac_version
_fmtk           = cat._fmtk
_dec51          = cat._dec51
_dec54          = cat._dec54


# ---------------------------------------------------------------------------
# Helpers for building minimal Lua bytecode fixtures
# ---------------------------------------------------------------------------

_HDR_51 = b'\x1bLua\x51\x00\x01\x04\x08\x04\x08\x00'  # LE, int4, sizet8, instr4, num8


def _enc_str51(s):
    """Lua 5.1 wire-format string (8-byte length prefix, no NUL stored)."""
    if s is None:
        return _struct.pack('<Q', 0)
    b = s.encode('utf-8')
    return _struct.pack('<Q', len(b) + 1) + b   # length includes NUL


def _const_str51(s):
    """Lua 5.1 constant entry of type 4 (string)."""
    b = s.encode('utf-8')
    return bytes([4]) + _struct.pack('<Q', len(b) + 1) + b


def _instr51(op, a=0, b=0, c=0, bx=None):
    if bx is not None:
        return op | (a << 6) | (bx << 14)
    return op | (a << 6) | (c << 14) | (b << 23)


def _make_proto51(src='@test', code=None, consts=b'', n_consts=0,
                  nups=0, npar=0, vararg=1, maxstack=2,
                  ldef=0, lldef=0):
    """Minimal Lua 5.1 proto binary (no line-info, no locals, no upvalue names)."""
    if code is None:
        code = [_instr51(30, 0, b=1)]   # RETURN 0 1
    buf  = _enc_str51(src)
    buf += _struct.pack('<II', ldef, lldef)
    buf += bytes([nups, npar, vararg, maxstack])
    buf += _struct.pack('<I', len(code))
    for ins in code:
        buf += _struct.pack('<I', ins)
    buf += _struct.pack('<I', n_consts) + consts
    buf += _struct.pack('<I', 0) * 4   # protos, lineinfo, locvars, upvalue_names
    return buf



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


# ---------------------------------------------------------------------------
# Tests for the Luac Decompiler (decompile_luac and helpers)
# ---------------------------------------------------------------------------

class TestLuacDecompilerHelpers(unittest.TestCase):
    """Unit tests for _fmtk, _luac_version, _dec51, _dec54."""

    def test_fmtk_nil(self):
        self.assertEqual(_fmtk(None), 'nil')

    def test_fmtk_booleans(self):
        self.assertEqual(_fmtk(True),  'true')
        self.assertEqual(_fmtk(False), 'false')

    def test_fmtk_integer(self):
        self.assertEqual(_fmtk(42), '42')

    def test_fmtk_float(self):
        self.assertEqual(_fmtk(3.14), '3.14')

    def test_fmtk_string_plain(self):
        self.assertEqual(_fmtk('hello'), '"hello"')

    def test_fmtk_string_with_quote(self):
        self.assertEqual(_fmtk('a"b'), '"a\\"b"')

    def test_fmtk_nan(self):
        self.assertEqual(_fmtk(float('nan')), '(0/0)')

    def test_fmtk_inf(self):
        self.assertEqual(_fmtk(float('inf')), '(1/0)')

    def test_fmtk_neg_inf(self):
        self.assertEqual(_fmtk(-float('inf')), '(-1/0)')

    def test_luac_version_51(self):
        self.assertEqual(_luac_version(b'\x1bLua\x51abcd'), '5.1')

    def test_luac_version_53(self):
        self.assertEqual(_luac_version(b'\x1bLua\x53abcd'), '5.3')

    def test_luac_version_54(self):
        self.assertEqual(_luac_version(b'\x1bLua\x54abcd'), '5.4')

    def test_luac_version_unknown_returns_none(self):
        self.assertIsNone(_luac_version(b'\x1bLua\x52abcd'))

    def test_luac_version_garbage_returns_none(self):
        self.assertIsNone(_luac_version(b'not lua'))

    def test_dec51_fields(self):
        # op=1, A=2, C=4, B=3  (Lua 5.1: iABC)
        instr = 1 | (2 << 6) | (4 << 14) | (3 << 23)
        op, a, b, c, bx, sbx = _dec51(instr)
        self.assertEqual(op, 1)
        self.assertEqual(a,  2)
        self.assertEqual(b,  3)
        self.assertEqual(c,  4)

    def test_dec54_fields(self):
        # op=2, A=5, k=1, B=6, C=7  (Lua 5.4: iABC with k bit)
        instr = 2 | (5 << 7) | (1 << 15) | (6 << 16) | (7 << 24)
        op, a, k, b, c, bx, sbx, sj = _dec54(instr)
        self.assertEqual(op, 2)
        self.assertEqual(a,  5)
        self.assertEqual(k,  1)
        self.assertEqual(b,  6)
        self.assertEqual(c,  7)


class TestLuacDecompiler51(unittest.TestCase):
    """Integration tests for decompile_luac with Lua 5.1 bytecode."""

    def _decompile(self, code_instrs, consts_bytes=b'', n_consts=0, src='@test.lua',
                   npar=0, vararg=1, maxstack=2):
        proto = _make_proto51(src=src, code=code_instrs,
                              consts=consts_bytes, n_consts=n_consts,
                              npar=npar, vararg=vararg, maxstack=maxstack)
        return decompile_luac(_HDR_51 + proto)

    def test_header_contains_version(self):
        result = self._decompile([_instr51(30, 0, b=1)])
        self.assertIn('Lua 5.1', result)

    def test_header_contains_source_name(self):
        result = self._decompile([_instr51(30, 0, b=1)], src='@myscript.lua')
        self.assertIn('@myscript.lua', result)

    def test_header_contains_branding(self):
        result = self._decompile([_instr51(30, 0, b=1)])
        self.assertIn('Cat Logger', result)

    def test_return_instruction_present(self):
        result = self._decompile([_instr51(30, 0, b=1)])  # RETURN 0 1
        self.assertIn('RETURN', result)

    def test_reconstruction_return_emitted(self):
        result = self._decompile([_instr51(30, 0, b=1)])
        # Reconstructed section should contain a bare 'return'
        recon = result.split('Reconstructed source', 1)[-1]
        self.assertIn('return', recon)

    def test_getglobal_loadk_call_sequence(self):
        """GETGLOBAL r0=K0, LOADK r1=K1, CALL r0(r1), RETURN."""
        code = [
            _instr51(5,  0, bx=0),       # GETGLOBAL  r0 = K0 ("print")
            _instr51(1,  1, bx=1),       # LOADK      r1 = K1 ("hello world")
            _instr51(28, 0, b=2, c=1),   # CALL       r0(r1)
            _instr51(30, 0, b=1),        # RETURN
        ]
        consts = _const_str51("print") + _const_str51("hello world")
        result = self._decompile(code, consts_bytes=consts, n_consts=2, maxstack=5)
        self.assertIn('"print"',      result)   # constant shown in constant table
        self.assertIn('"hello world"', result)
        # Disassembly comment
        self.assertIn('GETGLOBAL', result)
        self.assertIn('LOADK',     result)
        self.assertIn('CALL',      result)
        # Reconstructed section: assignment targets must NOT include the expression itself
        recon = result.split('Reconstructed source', 1)[-1]
        self.assertIn('r0 = _G["print"]',    recon)
        self.assertIn('r1 = "hello world"',  recon)
        self.assertIn('_G["print"]("hello world")', recon)

    def test_constants_section_shown(self):
        consts = _const_str51("greet")
        result = self._decompile([_instr51(30, 0, b=1)],
                                 consts_bytes=consts, n_consts=1)
        self.assertIn('Constants', result)
        self.assertIn('"greet"', result)

    def test_bad_magic_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            decompile_luac(b'not lua bytecode at all')
        self.assertIn('magic', str(ctx.exception).lower())

    def test_unsupported_version_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            decompile_luac(b'\x1bLua\x52\x00\x00\x00\x00\x00')
        self.assertIn('0x52', str(ctx.exception))

    def test_truncated_bytecode_raises_value_error(self):
        with self.assertRaises(ValueError):
            decompile_luac(_HDR_51 + b'\x00' * 3)   # too short to parse

    def test_output_is_string(self):
        result = self._decompile([_instr51(30, 0, b=1)])
        self.assertIsInstance(result, str)

    def test_output_non_empty(self):
        result = self._decompile([_instr51(30, 0, b=1)])
        self.assertGreater(len(result), 50)


if __name__ == "__main__":
    unittest.main()

