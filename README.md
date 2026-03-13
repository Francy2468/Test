# Test

Catmio Lua deobfuscation toolset.

## Settings

`catlogger.lua` has `DUMP_ALL_STRINGS = false` — local variables named `_ref_N` (string constants inlined by the obfuscator into every call site) are **not** re-emitted at the top of the dump output.

`catlogger.lua` has `DUMP_WAD_STRINGS = false` — decoded WAD string-pool entries (local variables named `_wad_N`, e.g. `local _wad_1 = "gsub"`) are **not** emitted at the top of the dump output. Keep this `false`; do **not** set it to `true` or otherwise re-introduce `_wad_N` declarations into the output.

`catlogger.lua` also has `DUMP_DECODED_STRINGS = false` — decoded string pool entries are **not** emitted as inline comments in the output.

All three settings (`DUMP_ALL_STRINGS`, `DUMP_WAD_STRINGS`, and `DUMP_DECODED_STRINGS`) ensure the deobfuscated output is clean and readable, with no raw decoded-string noise.

## Usage

Run with **Lua 5.4** (Lua 5.3 hits a "control structure too long" limit on large scripts):

```bash
lua5.4 catlogger.lua <input.lua> <output.lua>
```
