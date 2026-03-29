import lupa
from lupa import LuaRuntime
lua = LuaRuntime()
with open('/workspaces/Test/A7kP9xQ2LmZ4bR1c.lua', 'r') as f:
    code = f.read()
lua.execute(code)
print('Envlogger loaded successfully')
# Simulate dump
dump = lua.eval('_G')
print('Dump generated, length:', len(str(dump)))
print('First 1000 chars of dump:')
print(str(dump)[:1000])