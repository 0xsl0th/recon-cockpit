"""Execute the pinned NSE shim with native Lua, without loading Nmap or sockets."""

import ctypes
import ctypes.util
import os
import sys

import pytest

from recon_cockpit.secure_agent.network_tools_runtime import NMAP_SERVICE_NSE_SHIM


pytestmark = pytest.mark.integration


@pytest.fixture
def lua():
    if os.environ.get("RECON_LINUX_INTEGRATION") != "1":
        pytest.skip("set RECON_LINUX_INTEGRATION=1 for the native NSE shim contract")
    assert sys.platform == "linux"
    path = ctypes.util.find_library("lua5.4")
    assert path is not None, "the reviewed Nmap profile requires its distribution Lua 5.4 library"
    library = ctypes.CDLL(path)
    library.luaL_newstate.argtypes = []
    library.luaL_newstate.restype = ctypes.c_void_p
    library.luaL_openlibs.argtypes = [ctypes.c_void_p]
    library.luaL_openlibs.restype = None
    library.luaL_loadbufferx.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                       ctypes.c_char_p, ctypes.c_char_p]
    library.luaL_loadbufferx.restype = ctypes.c_int
    library.lua_pcallk.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                 ctypes.c_ssize_t, ctypes.c_void_p]
    library.lua_pcallk.restype = ctypes.c_int
    library.lua_tolstring.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    library.lua_tolstring.restype = ctypes.c_char_p
    library.lua_close.argtypes = [ctypes.c_void_p]
    library.lua_close.restype = None
    return library


@pytest.mark.parametrize("mutation,allowed", [
    ("", True),
    ("engine.scriptargs = nil", False),
    ("engine.scriptargs = 'http.useragent=unreviewed'", False),
    ("engine.scriptargsfile = '/tmp/args'", False),
    ("engine.scriptversion = false", False),
    ("engine.default = true", False),
    ("engine.scriptupdatedb = true", False),
    ("engine.scripthelp = true", False),
    ("rules[1] = 'version'", False),
    ("phase = 'NSE_PRE_SCAN'", False),
    ("phase = 'NSE_POST_SCAN'", False),
    ("hosts[2] = {ip = '127.0.0.2'}", False),
])
def test_nse_shim_accepts_only_native_empty_arguments_and_version_only_dispatch(lua, mutation, allowed):
    # NmapOps::ValidateOptions turns absent CLI script arguments into "".
    # Run the actual compiled shim, so nil-only and truthiness checks both fail
    # this contract; populated args, script selections and broader phases fail.
    source = (b"local engine = {scriptversion=true, default=false, scriptupdatedb=false, scripthelp=false, scriptargs=''}\n"
              b"local rules, hosts, phase = {}, {{ip='127.0.0.1'}}, 'NSE_SCAN'\n"
              + mutation.encode("ascii") + b"\n"
              b"local shim = assert(load([=[" + NMAP_SERVICE_NSE_SHIM + b"]=]))\n"
              b"local main = shim(engine, rules)\n"
              b"assert(type(main) == 'function')\n"
              b"main(hosts, phase)\n")
    state = lua.luaL_newstate()
    assert state
    try:
        lua.luaL_openlibs(state)
        assert lua.luaL_loadbufferx(state, source, len(source), b"@nse-contract", b"t") == 0
        status = lua.lua_pcallk(state, 0, 0, 0, 0, None)
        if allowed:
            assert status == 0, lua.lua_tolstring(state, -1, None)
        else:
            assert status != 0
            assert b"assertion failed" in lua.lua_tolstring(state, -1, None)
    finally:
        lua.lua_close(state)
