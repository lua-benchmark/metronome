# metronome - Lua SAST benchmark snapshot

Frozen snapshot of an upstream project, republished for Lua static-analysis benchmarking.
**This is not a fork for contribution.** File issues and pull requests upstream.

## Provenance

| | |
|---|---|
| Upstream | <https://github.com/maranda/metronome> |
| Branch | `master` |
| Commit | `3b791f201a6a601d39ae9215f40497aafa3bcf01` |
| Snapshot taken | 2026-09-18 |
| Upstream stars at snapshot | 175 |
| Deliberately vulnerable (GOAT) | No |

The tree is byte-identical to upstream at that commit, with two exceptions: the `.git` directory
was removed and replaced by a single `initial version` commit, and this `BENCHMARK.md` was added.
No upstream file was modified, so every line number still matches upstream.

## Corpus metadata

**Project type:** XMPP server (Prosody fork) with BOSH/WebSocket/HTTP modules and s2s

**Lua version:** 5.1 (5.2-compatible)

**Frameworks and libraries:** luaexpat (lxp), LuaSocket (socket, socket.url), LuaSec (ssl), LuaFileSystem (lfs), luaevent.core, LuaDBI (DBI, mod_storage_sql), Prosody-derived core (util.stanza, net.http.server, core.modulemanager)

**Size class:** Medium (~34228 LOC)

## Taint sources of interest

XMPP stanzas via XML stream parse (lxp/luaexpat SAX in util/xmppstream.lua, StartDoctypeDecl/Comment/PI restricted handlers - the XXE surface; module:hook stanza events), HTTP request body (request.body in mod_bosh, mod_http_upload, mod_register_api), HTTP headers and cookies (request.headers.*, sec_websocket_key), HTTP query (request.url.query, net.http.urldecode), Raw socket / s2s stream data (net.server onincoming), Local file read (util.datamanager envloadfile, lfs.dir)
