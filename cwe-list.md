CWE-22
Example 1
Source:
[mod_http_upload.lua:405](plugins/mod_http_upload.lua#L405)

step 1:
[mod_http_upload.lua:408](plugins/mod_http_upload.lua#L408)

step 2:
[mod_http_upload.lua:391](plugins/mod_http_upload.lua#L391)

Sink:
[mod_http_upload.lua:417](plugins/mod_http_upload.lua#L417)

CWE-78
Example 1
Source:
[mod_muc_log_http.lua:451](plugins/muc_log_http/mod_muc_log_http.lua#L451)

step 1:
[mod_muc_log_http.lua:453](plugins/muc_log_http/mod_muc_log_http.lua#L453)

step 2:
[mod_muc_log_http.lua:454](plugins/muc_log_http/mod_muc_log_http.lua#L454)

step 3:
[mod_muc_log_http.lua:436](plugins/muc_log_http/mod_muc_log_http.lua#L436)

step 4:
[mod_muc_log_http.lua:441](plugins/muc_log_http/mod_muc_log_http.lua#L441)

Sink:
[mod_muc_log_http.lua:439](plugins/muc_log_http/mod_muc_log_http.lua#L439)

CWE-94
Example 1
Source:
[mod_register_api.lua:530](plugins/register_api/mod_register_api.lua#L530)

step 1:
[mod_register_api.lua:322](plugins/register_api/mod_register_api.lua#L322)

step 2:
[mod_register_api.lua:324](plugins/register_api/mod_register_api.lua#L324)

Sink:
[mod_register_api.lua:328](plugins/register_api/mod_register_api.lua#L328)

CWE-1333
Example 1
Source:
[mod_mam_browser.lua:263](plugins/mam_browser/mod_mam_browser.lua#L263)

step 1:
[mod_mam_browser.lua:267](plugins/mam_browser/mod_mam_browser.lua#L267)

step 2:
[mod_mam_browser.lua:108](plugins/mam_browser/mod_mam_browser.lua#L108)

step 3:
[mod_mam_browser.lua:113](plugins/mam_browser/mod_mam_browser.lua#L113)

Sink:
[mod_mam_browser.lua:134](plugins/mam_browser/mod_mam_browser.lua#L134)

CWE-328
Example 1
Source/Sink:
[mod_http_upload_external.lua:124](plugins/http_upload_external/mod_http_upload_external.lua#L124)

Note: engineered host: Added pure-Lua 'md5' rock import next to existing HMAC-SHA256 import, plus md5.sumhexa(secret..message) digest used as an upload-URL slot verification/dedup tag in reachable magic_crypto_dust().

CWE-400
Example 1
Source:
[mod_ping.lua:32](plugins/mod_ping.lua#L32)

step 1:
[mod_ping.lua:33](plugins/mod_ping.lua#L33)

step 2:
[mod_ping.lua:15](plugins/mod_ping.lua#L15)

Sink:
[mod_ping.lua:19](plugins/mod_ping.lua#L19)

Note: engineered host: Added `local sleep = require "socket".sleep;` (LuaSocket already a hard dep) plus a guarded blocking sleep on the XMPP ping IQ handler driven by an attacker-controlled 'delay' stanza attribute in mod_ping.lua; guard rejects negatives but imposes no upper clamp.

CWE-117
Example 1
Source:
[mod_bosh.lua:152](plugins/mod_bosh.lua#L152)

step 1:
[mod_bosh.lua:90](plugins/mod_bosh.lua#L90)

step 2:
[mod_bosh.lua:84](plugins/mod_bosh.lua#L84)

Sink:
[mod_bosh.lua:93](plugins/mod_bosh.lua#L93)

Note: engineered host: Added pure-Lua 'lualogging' rock (require 'logging' + 'logging.console' appender) in mod_bosh; the client's X-Forwarded-For header is logged unsanitized via LuaLogging logger:info (the documented CWE-117 sink).

CWE-89
Example 1
Source:
[mod_usage_report.lua:55](plugins/mod_usage_report.lua#L55)

step 1:
[mod_usage_report.lua:62](plugins/mod_usage_report.lua#L62)

step 2:
[mod_usage_report.lua:63](plugins/mod_usage_report.lua#L63)

step 3:
[mod_usage_report.lua:30](plugins/mod_usage_report.lua#L30)

step 4:
[mod_usage_report.lua:64](plugins/mod_usage_report.lua#L64)

Sink:
[mod_usage_report.lua:68](plugins/mod_usage_report.lua#L68)

Note: engineered host: New reporting module mod_usage_report.lua opening a LuaSQL (luasql.postgres) connection over module:provides('http'); 'account' query param concatenated raw into SQL text passed to conn:execute (documented CWE-89 sink). Decoy strips double quotes only, leaving single-quote breakout open.

CWE-798
Example 1
Source/Sink:
[mod_usage_report.lua:24](plugins/mod_usage_report.lua#L24)

Note: engineered host: In the engineered LuaSQL host mod_usage_report.lua, the DB connection password default was changed in-place from empty to a hardcoded literal ("R3port-DB-2019!") that flows into env:connect argument 3. Reuses the CWE-89 luasql.postgres dependency; no new dependency.

CWE-502
Example 1
Source:
[mod_usage_report.lua:99](plugins/mod_usage_report.lua#L99)

step 1:
[mod_usage_report.lua:100](plugins/mod_usage_report.lua#L100)

step 2:
[mod_usage_report.lua:84](plugins/mod_usage_report.lua#L84)

Sink:
[mod_usage_report.lua:89](plugins/mod_usage_report.lua#L89)

Note: engineered host: Added a POST /usage_report/import route to mod_usage_report.lua restoring a serialized snapshot via the pure-Lua 'serpent' rock; serpent.load(blob,{safe=false}) executes the payload as a Lua chunk (RCE). metronome has no real deserializer library, so 502 needs serpent.

CWE-918
Example 1
Source:
[mod_webhook_relay.lua:50](plugins/mod_webhook_relay.lua#L50)

step 1:
[mod_webhook_relay.lua:51](plugins/mod_webhook_relay.lua#L51)

step 2:
[mod_webhook_relay.lua:52](plugins/mod_webhook_relay.lua#L52)

step 3:
[mod_webhook_relay.lua:65](plugins/mod_webhook_relay.lua#L65)

step 4:
[mod_webhook_relay.lua:66](plugins/mod_webhook_relay.lua#L66)

Sink:
[mod_webhook_relay.lua:41](plugins/mod_webhook_relay.lua#L41)

Note: engineered host: New module mod_webhook_relay.lua posting to an operator webhook via LuaSocket socket.http.request; the URL host is made attacker-controlled from the POST 'target' param. socket.http.request is the documented SSRF sink (metronome's async net.http is not).

CWE-295
Example 1
Source/Sink:
[mod_webhook_relay.lua:85](plugins/mod_webhook_relay.lua#L85)

Note: engineered host: In mod_webhook_relay.lua a POST /secure route builds an outbound TLS channel with LuaSec ssl.newcontext({mode='client',protocol='any'|'sslv23',verify='none'}) + ssl.wrap + dohandshake, disabling certificate verification. LuaSec is a core dependency.

CWE-79
Example 1
Source:
[mod_status_dashboard.lua:30](plugins/mod_status_dashboard.lua#L30)

step 1:
[mod_status_dashboard.lua:31](plugins/mod_status_dashboard.lua#L31)

step 2:
[mod_status_dashboard.lua:24](plugins/mod_status_dashboard.lua#L24)

Sink:
[mod_status_dashboard.lua:36](plugins/mod_status_dashboard.lua#L36)

Note: engineered host: New module mod_status_dashboard.lua running a standalone Pegasus HTTP listener serving an operator status page; query param 'name' reflected unescaped into a text/html body via Pegasus response:write (documented XSS sink). Adds pegasus rock. Decoy strips only '<script'.

CWE-601
Example 1
Source:
[mod_status_dashboard.lua:50](plugins/mod_status_dashboard.lua#L50)

step 1:
[mod_status_dashboard.lua:51](plugins/mod_status_dashboard.lua#L51)

step 2:
[mod_status_dashboard.lua:57](plugins/mod_status_dashboard.lua#L57)

Sink:
[mod_status_dashboard.lua:60](plugins/mod_status_dashboard.lua#L60)

Note: engineered host: In mod_status_dashboard.lua (Pegasus) a GET /status/go route calls response:redirect(location) driven by the 'next' query param, with no same-host/allowlist validation. Reuses the CWE-79 Pegasus dependency; a dispatch() wrapper routes to the redirect handler.

CWE-327
Example 1
Source/Sink:
[mod_token_service.lua:32](plugins/mod_token_service.lua#L32)

Note: engineered host: New module mod_token_service.lua using luaossl openssl.cipher.new('des-cbc') to seal a session ticket minted on every resource-bind. metronome has no symmetric cipher API, so a documented crypto sink (luaossl) was added.

CWE-338
Example 1
Source:
[mod_token_service.lua:44](plugins/mod_token_service.lua#L44)

step 1:
[mod_token_service.lua:46](plugins/mod_token_service.lua#L46)

Sink:
[mod_token_service.lua:56](plugins/mod_token_service.lua#L56)

Note: engineered host: In mod_token_service.lua an HMAC signing key for integration tickets is derived from math.random (weak PRNG) then passed to luaossl openssl.hmac.new(key,'sha256'). Weak source = math.random; sink = key argument of hmac.new. luaossl is the engineered dependency.

CWE-347
Example 1
Source:
[mod_token_service.lua:92](plugins/mod_token_service.lua#L92)

step 1:
[mod_token_service.lua:93](plugins/mod_token_service.lua#L93)

step 2:
[mod_token_service.lua:110](plugins/mod_token_service.lua#L110)

Sink:
[mod_token_service.lua:102](plugins/mod_token_service.lua#L102)

Note: engineered host: In mod_token_service.lua a GET /token_service/whoami handler reads an attacker Bearer JWT and calls luajwt jwt.decode(token, ticket_secret, false) with verify=false, then trusts the claims. luajwt is the documented CWE-347 sink; signature never checked. Adds require 'luajwt' + module:depends('http') below all frozen anchors.

CWE-90
Example 1
Source:
[mod_directory_lookup.lua:50](plugins/mod_directory_lookup.lua#L50)

step 1:
[mod_directory_lookup.lua:57](plugins/mod_directory_lookup.lua#L57)

step 2:
[mod_directory_lookup.lua:26](plugins/mod_directory_lookup.lua#L26)

step 3:
[mod_directory_lookup.lua:31](plugins/mod_directory_lookup.lua#L31)

Sink:
[mod_directory_lookup.lua:34](plugins/mod_directory_lookup.lua#L34)

Note: engineered host: New module mod_directory_lookup.lua doing an LDAP directory (vCard) lookup via LuaLDAP conn:search; the 'uid' query param is concatenated into the RFC4515 filter with only a '*' strip (no ')(' or '|' escaping). metronome has no LDAP client so LuaLDAP is added.

CWE-209
Example 1
Source:
[handler.lua:35](net/http_external/handler.lua#L35)

step 1:
[handler.lua:37](net/http_external/handler.lua#L37)

step 2:
[handler.lua:15](net/http_external/handler.lua#L15)

step 3:
[handler.lua:27](net/http_external/handler.lua#L27)

Sink:
[handler.lua:48](net/http_external/handler.lua#L48)

Note: engineered host: New OpenResty companion sidecar net/http_external/{handler.lua,nginx.conf} (the external upload service mod_http_upload_external talks to). location /ext/upload -> handler.lua; a decode error captured via xpcall(...,debug.traceback) is echoed with ngx.say, leaking internal paths+line numbers. Adds OpenResty ngx + lua-cjson.

CWE-1004
Example 1
Source/Sink:
[handler.lua:56](net/http_external/handler.lua#L56)

Note: engineered host: In the net/http_external sidecar the admin session cookie is created via lua-resty-session session.start{ cookie_http_only = false }, exposing the session cookie to JavaScript. Adds lua-resty-session 4.x; reachable via nginx location /ext/admin.

CWE-614
Example 1
Source/Sink:
[handler.lua:68](net/http_external/handler.lua#L68)

Note: engineered host: In the net/http_external sidecar, a new /ext/share download-portal route creates a distinct sensitive session cookie via lua-resty-session session.start{ cookie_name='ext_share', cookie_secure=false }, so the cookie is sent over plaintext HTTP. Distinct from the frozen CWE-1004 cookie. cookie_same_site left Lax, no __Host- prefix.

CWE-22
Example 2
Source:
[mod_http_upload.lua:469](plugins/mod_http_upload.lua#L469)

step 1:
[mod_http_upload.lua:470](plugins/mod_http_upload.lua#L470)

step 2:
[mod_http_upload.lua:462](plugins/mod_http_upload.lua#L462)

step 3:
[mod_http_upload.lua:30](plugins/mod_http_upload.lua#L30)

Sink:
[mod_http_upload.lua:475](plugins/mod_http_upload.lua#L475)

CWE-22
Example 3
Source:
[mod_mam_browser.lua:284](plugins/mam_browser/mod_mam_browser.lua#L284)

step 1:
[mod_mam_browser.lua:288](plugins/mam_browser/mod_mam_browser.lua#L288)

step 2:
[mod_mam_browser.lua:167](plugins/mam_browser/mod_mam_browser.lua#L167)

step 3:
[mod_mam_browser.lua:169](plugins/mam_browser/mod_mam_browser.lua#L169)

Sink:
[mod_mam_browser.lua:57](plugins/mam_browser/mod_mam_browser.lua#L57)

CWE-22
Example 4
Source:
[mod_register_api.lua:316](plugins/register_api/mod_register_api.lua#L316)

step 1:
[mod_register_api.lua:565](plugins/register_api/mod_register_api.lua#L565)

step 2:
[mod_register_api.lua:551](plugins/register_api/mod_register_api.lua#L551)

step 3:
[mod_register_api.lua:566](plugins/register_api/mod_register_api.lua#L566)

Sink:
[mod_register_api.lua:557](plugins/register_api/mod_register_api.lua#L557)

CWE-22
Example 5
Source:
[mod_admin_web.lua:164](plugins/admin_web/mod_admin_web.lua#L164)

step 1:
[mod_admin_web.lua:166](plugins/admin_web/mod_admin_web.lua#L166)

step 2:
[mod_admin_web.lua:154](plugins/admin_web/mod_admin_web.lua#L154)

Sink:
[mod_admin_web.lua:169](plugins/admin_web/mod_admin_web.lua#L169)

CWE-22
Example 6
Source:
[mod_muc_log_http.lua:463](plugins/muc_log_http/mod_muc_log_http.lua#L463)

step 1:
[mod_muc_log_http.lua:465](plugins/muc_log_http/mod_muc_log_http.lua#L465)

step 2:
[mod_muc_log_http.lua:556](plugins/muc_log_http/mod_muc_log_http.lua#L556)

step 3:
[mod_muc_log_http.lua:558](plugins/muc_log_http/mod_muc_log_http.lua#L558)

Sink:
[mod_muc_log_http.lua:542](plugins/muc_log_http/mod_muc_log_http.lua#L542)

CWE-22
Example 7
Source:
[mod_private.lua:53](plugins/mod_private.lua#L53)

step 1:
[mod_private.lua:73](plugins/mod_private.lua#L73)

step 2:
[mod_private.lua:40](plugins/mod_private.lua#L40)

step 3:
[mod_private.lua:26](plugins/mod_private.lua#L26)

step 4:
[datamanager.lua:231](util/datamanager.lua#L231)

step 5:
[datamanager.lua:182](util/datamanager.lua#L182)

Sink:
[datamanager.lua:196](util/datamanager.lua#L196)

CWE-78
Example 2
Source:
[mod_register_api.lua:656](plugins/register_api/mod_register_api.lua#L656)

step 1:
[mod_register_api.lua:659](plugins/register_api/mod_register_api.lua#L659)

step 2:
[mod_register_api.lua:624](plugins/register_api/mod_register_api.lua#L624)

Sink:
[mod_register_api.lua:619](plugins/register_api/mod_register_api.lua#L619)

CWE-78
Example 3
Source:
[mod_turnadmin.lua:66](plugins/mod_turnadmin.lua#L66)

step 1:
[mod_turnadmin.lua:67](plugins/mod_turnadmin.lua#L67)

step 2:
[mod_turnadmin.lua:52](plugins/mod_turnadmin.lua#L52)

Sink:
[mod_turnadmin.lua:56](plugins/mod_turnadmin.lua#L56)

CWE-78
Example 4
Source:
[mod_server_status.lua:225](plugins/mod_server_status.lua#L225)

step 1:
[mod_server_status.lua:231](plugins/mod_server_status.lua#L231)

step 2:
[auxiliary.lua:41](util/auxiliary.lua#L41)

Sink:
[auxiliary.lua:46](util/auxiliary.lua#L46)

CWE-94
Example 2
Source:
[mod_websocket.lua:190](plugins/mod_websocket.lua#L190)

step 1:
[mod_websocket.lua:191](plugins/mod_websocket.lua#L191)

step 2:
[mod_websocket.lua:138](plugins/mod_websocket.lua#L138)

step 3:
[mod_websocket.lua:134](plugins/mod_websocket.lua#L134)

Sink:
[mod_websocket.lua:144](plugins/mod_websocket.lua#L144)

CWE-94
Example 3
Source:
[mod_admin_telnet.lua:259](plugins/mod_admin_telnet.lua#L259)

step 1:
[mod_admin_telnet.lua:264](plugins/mod_admin_telnet.lua#L264)

step 2:
[mod_admin_telnet.lua:251](plugins/mod_admin_telnet.lua#L251)

step 3:
[mod_admin_telnet.lua:240](plugins/mod_admin_telnet.lua#L240)

Sink:
[mod_admin_telnet.lua:246](plugins/mod_admin_telnet.lua#L246)

CWE-1333
Example 2
Source:
[mod_muc_log_http.lua:585](plugins/muc_log_http/mod_muc_log_http.lua#L585)

step 1:
[mod_muc_log_http.lua:528](plugins/muc_log_http/mod_muc_log_http.lua#L528)

step 2:
[mod_muc_log_http.lua:587](plugins/muc_log_http/mod_muc_log_http.lua#L587)

step 3:
[mod_muc_log_http.lua:574](plugins/muc_log_http/mod_muc_log_http.lua#L574)

Sink:
[mod_muc_log_http.lua:568](plugins/muc_log_http/mod_muc_log_http.lua#L568)

CWE-1333
Example 3
Source:
[mod_vjud.lua:111](plugins/mod_vjud.lua#L111)

step 1:
[mod_vjud.lua:73](plugins/mod_vjud.lua#L73)

step 2:
[mod_vjud.lua:123](plugins/mod_vjud.lua#L123)

Sink:
[mod_vjud.lua:82](plugins/mod_vjud.lua#L82)

CWE-1333
Example 4
Source:
[mod_messagefilter.lua:42](plugins/mod_messagefilter.lua#L42)

step 1:
[mod_messagefilter.lua:43](plugins/mod_messagefilter.lua#L43)

step 2:
[mod_messagefilter.lua:22](plugins/mod_messagefilter.lua#L22)

Sink:
[mod_messagefilter.lua:25](plugins/mod_messagefilter.lua#L25)

CWE-1333
Example 5
Source:
[mam.lib.lua:317](plugins/mam/mam.lib.lua#L317)

step 1:
[mam.lib.lua:325](plugins/mam/mam.lib.lua#L325)

step 2:
[mam.lib.lua:384](plugins/mam/mam.lib.lua#L384)

Sink:
[mam.lib.lua:227](plugins/mam/mam.lib.lua#L227)

CWE-89
Example 2
Source:
[mod_storage_sql.lua:318](plugins/mod_storage_sql.lua#L318)

step 1:
[mod_private.lua:54](plugins/mod_private.lua#L54)

step 2:
[mod_storage_sql.lua:319](plugins/mod_storage_sql.lua#L319)

step 3:
[mod_storage_sql.lua:198](plugins/mod_storage_sql.lua#L198)

step 4:
[mod_storage_sql.lua:199](plugins/mod_storage_sql.lua#L199)

Sink:
[mod_storage_sql.lua:202](plugins/mod_storage_sql.lua#L202)

Note: engineered host: LuaSQL (luasql.sqlite3) grafted into mod_storage_sql.lua for an ad-hoc lookup alongside LuaDBI. Attacker-controlled non-prepped free-text key (tag.name..":"..tag.attr.xmlns from a jabber:iq:private query in mod_private.lua) is threaded via optional 2nd arg private:get -> keyval_store:get(username,lookup) -> audit_recent_entry -> collect_lookup_filters (decoy strips backticks only) -> build_lookup_sql concat -> conn:execute. Single-quote strip removed; breakout via xmlns attribute possible.

CWE-89
Example 3
Source:
[mod_register_api.lua:996](plugins/register_api/mod_register_api.lua#L996)

step 1:
[mod_register_api.lua:980](plugins/register_api/mod_register_api.lua#L980)

step 2:
[mod_register_api.lua:987](plugins/register_api/mod_register_api.lua#L987)

Sink:
[mod_register_api.lua:1009](plugins/register_api/mod_register_api.lua#L1009)

Note: engineered host: Graft LuaSQL conn:execute into register_api for a 'GET /usage' per-account stats endpoint (lazy require luasql.sqlite3; no new file). 'account' query param concatenated into single-quoted SQL literal; decoy strips only ';' and backtick so single-quote breakout is intact.

CWE-502
Example 2
Source:
[mod_register_api.lua:1058](plugins/register_api/mod_register_api.lua#L1058)

step 1:
[mod_register_api.lua:1046](plugins/register_api/mod_register_api.lua#L1046)

step 2:
[mod_register_api.lua:1039](plugins/register_api/mod_register_api.lua#L1039)

Sink:
[mod_register_api.lua:1033](plugins/register_api/mod_register_api.lua#L1033)

Note: engineered host: Grafted pure-Lua 'serpent' rock into register_api for a POST /register_account/import settings-import endpoint. Request body passed to serpent.load(blob,{safe=false}) = RCE. No new file; require added below max anchor.

CWE-918
Example 2
Source:
[mod_http_upload_external.lua:200](plugins/http_upload_external/mod_http_upload_external.lua#L200)

step 1:
[mod_http_upload_external.lua:202](plugins/http_upload_external/mod_http_upload_external.lua#L202)

step 2:
[mod_http_upload_external.lua:134](plugins/http_upload_external/mod_http_upload_external.lua#L134)

step 3:
[mod_http_upload_external.lua:137](plugins/http_upload_external/mod_http_upload_external.lua#L137)

Sink:
[mod_http_upload_external.lua:140](plugins/http_upload_external/mod_http_upload_external.lua#L140)

Note: engineered host: Grafted LuaSocket socket.http into mod_http_upload_external for an upload-completion callback to a client-influenced URL. Added require socket.http/socket.url below the frozen line-124 anchor plus notify_completion_endpoint and a source read in handle_iq; URL host attacker-controlled.

CWE-918
Example 3
Source:
[mod_spim_block.lua:364](plugins/spim_block/mod_spim_block.lua#L364)

step 1:
[mod_spim_block.lua:369](plugins/spim_block/mod_spim_block.lua#L369)

step 2:
[mod_spim_block.lua:175](plugins/spim_block/mod_spim_block.lua#L175)

step 3:
[mod_spim_block.lua:135](plugins/spim_block/mod_spim_block.lua#L135)

Sink:
[mod_spim_block.lua:138](plugins/spim_block/mod_spim_block.lua#L138)

Note: engineered host: Graft LuaSocket socket.http.request into spim_block reCAPTCHA verify; make the verification-endpoint host client-influenced via a POST 'endpoint' field. Adds require socket.http (LuaSocket hard dep). No new file.

CWE-798
Example 2
Source/Sink:
[mod_storage_sql.lua:342](plugins/mod_storage_sql.lua#L342)

Note: engineered host: Graft a LuaSQL env:connect with a hardcoded DB password ("R3p0rt!ng-Repl1ca-9x") into mod_storage_sql as a reporting read-replica, warmed at module init. No new file.

CWE-327
Example 2
Source/Sink:
[mod_extdisco.lua:31](plugins/mod_extdisco.lua#L31)

Note: engineered host: Grafted luaossl openssl.cipher.new('des-cbc') into mod_extdisco.lua to seal the shared TURN secret emitted as a service secret-token attribute. luaossl C-binding rock. No new file. Distinct from example 1 (mod_token_service session tickets).

CWE-295
Example 2
Source/Sink:
[http.lua:192](net/http.lua#L192)

Note: engineered host: Grafted an explicit ssl.newcontext{verify='none'} client context into metronome's core outbound HTTP client net/http.lua (previously built using_https without a verify field). Existing core file, no new file. Distinct from example 1 (mod_webhook_relay). This is the net.http.request client used by register_api/spim_block/http_upload_external.

CWE-347
Example 2
Source:
[mod_auth_external.lua:156](plugins/mod_auth_external.lua#L156)

step 1:
[mod_auth_external.lua:158](plugins/mod_auth_external.lua#L158)

step 2:
[mod_auth_external.lua:134](plugins/mod_auth_external.lua#L134)

step 3:
[mod_auth_external.lua:143](plugins/mod_auth_external.lua#L143)

Sink:
[mod_auth_external.lua:138](plugins/mod_auth_external.lua#L138)

Note: engineered host: Grafted luajwt jwt.decode(token,key,false) into mod_auth_external as a SASL bearer-token shortcut; adds require luajwt + external_auth_token_key option. No new file.

CWE-90
Example 2
Source:
[mod_vjud.lua:139](plugins/mod_vjud.lua#L139)

step 1:
[mod_vjud.lua:141](plugins/mod_vjud.lua#L141)

step 2:
[mod_vjud.lua:194](plugins/mod_vjud.lua#L194)

step 3:
[mod_vjud.lua:188](plugins/mod_vjud.lua#L188)

Sink:
[mod_vjud.lua:198](plugins/mod_vjud.lua#L198)

Note: engineered host: Grafted LuaLDAP conn:search into mod_vjud vCard directory search (LDAP-backed). Added require lualdap + open_simple + conn:search helper chain. No new file. Distinct from example 1 (mod_directory_lookup).

CWE-328
Example 2
Source/Sink:
[mod_auth_internal_hashed.lua:77](plugins/mod_auth_internal_hashed.lua#L77)

Note: engineered host: Grafted pure-Lua 'md5' rock into mod_auth_internal_hashed to derive a legacy password verifier via md5.sumhexa(salt..password) next to the SCRAM key derivation in provider.set_password. Adds require md5 + one digest call. No new file. Distinct from example 1 (http_upload_external slot tag).

CWE-338
Example 2
Source:
[mod_jingle_nodes.lua:39](plugins/mod_jingle_nodes.lua#L39)

step 1:
[mod_jingle_nodes.lua:45](plugins/mod_jingle_nodes.lua#L45)

Sink:
[mod_jingle_nodes.lua:50](plugins/mod_jingle_nodes.lua#L50)

Note: engineered host: Graft luajwt jwt.encode into mod_jingle_nodes where the HMAC signing key for a TURN relay ticket is derived from math.random (weak PRNG). Documented-source shape. No new file. Distinct from example 1 (mod_token_service hmac.new).

CWE-117
Example 2
Source:
[mod_c2s.lua:76](plugins/mod_c2s.lua#L76)

step 1:
[mod_c2s.lua:47](plugins/mod_c2s.lua#L47)

Sink:
[mod_c2s.lua:50](plugins/mod_c2s.lua#L50)

Note: engineered host: Graft LuaLogging into mod_c2s to log a tainted session detail (stream 'from' attr) via logger:warn. No new file. Distinct from example 1 (mod_bosh X-Forwarded-For -> logger:info).

CWE-117
Example 3
Source:
[mod_muc_log_http.lua:605](plugins/muc_log_http/mod_muc_log_http.lua#L605)

step 1:
[mod_muc_log_http.lua:470](plugins/muc_log_http/mod_muc_log_http.lua#L470)

step 2:
[mod_muc_log_http.lua:606](plugins/muc_log_http/mod_muc_log_http.lua#L606)

step 3:
[mod_muc_log_http.lua:607](plugins/muc_log_http/mod_muc_log_http.lua#L607)

Sink:
[mod_muc_log_http.lua:610](plugins/muc_log_http/mod_muc_log_http.lua#L610)

Note: engineered host: Graft LuaLogging (require logging + logging.file) into muc_log_http to log the requested chatroom/path via logger:info. No new file. Distinct from examples 1 (mod_bosh) and 2 (mod_c2s).

CWE-400
Example 2
Source:
[mod_http_upload.lua:497](plugins/mod_http_upload.lua#L497)

step 1:
[mod_http_upload.lua:368](plugins/mod_http_upload.lua#L368)

step 2:
[mod_http_upload.lua:487](plugins/mod_http_upload.lua#L487)

Sink:
[mod_http_upload.lua:491](plugins/mod_http_upload.lua#L491)

Note: engineered host: Graft a blocking socket.sleep (LuaSocket hard dep) into mod_http_upload's upload throttle path honoring a client 'x_retry_after' backoff header. No new file. Distinct from example 1 (mod_ping delay).

CWE-79
Example 2
Source:
[handler.lua:85](net/http_external/handler.lua#L85)

step 1:
[handler.lua:86](net/http_external/handler.lua#L86)

step 2:
[handler.lua:87](net/http_external/handler.lua#L87)

step 3:
[handler.lua:89](net/http_external/handler.lua#L89)

Sink:
[handler.lua:92](net/http_external/handler.lua#L92)

Note: engineered host: OpenResty sidecar net/http_external/handler.lua; new nginx location /ext/status handler echoes the 'host' query param unescaped into a text/html body via ngx.say. Distinct from example 1 (Pegasus response:write).

CWE-79
Example 3
Source:
[handler.lua:108](net/http_external/handler.lua#L108)

step 1:
[handler.lua:105](net/http_external/handler.lua#L105)

step 2:
[handler.lua:109](net/http_external/handler.lua#L109)

step 3:
[handler.lua:112](net/http_external/handler.lua#L112)

Sink:
[handler.lua:115](net/http_external/handler.lua#L115)

Note: engineered host: OpenResty sidecar handler.lua; new nginx location /ext/preview echoes the POST 'note' field unescaped into text/html via ngx.print (distinct sink from ngx.say in examples 1/2). Decoy escapes only &, leaving < > open.

CWE-601
Example 2
Source:
[handler.lua:132](net/http_external/handler.lua#L132)

step 1:
[handler.lua:133](net/http_external/handler.lua#L133)

step 2:
[handler.lua:139](net/http_external/handler.lua#L139)

Sink:
[handler.lua:142](net/http_external/handler.lua#L142)

Note: engineered host: OpenResty sidecar handler.lua; new nginx location /ext/login redirects to the 'return' query arg via ngx.redirect with no host validation. Sink ngx.redirect, distinct from example 1 (Pegasus response:redirect).

CWE-601
Example 3
Source:
[handler.lua:156](net/http_external/handler.lua#L156)

step 1:
[handler.lua:162](net/http_external/handler.lua#L162)

step 2:
[handler.lua:164](net/http_external/handler.lua#L164)

Sink:
[handler.lua:167](net/http_external/handler.lua#L167)

Note: engineered host: OpenResty sidecar handler.lua; new nginx location /ext/go forwards to the 'next' query arg via ngx.header.Location + ngx.exit(302) with no host validation. Distinct mechanism/route from examples 1 (Pegasus resp:redirect) and 2 (ngx.redirect /ext/login).

CWE-209
Example 2
Source:
[handler.lua:195](net/http_external/handler.lua#L195)

step 1:
[handler.lua:196](net/http_external/handler.lua#L196)

step 2:
[handler.lua:182](net/http_external/handler.lua#L182)

step 3:
[handler.lua:204](net/http_external/handler.lua#L204)

Sink:
[handler.lua:207](net/http_external/handler.lua#L207)

Note: engineered host: OpenResty sidecar handler.lua; new nginx location /ext/maintenance where an unknown 'op' misses the dispatch table causing a nil-call runtime error captured by xpcall(...,debug.traceback) and echoed via ngx.say. Distinct route from example 1 (/ext/upload).

CWE-209
Example 3
Source:
[handler.lua:237](net/http_external/handler.lua#L237)

step 1:
[handler.lua:238](net/http_external/handler.lua#L238)

step 2:
[handler.lua:246](net/http_external/handler.lua#L246)

Sink:
[handler.lua:249](net/http_external/handler.lua#L249)

Note: engineered host: OpenResty sidecar handler.lua; new nginx location /ext/error where a POST manifest is decoded and a spool segment file opened under pcall; the raw pcall error (cjson decode failure or io.open error embedding internal path /var/spool/metronome/ext/...) is echoed via ngx.print. Distinct route/mechanism from examples 1 (/ext/upload xpcall) and 2 (/ext/maintenance nil-call).

CWE-1004
Example 2
Source/Sink:
[handler.lua:259](net/http_external/handler.lua#L259)

Note: engineered host: OpenResty sidecar handler.lua; new /ext/reports handler bootstraps a lua-resty-session session with cookie_http_only=false (cookie_name ext_reports). Distinct route/cookie from example 1 (/ext/admin ext_admin). lua-resty-session already required.

CWE-1004
Example 3
Source/Sink:
[handler.lua:272](net/http_external/handler.lua#L272)

Note: engineered host: OpenResty sidecar handler.lua; new /ext/console handler creates a lua-resty-session session via session.new with cookie_http_only=false (cookie_name ext_console). Distinct route/cookie from examples 1 (/ext/admin) and 2 (/ext/reports); session.new varies shape from prior session.start.

CWE-614
Example 2
Source/Sink:
[handler.lua:285](net/http_external/handler.lua#L285)

Note: engineered host: OpenResty sidecar handler.lua; new /ext/signin handler creates a lua-resty-session session with cookie_secure=false (cookie_name ext_signin). Distinct route/cookie from example 1 (/ext/share ext_share). lua-resty-session already required.

CWE-614
Example 3
Source/Sink:
[handler.lua:298](net/http_external/handler.lua#L298)

Note: engineered host: OpenResty sidecar handler.lua; new /ext/gallery handler creates a lua-resty-session session via session.new with cookie_secure=false (cookie_name ext_gallery). Distinct route/cookie from examples 1 (/ext/share) and 2 (/ext/signin); session.new varies shape.

CWE-611
Example 1
Source:
[handler.lua:336](net/http_external/handler.lua#L336)

step 1:
[handler.lua:337](net/http_external/handler.lua#L337)

Sink:
[handler.lua:320](net/http_external/handler.lua#L320)

Note: engineered host: OpenResty sidecar handler.lua; new /ext/import handler parses uploaded XMPP data-form XML with xmlua (LuaJIT libxml2) with external entity resolution ENABLED (NOENT + DTDLOAD). Adds require xmlua. FFI/libxml2 only in the sidecar; metronome PUC-5.1 core cannot host XXE.

CWE-611
Example 2
Source:
[handler.lua:395](net/http_external/handler.lua#L395)

step 1:
[handler.lua:396](net/http_external/handler.lua#L396)

step 2:
[handler.lua:371](net/http_external/handler.lua#L371)

step 3:
[handler.lua:402](net/http_external/handler.lua#L402)

Sink:
[handler.lua:374](net/http_external/handler.lua#L374)

Note: engineered host: OpenResty sidecar handler.lua; new /ext/roster handler parses uploaded XML via LuaJIT-FFI libxml2 xmlReadMemory with options bit.bor(XML_PARSE_NOENT, XML_PARSE_DTDLOAD). Distinct route/sink API from example 1 (xmlua.XML.parse).
