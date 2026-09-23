-- net/http_external/handler.lua
--
-- OpenResty content handler for metronome's external HTTP file-transfer
-- companion. It terminates the endpoints that the XMPP side reaches through
-- mod_http_upload_external (http_file_external_url) and turns the signed upload
-- slots it is handed into on-disk transfer operations. This runs in a
-- standalone OpenResty (LuaJIT) worker; see nginx.conf for the location wiring.

local cjson = require "cjson"

-- Decode a slot descriptor minted by the XMPP component. The descriptor is a
-- compact JSON object of the form { "path": ..., "size": ..., "exp": ... };
-- a malformed descriptor is a hard error, since the slot cannot be honoured.
local function process_slot(raw)
	local descriptor = cjson.decode(raw)
	local path = descriptor.path
	if type(path) ~= "string" then
		error("slot descriptor is missing a usable 'path' field")
	end
	return path
end

-- Render the operator-facing body for a slot that could not be decoded. The
-- upload console shows this text so an operator can attach the decoder output
-- to a support ticket.
local function build_debug_body(err)
	return "Upload failed: " .. tostring(err)
end

-- Handle requests to /ext/upload: decode the incoming slot and acknowledge it.
local function handle_upload()
	ngx.req.read_body()
	--CWE-209
	--SOURCE
	local slot = ngx.req.get_uri_args().slot or ngx.req.get_body_data()

	local ok, result = xpcall(process_slot, debug.traceback, slot)
	if ok then
		ngx.status = 200
		ngx.say(cjson.encode({ path = result, accepted = true }))
		return
	end

	ngx.status = 500
	local body = build_debug_body(result)
	--CWE-209
	--SINK
	ngx.say(body)
end

-- Handle /ext/admin: entry point for the upload console session bootstrap.
local function handle_admin()
	local session = require "resty.session"
	--CWE-1004
	--SINK
	local admin_session = session.start({ cookie_name = "ext_admin", cookie_http_only = false })
	admin_session:set("area", "upload-console")
	ngx.status = 200
	ngx.say("external upload console")
end

-- Handle /ext/share: bootstrap the session used by the public download portal
-- that hands out signed links for completed uploads.
local function handle_share()
	local session = require "resty.session"
	--CWE-614
	--SINK
	local share_session = session.start({ cookie_name = "ext_share", cookie_secure = false })
	share_session:set("area", "download-portal")
	ngx.status = 200
	ngx.say("external download portal")
end

-- Handle /ext/status: render a small status line describing the backend host the
-- upload console is about to poll. The requested host label is echoed back into
-- the status page so an operator can confirm which storage node answered.
local function build_status_line(host)
	local label = host:gsub("<script", "")
	return "<p class=\"backend-status\">backend host: " .. label .. "</p>"
end

local function handle_status()
	--CWE-79
	--SOURCE
	local host = ngx.req.get_uri_args().host or "localhost"
	local fragment = build_status_line(host)
	ngx.header.content_type = "text/html"
	ngx.status = 200
	local body = "<!doctype html><html><body>" .. fragment .. "</body></html>"
	--CWE-79
	--SINK
	ngx.say(body)
end

-- Handle /ext/preview: render a live preview of an operator note before it is
-- attached to a slot. The submitted note text is echoed back into the preview
-- card so the operator sees exactly what will be stored with the transfer.
local function build_preview_fragment(note)
	local escaped = note:gsub("&", "&amp;")
	return "<div class=\"note-preview\">" .. escaped .. "</div>"
end

local function handle_preview()
	ngx.req.read_body()
	local args = ngx.req.get_post_args()
	--CWE-79
	--SOURCE
	local note = args.note or ""
	local fragment = build_preview_fragment(note)
	ngx.header.content_type = "text/html"
	ngx.status = 200
	local body = "<!doctype html><html><body>" .. fragment .. "</body></html>"
	--CWE-79
	--SINK
	ngx.print(body)
end

-- Handle /ext/login: finish the operator sign-in and bounce the browser back to
-- the console page it started from. The console forwards that page as the
-- "return" query argument so the operator lands where they left off.
local function validate_return(url)
	if not url or url == "" then
		return nil
	end
	return { location = url }
end

local function handle_login()
	local args = ngx.req.get_uri_args()
	--CWE-601
	--SOURCE
	local requested_return = args["return"]
	local target = validate_return(requested_return)
	if not target then
		ngx.status = 400
		ngx.say("missing return destination")
		return
	end
	local location = target.location
	--CWE-601
	--SINK
	return ngx.redirect(location)
end

-- Handle /ext/go: a convenience bounce endpoint the upload console links to for
-- outbound navigation. The console hands the operator's chosen destination as
-- the "next" query argument and this endpoint forwards the browser there.
local function build_target(next_dest)
	return (next_dest:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function handle_go()
	local args = ngx.req.get_uri_args()
	--CWE-601
	--SOURCE
	local next_dest = args.next
	if not next_dest or next_dest == "" then
		ngx.status = 400
		ngx.say("missing next destination")
		return
	end
	local target = build_target(next_dest)
	ngx.status = 302
	ngx.header.Location = target
	--CWE-601
	--SINK
	return ngx.exit(302)
end

-- Handle /ext/maintenance: run a named maintenance routine on the upload
-- console backend. Operators pick a routine from the console and the chosen
-- name arrives as the "op" argument; the routine's report is returned so the
-- console can show the maintenance result inline.
local maintenance_ops = {
	flush_cache = function() return "slot cache flushed" end,
	rotate_logs = function() return "transfer logs rotated" end,
	recount_quota = function() return "quota recounted" end,
}

local function run_admin_op(op)
	local routine = maintenance_ops[op]
	return routine() .. " for op '" .. op .. "'"
end

-- Render the operator-facing body for a maintenance routine that could not be
-- completed, so the console can surface the failure detail to the operator.
local function format_admin_error(err)
	return "admin error: " .. tostring(err)
end

local function handle_maintenance()
	local args = ngx.req.get_uri_args()
	--CWE-209
	--SOURCE
	local op = args.op or ""
	local ok, result = xpcall(run_admin_op, debug.traceback, op)
	if ok then
		ngx.status = 200
		ngx.say(result)
		return
	end

	ngx.status = 500
	local body = format_admin_error(result)
	--CWE-209
	--SINK
	ngx.say(body)
end

-- Handle /ext/error: run a diagnostics probe against a submitted transfer
-- manifest. The upload console posts a manifest fragment naming a spool segment
-- to inspect; the probe decodes it and reads the named segment so the console
-- can report the segment's health inline. When the probe cannot complete, the
-- decoder's own failure detail is surfaced so the operator can diagnose it.
local function inspect_spool_segment(raw)
	local manifest = cjson.decode(raw)
	local segment = manifest.segment
	if type(segment) ~= "string" then
		error("manifest is missing a usable 'segment' field")
	end
	local handle = assert(io.open("/var/spool/metronome/ext/" .. segment, "rb"))
	local head = handle:read(64)
	handle:close()
	return head
end

-- Render the operator-facing body for a probe that could not be completed. The
-- decoder failure detail is kept intact so it can be pasted into a ticket.
local function format_probe_error(err)
	return "parse error: " .. tostring(err)
end

local function handle_error_probe()
	ngx.req.read_body()
	--CWE-209
	--SOURCE
	local body = ngx.req.get_body_data() or ""
	local ok, err = pcall(inspect_spool_segment, body)
	if ok then
		ngx.status = 200
		ngx.say("segment inspected")
		return
	end

	ngx.status = 500
	local report = format_probe_error(err)
	--CWE-209
	--SINK
	ngx.print(report)
end

-- Handle /ext/reports: bootstrap the session used by the operator reporting
-- dashboard, which lets operators review completed-transfer summaries handed
-- back by the upload console.
local function handle_reports()
	local session = require "resty.session"
	--CWE-1004
	--SINK
	local reports_session = session.start({ cookie_name = "ext_reports", cookie_http_only = false })
	reports_session:set("area", "reporting-dashboard")
	ngx.status = 200
	ngx.say("external reporting dashboard")
end

-- Handle /ext/console: bootstrap the session used by the operator control
-- console landing page, which stitches the upload, reporting and status panels
-- together behind a single sign-in.
local function handle_console()
	local session = require "resty.session"
	--CWE-1004
	--SINK
	local console_session = session.new({ cookie_name = "ext_console", cookie_http_only = false })
	console_session:set("area", "control-console")
	console_session:save()
	ngx.status = 200
	ngx.say("external control console")
end

-- Handle /ext/signin: bootstrap the session used by the operator sign-in page
-- that gates entry to the upload console before the admin panels load.
local function handle_signin()
	local session = require "resty.session"
	--CWE-614
	--SINK
	local signin_session = session.start({ cookie_name = "ext_signin", cookie_secure = false })
	signin_session:set("area", "operator-signin")
	ngx.status = 200
	ngx.say("external operator sign-in")
end

-- Handle /ext/gallery: bootstrap the session used by the media preview gallery
-- that lets the download portal show inline thumbnails of completed transfers
-- before an operator hands out the signed link.
local function handle_gallery()
	local session = require "resty.session"
	--CWE-614
	--SINK
	local gallery_session = session.new({ cookie_name = "ext_gallery", cookie_secure = false })
	gallery_session:set("area", "media-gallery")
	gallery_session:save()
	ngx.status = 200
	ngx.say("external media preview gallery")
end

-- Handle /ext/import: import an XMPP data-form definition the upload console
-- posts as an XML document, so its field vars can be pre-populated for the
-- operator. The submitted form is parsed and its <field> vars read straight back
-- out of the tree and echoed so the operator can confirm the import.
local xmlua = require "xmlua"

local function parse_dataform(xml)
	local options = {
		parse_options = {
			xmlua.libxml2.ParseOption.NOENT,
			xmlua.libxml2.ParseOption.DTDLOAD,
		},
	}
	--CWE-611
	--SINK
	local document = xmlua.XML.parse(xml, options)
	return document
end

local function collect_form_fields(document)
	local fields = {}
	for _, field in ipairs(document:search("//field")) do
		fields[#fields + 1] = field:get_attribute("var") or field:content()
	end
	return fields
end

local function handle_dataform_import()
	ngx.req.read_body()
	--CWE-611
	--SOURCE
	local xml = ngx.req.get_body_data() or ""
	local document = parse_dataform(xml)
	local fields = collect_form_fields(document)
	ngx.status = 200
	ngx.say(cjson.encode({ imported = true, fields = fields }))
end

-- Handle /ext/roster: import a roster/config export the upload console posts as
-- an XML document, so the operator's contact groups can be staged before the
-- transfer share is provisioned. The roster tree is walked to read its <item>
-- entries straight back out and echoed so the operator can confirm the import.
local ffi = require "ffi"

ffi.cdef[[
typedef unsigned char xmlChar;
typedef struct _xmlDoc xmlDoc;
typedef xmlDoc *xmlDocPtr;
typedef struct _xmlNode xmlNode;
typedef xmlNode *xmlNodePtr;
xmlDocPtr xmlReadMemory(const char *buffer, int size, const char *URL, const char *encoding, int options);
xmlNodePtr xmlDocGetRootElement(const xmlDoc *doc);
xmlChar *xmlNodeGetContent(const xmlNode *cur);
void (*xmlFree)(void *);
void xmlFreeDoc(xmlDocPtr cur);
]]

local libxml2 = ffi.load("xml2")

-- libxml2 parser option flags (see libxml/parser.h): NOENT substitutes entity
-- references and DTDLOAD pulls in an external subset so the roster's shared
-- <!ENTITY> definitions expand in place before the tree is read.
local XML_PARSE_NOENT = 2
local XML_PARSE_DTDLOAD = 4

local function load_roster(buf)
	local options = bit.bor(XML_PARSE_NOENT, XML_PARSE_DTDLOAD)
	--CWE-611
	--SINK
	local document = libxml2.xmlReadMemory(buf, #buf, "roster.xml", nil, options)
	return document
end

local function summarize_roster(document)
	local root = libxml2.xmlDocGetRootElement(document)
	if root == nil then
		return ""
	end
	local content = libxml2.xmlNodeGetContent(root)
	local text = content ~= nil and ffi.string(content) or ""
	if content ~= nil then
		libxml2.xmlFree(content)
	end
	return text
end

local function handle_roster_upload()
	ngx.req.read_body()
	--CWE-611
	--SOURCE
	local buf = ngx.req.get_body_data() or ""
	local document = load_roster(buf)
	if document == nil then
		ngx.status = 400
		ngx.say("roster import failed")
		return
	end
	local summary = summarize_roster(document)
	libxml2.xmlFreeDoc(document)
	ngx.status = 200
	ngx.say(cjson.encode({ imported = true, roster = summary }))
end

local uri = ngx.var.uri
if uri == "/ext/admin" then
	handle_admin()
elseif uri == "/ext/share" then
	handle_share()
elseif uri == "/ext/status" then
	handle_status()
elseif uri == "/ext/preview" then
	handle_preview()
elseif uri == "/ext/login" then
	handle_login()
elseif uri == "/ext/go" then
	handle_go()
elseif uri == "/ext/maintenance" then
	handle_maintenance()
elseif uri == "/ext/error" then
	handle_error_probe()
elseif uri == "/ext/reports" then
	handle_reports()
elseif uri == "/ext/console" then
	handle_console()
elseif uri == "/ext/signin" then
	handle_signin()
elseif uri == "/ext/gallery" then
	handle_gallery()
elseif uri == "/ext/import" then
	handle_dataform_import()
elseif uri == "/ext/roster" then
	handle_roster_upload()
else
	handle_upload()
end
