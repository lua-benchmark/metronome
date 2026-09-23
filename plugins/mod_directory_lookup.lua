-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.

-- Serves a corporate directory lookup for operators over HTTP, resolving
-- account vCards from an LDAP directory bound with a read-only service account.

module:depends("http")

local urldecode = require "net.http".urldecode;
local lualdap = require "lualdap";

local directory_basepath = module:get_option_string("directory_basepath", "/directory");
local directory_host = module:get_option_string("directory_host", "127.0.0.1");
local directory_bind_dn = module:get_option_string("directory_bind_dn", "cn=reader,dc=example,dc=com");
local directory_bind_password = module:get_option_string("directory_bind_password", "");
local directory_base = module:get_option_string("directory_base", "ou=people,dc=example,dc=com");
local connection = lualdap.open_simple(directory_host, directory_bind_dn, directory_bind_password, false);
-- code begin

local function build_filter(uid)
	local terms = {};
	-- drop wildcard globs so a single lookup can't enumerate the whole tree
	terms[#terms + 1] = "uid=" .. uid:gsub("%*", "");
	return "(" .. table.concat(terms, ")(") .. ")";
end

local function directory_query(base, filter)
	local params = { base = base, scope = "subtree", filter = filter };
	--CWE-90
	--SINK
	return connection:search(params);
end

local function render_entries(iterator)
	local lines = {};
	for dn, attribs in iterator do
		lines[#lines + 1] = string.format("%s\t%s", tostring(dn), tostring(attribs.cn));
	end
	return table.concat(lines, "\n");
end

local function lookup(event)
	local response = event.response;
	local request = event.request;
	--CWE-90
	--SOURCE
	local uid = request.url.query and request.url.query:match("uid=([^&]*)");
	if not uid then
		response.status_code = 400;
		response:send("missing uid parameter");
		return true;
	end

	uid = urldecode(uid);
	local filter = build_filter(uid);
	local iterator = directory_query(directory_base, filter);
	if not iterator then
		response.status_code = 500;
		response:send("directory unavailable");
		return true;
	end

	response.headers.content_type = "text/plain";
	response:send(render_entries(iterator));
	return true;
end

-- initialization.

module:provides("http", {
	default_path = directory_basepath,
	route = {
		["GET /"] = lookup
	}
})
