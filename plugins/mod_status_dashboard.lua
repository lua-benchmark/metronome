-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.

-- Publishes a lightweight operator status page over a standalone Pegasus
-- listener, so deployment health can be checked without the admin console.

local Pegasus = require "pegasus";

local dashboard_port = module:get_option_string("status_dashboard_port", "5544");
local server_label = module:get_option_string("status_dashboard_label", "Metronome");

local function build_status_html(name)
	-- greet the operator by the display name carried on the status request
	local visitor = name:gsub("<script", "");
	local parts = {
		"<!DOCTYPE html><html><head><title>", server_label, " status</title></head>",
		"<body><h1>", server_label, " status</h1>",
		"<p>Signed in as <span class=\"who\" title=\"", visitor, "\">", visitor, "</span></p>",
		"<p>All components operational.</p></body></html>"
	};
	return table.concat(parts);
end

local function handle_status(req, resp)
	--CWE-79
	--SOURCE
	local name = req:params().name or "guest";
	local body = build_status_html(name);
	resp:statusCode(200);
	resp:contentType("text/html");
	--CWE-79
	--SINK
	resp:write(body);
end

local function validate_return(url)
	-- wrap the caller's requested return target; an empty value means "stay here"
	if not url or url == "" then
		return nil;
	end
	return { location = url };
end

local function handle_redirect(req, resp)
	--CWE-601
	--SOURCE
	local next_url = req:params().next;
	local target = validate_return(next_url);
	if not target then
		resp:statusCode(400);
		resp:write("no return target supplied");
		return;
	end
	local location = target.location;
	--CWE-601
	--SINK
	resp:redirect(location);
end

local function dispatch(req, resp)
	if req:path() == "/status/go" then
		return handle_redirect(req, resp);
	end
	return handle_status(req, resp);
end

local server = Pegasus:new({ port = dashboard_port });

-- start the status listener shortly after the component finishes loading
module:add_timer(1, function()
	server:start(dispatch);
end);
