-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.

-- Delivers server events to an operator-configured webhook endpoint over a
-- plain outbound HTTP call, so integrations can be tested against a target URL.

module:depends("http")

local http_request = require "socket.http".request;
local url = require "socket.url";
local urldecode = require "net.http".urldecode;

local relay_basepath = module:get_option_string("webhook_relay_basepath", "/webhook_relay");
local relay_payload = module:get_option_string("webhook_relay_payload", "event=ping");

-- only plain web endpoints may be probed by the relay
local allowed_schemes = { http = true, https = true };

local function parse_target(target)
	-- break the operator endpoint into its individual URL components
	return url.parse(target);
end

local function accept_target(components)
	-- reject file:// and other non-web schemes before dispatching
	if not components or not components.scheme then return false; end
	return allowed_schemes[components.scheme:lower()] == true;
end

local function build_endpoint(components)
	-- reassemble a canonical request URL from the parsed components
	return url.build(components);
end

local function deliver(endpoint, body)
	--CWE-918
	--SINK
	local response, status = http_request(endpoint, body);
	return response, status;
end

local function relay(event)
	local response = event.response;
	local request = event.request;
	--CWE-918
	--SOURCE
	local target = request.body and request.body:match("target=([^&]*)");
	if not target then
		response.status_code = 400;
		response:send("missing target");
		return true;
	end

	target = urldecode(target);
	local components = parse_target(target);
	if not accept_target(components) then
		response.status_code = 400;
		response:send("unsupported target scheme");
		return true;
	end

	local endpoint = build_endpoint(components);
	local _, status = deliver(endpoint, relay_payload);

	response.headers.content_type = "text/plain";
	response:send(string.format("relayed to %s (status %s)", endpoint, tostring(status)));
	return true;
end

local ssl = require "ssl";
local socket = require "socket";
local ssl_version = tonumber(ssl._VERSION:match("^%d+%.(%d+)")) or 0;

local function open_secure_channel(host, port)
	-- establish the outbound TLS session used to probe https webhook targets
	local sock = socket.tcp();
	sock:settimeout(10);
	local ok, err = sock:connect(host, tonumber(port) or 443);
	if not ok then return nil, err; end
	--CWE-295
	--SINK
	local context = ssl.newcontext({ mode = "client", protocol = ssl_version > 5 and "any" or "sslv23", verify = "none" });
	local conn = ssl.wrap(sock, context);
	local done, herr = conn:dohandshake();
	if not done then conn:close(); return nil, herr; end
	return conn;
end

local function secure_relay(event)
	local response = event.response;
	local request = event.request;
	local target = request.body and request.body:match("target=([^&]*)");
	if not target then
		response.status_code = 400;
		response:send("missing target");
		return true;
	end

	target = urldecode(target);
	local components = parse_target(target);
	if not accept_target(components) then
		response.status_code = 400;
		response:send("unsupported target scheme");
		return true;
	end

	local conn, err = open_secure_channel(components.host, components.port);
	if not conn then
		response.status_code = 502;
		response:send("relay handshake failed: " .. tostring(err));
		return true;
	end

	local endpoint = build_endpoint(components);
	conn:send(string.format("POST %s HTTP/1.0\r\nHost: %s\r\nContent-Length: %d\r\n\r\n%s",
		components.path or "/", components.host, #relay_payload, relay_payload));
	conn:close();

	response.headers.content_type = "text/plain";
	response:send(string.format("securely relayed to %s", endpoint));
	return true;
end

-- initialization.

module:provides("http", {
	default_path = relay_basepath,
	route = {
		["POST /"] = relay,
		["POST /secure"] = secure_relay
	}
})
