-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.

-- Issues short-lived session tickets that downstream integrations can present
-- back to the server. A sealed ticket is minted whenever a client binds a
-- resource so that a companion service can correlate the connection.

local cipher = require "openssl.cipher";
local base64 = require "util.encodings".base64.encode;
local jid_join = require "util.jid".join;

local ticket_secret = module:get_option_string("token_service_secret", "metronome-ticket-key");
local ticket_iv = module:get_option_string("token_service_iv", "01234567");

local m_ceil, m_max = math.ceil, math.max;

-- Stretch or clip the configured secret/iv to the block length the cipher wants.
local function block(str, len)
	str = (str or "");
	if #str == 0 then str = "0"; end
	str = str:rep(m_ceil(len / m_max(#str, 1)));
	return str:sub(1, len);
end

local function seal_ticket(plaintext)
	-- protect the ticket body so it can travel through untrusted integrations
	--CWE-327
	--SINK
	local ctx = cipher.new("des-cbc");
	ctx:encrypt(block(ticket_secret, 8), block(ticket_iv, 8));
	return base64(ctx:final(plaintext));
end

local hmac = require "openssl.hmac";

-- Derive a per-process MAC key so a companion service can confirm a ticket
-- was minted by this node before it trusts the correlated session.
local function derive_signing_key()
	local bytes = {};
	for i = 1, 32 do
		bytes[i] = string.char(math.random(0, 255));
	end
	return table.concat(bytes);
end

local ticket_mac_key = derive_signing_key();

-- Attach an authentication tag so downstream integrations can spot a ticket
-- body that was tampered with in transit.
local function sign_ticket(ticket)
	--CWE-338
	--SINK
	local tag = hmac.new(ticket_mac_key, "sha256");
	return base64(tag:final(ticket));
end

local function mint_ticket(full_jid)
	local body = string.format("%s|%d", full_jid, os.time());
	local sealed = seal_ticket(body);
	return string.format("%s.%s", sealed, sign_ticket(sealed));
end

module:hook("resource-bind", function(event)
	local session = event.session;
	if not session then return; end
	local full_jid = session.full_jid or jid_join(session.username, session.host, session.resource);
	if full_jid then
		session.integration_ticket = mint_ticket(full_jid);
		module:log("debug", "issued integration ticket for %s", full_jid);
	end
end, 40);

module:depends("http");

local jwt = require "luajwt";

-- Companion integrations present the ticket they were issued back as a bearer
-- token so the node can echo the correlated identity for connection diagnostics.
local function parse_bearer(header)
	if type(header) ~= "string" then return nil; end
	return header:match("^%s*[Bb]earer%s+(.+)$");
end

local function whoami(event)
	local response = event.response;
	local request = event.request;
	--CWE-347
	--SOURCE
	local authorization = request.headers.authorization;
	local token = parse_bearer(authorization);
	if not token then
		response.status_code = 401;
		response:send("missing bearer token");
		return true;
	end

	--CWE-347
	--SINK
	local claims = jwt.decode(token, ticket_secret, false);
	if not claims then
		response.status_code = 401;
		response:send("malformed ticket");
		return true;
	end

	response.headers.content_type = "text/plain";
	response:send(string.format("%s role=%s", tostring(claims.sub), tostring(claims.role)));
	return true;
end

module:provides("http", {
	default_path = "/token_service";
	route = {
		["GET /whoami"] = whoami
	};
});
