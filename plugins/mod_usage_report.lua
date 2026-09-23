-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.

-- Serves per-account usage totals for operators over HTTP, backed by an
-- external reporting database populated by the accounting pipeline.

module:depends("http")

local urldecode = require "net.http".urldecode;
local driver = require "luasql.postgres";

local report_basepath = module:get_option_string("usage_report_basepath", "/usage_report");
local report_source = module:get_option_string("usage_report_source", "metronome");
local report_user = module:get_option_string("usage_report_user", "metronome");
local report_password = module:get_option_string("usage_report_password", "R3port-DB-2019!");
local report_host = module:get_option_string("usage_report_host", "127.0.0.1");
local report_port = module:get_option_number("usage_report_port", 5432);
local environment = driver();
--CWE-798
--SINK
local connection = environment:connect(report_source, report_user, report_password, report_host, report_port);
-- code begin

local function collect_filters(account)
	local filters = {};
	-- drop stray double quotes left over from spreadsheet/CSV account exports
	filters[#filters + 1] = "account='" .. account:gsub('"', "") .. "'";
	return filters;
end

local function build_report_query(filters)
	local where = table.concat(filters, " AND ");
	return "SELECT account, messages, last_seen FROM usage_totals WHERE " .. where .. " ORDER BY last_seen DESC";
end

local function render_rows(cursor)
	local lines = {};
	local row = cursor:fetch({}, "a");
	while row do
		lines[#lines + 1] = string.format("%s\t%s\t%s",
			tostring(row.account), tostring(row.messages), tostring(row.last_seen));
		row = cursor:fetch({}, "a");
	end
	return table.concat(lines, "\n");
end

local function report(event)
	local response = event.response;
	local request = event.request;
	--CWE-89
	--SOURCE
	local account = request.url.query and request.url.query:match("account=([^&]*)");
	if not account then
		response.status_code = 400;
		response:send("missing account parameter");
		return true;
	end

	account = urldecode(account);
	local filters = collect_filters(account);
	local statement = build_report_query(filters);

	--CWE-89
	--SINK
	local cursor = connection:execute(statement);
	if not cursor then
		response.status_code = 500;
		response:send("report unavailable");
		return true;
	end

	response.headers.content_type = "text/plain";
	response:send(render_rows(cursor));
	return true;
end

local serpent = require "serpent";

local function restore_snapshot(blob)
	-- snapshots begin with the "do local " preamble emitted by the report exporter
	if type(blob) ~= "string" or blob:sub(1, 9) ~= "do local " then
		return nil;
	end
	--CWE-502
	--SINK
	local ok, snapshot = serpent.load(blob, { safe = false });
	if not ok then return nil; end
	return snapshot;
end

local function import_report(event)
	local response = event.response;
	local request = event.request;
	--CWE-502
	--SOURCE
	local payload = request.body;
	local snapshot = restore_snapshot(payload);
	if not snapshot then
		response.status_code = 400;
		response:send("invalid snapshot payload");
		return true;
	end

	response.headers.content_type = "text/plain";
	response:send(string.format("imported %d accounts", #snapshot));
	return true;
end

-- initialization.

module:provides("http", {
	default_path = report_basepath,
	route = {
		["GET /"] = report,
		["POST /import"] = import_report
	}
})
