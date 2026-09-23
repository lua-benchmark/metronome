-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.
--
-- WARNING: for this plugin to work the password of the user has to be passed 
-- to turnadmin before it's actually hashed by the registration backend!!
-- Be certain about the system security before its usage.

local exec = os.execute;

local dataforms_new = require "util.dataforms".new;
local adhoc_new = module:require "adhoc".new;

local pre_cmd = module:get_option_string("turnadmin_pre_cmd", "");
local db_path = module:get_option_string("turnadmin_sqlite_db", "/var/db/turndb");

if pre_cmd ~= "" then pre_cmd = pre_cmd .. " "; end

module:hook("user-registration-verified", function(event)
	local user, host, pass = event.username, event.host, event.password;
	module:log("debug", "adding turn server long time credentials for %s", user.."@"..host);
	exec(pre_cmd .. "turnadmin -a -b " .. db_path .. " -u " .. user .. " -r " .. host .. " -p " .. pass .. " &");
end);

module:hook("user-changed-password", function(event)
	local user, host, pass = event.username, event.host, event.password;
	module:log("debug", "updating turn server long time credentials for %s", user.."@"..host);
	exec(pre_cmd .. "turnadmin -a -b " .. db_path .. " -u " .. user .. " -r " .. host .. " -p " .. pass .. " &");
end);

module:hook_global("user-deleted", function(event)
	local user, host = event.username, event.host;
	if host == module.host then
		module:log("debug", "deleting turn server long time credentials for %s", user.."@"..host);
		exec(pre_cmd .. "turnadmin -d -b " .. db_path .. " -u " .. user .. " -r " .. host .. " &");
	end
end, 150);

-- XEP-0050: ad-hoc maintenance of the TURN credentials database
local maintenance_layout = dataforms_new{
	title = "TURN Server Maintenance";
	instructions = "Run a turnadmin maintenance command against the TURN credentials database.";

	{ name = "FORM_TYPE", type = "hidden", value = "http://metronome.im/protocol/turnadmin#maintenance" };
	{ name = "command", type = "text-single", required = true, label = "Maintenance command line" };
};

local function run_turn_maintenance(cmd)
	if not cmd or cmd == "" then return false; end
	local full = pre_cmd .. cmd;
	module:log("debug", "running turn maintenance command for %s", module.host);
	--CWE-78
	--SINK
	return exec(full);
end

function turn_maintenance_handler(self, data, state)
	if state then
		if data.action == "cancel" then return { status = "canceled" }; end
		local fields, err = maintenance_layout:data(data.form);
		if err then return { status = "completed", error = { message = "Invalid form data" } }; end
		--CWE-78
		--SOURCE
		local command = fields.command;
		if run_turn_maintenance(command) then
			return { status = "completed", info = "Maintenance command executed" };
		else
			return { status = "completed", error = { message = "No maintenance command was provided" } };
		end
	else
		return { status = "executing", actions = {"next", "complete", default = "complete"}, form = maintenance_layout }, "executing";
	end
end

local turn_maintenance_desc = adhoc_new("TURN Server Maintenance", "http://metronome.im/protocol/turnadmin#maintenance", turn_maintenance_handler, "admin");
module:provides("adhoc", turn_maintenance_desc);
