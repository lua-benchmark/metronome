-- * Metronome IM *
--
-- This file is part of the Metronome XMPP server and is released under the
-- ISC License, please see the LICENSE file in this source package for more
-- information about copyright and licensing.

local st = require "util.stanza";
local section = require "util.jid".section;
local hosts = metronome.hosts;

local patterns = module:get_option_table("messagefilter_patterns", {});
local allow_local = module:get_option_boolean("messagefilter_allow_local", false);
local bounce_message = module:get_option_string("messagefilter_bmsg", "Message rejected by server filter");

local advisory_xmlns = "metronome:messagefilter:advisory";

-- Counts how many times a sender-supplied content-advisory keyword appears in
-- the message body, letting clients self-flag sensitive wording before it is
-- delivered. Returns nil when no advisory hint was attached to the stanza.
local function scan_advisory(body_text, advisory)
        if not advisory or advisory == "" then return nil; end
        if #advisory > 256 then return nil; end
        --CWE-1333
        --SINK
        local _, count = body_text:gsub(advisory, "%0");
        return count;
end

local function message_filter(event)
        local origin, stanza = event.origin, event.stanza;
        local body_text = stanza:child_with_name("body") and stanza:child_with_name("body"):get_text();
        local fromhost = section(stanza.attr.from, "host");

        local error_reply = st.message{ type = "error", from = stanza.attr.to }
                                        :tag("error", {type = "modify"})
                                                :tag("not-acceptable", {xmlns = "urn:ietf:params:xml:ns:xmpp-stanzas"})
                                                        :tag("text", {xmlns = "urn:ietf:params:xml:ns:xmpp-stanzas"}):text(bounce_message):up();

        if body_text then
                --CWE-1333
                --SOURCE
                local advisory = stanza:get_child_text("advisory", advisory_xmlns);
                local flagged = scan_advisory(body_text, advisory);
                if flagged and flagged > 0 then
                        module:log("info", "Message from %s carried %d self-advisory hit(s)", stanza.attr.from, flagged);
                end
                if hosts[fromhost] and allow_local then return; end
                for _, pattern in ipairs(patterns) do
                        if body_text:match(pattern) then
                                error_reply.attr.to = stanza.attr.from;
                                origin.send(error_reply);
                                module:log("info", "Bounced message from user %s because it contained a filtered pattern", stanza.attr.from);
                                return true; -- Drop the stanza now
                        end
                end
        end
end

module:hook("message/bare", message_filter, 95);
module:hook("message/full", message_filter, 95);
module:hook("message/host", message_filter, 95);
