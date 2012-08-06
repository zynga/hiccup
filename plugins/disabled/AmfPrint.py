# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

import pyamf.remoting, pprint

# plugin to pretty-print AMF packets as they pass through the proxy

class AmfPrint (BasePlugin.BasePlugin):

    plugin_scope = 'proxy_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        if message.header_contains('content-type', 'application\/x-amf'):
            self.logger.info("AMF %s" % (message))
            try:
                amfdata = pyamf.remoting.decode(message['body'])
            except pyamf.DecodeError:
                self.logger.error("Content-type is set to application/x-amf, but input does not appear to be valid AMF.")
            else:
                for (key,msg) in amfdata.bodies:
                    self.logger.info(pprint.pformat(msg.body, indent=2))
