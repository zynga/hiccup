# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# simple debug plugin, that includes Burp scope in decision to process

class ScopeTest (BasePlugin.BasePlugin):

    plugin_scope = 'proxy_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        if (message.in_burp_scope()):
            self.logger.info("processing %s" % (message))
        else:
            self.logger.info("not in scope, skipping %s" % (message))

    def process_response(self, message):
        if (message.in_burp_scope()):
            self.logger.info("processing %s" % (message))
        else:
            self.logger.info("not in scope, skipping %s" % (message))
