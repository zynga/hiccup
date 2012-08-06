# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# prints Content-type from header for each message that passes through the plugin

class ContentType (BasePlugin.BasePlugin):

    plugin_scope = 'http_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        pass

    def process_response(self, message):
        self.logger.info("Content-type: %s in %s" % (message['contenttype'], message))
