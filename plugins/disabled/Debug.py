# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# simple debug plugin

class Debug (BasePlugin.BasePlugin):

    plugin_scope = 'proxy_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)
        self.global_config.register_menuitem("%s test" % self.plugin_name, self.plugin_name)

    def process_request(self, message):
        self.logger.info("processing '%s' %s" % (message['tool'], message))

    def process_response(self, message):
        self.logger.info("processing '%s' %s" % (message['tool'], message))

    def process_menuitem_click(self, caption, messages):
        self.logger.info("'%s' menu item clicked" % caption)
        for m in messages:
            self.logger.info(" processing selected message : %s" % m)
