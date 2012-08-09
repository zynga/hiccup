# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# highlight messages that will be visible in Burp, based on certain test results

class Highlighter (BasePlugin.BasePlugin):

    plugin_scope = 'http_only'
    
    #accepted colors : 'red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'pink', 'magenta', 'gray'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)
        self.global_config.register_menuitem('Highlight yellow', self.plugin_name)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        self.logger.debug("processing %s" % (message))
        if message.host_in_domain('google.com'):
            message.set_highlight('cyan')
        if message.body_contains('internal only'):
            message.set_highlight('red')

    def process_menuitem_click(self, caption, messages):
        self.logger.debug("processing menuclick '%s'" % caption)
        if (caption == 'Highlight yellow'):
            for m in messages:
                m.set_highlight('yellow')
