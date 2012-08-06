# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# apply highlight ta all messages that are HTTP, rather than HTTPS/SSL/TLS

class PlaintextHighlighter (BasePlugin.BasePlugin):

    required_config = []
    plugin_scope = 'http_only'
    
    #legit colors : 'red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'pink', 'magenta', 'gray'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        self.logger.debug("processing %s" % (message))
        if message.is_https() == False:
            message.set_highlight('red')
