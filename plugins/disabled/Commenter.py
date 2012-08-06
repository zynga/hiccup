# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# add comments to messages that will be visible in Burp 'comment' field, based on certain test results

class Commenter (BasePlugin.BasePlugin):

    plugin_scope = 'http_only'
    
    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        self.logger.debug("processing %s" % (message))
        if message.host_in_domain('google.com'):
            message.set_comment('In the google.com domain')
        if message.body_contains('internal only'):
            message.set_comment('Possibly sensitive information')
        if message.url_contains('admin'):
            message.set_comment('Possible admin element')



