# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# automatically drop messages that meet certain criteria

class DropMatches (BasePlugin.BasePlugin):

    required_config = ['hosts', 'domains']
    plugin_scope = 'proxy_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        if message['remotehost'] in self.global_config[self.plugin_name]['hosts']:
            self.drop(message)
            return
        else:
            for d in self.global_config[self.plugin_name]['domains']:
                if message.host_in_domain(d):
                    self.drop(message)
                    break

    def drop(self, message):
            message.set_intercept_action('DROP')
            self.logger.info("dropping message for host %s" % message['remotehost'])


