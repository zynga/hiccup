# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

# intercept messages in Burp, based on certain test results

class ConditionalIntercepts (BasePlugin.BasePlugin):

    required_config = ['host_contains', 'url_contains', 'body_contains', 'header_exists', 'headers_contain']

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        self.logger.debug("process_message called w/ config : %s" % self.global_config[self.plugin_name])
        for searchstr in self.global_config[self.plugin_name]['host_contains']:
            if (searchstr in message['remotehost']):
                self.do_intercept(message, searchstr)
                return
        for searchstr in self.global_config[self.plugin_name]['url_contains']:
            if (searchstr in message['url']):
                self.do_intercept(message, searchstr)
                return
        for searchstr in self.global_config[self.plugin_name]['body_contains']:
            if (searchstr in message['body']):
                self.do_intercept(message, searchstr)
                return
        for searchstr in self.global_config[self.plugin_name]['header_exists']:
            if message.has_header(searchstr):
                self.do_intercept(message, searchstr)
                return
        for searchstr in self.global_config[self.plugin_name]['headers_contain']:
            if message.headers_contain(searchstr):
                self.do_intercept(message, searchstr)
                return

    def do_intercept(self, message, searchstr):
        message.set_intercept_action("DO_INTERCEPT")
        self.logger.info("found match for \'%s\' in %s" % (searchstr, message))
