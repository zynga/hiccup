# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

import re

# perform substitions against headers

class HeaderReplace (BasePlugin.BasePlugin):

    required_config = ['targets',]
    plugin_scope = 'proxy_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        for target in self.global_config[self.plugin_name]['targets']:
            strfind = target[0]
            strreplace = target[1]
            (message['headers'], count) = re.subn(strfind, strreplace, message['headers'])
            if count > 0:
                self.logger.info("replaced %s matching '%s' header/s %s" % (count, strfind, message))
