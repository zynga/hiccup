# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

import re, pprint, json

# plugin to pretty-print JSON packets as they pass through the proxy

class JsonPrint (BasePlugin.BasePlugin):

    plugin_scope = 'proxy_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)


    def process_message(self, message):
        m = re.search('content-type\:\s+application\/json(; charset=(\S+)){0,1}', message['headers'], flags=re.IGNORECASE)
        if (m):
            try:
                jsondata = json.read(message['body'])
            except Exception, e:
                self.logger.error("exception while reading JSON: %s" % e)
            else:
                self.logger.info("JSON detected in %s" % message)
                self.logger.info("\t%s" % pprint.pformat(jsondata))
