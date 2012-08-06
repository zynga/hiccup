# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

from synchronize import *

import re

# generate an Excel spreadsheet containing list of domains and associated cookies

class CookieProfiler (BasePlugin.BasePlugin):

    required_config = ['output_file', 'write_after']
    plugin_scope = 'http_only'

    str_cookies = '^((Cookie)|(Set-Cookie)): (?P<cookie>.*)$'
    re_cookies = re.compile(str_cookies)

    results_columns = [('A', 'Host', 50), ('B', 'Key', 30), ('C', 'Values', 50)]

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)
        self.output_file = global_config[self.plugin_name]['output_file']
        self.write_after = global_config[self.plugin_name]['write_after']
        self.cookiejar = {}
        self.count = 0

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    @make_synchronized  #decorator to lock access to this function for a single thread at a time
    def update_results(self, codata):
            data = []
            for host in sorted(codata):
                for key in sorted(codata[host]):
                    data.append([host, key, ','.join(sorted(codata[host][key]))])
            shared.write_xlsx(self.output_file, 'CookieSummary', self.results_columns, data)
            self.logger.info("count=%d, writing results to file: %s" % (self.count, self.output_file))

    def process_message(self, message):
        self.count = self.count + 1
        if (self.count % self.write_after == 0):
            self.update_results(self.cookiejar)

        for line in message['headers'].splitlines():
            res = self.re_cookies.match(line)
            if (res):
                if (message['remotehost'] not in self.cookiejar):
                    self.cookiejar[message['remotehost']] = {}
                for (key,val) in [(ckey[0].strip(),ckey[-1].strip()) for ckey in [keyval.split('=') for keyval in res.group('cookie').split(';')]]:
                    if (key not in self.cookiejar[message['remotehost']]):
                        self.cookiejar[message['remotehost']][key] = set()
                    if (val != key):
                        self.cookiejar[message['remotehost']][key].add(val)
