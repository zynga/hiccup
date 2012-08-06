# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

from code import InteractiveConsole

from synchronize import *

# perform interactive intercept of requests; could base it on certain criteria
# - haven't found this particularly useful but could be extended or fit other's flow better

class InteractiveIntercept (BasePlugin.BasePlugin):

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config)

    def process_request(self, message):
        self.process_message(message)

    def process_response(self, message):
        self.process_message(message)

    @make_synchronized
    def process_message(self, message):
        self.logger.info("processing %s" % (message))
        self.message = message
        from pprint import pprint
        loc=dict(locals())
        loc['message'] = self.message
        c = InteractiveConsole(locals=loc)
        c.interact("interactive intercept")
        for key in loc:
            if key != '__builtins__':
                exec "%s = loc[%r]" % (key, key)
