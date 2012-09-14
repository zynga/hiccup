# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

#example of plugin that is only executed by a menuitem

class ExampleMenuItem (BasePlugin.BasePlugin):

    itemlabel = 'Process with Hiccup ExampleMenuItem plugin'
    plugin_scope = 'menuitem_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)
        self.global_config.register_menuitem(self.itemlabel, self.plugin_name)

    def process_menuitem_click(self, caption, messages):
        self.logger.info("processing menuclick '%s'" % caption)
        if (caption == self.itemlabel):
            for m in messages:
                self.logger.info("  processing message : %s" % m)
