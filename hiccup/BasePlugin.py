# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

import SharedFunctions as shared
import logging

class BasePlugin:

    required_config = []
    config_complete = False
    plugin_name = None
    logger = None
    plugin_scope = None

    plugin_scopes = {
        'all': 0,
        'proxy_only': 1,
        'http_only': 2,
        'menuitem_only': 3
    }

    def __init__(self, global_config, reqdconf=[], plugin_scope=None):
        self.logger = logging.getLogger()
        self.logger.debug("initializing '%s', required_config %s" % (self.__module__, reqdconf))
        self.global_config = global_config
        self.plugin_name = self.__module__
        if plugin_scope == None:
            plugin_scope = global_config['defaults']['default_plugin_scope']
            self.logger.debug("plugin did not provide scope, using default: %s" % plugin_scope)
        elif plugin_scope not in self.plugin_scopes:
            self.logger.error("plugin provided invalid scope '%s', using default '%s'" % (plugin_scope, global_config['defaults']['default_plugin_scope']))
            plugin_scope = global_config['defaults']['default_plugin_scope']
        self.plugin_scope = plugin_scope
        self.logger.debug("plugin initializing with scope : %s" % plugin_scope)
        self.required_config = reqdconf
        if self.global_config.test_plugin_config(self.plugin_name, reqdconf):
            self.config_complete = True
            self.logger.debug("'%s' plugin initialized" % (self.__module__))

    def __del__(self):
        pass

    def required_config_loaded(self):
        return self.config_complete

    def scope_proxy_only(self):
        return self.plugin_scopes[self.plugin_scope] == self.plugin_scopes['proxy_only']

    def scope_http_only(self):
        return self.plugin_scopes[self.plugin_scope] == self.plugin_scopes['http_only']

    def scope_menuitem_only(self):
        return self.plugin_scopes[self.plugin_scope] == self.plugin_scopes['menuitem_only']

    def scope_all(self):
        return self.plugin_scopes[self.plugin_scope] == self.plugin_scopes['all']

