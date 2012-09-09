# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

import FileWatcher
import os, ConfigParser, logging, json, yaml
from java.net import URL

class GlobalConfig:
    base_section = 'defaults'
    logger = None
    filename = ''
    file_watcher = None
    config_data = {}
    config_internals = {
        'intercept_actions': {
            'FOLLOW_RULES': 0, 'DO_INTERCEPT': 1,'DONT_INTERCEPT': 2, 'DROP': 3,
            'FOLLOW_RULES_AND_REHOOK': 0x10, 'DO_INTERCEPT_AND_REHOOK': 0x11, 'DONT_INTERCEPT_AND_REHOOK': 0x12
        },
        'menu_handler': {},
        'handler_map': {}
    }
    config_state = {}
    config_callbacks = None
    valid = False

    def __init__(self, configfile, callbacks=None):
        self.logger = logging.getLogger()
        self.filename = configfile
        self.config_data = self.load_from_file(configfile)
        self.config_data['internals'] = self.config_internals
        self.config_data['state'] = self.config_state
        if callbacks != None:
            self.add_callbacks(callbacks)
        self.logger.debug("initialized")

    def add_callbacks(self, callbacks):
        self.config_callbacks = callbacks
        self.config_data['callbacks'] = self.config_callbacks
        #do burp-specific config according to config file
        if self.base_section in self.config_data:
            if 'intercept_enabled' in self.config_data[self.base_section]:
                if self.config_data[self.base_section]['intercept_enabled']:
                    self.config_callbacks.setProxyInterceptionEnabled(True)
                else:
                    self.config_callbacks.setProxyInterceptionEnabled(False)
            listener_defined = False
            default_listener_port = 8080
            if 'listener_port' in self.config_data[self.base_section]:
                if isinstance(self.config_data[self.base_section]['listener_port'], int):
                    if (self.config_data[self.base_section]['listener_port'] > 0 and
                        self.config_data[self.base_section]['listener_port'] < 65537):
                            listener_defined = True
                            self.logger.debug('read listener port from config : %s' % self.config_data[self.base_section]['listener_port'])
                    else:
                        self.logger.error("configuration item 'listener_port' must be a valid port number - defaulting to %s" % default_listener_port)
                else:
                    self.logger.error("configuration item 'listener_port' must be a number - defaulting to %s" % default_listener_port)
            if (listener_defined == False):
                self.config_data[self.base_section]['listener_port'] = default_listener_port
            if 'burp_scope_include' in self.config_data[self.base_section]:
                for item in self.config_data[self.base_section]['burp_scope_include']:
                    self.logger.debug("adding '%s' to Burp scope" % item)
                    self.config_data['callbacks'].includeInScope(URL(item))
            if 'burp_scope_exclude' in self.config_data[self.base_section]:
                for item in self.config_data[self.base_section]['burp_scope_exclude']:
                    self.logger.debug("excluding '%s' from Burp scope" % item)
                    self.config_data['callbacks'].excludeFromScope(URL(item))
        #tweak other burp-specific settings
        tmpconf = self['callbacks'].saveConfig()
        for name in ('proxy', 'target'):
            for mimetype in ('html', 'script', 'xml', 'css', 'othertext', 'images', 'flash', 'otherbinary'):
                tmpconf['%s.showmime%s' % (name, mimetype)] = 'true'
            for status in ('2xx', '3xx', '4xx', '5xx'):
                tmpconf['%s.showstatus%s' % (name, status)] = 'true'
        tmpconf['proxy.interceptresponses'] = 'true'
        tmpconf['proxy.listener0'] = '1.%s.0.0..0.0.1.0..0..0.' % self.config_data[self.base_section]['listener_port']
        self['callbacks'].loadConfig(tmpconf)
        self.logger.debug("added callbacks")

    def reload_from_file(self):
        self.logger.debug("reload_from_file() called")
        self.config_state = self.config_data['state']
        self.config_internals = self.config_data['internals']
        self.config_data = self.load_from_file(self.filename)
        self.config_data['internals'] = self.config_internals
        self.config_data['state'] = self.config_state
        self.config_data['callbacks'] = self.config_callbacks

    def test_plugin_config(self, pname, reqdconfitems):
        if len(reqdconfitems) == 0:
            return True
        if pname not in self.config_data:
            return False
        for item in reqdconfitems:
            if item not in self.config_data[pname]:
                return False
        return True

    def load_from_file(self, filename):
        self.valid = False
        if (os.path.isfile(filename)):
            try:
                cfgfile = open(filename, 'r')
                configobj = yaml.load(cfgfile.read())
                self.logger.debug("config read from file: %s" % configobj)
            except Exception, e:
                self.logger.error("exception reading config file: %s" % e)
                return {}
            else:
                self.valid = True
                return configobj
            cfgfile.close()
        else:
            self.logger.error("config file '%s' not found" % os.path.join(os.getcwd(), filename))
            return {}

    def is_valid(self):
        return self.valid

    def register_menuitem(self, caption, plugin_name):
        if caption in self['internals']['handler_map']:
            self.logger.error("menu item '%s' already registered for plugin '%s'" % (caption, self['internals']['handler_map'][caption]))
        else:
            self['callbacks'].registerMenuItem(caption, self['internals']['menu_handler'])
            self['internals']['handler_map'][caption] = plugin_name
            self.logger.debug("register_menuitem() added '%s' to map for '%s'" % (caption, plugin_name))

    #act like a dict
    def __getitem__(self, key):
        if key in self.config_data:
            return self.config_data[key]
        else:
            raise KeyError("'%s' not found in configuration" % key)
        
    def __setitem__(self, key, value):
        self.config_data[key] = value

    def __iter__(self):
        return self.config_data.iterkeys()

    def iterkeys(self):
        return self.config_data.iterkeys()

    def __contains(self, key):
        if key in self.config_data:
            return True
        return False
