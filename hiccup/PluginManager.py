# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

import FileWatcher, GlobalConfig
import SharedFunctions as shared

import sys, os, re, logging, traceback, inspect

class PluginManager:

    file_watcher = None
    dname = None
    logger = None
    auto_delete_class_files = False

    def __init__(self, config):
        self.global_config = config
        self.logger = logging.getLogger()
        self.logger.debug("initializing")
        self.pluginmods = {}
        self.pluginobjs = {}
        if 'plugin_directory' not in config['defaults']:
            raise Exception("'plugin_directory' not defined in config file" % (self.__module__))
        else:
            self.dname = config['defaults']['plugin_directory']
            sys.path.append(self.dname)
            if 'auto_delete_class_files' in config['defaults']:
                if config['defaults']['auto_delete_class_files'] == True:
                    self.auto_delete_class_files = True
                else:
                    self.auto_delete_class_files = False
            #initialize plugins
            plugins = self.find_plugins(self.dname)
            for (i, pname) in enumerate(plugins):
                    self.enable_plugin(pname)
            self.file_watcher = FileWatcher.FileWatcher(self.dname, ["%s.py" % pname for pname in plugins])

    def find_plugins(self, dname):
        plugins = []
        dirList = os.listdir(dname)
        for n in dirList:
            if (os.path.isdir(n) == False):
                m = re.match('(\S+)\.py$', n)
                if (m):
                    plugins.append(m.group(1))
        return plugins

    def enable_plugin(self, pname):
        try:
            self.logger.debug("enabling plugin '%s'" % (pname))
            try:
                self.pluginmods[pname] = __import__(pname)
            except Exception, e:
                self.logger.error("exception importing '%s' plugin:\n%s" % (pname, shared.indent(traceback.format_exc().strip(), 1)))
            else:
                try:
                    self.pluginobjs[pname] = getattr(self.pluginmods[pname], pname)(self.global_config)
                except AttributeError, e:
                    self.logger.error("plugin '%s' could not be loaded (%s)" % (pname, e))
                    self.disable_plugin(pname)
                else:
                    if not self.pluginobjs[pname].required_config_loaded():
                        self.logger.error("plugin '%s' requires config section '%s' with parameters %s" % (pname, pname, self.pluginobjs[pname].required_config))
                        self.disable_plugin(pname)
                    else:
                        self.logger.info("enabled plugin '%s'" % (pname))
        except Exception, e:
            self.logger.error("exception when initializing plugin '%s':\n%s" % (pname, shared.indent(traceback.format_exc().strip(), 1)))
            self.disable_plugin(pname)

    def disable_plugin(self, pname):
        self.logger.info("disabling plugin '%s'" % (pname))
        if (pname in sys.modules):
            del(sys.modules[pname])
        if (pname in self.pluginmods):
            del(self.pluginmods[pname])
        if (pname in self.pluginobjs):
            del(self.pluginobjs[pname])
        if self.file_watcher != None:
            self.file_watcher.remove_item("%s.py" % pname)
        if self.auto_delete_class_files == True:
            self.logger.debug("  testing for class file : %s" % (os.path.join("%s" % self.dname, "%s$py.class" % pname)))
            if (os.path.isfile(os.path.join("%s" % self.dname, "%s$py.class" % pname))):
                self.logger.debug("  disable_plugin removing stale .class file for disabled plugin '%s'" % pname)
                try:
                    os.remove(os.path.join("%s" % self.dname, "%s$py.class" % pname))
                except OSError, e:
                    self.logger.debug("failed to remove stale file %s$py.class but don't really care" % pname)

    def reload_plugin(self, pname):
        if pname in self.pluginmods and pname in self.pluginobjs:
            try :
                self.logger.debug("reloading plugin '%s'" % (pname))
                self.pluginmods[pname] = reload(sys.modules[pname])
                self.pluginobjs[pname] = getattr(self.pluginmods[pname], pname)(self.global_config)
            except Exception, e:
                self.logger.error("exception reloading '%s' plugin:\n%s" % (pname, shared.indent(traceback.format_exc().strip(), 1)))
                self.disable_plugin(pname)
            else:
                if not self.pluginobjs[pname].required_config_loaded():
                    self.logger.error("plugin '%s' requires config section [%s] with parameters %s" % (pname, pname, self.pluginobjs[pname].required_config))
                    self.disable_plugin(pname)
                else:
                    self.logger.info("reloaded plugin '%s'" % (pname))

    def reload_changed(self):
        plugins = self.find_plugins(self.dname)
        for (i, pname) in enumerate(plugins):
            if (pname not in self.pluginmods.keys()):
                self.enable_plugin(pname)
                self.file_watcher.add_item("%s.py" % pname)
        for pname in self.pluginobjs.keys():
            if (pname not in plugins):
                self.disable_plugin(pname)
        for pname in self.pluginmods.keys():
            if (pname not in plugins):
                self.file_watcher.remove_item("%s.py" % pname)
        for fname in self.file_watcher.get_changed():
            pname = ''.join(fname.split('.')[:-1])
            self.reload_plugin(pname)

    def reload_all(self):
        plugins = self.find_plugins(self.dname)
        self.logger.debug("reloading all plugins")
        for (i, pname) in enumerate(plugins):
            self.enable_plugin(pname)
            self.file_watcher.add_item("%s.py" % pname)

    def in_plugin_scope(self, message, key):
        if self.pluginobjs[key].scope_all():
            self.logger.debug('in_plugin_scope() returning True for scope_all()');
            return True
        elif self.pluginobjs[key].scope_proxy_only() and message.from_proxy():
            self.logger.debug('in_plugin_scope() returning True for scope_proxy_only()');
            return True
        elif self.pluginobjs[key].scope_http_only() and message.from_proxy() == False:
            self.logger.debug('in_plugin_scope() returning True for scope_http_only()');
            return True
        return False  #this case will catch 'menuitem_only' scopes, which should not be processed here

    def process_request(self, message):
        self.logger.debug("process_request called")
        for key in sorted(self.pluginobjs.keys()):
            if self.in_plugin_scope(message, key):
                self.logger.debug("plugin '%s' is in scope, processing" % key)
                if (hasattr(self.pluginobjs[key], 'process_request') and inspect.ismethod(self.pluginobjs[key].process_request)):
                    try:
                        self.pluginobjs[key].process_request(message)
                    except Exception, e:
                        self.logger.error("exception in '%s' process_request():\n%s" % (key, shared.indent(traceback.format_exc().strip(), 1)))
                else:
                    self.logger.error("skipping plugin '%s', process_request not defined" % key)
            else:
                self.logger.debug("plugin '%s' is not in scope, SKIPPING" % key)

    def process_response(self, message):
        self.logger.debug("process_response called")
        for key in sorted(self.pluginobjs.keys()):
            if self.in_plugin_scope(message, key):
                self.logger.debug("plugin '%s' is in scope, processing" % key)
                if (hasattr(self.pluginobjs[key], 'process_response') and inspect.ismethod(self.pluginobjs[key].process_response)):
                    try:
                        self.pluginobjs[key].process_response(message)
                    except Exception, e:
                        self.logger.error("exception in '%s' process_response():\n%s" % (key, shared.indent(traceback.format_exc().strip(), 1)))
                else:
                    self.logger.error("skipping plugin '%s', process_response not defined" % key)
            else:
                self.logger.debug("plugin '%s' is not in scope, SKIPPING" % key)

    def process_menuitem_click(self, caption, messages):
        self.logger.debug("process_menuitem_click() called with caption '%s'" % caption)
        self.logger.debug("current handler_map : %s" % self.global_config['internals']['handler_map'])
        if (caption in self.global_config['internals']['handler_map']):
            pname = self.global_config['internals']['handler_map'][caption]
            self.logger.debug("click '%s' maps to plugin '%s'" % (caption, pname))
            if (pname in self.pluginobjs):
                if (hasattr(self.pluginobjs[pname], 'process_menuitem_click') and inspect.ismethod(self.pluginobjs[pname].process_menuitem_click)):
                    self.pluginobjs[pname].process_menuitem_click(caption, messages)
                else:
                    self.logger.error("could not process menu click, plugin '%s' has no process_menuitem_click() function" % pname)
            else:
                self.logger.error("could not process menu click, plugin '%s' not loaded" % pname)
        else:
            self.logger.error("could not process menu click, no mapping to plugin")

