# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from burp import IBurpExtender
import sys, os, re, time, logging

from hiccup import GlobalConfig, PluginManager, FileWatcher, Message, MenuItemHandler
from hiccup import SharedFunctions as shared

class BurpExtender(IBurpExtender):

    config_file = 'hiccup.yaml'
    conf_watcher = None

    init_level = 0 #0 at launch, 1 with fwatcher, 2 with config, 3 with callbacks, 4 with pluginmanager
    init_sleep = 3 #seconds to wait before retesting for callbacks
    file_watcher = None
    global_config = None
    plugin_manager = None
    callbacks = None

    logger = None
    handler = None
    log_level = logging.INFO  #default - logging.INFO or logging.DEBUG
    log_format = '[%(module)s] %(message)s'

    ######
    ### INIT FUNCTIONS
    ######
    def __init__(self):
        self.__init_logger()
        self.__init_filewatcher()
        self.__init_config()

    def __init_logger(self):
        if self.logger == None:
            self.logger = logging.getLogger()
        if self.global_config != None:
            try:
                self.log_level = logging.DEBUG if self.global_config['defaults']['log_level'] == 'debug' else logging.INFO
            except TypeError, e:
                self.logger.error("config file does not define global -> log_level, using default")
            try:
                self.log_format = self.global_config['defaults']['log_format']
            except TypeError, e:
                self.logger.error("config file does not define global -> log_format, using default")
        self.logger.setLevel(self.log_level)
        if self.handler == None:
            self.handler = logging.StreamHandler(sys.stdout)
        self.handler.setFormatter(logging.Formatter(self.log_format))
        self.logger.addHandler(self.handler)

    def __init_filewatcher(self):
        try:
            self.file_watcher = FileWatcher.FileWatcher('hiccup', ['GlobalConfig.py', 'PluginManager.py', 'SharedFunctions.py', 'zSharedFunctions.py', 'Message.py', 'BasePlugin.py', 'MenuItemHandler.py'])
        except Exception, e:
            self.logger.error("exception initializing FileWatcher : %s" % (e))
        else:
            self.__change_init(1)

    def __init_config(self):
        if os.path.isfile(self.config_file) == False:
            self.logger.error("Configuration file '%s' not found." % (os.path.join(os.getcwd(), self.config_file)))
        else:
            self.global_config = GlobalConfig.GlobalConfig(self.config_file)
            self.conf_watcher = FileWatcher.FileWatcher('.', [self.config_file,])
            if self.global_config.is_valid():
                self.__init_logger()
                self.__change_init(2)
            else:
                self.__change_init(1, True)

    def __init_callbacks(self, callbacks):
        if self.init_level > 1:
            try:
                self.callbacks = callbacks
                self.global_config.add_callbacks(callbacks)
            except Exception, e:
                self.logger.error("exception initializing callbacks : %s" % (e))
                self.callbacks = None
            else:
                self.__change_init(3)
                self.__init_menuhandler()
                self.__init_pluginmanager()

    def __init_pluginmanager(self):
        while self.init_level != 3:
            self.logger.info("waiting for Burp to finish initializing environment")
            time.sleep(self.init_sleep)
        try:
            self.logger.debug("starting PluginManager")
            self.plugin_manager = PluginManager.PluginManager(self.global_config)
            self.global_config['internals']['menu_handler'].set_plugin_manager(self.plugin_manager)
        except Exception, e:
            self.logger.error("exception initializing PluginManager : %s" % (e))
        else:
            self.__change_init(4, True)

    def __init_menuhandler(self):
        self.global_config['internals']['menu_handler'] = MenuItemHandler.MenuItemHandler(self.global_config, self.logger, self.plugin_manager, self)

    def __change_init(self, level, notify=False):
        if level == 1:
            self.logger.debug("switching to init_level 1")
            if notify: self.logger.info("Burp will proxy messages but they will not be processed by Hiccup")
        elif level == 2:
            self.logger.debug("switching to init_level 2")
            if notify: self.logger.info("Burp will proxy messages but they will not be processed by Hiccup")
        elif level == 3:
            self.logger.debug("switching to init_level 3")
            if notify: self.logger.info("Burp will proxy messages but they will not be processed by Hiccup")
        elif level == 4:
            self.logger.debug("switching to init_level 4")
            if notify: self.logger.info("Hiccup initialized")
        else:
            self.logger.error("__change_init to unrecognized init_level: %s" % level)

        self.init_level = level

    ### BURP FUNCTIONS
    #registerExtenderCallbacks called on startup to register callbacks object
    def registerExtenderCallbacks(self, callbacks):
        self.logger.debug("registerExtenderCallbacks received call (init_level:%s)" % (self.init_level))
        self.__init_callbacks(callbacks)

    ## processHttpMessage called whenever any of Burp's tools makes an HTTP request or receives a response
    ## - for requests, involved immediately before request sent to network
    ## - for responses, invoked immediately after request is received from network
    def processHttpMessage(self, toolName, messageIsRequest, messageInfo):
        self.reload_on_change()
        if self.init_level == 4:
            messageType = toolName
            messageReference = '~'
            remoteHost = messageInfo.getHost()
            remotePort = messageInfo.getPort()
            serviceIsHttps = True if messageInfo.getProtocol() == 'https' else False
            httpMethod = ''
            url = '%s://%s%s' % (messageInfo.getUrl().getProtocol(), messageInfo.getUrl().getHost(), messageInfo.getUrl().getPath())
            if (messageInfo.getUrl().getQuery() != None):
                url = '%s?%s' % (url, messageInfo.getUrl().getQuery())
            resourceType = ''
            statusCode = '' if messageIsRequest else messageInfo.getStatusCode()
            responseContentType = ''
            messageRaw = messageInfo.getRequest() if messageIsRequest else messageInfo.getResponse()
            interceptAction = ['',]
            message = Message.Message(self.global_config, messageType, messageReference, messageIsRequest,
                                remoteHost, remotePort, serviceIsHttps, httpMethod, url, resourceType,
                                statusCode, responseContentType, messageRaw, interceptAction)
            self.__process_message(message)
            if message.is_changed():
                message.update_content_length()
                messageInfo.setRequest(message['headers'] + message['body']) if messageIsRequest else messageInfo.setResponse(message['headers'] + message['body'])
            if message.is_highlighted():
                messageInfo.setHighlight(message.get_highlight())
            if message.is_commented():
                messageInfo.setComment(message.get_comment())

    ## processProxyMessage method, called by Burp when a message is passed through the proxy.
    def processProxyMessage(self, messageReference, messageIsRequest, remoteHost, remotePort,
                                  serviceIsHttps, httpMethod, url, resourceType, statusCode,
                            responseContentType, messageRaw, interceptAction):
        self.reload_on_change()
        if self.init_level == 4:
            messageType = 'proxy'
            message = Message.Message(self.global_config, messageType, messageReference, messageIsRequest,
                                remoteHost, remotePort, serviceIsHttps, httpMethod, url,
                                resourceType, statusCode, responseContentType, messageRaw, interceptAction)
            self.__process_message(message)
            interceptAction[0] = message['interceptaction']
            if message.is_changed() == False:
                return message['raw']
            else:
                message.update_content_length()
                return message['headers'] + message['body']

    ## applicationClosing method, called by Burp immediately before exit
    def applicationClosing(self):
        self.logger.info("Hiccup shutting down during Burp exit")
        if (self.global_config['defaults']['auto_delete_class_files'] == True):
            for fname in os.listdir(self.global_config['defaults']['plugin_directory']):
                if (fname.endswith('$py.class')):
                    self.logger.debug("deleting stale .class file : %s" % fname)
                    os.remove(os.path.join(self.global_config['defaults']['plugin_directory'], fname))
    ######
    ### INTERNAL FUNCTIONS
    ######

    # run message (request/response) through plugins via plugin_manager
    def __process_message(self, message):
        if (message.is_request()):
            self.plugin_manager.process_request(message)
        else:
            self.plugin_manager.process_response(message)

    # do config/module/plugin reloads, if changes detected
    def reload_on_change(self):
        self.logger.debug("testing for config/module/plugin changes")
        if len(self.conf_watcher.get_changed()) > 0:
            self.logger.info("configuration file change detected, reloading")
            self.global_config.reload_from_file()
            if self.global_config.is_valid() == False:
                self.__change_init(1, True)
            else:
                self.plugin_manager = PluginManager.PluginManager(self.global_config)
                self.global_config['internals']['menu_handler'].set_plugin_manager(self.plugin_manager)
                self.__init_logger()
                self.__change_init(4, True)
        if self.init_level > 2:
            for fname in self.file_watcher.get_changed():
                modname = ''.join(fname.split('.')[:-1])
                self.logger.info(" module change detected, reloading '%s'" % (modname))
                if modname == 'BasePlugin':
                    self.plugin_manager = PluginManager.PluginManager(self.global_config)
                    self.global_config['internals']['menu_handler'].set_plugin_manager(self.plugin_manager)
                else:
                    reload(sys.modules["hiccup." + modname])
                    if (modname == 'GlobalConfig'):
                        self.global_config = GlobalConfig.GlobalConfig(self.config_file, self.callbacks)
                        self.plugin_manager = PluginManager.PluginManager(self.global_config)
                        self.global_config['internals']['menu_handler'].set_plugin_manager(self.plugin_manager)
                    elif (modname == 'PluginManager'):
                        self.plugin_manager = PluginManager.PluginManager(self.global_config)
                        self.global_config['internals']['menu_handler'].set_plugin_manager(self.plugin_manager)
        if self.init_level == 4:
            self.plugin_manager.reload_changed()
