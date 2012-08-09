# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from burp import IMenuItemHandler
import sys, os, re, time, logging

import GlobalConfig, Message
import SharedFunctions as shared

class MenuItemHandler(IMenuItemHandler):

    def __init__(self, config, logger, mgr, hiccup):
        self.global_config = config
        self.logger = logger
        self.plugin_manager = mgr
        self.hiccup = hiccup

    ## menuItemClicked method, called by Burp when the user clicks a custom menu item.
    def menuItemClicked(self, menuItemCaption, selectedMessages):
        self.hiccup.reload_on_change()
        self.logger.debug("menuItemClicked : %s" % menuItemCaption)
        messages = []
        for messageInfo in selectedMessages:
            self.logger.debug("menuItemClicked() messageInfo : %s" % messageInfo)
            messageReference = '~'
            remoteHost = messageInfo.getHost()
            remotePort = messageInfo.getPort()
            serviceIsHttps = True if messageInfo.getProtocol() == 'https' else False
            httpMethod = ''
            url = '%s://%s%s' % (messageInfo.getUrl().getProtocol(), messageInfo.getUrl().getHost(), messageInfo.getUrl().getPath())
            resourceType = ''
            responseContentType = ''
            interceptAction = ['',]
            #deal with request
            messages.append(Message.Message(self.global_config, 'clicked', messageReference, True,
                            remoteHost, remotePort, serviceIsHttps, httpMethod, url, resourceType,
                            '', responseContentType, messageInfo.getRequest(), interceptAction, messageInfo))
            #and response
            messages.append(Message.Message(self.global_config, 'clicked', messageReference, False,
                            remoteHost, remotePort, serviceIsHttps, httpMethod, url, resourceType,
                            messageInfo.getStatusCode(), responseContentType, messageInfo.getResponse(),
                            interceptAction, messageInfo))
        self.plugin_manager.process_menuitem_click(menuItemCaption, messages)
        for message in messages:
            if message.is_highlighted():
                self.logger.debug("need to update highlight for msg : %s" % message)
                message['messageinfo'].setHighlight(message.get_highlight())
            if message.is_commented():
                self.logger.debug("need to update comment for msg : %s" % message)
                message['messageinfo'].setComment(message.get_comment())

    def set_plugin_manager(self, mgr):
        self.plugin_manager = mgr

