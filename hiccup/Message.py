# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import SharedFunctions as shared
from java.net import URL

import re, logging, urlparse

class Message:

    def __init__(self, config, toolName, messageReference, messageIsRequest, remoteHost,
                 remotePort, serviceIsHttps, httpMethod, url, resourceType, statusCode,
                 responseContentType, message, interceptAction):
        #create new Message object, based on data passed in from Burp
        self.logger = logging.getLogger()
        self.global_config = config
        self.message = {}
        self.message['tool'] = toolName
        self.logger.debug("new Message object w/ reference : %s" % messageReference)
        if (messageReference != '~'):
            self.message['ref'] = messageReference + 1
        else:
            self.message['ref'] = messageReference
        self.message['method'] = httpMethod
        #parse out the url
        self.j_url = url
        if (str(url).startswith('http://') or str(url).startswith('https://')):
            self.message['url'] = str(url)
        else:
            self.message['url'] = "%s://%s%s" % (('https' if serviceIsHttps else 'http'), remoteHost, url)
        self.message['parsed-url'] = urlparse.urlparse(self.message['url'])
        self.message['isreq'] = messageIsRequest
        if messageIsRequest:
            self.message['type'] = 'request'
        else:
            self.message['type'] = 'response'
        self.message['ishttps'] = serviceIsHttps
        self.message['raw'] = message
        (self.message['headers'], self.message['body']) = self._separate_message(message, 'string')
        (self.message['raw-headers'], self.message['raw-body']) = self._separate_message(message, 'raw')
        self.message['parsed-headers'] = self._parse_headers()
        self.message['referer'] = self.get_header('referer')
        #Burp doesn't always provide the Content-type even if the header exists
        if messageIsRequest == False:
            if responseContentType != '':
                self.message['contenttype'] = responseContentType
            else:
                self.message['contenttype'] = self._parse_content_type()
        else:
            self.message['contenttype'] = None
        self.message['resourcetype'] = resourceType
        self.message['statuscode'] = statusCode
        self.message['remotehost'] = remoteHost
        self.message['remoteport'] = remotePort
        self.message['interceptaction'] = interceptAction[0]
        self.message['highlight'] = None
        self.message['comment'] = None

    def is_changed(self):
        if (self.message['raw'].tostring() == self.message['headers'] + self.message['body']):
            return False
        else:
            return True

    def from_proxy(self):
        if (self.message['tool'] == 'proxy' and self.message['ref'] != '~'):
            self.logger.debug("message is from proxy : %s" % self)
            return True
        self.logger.debug("message is NOT from proxy : %s" % self)
        return False

    def is_request(self):
        return self.message['isreq']

    def is_https(self):
        return self.message['ishttps']

    def set_intercept_action(self, intercept):
        self.logger.debug("setting intercept action: %s" % intercept)
        if intercept in self.global_config['internals']['intercept_actions']:
            self.message['interceptaction'] = self.global_config['internals']['intercept_actions'][intercept]
        else:
            self.logger.error("could not set intercept action to '%s', using default '%s'" % (intercept, self.global_config['default_intercept_action']))
            self.message['interceptaction'] = self.global_config['default_intercept_action']

    def in_burp_scope(self):
        jurl = URL(self['url'])
        self.logger.debug("testing message scope for url: %s" % jurl)
        return self.global_config['callbacks'].isInScope(jurl)

    def is_highlighted(self):
        if self.message['highlight'] != None:
            return True
        return False

    def set_highlight(self, color):
        if color in [ None, 'red', 'orange', 'yellow', 'green', 'cyan', 'blue', 'pink', 'magenta', 'gray']:
            self.message['highlight'] = color
        else:
            self.logger.error("highlight color '%s' is not valid, setting to None" % color)
            self.message['highlight'] = None

    def get_highlight(self):
        return self.message['highlight']

    def is_commented(self):
        if 'comment' in self.message and self.message['comment'] != None:
            self.logger.debug("is_commented returning True")
            return True
        return False

    def set_comment(self, comment):
        self.message['comment'] = comment

    def get_comment(self):
        return self.message['comment']

    def host_in_domain(self, domain):
        if self.message['remotehost'].endswith(domain):
            return True
        return False

    def path_contains(self, pathfrag):
        if pathfrag in self.message['parsed-url'].path:
            return True
        return False

    def path_starts_with(self, pathfrag):
        if self.message['parsed-url'].path.startswith(pathfrag):
            return True
        return False

    def url_contains(self, expr):
        if (re.search(expr, self.message['url'], re.IGNORECASE) != None):
            return True
        return False

    def url_matches(self, expr):
        if (re.match(expr, self.message['url'], re.IGNORECASE) != None):
            return True
        return False

    def message_contains(self, expr):
        if re.search(expr, self.message['headers'], re.IGNORECASE) or re.search(expr, self.message['body'], re.IGNORECASE):
            return True
        return False
    
    def has_header(self, header):
        return h.lower() in self.message['parsed-headers']

    def has_headers(self, headers):
        for h in headers:
            if h.lower() not in self.message['parsed-headers']:
                return False
        return True

    def headers_contain(self, expr):
        self.logger.debug("headers_contain searching for expr '%s'" % expr)
        for header in self.message['parsed-headers']:
            if re.search(expr, self.message['parsed-headers'][header], re.IGNORECASE):
                return True
        return False

    def header_contains(self, header, expr):
        if header.lower() in self.message['parsed-headers']:
            if re.search(expr, self.message['parsed-headers'][header], re.IGNORECASE):
                return True
        return False

    def body_contains(self, expr):
        if re.search(expr, self.message['body'], re.IGNORECASE):
            return True
        return False

    def has_header(self, header):
        if header.lower() in self.message['parsed-headers']:
            return True
        return False

    def get_header(self, header):
        if header.lower() in self.message['parsed-headers']:
            return self.message['parsed-headers'][header.lower()]
        return None

    def update_content_length(self):
        re_contentlength = re.compile('Content\-Length\:\s+\d+')
        self.message['headers'] = re.sub(re_contentlength, "Content-Length: " +
            str(len(self.message['body'])), self.message['headers'])

    #helpers
    def _parse_headers(self):
        res = {}
        for header in self.message['headers'].splitlines()[1:]:
            header = header.split(":", 1)
            if len(header) == 2:
                res[header[0].strip().lower()] = header[1].strip()
        return res

    def _parse_content_type(self):
        for header in self.message['headers'].splitlines()[1:]:
            header = header.split(":", 1)
            if len(header) == 2 and header[0].strip().lower() == 'content-type':
                return header[1].split(";", 1)[0].strip()

    def _separate_message(self, rawmsg, format):
        headers = ''
        content = ''
        #find 13, 10, 13, 10 sequence (CRLF-CRLF marker between header and content)
        for index,value in enumerate(rawmsg):
            if value == 13:
                try:
                    if (rawmsg[index+1] == 10 and rawmsg[index+2] == 13 and rawmsg[index+3] == 10):
                        headers = rawmsg[0:index+4]
                        content = rawmsg[index+4:]
                        break
                except IndexError, e:
                    break
        if (headers == ''):
            #we didn't find the CRLF-CRLF marker -> case where there are only headers, no content
            headers = message
            content = array.array('B', '')
        if (format == 'string'):
            return (headers.tostring(), content.tostring())
        else:
            return (headers,content)

    def __str__(self):
        return "%s [%s] %s" % (self.message['type'], self.message['ref'], self.message['url'])

    def __getitem__(self, key):
        if key in self.message:
            return self.message[key]
        else:
            return None

    def __setitem__(self, key, value):
        self.message[key] = value
