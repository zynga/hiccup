# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

import json
import re

# plugin to automatically manipulate JSON data structures as they pass through the proxy

class JsonManipulation (BasePlugin.BasePlugin):

    required_config = ['delete_keys', 'set_values']

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config)

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
                self.logger.error("exception reading JSON: %s" % e)
            else:
                count = self.traverse_json_obj(jsondata, 0, 0)
                self.logger.info("made %s modifications in %s" % (count, message))
                if (count > 0):
                    message['body'] = json.write(jsondata)

    def traverse_json_obj(self, obj, level, count):
        level = level + 1
        if (obj == None):
            pass
        elif (isinstance(obj,str) or isinstance(obj,unicode)):
            pass
        elif (isinstance(obj,int) or isinstance(obj,long) or isinstance(obj,float)):
            pass
        elif (isinstance(obj,bool)):
            pass
        elif(isinstance(obj,dict)):
            #all manipulation is at the dict level
            for delkey in self.global_config[self.plugin_name]['delete_keys']:
                if (delkey in obj.keys()):
                    del obj[delkey]
                    count = count + 1
            for (setkey, setval) in self.global_config[self.plugin_name]['set_values'].iteritems():
                if (setkey in obj.keys()):
                    #deal with list case
                    if (isinstance(obj[setkey], list)):
                        for i in range(0,len(obj[setkey])):
                            obj[setkey][i] = setval
                    #otherwise it's just a single value to replace
                    else:
                        obj[setkey] = setval
                    count = count + 1
            for (k,subobj) in obj.iteritems():
                count = self.traverse_json_obj(subobj, level, count)
        else:
            for (subobj) in obj:
                count = self.traverse_json_obj(subobj, level, count)
        return count
