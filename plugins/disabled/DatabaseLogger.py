# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

from hiccup import BasePlugin
from hiccup import SharedFunctions as shared

from java.sql import DriverManager
from java.sql import SQLException
from java.lang import Class

import os, sys

# plugin to log all requests/responses, and content of certain types, to an SQLite database
# - filename that data will be logged to is set here:

class DatabaseLogger (BasePlugin.BasePlugin):

    required_config = ['storable_types', 'output_file']
    plugin_scope = 'proxy_only'

    def __init__(self, global_config):
        BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)
        self.dbfile = self.global_config[self.plugin_name]['output_file']
        self.dburl = "jdbc:sqlite:" + self.dbfile
        dbdriver = "org.sqlite.JDBC"
        Class.forName(dbdriver)
        if (os.path.isfile(self.dbfile) == True):
            #use existing db schema
            self.logger.info("%s already exists, will be appending to database" % (self.dbfile))
            self.db = DriverManager.getConnection(self.dburl)
            stmt = self.db.createStatement()
        else:
            #create db file
            self.logger.info("creating db file %s" % (self.dbfile))
            self.db = DriverManager.getConnection(self.dburl)
            stmt = self.db.createStatement()
            stmt.executeUpdate('''CREATE TABLE IF NOT EXISTS "hiccuplog" (ref INTEGER, type BOOLEAN, url TEXT, headers TEXT, content BLOB)''')

    def __del__(self):
        self.db.close()
        BasePlugin.BasePlugin.__del__(self)

    def process_request(self, message):
        self.process_message(message)
    
    def process_response(self, message):
        self.process_message(message)

    def process_message(self, message):
        self.logger.info("logging %s" % (message))
        try:
            prep = self.db.prepareStatement("INSERT INTO hiccuplog VALUES (?,?,?,?,?)")
            if (message['ref'] != '~'):
                prep.setInt(1, message['ref'])
            else:
                prep.setInt(1, -1)
            if message.is_request():
                prep.setBoolean(2, 0)
            else:
                prep.setBoolean(2, 1)
            prep.setString(3, message['url'])
            prep.setString(4, message['headers'])
            # limit the MIME types for which we will save content to the database
            if (self.is_storable_content(message['contenttype'])):
                prep.setString(5, message['body'])
            else:
                prep.setString(5, 'CONTENT NOT STORED (Content-type: %s)' % message['contenttype'])
            prep.addBatch()
            prep.executeBatch()
        except IOError, msg:
            self.logger.error("problem preparing query - %s" % (msg))
        except SQLException, msg:
            self.logger.error("database problem - %s" % (msg))

    def is_storable_content(self, ctype):
        if ctype == None:
            return True
        else:
            for stortype in self.global_config[self.plugin_name]['storable_types']:
                if ctype.startswith(stortype):
                    return True
        return False
