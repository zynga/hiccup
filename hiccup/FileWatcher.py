# Hiccup - Burp Suite Python Extensions
# Copyright 2012 Zynga Inc.

import os
import logging

class FileWatcher:

    def __init__(self, dname, fnames):
        self.dname = dname
        self.fnames = {}
        self.logger = logging.getLogger()
        for fname in fnames:
            fstat = self.__fstat(self.dname, "%s" % fname)
            if fstat != False:
                self.fnames[fname] = fstat
        self.logger.debug("initialized (%s : %s)" % (self.dname, self.fnames.keys()))

    def get_changed(self):
        changed = []
        for (fname,v) in self.fnames.iteritems():
            tmpv = self.__fstat(self.dname, "%s" % fname)
            if (tmpv != False and tmpv != v):
                self.logger.debug("change detected in %s" % (os.path.join(self.dname, "%s" % fname)))
                self.fnames[fname] = tmpv
                changed.append(fname)
        return changed

    def remove_item(self, fname):
        if (fname in self.fnames.keys()):
            del(self.fnames[fname])

    def add_item(self, fname):
        if (fname not in self.fnames.keys()):
            fstat = self.__fstat(self.dname, "%s" % fname)
            if (fstat != False):
                self.fnames[fname] = fstat

    def __fstat(self, dname, fname):
        try:
            fstat = os.stat(os.path.join(dname, fname)).st_mtime
        except OSError, e:
            return False
        else:
            return fstat
