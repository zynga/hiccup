Hiccup Plugins
==============

Example Plugin
--------------
A basic debug plugin template looks like this:

    from hiccup import BasePlugin
    from hiccup import SharedFunctions as shared

    class Debug (BasePlugin.BasePlugin):

        required_config = []
        plugin_scope = 'proxy_only'

        def __init__(self, global_config):
            BasePlugin.BasePlugin.__init__(self, global_config, self.required_config, self.plugin_scope)

        def process_request(self, message):
            self.logger.info("processing '%s' request %s" % (message['type'], message))

        def process_response(self, message):
            self.logger.info("processing '%s' response %s" % (message['type'], message))


Plugin Manager
--------------

The PluginManager class (hiccup/PluginManager.py) locates, loads, reloads, and unloads plugins according to file existence/changes as monitored by FileWatcher.  It also pushes messages from Burp Extender through to individual plugins.

Hiccup uses the plugin\_directory configuration flag to identify the location where plugins are to be loaded from.  Plugins that are not currently required to be loaded can can be stored in subdirectories inside of this location.

The plugin\_directory location will be automatically monitored by the PluginManager, which will load, unload, and reload plugins automatically (as they are moved into or out of the directory, or as changed are detected to individual plugin files).

As plugins are loaded, Jython will automatically create a $py.class file.  These can be automatically removed whena  plugin is unloaded (if the global configuration flag 'auto\_delete\_class\_files' is set to True), or can be manually deleted if necessary.


Plugin Structure
----------------
A plugin should:

* Have a unique filename (e.g. UniqueName.py) and define a class with that same name (e.g. UniqueName) that extends BasePlugin.BasePlugin.

* Define an \_\_init\_\_() function, that at a minimum calls BasePlugin.BasePlugin.\_\_init\_\_(self, global\_config).  This constructor may also be used to register menu items, setup other variables used by the plugin, etc.

* Define, as required, process\_request() and process\_response() functions that accept an argument 'message' (a Message object).

* Defined, as required, a process\_menuitem\_click() function that accepts a 'caption' (string with button label) and 'message' (array of Message objects) arguments.

* Define required\_config, a list of variables that this plugin requires be defined in the Hiccup configuration file.  If no configuration items are required then this does not need to be defined.

* Define plugin\_scope, a variable set to one of 'all', 'proxy\_only', or 'http\_only'.  (This is used by Hiccup to determine what message types this particular plugin should be executed for.  If the scope is not defined in the plugin, it will revert to a global default per the configuration file.)

A plugin can access its required\_config items through the global\_config object.  It can also access the IBurpExtenderCallbacks interface through global\_config['callbacks'], and can store temporary data in global\_config['state'].

There is currently minimal plugin validation performed by Hiccup.  Erroneously-defined plugins may cause undetected errors when loaded by PluginManager, but error details should be included in other console output.  Third-party plugins should be reviewed for correctness and security prior to use.

Plugin Scope
------------
The PluginManager executes plugins for each message based on the scope defined for that plugin.  Scope maps to the processHttpMessage() and processProxyMessage() functions defined by Burp Extender.  Plugin scope is treated as follows:

* A plugin with scope 'proxy\_only' will be executed only for messages associated with the Burp Proxy component.  (Plugins are executed only for processProxyMessage() calls.)

* A plugin with scope 'http\_only' scope will be executed for messages associated with all Burp components (Proxy, Repeater, Intruder, Scanner, etc).  Messages will only ever be processed once. (Plugins are executed only for processHttpMessage() calls.)

* A plugin with scope 'all' will be executed for every message.  Messages that pass through the Burp Proxy component will be processed twice.  (Plugins are executed for both processHttpMessage() and processProxyMessage() calls.)

Scope is not relevant when plugins are executed by a menu click event.

Plugin Distribution
-------------------
Should you wish to distribute your plugins to others, you can share the file directly (say, as a mailing list / forum post or gist, or by providing the .py file as a download).  Alternatively, you could setup a Github repository and allow people to use git to clone your repository and pull updates as necessary.

Again, third-party plugins should not necessarily be trusted and should be reviewed for correctness and security prior to use.


Authors
=======
Hiccup was developed by Jamie Finnigan (http://twitter.com/chair6), based on initial work by David Robert (http://blog.ombrepixel.com/post/2010/08/30/Extending-Burp-Suite-in-Python), and is continued as an official Zynga OpenSource (http://code.zynga.com/) project.


License
=======
Copyright (c) 2012 Zynga Inc. http://zynga.com/

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
