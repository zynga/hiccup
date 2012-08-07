Hiccup - Burp Suite Python Extensions
=====================================

Hiccup is a framework that allows the Burp Suite (a web application security testing tool, [http://portswigger.net/burp/](http://portswigger.net/burp/)) to be extended and customized, through the interface provided by Burp Extender ([http://portswigger.net/burp/extender/](http://portswigger.net/burp/extender/)).  Its aim is to allow for the development and integration of custom testing functionality into the Burp tool using Python request/response handler plugins.

TLDR
----
Hiccup lets you write Python plugins for Burp that allow for customized handling of requests, responses, and menuitem clicks.  The quickest way to see what Hiccup supports is to look at the example plugins, in plugins/disabled.


Installing and Using Hiccup
---------------------------

1. Clone/unzip this repository/file into its own directory, retaining the existing subdirectory structure.
2. Copy a Burp Suite JAR file (free or professional, see [http://portswigger.net/burp/download.html](http://portswigger.net/burp/download.html)) into this same directory.
3. Review the hiccup.yaml configuration file and make any immediate changes that might be necessary.
4. From a shell or window, run the hiccup.sh (Mac OS X or Linux) or hiccup.bat (Windows) file, and start using Burp.  Watch the terminal/DOS window for confirmation that Hiccup has initialized and for output from the plugins.
5. Use web browser and Burp as usual.  Hiccup plugin output will appear in the terminal/DOS window.
6. Move plugins in and out of the plugins/ directory to enable or disable them (plugins located in the plugins/disabled/ directory, or other sub-directories, will not be loaded).  Modify, or create new plugins as necessary.  Movements and edits to plugins are detected and reloaded automatically.


Extensions Framework
--------------------

The framework is made up of components as follow:

* hiccup/hiccup.yaml

    Base configuration file for the Hiccup framework.  The YAML file contains global settings along with plugin-specific configuration items, and is easily extended with new sections added as required for additional plugins.  Hiccup will detect any changes to the configuration file during runtime and reload as required.

* hiccup/BurpExtender.py

    Main interface from Hiccup to Burp Extender.  Defines the processProxyMessage and processHttpMessage functions, which create the Message object with the request/response data and passes it to the PluginManager for handling.  It also registers the Burp Extender callbacks object (through the registerExtenderCallbacks function) which exposes all IBurpExtenderCallbacks functions ([http://portswigger.net/burp/extender/burp/IBurpExtenderCallbacks.html](http://portswigger.net/burp/extender/burp/IBurpExtenderCallbacks.html)), and initializes GlobalConfig and PluginManager at load time.

* hiccup/MenuItemHandler.py

    Secondary interface from Hiccup to Burp Extender.  Defines the menuItemClicked function, which creates an array of Message objects with associated request/response data and passes it to the PluginManager for handling.

* hiccup/Message.py

    The object that stores various data associated with the request/response being processed.  Data values stored include ref, method, url, headers (raw and parsed), body, contenttype, resourcetype, statuscode, remotehost, and remoteport.  Various helper methods are provided to aid in ease of plugin development, and additional helper methods can be added to the base object as necessary.

    Plugins make their changes directly to this object as processing occurs.

* hiccup/PluginManager.py

    Locates, loads, reloads, and unloads plugins according to file existence/changes as monitored by FileWatcher.  Pushes messages from Burp Extender through to individual plugins.

    See plugins/README.md for detailed documentation.

* hiccup/FileWatcher.py

    Generic file change tracker, used by various Hiccup elements to detect changes to files.

* hiccup/GlobalConfig.py

    Defines configuration options and state-related objects that are used globally by Hiccup.  A GlobalConfig object is initialized when Hiccup is first loaded, and is passed to each plugin for reference as appropriate.

    Configuration is read in from the YAML configuration file, hiccup.yaml.

* hiccup/SharedFunctions.py

    Stores generic shared functions.

* hiccup/BasePlugin.py

    The base class from which plugins should be defined as subclasses.

* plugins/

    Holds Python request/response handler plugins.

    The plugins directory will be automatically monitored by the PluginManager, which will load, unload, and reload plugins automatically (as they are moved into or out of the directory, or as changed are detected to individual plugin files).

    See plugins/README.md for detailed documentation.

* plugins/disabled/

    Plugins that should not be loaded by PluginManager are stored in this directory (or other sub-directories that are created).


Plugins
-------

See plugins/README.md.


Authors
=======
Hiccup was developed by Jamie Finnigan (http://twitter.com/chair6), based on initial work by David Robert (http://blog.ombrepixel.com/post/2010/08/30/Extending-Burp-Suite-in-Python), and is continued as an official Zynga OpenSource (http://code.zynga.com/) project.


License
=======
Copyright (c) 2012 Zynga Inc. http://zynga.com/

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
