#!/usr/bin/env python
#
# thug.py
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston,
# MA  02111-1307  USA

import sys
import os
import errno
import getopt
import datetime
import urlparse
import hashlib
import httplib2
import logging

from DOM.W3C import w3c
from DOM.Personality import Personality
from DOM import Window, DFT
from Logging.ThugLogging import ThugLogging
from Plugins.ThugPlugins import *

__thug_version__ = '0.4.1'

log = logging.getLogger("Thug")
log.setLevel(logging.WARN)


class ThugOpts(dict):
    proxy_schemes = ('http', 'socks4', 'socks5', )

    def __init__(self):
        self._proxy_info = None
        self.local       = False
        self.ast_debug   = False
        self._useragent  = 'xpie61'
        self._referer    = 'about:blank'
        self.Personality = Personality()

    def set_proxy_info(self, proxy):
        p = urlparse.urlparse(proxy)
        if p.scheme.lower() not in self.proxy_schemes:
            log.warning('[WARNING] Skipping invalid proxy scheme (valid schemes: http, socks4, socks5)')
            return

        proxy_type = getattr(httplib2.socks, "PROXY_TYPE_%s" % (p.scheme.upper(),))
        self._proxy_info = httplib2.ProxyInfo(proxy_type = proxy_type,
                                              proxy_host = p.hostname,
                                              proxy_port = p.port if p.port else 8080,
                                              proxy_user = p.username,
                                              proxy_pass = p.password)

    def get_proxy_info(self):
        return self._proxy_info

    proxy_info = property(get_proxy_info, set_proxy_info)

    def get_useragent(self):
        return self._useragent

    def set_useragent(self, useragent):
        self._useragent = useragent

    useragent = property(get_useragent, set_useragent)

    def get_referer(self):
        return self._referer

    def set_referer(self, referer):
        self._referer = referer

    referer = property(get_referer, set_referer)


class Thug:
    def __init__(self, args):
        self.args      = args
        log.ThugLogging = ThugLogging(__thug_version__)
        log.ThugOpts    = ThugOpts()

    def __call__(self):
        self.analyze()

    def usage(self):
        msg = """
Synopsis:
    Thug: Pure Python honeyclient implementation

    Usage:
        python thug.py [ options ] url

    Options:
        -h, --help          \tDisplay this help information
        -o, --output=       \tLog to a specified file
        -r, --referer=      \tSpecify a referer
        -p, --proxy=        \tSpecify a proxy (see below for format and supported schemes)
        -l, --local         
        -v, --verbose       \tEnable verbose mode    
        -d, --debug         \tEnable debug mode
        -a, --ast-debug     \tEnable AST debug mode (requires debug mode) 
        -u, --useragent=    \tSelect a user agent (see below for values, default: xpie61)

    Proxy Format:
        scheme://[username:password@]host:port (supported schemes: http, socks4, socks5)

    Available User-Agents:
"""
        for key, value in sorted(log.ThugOpts.Personality.iteritems(), key = lambda (k, v): (v['id'], k)):
            msg += "\t%s\t\t\t%s\n" % (key, value['description'], )

        print msg
        sys.exit(0)

    def run(self, window):
        dft = DFT.DFT(window)
        dft.run()

    def run_local(self, url):
        log.ThugLogging.set_url(url)
        log.ThugOpts.local = True

        html   = open(url, 'r').read()
        doc    = w3c.parseString(html)
        window = Window.Window('about:blank', doc, personality = log.ThugOpts.useragent)
        window.open()
        self.run(window)

    def run_remote(self, url):
        if urlparse.urlparse(url).scheme is '':
            url = 'http://%s' % (url, )

        log.ThugLogging.set_url(url)

        doc    = w3c.parseString('')
        window = Window.Window(log.ThugOpts.referer, doc, personality = log.ThugOpts.useragent)
        window = window.open(url)
        if window:
            self.run(window)

    def build_logbasedir(self, url):
        t = datetime.datetime.now()
        m = hashlib.md5()
        m.update(url)

        base = os.getenv('THUG_LOGBASE', '..')
        log.baseDir = os.path.join(base, 'logs', m.hexdigest(), t.strftime("%Y%m%d%H%M%S"))
        
        try:
            os.makedirs(log.baseDir)
        except OSError as e:
            if e.errno == errno.EEXIST:
                pass
            else:
                raise

        with open(os.path.join(base, 'logs', 'thug.csv'), 'a+r') as fd:
            csv_line = '%s,%s\n' % (m.hexdigest(), url, )
            for l in fd.readlines():
                if l == csv_line:
                    return

            fd.write(csv_line)

    def analyze(self):
        p = getattr(self, 'run_remote', None)

        try:
            options, args = getopt.getopt(self.args, 'hu:o:r:p:lvda',
                ['help', 
                'useragent=', 
                'logfile=',
                'referer=',
                'proxy=',
                'verbose',
                'debug', 
                'ast-debug',
                ])
        except getopt.GetoptError:
            self.usage()

        if not options and not args:
            self.usage()

        for option in options:
            if option[0] == '-h' or option[0] == '--help':
                self.usage()

        self.build_logbasedir(args[0])

        for option in options:
            if option[0] in ('-u', '--useragent', ):
                log.ThugOpts.useragent = option[1]
            if option[0] in ('-o', '--output', ):
                fh = logging.FileHandler(os.path.join(log.baseDir, option[1]))
                log.addHandler(fh)
            if option[0] in ('-r', '--referer', ):
                log.ThugOpts.referer = option[1]
            if option[0] in ('-p', '--proxy', ):
                log.ThugOpts.proxy_info = option[1]
            if option[0] in ('-l', '--local', ):
                p = getattr(self, 'run_local')
            if option[0] in ('-v', '--verbose', ):
                log.setLevel(logging.INFO)
            if option[0] in ('-d', '--debug', ):
                log.setLevel(logging.DEBUG)
            if option[0] in ('-a', '--ast-debug', ):
                log.ThugOpts.ast_debug = True

        if p:
            ThugPlugins(PRE_ANALYSIS_PLUGINS, self)()
            p(args[0])
            ThugPlugins(POST_ANALYSIS_PLUGINS, self)()
        
        log.ThugLogging.log_event()
        return log

if __name__ == "__main__":
    Thug(sys.argv[1:])()
