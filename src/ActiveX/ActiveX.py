#!/usr/bin/env python
#
# ActiveX.py
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

#import new
import logging
import traceback
import PyV8
from .CLSID import CLSID
import inspect
import traceback

log = logging.getLogger("Thug")

acropdf   = ( 'acropdf.pdf',
              'pdf.pdfctrl',
              'CA8A9780-280D-11CF-A24D-444553540000', )

shockwave = ( 'shockwaveflash.shockwaveflash',
              'shockwaveflash.shockwaveflash.9',
              'shockwaveflash.shockwaveflash.10',
              'swctl.swctl',
              'swctl.swctl.8',
              '233C1507-6A77-46A4-9443-F871F945D258', )

java_deployment_toolkit = ( 'CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA',
                            '8AD9C840-044E-11D1-B3E9-00805F499D93', )

class _ActiveXObject(object):
    shockwave_flash = { 'shockwaveflash.shockwaveflash'    : '10',
                        'shockwaveflash.shockwaveflash.9'  : '9' ,
                        'shockwaveflash.shockwaveflash.10' : '10',
                        'shockwaveflash.shockwaveflash.11' : '11',
                        'shockwaveflash.shockwaveflash.12' : '12'}

    def __init__(self, window, cls, typename = 'name'):
        self.funcattrs = dict()
        self._window   = window
        obj            = None
        methods        = dict()
        self.shockwave = log.ThugVulnModules.shockwave_flash.split('.')[0]
        self.cls       = cls

        if typename == 'id':
            if len(cls) > 5 and cls[:6].lower() == 'clsid:':
                cls = cls[6:].upper()

            if cls.startswith('{') and cls.endswith('}'):
                cls = cls[1:-1]

        if typename == 'name':
            cls = cls.lower()

        # Adobe Acrobat Reader
        if cls in acropdf and log.ThugVulnModules.acropdf_disabled:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        # Shockwave Flash
        if cls in shockwave and log.ThugVulnModules.shockwave_flash_disabled:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        if cls in self.shockwave_flash and self.shockwave not in (self.shockwave_flash[cls], ):
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        _cls = cls

        # Java Deployment Toolkit
        if cls in java_deployment_toolkit and log.ThugVulnModules.javaplugin_disabled:
            log.warning("Unknown ActiveX Object: %s", cls)
            raise TypeError()

        # JavaPlugin
        if cls.lower().startswith('javaplugin'):
            if log.ThugVulnModules.javaplugin_disabled or not cls.endswith(log.ThugVulnModules.javaplugin):
                log.warning("Unknown ActiveX Object: %s", cls)
                raise TypeError()
            else:
                _cls = 'javaplugin'

        # JavaWebStart
        if cls.lower().startswith('javawebstart.isinstalled'):
            if log.ThugVulnModules.javaplugin_disabled or not cls.endswith(log.ThugVulnModules.javawebstart_isinstalled):
                log.warning("Unknown ActiveX Object: %s", cls)
                raise TypeError()
            else:
                _cls = 'javawebstart.isinstalled'

        for c in CLSID:
            if _cls in c[typename]:
                obj = c
                break

        if not obj:
            log.warning("Unknown ActiveX Object: %s", cls)
            #return None
            raise TypeError()

        log.warning("ActiveXObject: %s", cls)

        for method_name, method in obj['methods'].items():
            #_method = new.instancemethod(method, self, _ActiveXObject)
            _method = method.__get__(self, _ActiveXObject)
            setattr(self, "@@%s" % (method_name, ), _method)
            methods[method] = _method

        for attr_name, attr_value in obj['attrs'].items():
            setattr(self, attr_name, attr_value)

        for attr_name, attr_value in obj['funcattrs'].items():
            self.funcattrs[attr_name] = methods[attr_value]

        if cls.lower() in ('wscript.shell', ) and (not hasattr(window, 'WScript') or window.WScript is None):
            window.WScript = self

    def __setattr__(self, name, value):
        self.__dict__[name] = value

        if name in self.funcattrs:
            self.funcattrs[name](value)

    def __getattribute__(self, name):
        #log.warning("__getattribute__(self, %s)" % name)
        try:
            method = super(_ActiveXObject, self).__getattribute__(name)
        except AttributeError:
            method = None
            for key, value in self.__dict__.items():
                if(key.lower() == name.lower()):
                    method = value

            if method is None:
                log.warning("Unknown ActiveX Object (%s) attribute: %s" % (self.cls, name, ))
                raise

        try:
            if name != '__dict__' and hasattr(method, '__self__'):
            # Prevent recursion overflow
                #log.warning('method: %s' % method)
                #log.warning('isinstance(method, ActiveX): %s' % isinstance(method.__self__, _ActiveXObject))
                return ActiveXMethod(method)
                #return method
                #if(isinstance(method.__self__, _ActiveXObject)):
                   #result = method(self)
                   #log.warning('Called method, result: %s' % result)
                   #return result
        except Exception as e:
            print "Exception caught in ActiveX/ActiveX.py:"
            print e
            raise e

        return method
        
    def __getattr__(self, name):
        #print "%s . %s" % (self.cls, name)
        for key, value in self.__dict__.items():
            key = key[2:] if key.startswith('@@') else key
            if key.lower() == name.lower():
                if inspect.isroutine(value):
                    args = inspect.getargspec(value)
                    #print args
                    _args = len(args.args) - 1
                    _defaults = len(args.defaults) if args.defaults else 0
                    #TODO determine suitable methods to proxy through ActiveXMethod
                    if self.cls.lower() == "adodb.stream" and name.lower() == "readtext":
                        #return value
                        return ActiveXMethod(value)
                return value

        if name not in ('__watchpoints__'):
            log.warning("Unknown ActiveX Object (%s) attribute: %s", self.cls, name)

        raise AttributeError

def register_object(s, clsid):
    funcattrs = dict() #pylint:disable=unused-variable
    methods   = dict()
    obj       = None

    if not clsid.startswith('clsid:'):
        log.warning("Unknown ActiveX object: %s", clsid)
        return None

    clsid = clsid[6:].upper()
    if clsid.startswith('{') and clsid.endswith('}'):
        clsid = clsid[1:-1]

    # Adobe Acrobat Reader
    if clsid in acropdf and log.ThugVulnModules.acropdf_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    # Shockwave Flash
    if clsid in shockwave and log.ThugVulnModules.shockwave_flash_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    # Java Deployment Toolkit
    if clsid in java_deployment_toolkit and log.ThugVulnModules.javaplugin_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    # JavaPlugin
    if clsid.lower().startswith('javaplugin') and log.ThugVulnModules.javaplugin_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    # JavaWebStart
    if clsid.lower().startswith('javawebstart.isinstalled') and log.ThugVulnModules.javaplugin_disabled:
        log.warning("Unknown ActiveX Object: %s", clsid)
        raise TypeError()

    for c in CLSID:
        if clsid in c['id']:
            obj = c
            break

    if obj is None:
        log.warning("Unknown ActiveX object: %s", clsid)
        #return None
        raise TypeError()

    for method_name, method in obj['methods'].items():
        #_method = new.instancemethod(method, s, s.__class__)
        _method = method.__get__(s, s.__class__)
        setattr(s, method_name, _method)
        methods[method] = _method

    for attr_name, attr_value in obj['attrs'].items():
        setattr(s, attr_name, attr_value)

    # PLEASE REVIEW ME!
    for attr_name, attr_value in obj['funcattrs'].items():
        if 'funcattrs' not in s.__dict__:
            s.__dict__['funcattrs'] = dict()

        s.__dict__['funcattrs'][attr_name] = methods[attr_value]

class ActiveXMethod(object):
    def __init__(self, method):
        self.method = method
        self.result = None
        log.debug('ActiveXMethod instantiated for %s' % (self.desc()))

    def desc(self):
        return "%s %s" % (self.method.im_self.cls, self.method.im_func.func_name)

    def callResult(self):
        if self.result is None:
            self.result = self.method()
        return self.result

    def __call__(self, *args):
        log.debug('ActiveXMethod %s called' % self.desc())
        #print "type: %s" % (type(self.method.im_class))
        #print dir(self.method)
        result = self.method(*args)
        return result

    def __name__(self):
        log.debug('ActiveXMethod %s __name__ called' % self.desc());
        return 'ActiveXMethod {%s}' % self.desc()

    def __repr__(self):
        log.debug('ActiveXMethod %s __repr__ called' % self.desc())
        return super(ActiveXMethod, self).__repr__()

    def __str__(self):
        log.debug('ActiveXMethod %s __str__ called' % self.desc())
        return self.callResult()

    def toString(self):
        log.debug('ActiveXMethod %s toString called' % self.desc())
        return self.callResult()

    def valueOf(self):
        log.debug('ActiveXMethod %s valueOf called' % self.desc())
        return self.callResult()

    def __getattr__(self, name):
        log.debug("ActiveXMethod.__getattr__(%s, %s)" % (self.desc(), name))
        try:
            method = super(self.__class__, self).__getattribute__(name)
        except AttributeError:
            result = self.callResult()
            if type(result) is str:
                if name.lower() == 'length':
                    return len(result)
                #elif name.lower() == 'charcodeat':
                    #TODO hmm, how to get a reference here to the javascript instance method charCodeAt...?
                    #return None
                else:
                    log.warning("Unhandled attribute (%s) for type (%s) in ActiveXMethod (%s)" % (name, type(result), self.desc()))
            else:
                log.warning("Unhandled type (%s) in ActiveXMethod (%s) for attribute %s" % (type(result), self.desc(), name))

            #TODO: implement 'all' possible attributes ...
            #      or rather, find a generic solution for attributes
            #      If the result doesn't have requested attribute, maybe raise AttributeError?

            return None

    def __getitem__(self, index):
        log.debug("ActiveXMethod.__getitem__(%s, %d)" % (self.desc(), index))
        result = self.callResult()
        return result[index];

    def __len__(self):
        result = self.callResult()
        return len(result)

    #def __getattribute__(self, name):
        #log.debug("__getattribute__(%s)" % (name))
        #try:
            #return object.__getattribute__(self, name)
        #except AttributeError:
            #log.debug("!!! Unknown attribute %s" % name)
