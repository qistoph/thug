try:
    from io import BytesIO
except ImportError:
    try:
        from cStringIO import BytesIO
    except ImportError:
        from StringIO import BytesIO

import os
import logging
import hashlib

from Magic.Magic import Magic
log = logging.getLogger("Thug")

def open(self): #pylint:disable=redefined-builtin
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] open")
    self.fobject = BytesIO()

def _Write(self, dat):
    log.ThugLogging.add_behavior_warn('[Adodb.Stream ActiveX] Writing with charset: %s' % self.Charset)

    dat = unicode(dat, 'utf-8')
    if self.Charset == '437':
        dat = dat.encode('cp437')
    else:
        dat = dat.encode('latin1')

    self.fobject.write(dat)

def Write(self, s):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Write")
    _Write(self, s)

def WriteText(self, dat, opt = 0):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] WriteText (..., %d)" % (opt))
    _Write(self, dat)

def SaveToFile(self, filename, opt = 0):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] SaveToFile(%s, %s)" % (filename, opt, ))
    log.ThugLogging.log_exploit_event(self._window.url,
                                      "Adodb.Stream ActiveX",
                                      "SaveToFile",
                                      data = {
                                                "file": filename
                                             },
                                      forward = False)

    content = self.fobject.getvalue()
    mtype   = Magic(content).get_mime()

    log.ThugLogging.log_file(content, url = filename, sampletype = mtype)
    self._files[filename] = content

    md5 = hashlib.md5()
    md5.update(content)

    mime_base = os.path.join(log.ThugLogging.baseDir, mtype)
    log.ThugLogging.store_content(mime_base, md5.hexdigest(), content)

def LoadFromFile(self, filename):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] LoadFromFile(%s)" % (filename, ))
    if filename not in self._files:
        raise TypeError()

    self._current = filename

def ReadText(self, NumChars = -1):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] ReadText")

    data = self._files[self._current]

    if self.Charset == '437':
        data = data.decode('cp437')
    else:
        data = data.decode('latin1')

    data = data.encode('utf-8')

    if NumChars == -1:
        return data

    return data[:NumChars - 1]

def Close(self):
    log.ThugLogging.add_behavior_warn("[Adodb.Stream ActiveX] Close")
    self.fobject.close()
