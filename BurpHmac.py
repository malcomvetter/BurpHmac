from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import IParameter
from datetime import datetime
import hashlib
import hmac
import base64

class BurpExtender(IBurpExtender, ISessionHandlingAction):
    #
    # implement IBurpExtender
    #
    
    #update me:
    key = "fuM0sCVI/EGFcAAAAlQqsdMmRRRRC2/iLqCWK7khdpU=";

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HMAC Header")
        callbacks.registerSessionHandlingAction(self)
        return

    def createHmac(message):
        Print("creating hmac")
        msg = bytes(message).encode('utf-8')
        Print("message: " + msg)
        Print("key: " + b64decode(key))
        _hmac = base64.b64encode(hmac.new(b64decode(key), msg, digestmod=hashlib.sha256).digest())
        Print(_hmac)
        return _hmac

    def performAction(self, currentRequest, macroItems):
        requestInfo = self._helpers.analyzeRequest(currentRequest)
        headers = requestInfo.getHeaders()
        msgBody = currentRequest.getRequest()[requestInfo.getBodyOffset():]

        # Add Custom Hash Header Here
        # String hashstring = httpmethod + date + uri;  <-- replicate this
        hashstring = requestInfo.getMethod() + timestamp.isoformat() + requestInfo.getUrl()
        Print("hashstring: " + hashstring)
        headers.add('HMAC: %s' % createHmac(hashstring))

        # Build new Http Message with the new Hash Header
        message = self._helpers.buildHttpMessage(headers, msgBody)

        # Print Header into UI
        print self._helpers.bytesToString(message)

        # Update Request with New Header
        currentRequest.setRequest(message)
        return 