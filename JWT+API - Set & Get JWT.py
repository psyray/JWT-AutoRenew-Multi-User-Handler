import pdb
import re
import sys
import datetime
import base64
import json
import urllib2
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, JTabbedPane

# Burp specific imports
from burp import IBurpExtender, ITab
from burp import IHttpListener
from burp import ISessionHandlingAction
from java.io import PrintWriter
from burp import ICookie

# For using the debugging tools from
# https://github.com/securityMB/burp-exceptions
try:
    from exceptions_fix import FixBurpExceptions
except ImportError:
    pass

class Cookie(ICookie):

    def getDomain(self):
        return self.cookie_domain

    def getPath(self):
        return self.cookie_path

    def getExpiration(self):
        return self.cookie_expiration

    def getName(self):
        return self.cookie_name

    def getValue(self):
        return self.cookie_value

    def __init__(self, cookie_domain=None, cookie_name=None, cookie_value=None, cookie_path=None, cookie_expiration=None):
        self.cookie_domain = cookie_domain
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self.cookie_path = cookie_path
        self.cookie_expiration = cookie_expiration

class BurpExtender(IBurpExtender, ITab, IHttpListener, ISessionHandlingAction):

    # Tool mapping
    tool_mapping = {
        512: "COMPARER",
        256: "DECODER",
        1024: "EXTENDER",
        32: "INTRUDER",
        4: "PROXY",
        64: "REPEATER",
        16: "SCANNER",
        128: "SEQUENCER",
        8: "SPIDER",
        1: "SUITE",
        2: "TARGET"
    }

    # Define config and gui variables
    cookieName = 'access_token'
    refreshCookieName = 'refresh_token'
    cookieDomain = 'localhost'
    header_name = 'Authorization: Bearer'
    debug_enabled = False
    username_key = 'username'
    token_renewal_url = 'http://example.com/auth/realms/master/protocol/openid-connect/token'

    def __init__(self):
        # Create options fields with default values
        self.cookie_name_field = JTextField(self.cookieName, 20)
        self.refresh_cookie_name_field = JTextField(self.refreshCookieName, 20)
        self.cookie_domain_field = JTextField(self.cookieDomain, 20)
        self.header_name_field = JTextField(self.header_name, 20)
        self.username_key_field = JTextField(self.username_key, 20)
        self.token_renewal_url_field = JTextField(self.token_renewal_url, 40)
        self.debug_checkbox = JCheckBox("Enable Debugging", self.debug_enabled)
        self.apply_button = JButton("Apply", actionPerformed=self.apply_config)
        self.status_label = JLabel("")

    def _insert_breakpoint(self, message):
        print("insertBreakpoint")
        if self.debug_enabled:
            print("Breakpoint has been fetched: " + message)
            #pdb.set_trace()
        else:
            print("Debug not activated")
        return

    def _debug(self, message, value):
        if self.debug_enabled:
            print('===================================================================')
            print(message)
            print('===================================================================')
            print(str(value))
        return

    def _getUrlFromMessage(self, message):
        url = self.helpers.analyzeRequest(message.getHttpService(),message.getRequest()).getUrl()
        return url

    def apply_config(self, event):
        self.cookieName = self.cookie_name_field.getText()
        self.refreshCookieName = self.refresh_cookie_name_field.getText()
        self.cookieDomain = self.cookie_domain_field.getText()
        self.header_name = self.header_name_field.getText()
        self.username_key = self.username_key_field.getText()
        self.token_renewal_url = self.token_renewal_url_field.getText()
        self.debug_enabled = self.debug_checkbox.isSelected()
        self.status_label.setText("Configuration applied!")
        if self.debug_enabled:
            print("Debugging is enabled")
            # print("""
            # Debugging is enabled
            #     n (next) : Execute next step of code.
            #     s (step) : Step into the function called
            #     c (continue) : Continue to the next breakpoint
            #     l (list) : List source code around the current line
            #     p (print) : Display variable value
            # """)

    # Define some cookie functions
    def deleteCookie(self, domain, name):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                cookie_to_be_nuked = Cookie(cookie.getDomain(), cookie.getName(), None,  cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_nuked)
                break

    def createCookie(self, domain, name, value, path=None, expiration=None):
        cookie_to_be_created = Cookie(domain, name, value,  path, expiration)
        self.callbacks.updateCookieJar(cookie_to_be_created)

    def setCookie(self, domain, name, value):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                cookie_to_be_set = Cookie(cookie.getDomain(), cookie.getName(), value,  cookie.getPath(), cookie.getExpiration())
                self.callbacks.updateCookieJar(cookie_to_be_set)
                break

    def getCookieValue(self, domain, name):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name:
                return cookie.getValue()

    def getCookieValueCustomPath(self, domain, name, path):
        cookies = self.callbacks.getCookieJarContents()
        for cookie in cookies:
            if cookie.getDomain() == domain and cookie.getName() == name and (str(cookie.getPath()).lower().find(path.lower()) > -1):
                return cookie.getValue()

    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object
        self.callbacks = callbacks

        # Obtain an extension helpers object
        self.helpers = callbacks.getHelpers()

        # Set our extension name
        callbacks.setExtensionName("Auto renew JWT")

        # Register ourselves as a Session Handling Action
        callbacks.registerSessionHandlingAction(self)

        # Register ourselves as a HttpListener
        callbacks.registerHttpListener(self)

        # Register ourselves as a Burp Tab
        callbacks.addSuiteTab(self)

        # Used by the custom debugging tools
        sys.stdout = callbacks.getStdout()

        print("Auto renew JWT - Enabled!")

        return

    def getTabCaption(self):
        return "Auto renew JWT"

    def getUiComponent(self):
        panel = JPanel()
        panel.setLayout(None)

        label_cookie_name = JLabel("Cookie Name:")
        label_cookie_name.setBounds(10, 10, 200, 25)
        panel.add(label_cookie_name)

        self.cookie_name_field.setBounds(220, 10, 200, 25)
        panel.add(self.cookie_name_field)

        label_refresh_cookie_name = JLabel("Refresh Cookie Name:")
        label_refresh_cookie_name.setBounds(10, 40, 200, 25)
        panel.add(label_refresh_cookie_name)

        self.refresh_cookie_name_field.setBounds(220, 40, 200, 25)
        panel.add(self.refresh_cookie_name_field)

        label_cookie_domain = JLabel("Cookie Domain:")
        label_cookie_domain.setBounds(10, 70, 200, 25)
        panel.add(label_cookie_domain)

        self.cookie_domain_field.setBounds(220, 70, 200, 25)
        panel.add(self.cookie_domain_field)

        label_header_name = JLabel("Header Name:")
        label_header_name.setBounds(10, 100, 200, 25)
        panel.add(label_header_name)

        self.header_name_field.setBounds(220, 100, 200, 25)
        panel.add(self.header_name_field)

        label_username_key = JLabel("Username Key:")
        label_username_key.setBounds(10, 130, 200, 25)
        panel.add(label_username_key)

        self.username_key_field.setBounds(220, 130, 200, 25)
        panel.add(self.username_key_field)

        label_token_renewal_url = JLabel("Token Renewal URL:")
        label_token_renewal_url.setBounds(10, 160, 200, 25)
        panel.add(label_token_renewal_url)

        self.token_renewal_url_field.setBounds(220, 160, 800, 25)
        panel.add(self.token_renewal_url_field)

        self.debug_checkbox.setBounds(10, 190, 200, 25)
        panel.add(self.debug_checkbox)

        self.apply_button.setBounds(10, 220, 100, 25)
        panel.add(self.apply_button)

        self.status_label.setBounds(10, 250, 400, 25)
        panel.add(self.status_label)

        return panel

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        # Only process responses
        if messageIsRequest:
            return

        #self._insert_breakpoint("processHttpMessage")

        response = self.helpers.analyzeResponse(currentMessage.getResponse())
        headers = response.getHeaders()
        url = self._getUrlFromMessage(currentMessage)
        body = currentMessage.getResponse()[response.getBodyOffset():].tostring()
        tool_name = self.tool_mapping.get(toolFlag, "Unknown tool")

        # Check if the response is JSON
        is_it_json = False
        for header in headers:
            if "Content-Type" in header and "application/json" in header:
                # The response type is application/json
                is_it_json = True
                break    
        if not is_it_json:
            return

        self._debug('Headers', headers)
        self._debug('Body', body)

        # Check if the response has access_token and refresh_token
        access_token = self._get_jwt_token(body, 'access_token')
        refresh_token = self._get_jwt_token(body, 'refresh_token')

        self._debug('Access Token', access_token)
        self._debug('Refresh Token', refresh_token)

        if access_token:
            jwt_payload = self._decode_jwt(access_token)
            self._debug('JWT Access Token Payload', jwt_payload)
            if jwt_payload:
                username_key = self.username_key or 'username'
                username = jwt_payload.get(username_key)
                self._debug("Username Key", username_key)
                self._debug("Extracted username", username)
                if username:
                    print("Saving tokens in cookie.jar")
                    path = "/{}".format(username)
                    self.createCookie(self.cookieDomain, self.cookieName, access_token, path)
                    self._debug("Access Token saved for username", username)
                    print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] RESPONSE_READ from " + str(tool_name) + " -> [Access Token (truncated):" + access_token[-40:] + "...] [Username:" + path+ "] [Url: " + str(url) + "]")
                    if refresh_token:
                        path = "/{}".format(username)
                        self.createCookie(self.cookieDomain, self.refreshCookieName, refresh_token, path)
                        self._debug("Refresh Token saved for username", username)
                        print("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] RESPONSE_READ from " + str(tool_name) + " -> [Refresh Token (truncated):" + access_token[-40:] + "...] [Username:" + path+ "] [Url: " + str(url) + "]")
                else:
                    print("Username Key not found in JWT Payload, have you updated the Username Key value in plugin config ?")

    def _get_jwt_token(self, response_body, token_name):
        # Regex pattern to extract access token from response body
        pattern = r'"{}":"(.+?)"'.format(token_name)

        matches = re.search(pattern, response_body)
        if matches:
            token = matches.group(1)
            return token
        else:
            return None

    def _decode_jwt(self, jwt):
        try:
            jwt = str(jwt)
            payload = jwt.split('.')[1]
            payload += '=' * (4 - len(payload) % 4)  # add padding
            decoded_payload = base64.urlsafe_b64decode(payload)
            decoded_payload_str = decoded_payload.decode('utf-8')
            return json.loads(decoded_payload_str)
        except Exception as e:
            print("Error decoding JWT: {}".format(e))
            return None

    def _renew_token(self, refresh_token):
        renewal_url = self.token_renewal_url
        if not renewal_url:
            print("Error: No token renewal URL provided in configuration.")
            return None

        # Create the request to renew the token
        req = urllib2.Request(renewal_url)
        req.add_header('Content-Type', 'application/json')
        data = json.dumps({'refresh_token': refresh_token})
        try:
            response = urllib2.urlopen(req, data.encode('utf-8'))
            response_body = response.read()
            new_access_token = self._get_jwt_token(response_body, 'access_token')
            if new_access_token:
                return new_access_token
            else:
                print("Error: Failed to retrieve new access token from renewal response.")
                return None
        except Exception as e:
            print("Error renewing token: {}".format(e))
            return None

    def getActionName(self):
        return "Auto renew JWT - Modify request"

    def performAction(self, currentMessage, macro_items):
        #self._insert_breakpoint("performAction")

        req_text = self.helpers.bytesToString(currentMessage.getRequest())
        headers = self.helpers.analyzeRequest(currentMessage).getHeaders()

        self._debug('Request', req_text)
        self._debug('Headers', headers)

        # Check if the request has the Authorization header with a JWT token
        for header in headers:
            if re.search(self.header_name + ".*", header, re.IGNORECASE):
                self._debug('Header', header)
                jwt_token = header.split(' ')[2]
                self._debug('JWT', str(jwt_token))
                decoded_jwt = self._decode_jwt(jwt_token)
                self._debug('Decoded JWT', decoded_jwt)

                if decoded_jwt:
                    exp = decoded_jwt.get('exp')
                    username_key = self.username_key or 'username'
                    username = decoded_jwt.get(username_key)

                    # Check if the token is expired
                    if exp and datetime.datetime.utcfromtimestamp(exp) < datetime.datetime.utcnow():
                        print("[{}] - TOKEN_EXPIRED: Token for user '{}' is expired - [ReqURL:{}]".format(
                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                        path = "/{}".format(username)

                        # Check for a valid token in the cookie jar
                        print('Get a valid token from cookie.jar')
                        new_token = self.getCookieValueCustomPath(self.cookieDomain, self.cookieName, path)
                        self._debug('New JWT', new_token)
                        if new_token:
                            decoded_new_jwt = self._decode_jwt(new_token)
                            self._debug('New decoded JWT', decoded_new_jwt)
                            new_exp = decoded_new_jwt.get('exp')

                            if new_exp and datetime.datetime.utcfromtimestamp(new_exp) > datetime.datetime.utcnow():
                                print("[{}] - VALID_TOKEN_FOUND: Found valid token for user '{}' in cookie jar - [ReqURL:{}]".format(
                                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                                new_header = "%s %s" % (self.header_name, new_token)
                                self._debug('New header', new_header)
                                req_text = re.sub(r"\r\n" + self.header_name + ".*\r\n", "\r\n" + new_header + "\r\n" , req_text, flags=re.IGNORECASE)
                                self._debug('Request to replace', req_text)
                                
                                try:
                                    self._debug('Request raw', self.helpers.stringToBytes(req_text))
                                    currentMessage.setRequest(self.helpers.stringToBytes(req_text))
                                except Exception as e:
                                    print("The error is: ",e)
                                print("Token has been replaced in request")
                            else:
                                print("[{}] - NO_VALID_TOKEN: No valid token found for user '{}' in cookie jar - [ReqURL:{}]".format(
                                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                                refresh_token = self.getCookieValueCustomPath(self.cookieDomain, self.refreshCookieName, path)
                                if refresh_token:
                                    new_token = self._renew_token(refresh_token)
                                    if new_token:
                                        print("[{}] - TOKEN_RENEWED: Token renewed for user '{}' - [ReqURL:{}]".format(
                                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                                        # Replace the old token with the new token
                                        new_header = "{} {}".format(self.header_name, new_token)
                                        headers = [h for h in headers if not re.search(self.header_name + ".*", h, re.IGNORECASE)]
                                        headers.append(new_header)
                                        currentMessage.setRequest(self.helpers.buildHttpMessage(headers, self.helpers.analyzeRequest(currentMessage.getRequest()).getBody()))
                                    else:
                                        print("[{}] - TOKEN_RENEWAL_FAILED: Token renewal failed for user '{}' - [ReqURL:{}]".format(
                                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))
                                else:
                                    print("[{}] - NO_REFRESH_TOKEN: No refresh token found for user '{}' - [ReqURL:{}]".format(
                                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))
                    else:
                        print("[{}] - TOKEN_VALID: Token for user '{}' is still valid - [ReqURL:{}]".format(
                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))
                else:
                    print("[{}] - JWT_DECODE_ERROR: Failed to decode JWT token - [ReqURL:{}]".format(
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self._getUrlFromMessage(currentMessage)))

        return

try:
    FixBurpExceptions()
except:
    pass
