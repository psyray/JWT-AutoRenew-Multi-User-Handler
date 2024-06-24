# -*- coding: utf-8 -*-
import pdb
import re
import sys
import datetime
import base64
import json
import urllib2
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, JTextArea, JScrollPane, JSplitPane, SwingUtilities
from java.awt import BorderLayout

# Burp specific imports
from burp import IBurpExtender, ITab
from burp import IHttpListener
from burp import ISessionHandlingAction
from burp import IExtensionStateListener
from burp import IContextMenuFactory
from burp import ICookie
from java.io import PrintWriter
from java.util import ArrayList

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

class BurpExtender(IBurpExtender, ITab, IHttpListener, ISessionHandlingAction, IExtensionStateListener):

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
        self.request_tool_map = {}
        self.debug_enabled = False
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
        self.log_area = JTextArea(10, 80)
        self.log_area.setEditable(False)
        self.log_scroll_pane = JScrollPane(self.log_area)
        self.autoscroll_checkbox = JCheckBox("Autoscroll", True)
        self.autoscroll_enabled = True
        self.autoscroll_checkbox.addActionListener(self.toggle_autoscroll)

    def _log(self, message):
        self.log_area.append(message + "\n")
        if self.autoscroll_enabled:
            self.log_area.setCaretPosition(self.log_area.getDocument().getLength())
        print(message)

    def _insert_breakpoint(self, message):
        self._log("insertBreakpoint")
        if self.debug_enabled:
            self._log("Breakpoint has been fetched: " + message)
            #pdb.set_trace()
        else:
            self._log("Debug not activated")
        return

    def _debug(self, message, value=''):
        if self.debug_enabled:
            separator1 = '=' * 35
            separator2 = '-' * 35
            if isinstance(message, str):
                self._log(separator1 + 'DEBUG START' + separator1)
                self._log(message)
                self._log(separator1 + 'DEBUG END' + separator1)
                if value:
                    self._log(str(value))
            elif isinstance(message, set):
                self._log(separator1 + 'DEBUG START' + separator1)
                for text in message:
                    self._log(str(text))
                    self._log(separator2)
                self._log(separator1 + 'DEBUG END' + separator1)

        return

    def _getUrlFromMessage(self, message):
        url = self.helpers.analyzeRequest(message.getHttpService(),message.getRequest()).getUrl()
        return url

    def toggle_autoscroll(self, event):
        self.autoscroll_enabled = self.autoscroll_checkbox.isSelected()

    def apply_config(self, event):
        self.cookieName = self.cookie_name_field.getText()
        self.refreshCookieName = self.refresh_cookie_name_field.getText()
        self.cookieDomain = self.cookie_domain_field.getText()
        self.header_name = self.header_name_field.getText()
        self.username_key = self.username_key_field.getText()
        self.token_renewal_url = self.token_renewal_url_field.getText()
        self.debug_enabled = self.debug_checkbox.isSelected()
        self.status_label.setText("Configuration applied!")
        self._log("Configuration applied!")
        if self.debug_enabled:
            self._log("Debugging is enabled")
            # self._log("""
            # Debugging is enabled
            #     n (next) : Execute next step of code.
            #     s (step) : Step into the function called
            #     c (continue) : Continue to the next breakpoint
            #     l (list) : List source code around the current line
            #     p (print) : Display variable value
            # """)
        # Save the configuration
        self.callbacks.saveExtensionSetting("config", self.saveConfig())

    def saveConfig(self):
        config = {
            'cookieName': self.cookieName,
            'refreshCookieName': self.refreshCookieName,
            'cookieDomain': self.cookieDomain,
            'header_name': self.header_name,
            'username_key': self.username_key,
            'token_renewal_url': self.token_renewal_url,
            'debug_enabled': self.debug_enabled
        }
        config_str = json.dumps(config)
        config_bytes = config_str.encode('utf-8')
        return base64.b64encode(config_bytes).decode('utf-8')

    # Method to load the configuration
    def loadConfig(self, config_str):
        try:
            config_bytes = base64.b64decode(config_str.encode('utf-8'))
            config = json.loads(config_bytes.decode('utf-8'))

            self.cookieName = config.get('cookieName', self.cookieName)
            self.refreshCookieName = config.get('refreshCookieName', self.refreshCookieName)
            self.cookieDomain = config.get('cookieDomain', self.cookieDomain)
            self.header_name = config.get('header_name', self.header_name)
            self.username_key = config.get('username_key', self.username_key)
            self.token_renewal_url = config.get('token_renewal_url', self.token_renewal_url)
            self.debug_enabled = config.get('debug_enabled', self.debug_enabled)

            self.cookie_name_field.setText(self.cookieName)
            self.refresh_cookie_name_field.setText(self.refreshCookieName)
            self.cookie_domain_field.setText(self.cookieDomain)
            self.header_name_field.setText(self.header_name)
            self.username_key_field.setText(self.username_key)
            self.token_renewal_url_field.setText(self.token_renewal_url)
            self.debug_checkbox.setSelected(self.debug_enabled)

            self.status_label.setText("Configuration loaded!")
            self._log("Configuration loaded successfully")
        except Exception as e:
            self._log("Error loading configuration: {}".format(e))
            self.status_label.setText("Error loading configuration")

    def getConfigAsJson(self):
        return self.saveConfig()

    def loadConfigFromJson(self, jsonConfig):
        self.loadConfig(jsonConfig)

    def extensionUnloaded(self):
        self._log("Extension was unloaded")
        self.callbacks.saveExtensionSetting("config", self.saveConfig())

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

        # Register to be notified of extension unload
        callbacks.registerExtensionStateListener(self)

        # Load configuration if available
        saved_config = self.callbacks.loadExtensionSetting("config")
        if saved_config:
            self.loadConfig(saved_config)

        # Used by the custom debugging tools
        sys.stdout = callbacks.getStdout()

        self._log("Auto renew JWT - Enabled!")

        # Analyze proxy history for tokens (limiting to last 100 requests)
        self.analyze_proxy_history(max_requests=100)

        return

    def getTabCaption(self):
        return "Auto renew JWT"

    def getUiComponent(self):
        panel = JPanel()
        panel.setLayout(BorderLayout())

        options_panel = JPanel()
        options_panel.setLayout(None)

        label_cookie_name = JLabel("Cookie Name:")
        label_cookie_name.setBounds(10, 10, 200, 25)
        options_panel.add(label_cookie_name)

        self.cookie_name_field.setBounds(220, 10, 200, 25)
        options_panel.add(self.cookie_name_field)

        label_refresh_cookie_name = JLabel("Refresh Cookie Name:")
        label_refresh_cookie_name.setBounds(10, 40, 200, 25)
        options_panel.add(label_refresh_cookie_name)

        self.refresh_cookie_name_field.setBounds(220, 40, 200, 25)
        options_panel.add(self.refresh_cookie_name_field)

        label_cookie_domain = JLabel("Cookie Domain:")
        label_cookie_domain.setBounds(10, 70, 200, 25)
        options_panel.add(label_cookie_domain)

        self.cookie_domain_field.setBounds(220, 70, 200, 25)
        options_panel.add(self.cookie_domain_field)

        label_header_name = JLabel("Header Name:")
        label_header_name.setBounds(10, 100, 200, 25)
        options_panel.add(label_header_name)

        self.header_name_field.setBounds(220, 100, 200, 25)
        options_panel.add(self.header_name_field)

        label_username_key = JLabel("Username Key:")
        label_username_key.setBounds(10, 130, 200, 25)
        options_panel.add(label_username_key)

        self.username_key_field.setBounds(220, 130, 200, 25)
        options_panel.add(self.username_key_field)

        label_token_renewal_url = JLabel("Token Renewal URL:")
        label_token_renewal_url.setBounds(10, 160, 200, 25)
        options_panel.add(label_token_renewal_url)

        self.token_renewal_url_field.setBounds(220, 160, 800, 25)
        options_panel.add(self.token_renewal_url_field)

        self.debug_checkbox.setBounds(10, 190, 200, 25)
        options_panel.add(self.debug_checkbox)

        self.apply_button.setBounds(10, 220, 100, 25)
        options_panel.add(self.apply_button)

        self.status_label.setBounds(10, 250, 400, 25)
        options_panel.add(self.status_label)

        # Add log area
        log_panel = JPanel()
        log_panel.setLayout(BorderLayout())
        log_label = JLabel("Log:")
        log_panel.add(log_label, BorderLayout.NORTH)
        log_panel.add(self.log_scroll_pane, BorderLayout.CENTER)
        log_panel.add(self.autoscroll_checkbox, BorderLayout.SOUTH)

        split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, options_panel, log_panel)
        split_pane.setDividerLocation(300)  # Set the initial position of the divider

        panel.add(split_pane, BorderLayout.CENTER)

        return panel

    def analyze_proxy_history(self, max_requests=100):
        self._log("Analyzing proxy history...")
        history = self.callbacks.getProxyHistory()
        analyzed_users = set()
        debug_text = set()
        count = 0

        self._log("Total requests in history: {}".format(len(history)))

        for entry in reversed(history):  # Analyze from the most recent to the oldest
            if count >= max_requests:
                break

            response_info = self.helpers.analyzeResponse(entry.getResponse())
            headers = response_info.getHeaders()
            body = entry.getResponse()[response_info.getBodyOffset():].tostring()

            # Check if the response is JSON
            if not self.is_application_json(headers):
                return

            debug_text.add("Analyzing {}".format(entry.getUrl()))

            # Check if the response has access_token
            access_token = self._get_jwt_token(body, 'access_token')
            if access_token:
                debug_text.add("Access Token \n{}".format(access_token))
                jwt_payload = self._decode_jwt(access_token)
                if jwt_payload:
                    debug_text.add("JWT Payload \n{}".format(jwt_payload))
                    username_key = self.username_key or 'username'
                    username = jwt_payload.get(username_key)
                    if username and username not in analyzed_users:
                        self._log("Found token for user: {}".format(username))
                        self.processHttpMessage(4, False, entry)
                        analyzed_users.add(username)
                    else:
                        debug_text.add("Username {} invalid or already renewed".format(str(username)))
                else:
                    debug_text.add("No JWT payload found")
            else:
                debug_text.add("No token found")

            count += 1

        self._debug(debug_text)

        self._log("Total users analyzed: {}".format(len(analyzed_users)))

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        # Only process responses
        if messageIsRequest:
            return
        debug_text = set()

        #self._insert_breakpoint("processHttpMessage")

        response = self.helpers.analyzeResponse(currentMessage.getResponse())
        headers = response.getHeaders()
        url = self._getUrlFromMessage(currentMessage)
        body = currentMessage.getResponse()[response.getBodyOffset():].tostring()
        tool_name = self.tool_mapping.get(toolFlag, "Unknown tool")

        # Check if the response is JSON
        if not self.is_application_json(headers):
            return

        debug_text.add("Processing HTTP message: ToolFlag= {}".format(tool_name))

        debug_text.add("Headers \n{}".format(headers))
        debug_text.add("Body \n{}".format(body))

        # Check if the response has access_token and refresh_token
        access_token = self._get_jwt_token(body, "access_token")
        refresh_token = self._get_jwt_token(body, "refresh_token")

        if access_token:
            debug_text.add("Access Token \n{}".format(access_token))
            jwt_payload = self._decode_jwt(access_token)
            debug_text.add("JWT Access Token Payload \n{}".format(jwt_payload))
            if jwt_payload:
                username_key = self.username_key or "username"
                username = jwt_payload.get(username_key)
                debug_text.add("Username Key {}".format(username_key))
                debug_text.add("Extracted username {}".format(username))
                if username:
                    self._log("Saving tokens in cookie.jar")
                    path = "/{}".format(username)
                    self.createCookie(self.cookieDomain, self.cookieName, access_token, path)
                    debug_text.add("Access Token saved for username {}".format(username))
                    self._log("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] RESPONSE_READ from " + str(tool_name) + " -> [Access Token (truncated):" + access_token[-40:] + "...] [Username:" + path+ "] [Url: " + str(url) + "]")
                    if refresh_token:
                        debug_text.add("Refresh Token \n{}".format(refresh_token))
                        path = "/{}".format(username)
                        self.createCookie(self.cookieDomain, self.refreshCookieName, refresh_token, path)
                        debug_text.add("Refresh Token saved for username {}".format(username))
                        self._log("[" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "] RESPONSE_READ from " + str(tool_name) + " -> [Refresh Token (truncated):" + access_token[-40:] + "...] [Username:" + path+ "] [Url: " + str(url) + "]")
                else:
                    self._log("Username Key not found in JWT Payload, have you updated the Username Key value in plugin config ?")
        
        self._debug(debug_text)

    def is_application_json(self, headers):
        is_it_json = False
        for header in headers:
            if "Content-Type" in header and "application/json" in header:
                # The response type is application/json
                is_it_json = True
                break    
        
        return is_it_json

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
            self._log("Error decoding JWT: {}".format(e))
            return None

    def _renew_token(self, refresh_token):
        renewal_url = self.token_renewal_url
        if not renewal_url:
            self._log("Error: No token renewal URL provided in configuration.")
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
                self._log("Error: Failed to retrieve new access token from renewal response.")
                return None
        except Exception as e:
            self._log("Error renewing token: {}".format(e))
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
                        self._log("[{}] - TOKEN_EXPIRED: Token for user '{}' is expired - [ReqURL:{}]".format(
                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                        path = "/{}".format(username)

                        # Check for a valid token in the cookie jar
                        self._log('Get a valid token from cookie.jar')
                        new_token = self.getCookieValueCustomPath(self.cookieDomain, self.cookieName, path)
                        self._debug('New JWT', new_token)
                        if new_token:
                            decoded_new_jwt = self._decode_jwt(new_token)
                            self._debug('New decoded JWT', decoded_new_jwt)
                            new_exp = decoded_new_jwt.get('exp')

                            if new_exp and datetime.datetime.utcfromtimestamp(new_exp) > datetime.datetime.utcnow():
                                self._log("[{}] - VALID_TOKEN_FOUND: Found valid token for user '{}' in cookie jar - [ReqURL:{}]".format(
                                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                                new_header = "%s %s" % (self.header_name, new_token)
                                self._debug('New header', new_header)
                                req_text = re.sub(r"\r\n" + self.header_name + ".*\r\n", "\r\n" + new_header + "\r\n" , req_text, flags=re.IGNORECASE)
                                self._debug('Request to replace', req_text)
                                
                                try:
                                    self._debug('Request raw', self.helpers.stringToBytes(req_text))
                                    currentMessage.setRequest(self.helpers.stringToBytes(req_text))
                                except Exception as e:
                                    self._log("The error is: ",e)
                                self._log("Token has been replaced in request")
                            else:
                                self._log("[{}] - NO_VALID_TOKEN: No valid token found for user '{}' in cookie jar - [ReqURL:{}]".format(
                                    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                                refresh_token = self.getCookieValueCustomPath(self.cookieDomain, self.refreshCookieName, path)
                                if refresh_token:
                                    new_token = self._renew_token(refresh_token)
                                    if new_token:
                                        self._log("[{}] - TOKEN_RENEWED: Token renewed for user '{}' - [ReqURL:{}]".format(
                                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))

                                        # Replace the old token with the new token
                                        new_header = "{} {}".format(self.header_name, new_token)
                                        headers = [h for h in headers if not re.search(self.header_name + ".*", h, re.IGNORECASE)]
                                        headers.append(new_header)
                                        currentMessage.setRequest(self.helpers.buildHttpMessage(headers, self.helpers.analyzeRequest(currentMessage.getRequest()).getBody()))
                                    else:
                                        self._log("[{}] - TOKEN_RENEWAL_FAILED: Token renewal failed for user '{}' - [ReqURL:{}]".format(
                                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))
                                else:
                                    self._log("[{}] - NO_REFRESH_TOKEN: No refresh token found for user '{}' - [ReqURL:{}]".format(
                                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))
                    else:
                        self._log("[{}] - TOKEN_VALID: Token for user '{}' is still valid - [ReqURL:{}]".format(
                            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username, self._getUrlFromMessage(currentMessage)))
                else:
                    self._log("[{}] - JWT_DECODE_ERROR: Failed to decode JWT token - [ReqURL:{}]".format(
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), self._getUrlFromMessage(currentMessage)))

        return

try:
    FixBurpExceptions()
except:
    pass
