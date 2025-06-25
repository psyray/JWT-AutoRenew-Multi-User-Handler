# JWT AutoRenew & Multi-User Handler

A Burp Suite extension for seamless JWT renewal and advanced multi-user session handling.

## Overview

**JWT AutoRenew & Multi-User Handler** is a Burp Suite extension designed to automate the renewal of short-lived JWT access tokens using refresh tokens. It ensures uninterrupted security testing by preventing 401 errors due to token expiration, and provides advanced features for multi-user authorization testing.

This extension is a complete rewrite and consolidation of the original [BurpExtension-JWT-4-session-handling](https://github.com/V9Y1nf0S3C/BurpExtension-JWT-4-session-handling), with a modern, user-friendly interface and enhanced capabilities.

## Key Features

- **Automatic JWT Renewal:**  
  Automatically renews expired JWT access tokens using the refresh token, ensuring Burp Suite tools (Scanner, Repeater, Intruder, etc.) always use valid tokens.

- **Session Handling Rules Integration:**  
  Fully compatible with Burp Suite's Session Handling Rules, allowing you to define custom rules, scope, and actions for token management.

- **Multi-User Support:**  
  Extracts a user identifier from the JWT payload and stores it in Burp's cookie jar (using the Path attribute), enabling per-user token management.

- **Authorization Testing Ready:**  
  Designed for use with [Auth Analyzer](https://github.com/simioni87/auth_analyzer) and similar tools, making it easy to test vertical and horizontal authorization by specifying tokens per user.

- **Highly Configurable:**  
  - Customizable JWT and refresh token variable names
  - Custom cookie domain
  - Custom authorization header name (e.g., Bearer ...)
  - Custom JWT payload key for user identification
  - Custom token renewal URL
  - Debug mode for detailed logging

- **User-Friendly GUI:**  
  All options are accessible via a dedicated Burp Suite tab, with real-time logs and easy configuration.

## Usage

1. **Install the extension** in Burp Suite (Extender > Extensions).
2. **Configure the options** in the "JWT AutoRenew & Multi-User Handler" tab:
   - Set the names for the access and refresh tokens, cookie domain, authorization header, user key, and token renewal URL.
   - Enable debug mode for detailed logs if needed.
3. **Define Session Handling Rules** to apply the extension's actions to your desired scope (Scanner, Repeater, Intruder, etc.).
4. **Start your tests**. The extension will automatically handle token renewal and user session management.

## Example Use Cases

- **Automated Scanning:**  
  Prevents Burp Scanner from failing due to expired tokens by auto-renewing JWTs in the background.

- **Manual Testing:**  
  Seamlessly updates tokens in Repeater, Intruder, and other Burp tools.

- **Authorization Testing:**  
  Works with Auth Analyzer to test access control for multiple users, by managing tokens per user and updating the Authorization header as needed.

## Future Enhancements

- **Headless Browser Auto-Login:**  
  Integration with headless browser login (see `jwt_4B_Chrome_Headless_AutoLogin.py`) is planned for future releases, to automate initial authentication and token retrieval.

## Credits

- Original concept and codebase: [V9Y1nf0S3C/BurpExtension-JWT-4-session-handling](https://github.com/V9Y1nf0S3C/BurpExtension-JWT-4-session-handling)
- Multi-user and authorization testing inspiration: [simioni87/auth_analyzer](https://github.com/simioni87/auth_analyzer)

## License

MIT License

---

**For questions, suggestions, or contributions, please open an issue or pull request.**
