---
layout: post
title: "Chrome credentials - 2025"
nav_order: 1
has_children: true
permalink: /Chrome Credentials - 2025/

---

# Chrome credentials - 2025 

*July 2025*

In September 2024, I was handed a project that had been collecting dust for a while. It was a kind of browser credential honeypot that needed a script to automatically inject passwords or cookies into the browser. A bit of a crazy idea — but fun nonetheless.
<br>

I'd already played around with some stealers before, so I knew the basics of the DPAPI setup: credentials live in SQLite databases, BCrypt32 CryptUnprotectData call, the Master key stored on disk, readable with user-level permissions.<br>

I didn’t know Google had just rolled out **Application Bound Encryption cookies protection in July 2024**. The master key is now also DPAPI-protected under the System and User context, and can’t be unwrapped directly by the user. 

By October/November, the first bypass PoCs appeared: <br>

- One used admin rights to mimic Chrome's logic: decrypt under System, then under user, then finish with AES using a hardcoded key. Turns out “Application Bound” is just DPAPI wrapped in DPAPI + some Chrome internal cooking made with AES and Xor. 

- The second used Chrome’s COM interface — IElevator — to get Chrome to decrypt cookies.

I needed to document this Chrome study somewhere, mostly as a personal reminder — hence, this blog post.


**DPAPI user-bound encryption** restricts the decryption on the host they were encrypted. But they can be decrypted by code running as the current user. No admin privileges are strictly needed here. An attacker with user-level access can extract and decrypt these secrets, assuming access to user profile files. 

**App-Bound Encryption (ABE) decryption**, however, requires elevated privileges. This is because it depends on:
- Impersonating the SYSTEM account and the target user token
- Calling platform APIs such as NCryptDecrypt 

**DLL injection**  into the Chrome process running as the current user is a powerful technique to bypass these boundaries, since injected code inherits Chrome’s token and CNG key context. Reflective DLL injection as xaitax set up does not necessarily require admin privileges, only that the attacker can run code in the user session, which is enough to perform elevator service call. 


The complexity and reliability of these attacks **also depend heavily on hardcoded or system-registered identifiers**, difficult to gather dynamically and can act as killswitch in any Chrome's update:
- CLSIDs and IIDs for COM interfaces
- The "Google Chromekey1" key name inside the Microsoft Software Key Storage Provider
- The fixed XOR key used for additional obfuscation


This change  in cookie encryption can also be a landmark for threat intelligence, to tracker infostealers mutation.

## References 

- **Chrome Extensions APIS :** [https://developer.chrome.com/docs/extensions/reference/](https://developer.chrome.com/docs/extensions/reference/)
- **Application Bound Encryption on Google Blog :** [https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- **Enumerating COM Objects :** [https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-com-objects-and-their-methods](https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-com-objects-and-their-methods)
- **OLE COM Object Viewer :** [https://learn.microsoft.com/en-us/windows/win32/com/ole-com-object-viewer](https://learn.microsoft.com/en-us/windows/win32/com/ole-com-object-viewer)
- **IElevator source code :** [https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/elevation_service/elevator.cc](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/elevation_service/elevator.cc)
- **Chrome cookies source code :** [https://source.chromium.org/chromium/chromium/src/+/main:net/cookies/canonical_cookie.cc](https://source.chromium.org/chromium/chromium/src/+/main:net/cookies/canonical_cookie.cc)
- **Chrome-App-Bound-Encryption-Decryption via COM IElevator GitHub :** [https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- **Chrome-App-Bound-Encryption-Decryption via algorithm :** [https://github.com/runassu/chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption)


T.C
