---
layout: post
title: "Chrome data reminder"
nav_order: 2
has_children: false
parent: "Chrome credentials - 2025"

---

# Chrome data reminder 

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
