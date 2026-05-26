# 🛡️ VaultX

**VaultX** is a secure, offline-first, zero-knowledge, client-side encrypted password manager Chrome Extension. Built strictly on **Chrome Manifest V3 (MV3)**, VaultX ensures that your master password, keys, and credentials never touch a remote server and are never stored on disk in plaintext.

The interface is styled entirely using Google's modern **Material Design 3 (M3)** specifications, providing a premium, native Google experience inside Chrome.

---

## ✨ Features

*   **Zero-Knowledge Architecture**: The developer, Google, or any third party has absolute zero access to your master password or vault. All decryption and encryption processes happen strictly on your local browser machine.
*   **Argon2id Key Derivation**: High-security WebAssembly-based KDF to derive 256-bit keys from your master password, heavily neutralizing offline brute-force or GPU-acceleration dictionary attacks.
*   **AES-256-GCM Authenticated Encryption**: Standard AES-GCM encryption with fresh, cryptographically secure 12-byte random Initialization Vectors (IVs) generated on every database write.
*   **Material Design 3 Theme**: Clean, responsive, Google-authentic M3 dark theme featuring elevation tokens, fully rounded pill shapes, floating action buttons (FAB), Outlined Text Fields, M3 toggles, and emphasized motion curves.
*   **Double Domain Isolation**: Secure background worker queries active tab hosts and validates credential domains before routing autofill payloads, stopping cross-site scripting (XSS) and iframe leaks.
*   **SPA Framework Autofill**: content scripts scan form structures and safely fill fields by dispatching synthetic `input` and `change` events, satisfying state frameworks like React, Vue, Angular, and Svelte.
*   **Anti-Interception DOM Protection**: Injects inputs by fetching and calling prototype descriptors (`HTMLInputElement.prototype` / `HTMLTextAreaElement.prototype`) to bypass page-level malicious hooks or value setter overrides.
*   **Secure In-Memory Caching**: Caches keys strictly inside volatile RAM (`chrome.storage.session`) with `TRUSTED_CONTEXTS` access level bounds. Keys are never written to disk, persist over short-lived background worker reloads, and are purged instantly when Chrome is closed.
*   **Auto-Lock Ecosystem**: Alarms actively monitor inactivity thresholds (e.g. 15 minutes) to wipe keys, while listener hooks lock the vault instantly if the OS locks or goes idle.
*   **Secure Clipboard Clearing**: Clipboard copies invoke background alarm timers to clear copied passwords in 30 seconds, protecting secrets from lingering in clipboard histories.
*   **Passphrase-Protected Encrypted Backups**: Exports your vault as an encrypted JSON backup file. Import backups cleanly into new installations by supplying the password that was active at the time of export.

---

## 🔒 Security & Cryptographic Blueprint

```
[Master Password] + [16-byte Random Salt]
       │
       ▼
┌──────────────┐
│  Argon2id   │ ◄─── (Memory: 32MB, Iterations: 2, Parallelism: 2)
└──────┬───────┘
       │ (32-byte Raw Key Material)
       ├─────────────────────────────────────────┐
       ▼                                         ▼
┌──────────────┐                          ┌──────────────┐
│  CryptoKey   │                          │  Array.fill  │
│  Validation  │                          │  Zero-Sweep  │
└──────┬───────┘                          └──────┬───────┘
       │                                         │
       ▼ (extractable = false)                   ▼ (Wipe Raw RAM bytes)
┌──────────────┐                          ┌──────────────┐
│  AES-256-GCM │ ◄── (12-byte Random IV)  │ Garbage Coll │
└──────────────┘                          └──────────────┘
```

### 1. Key Derivation Settings
VaultX packages UMD-compiled WebAssembly binaries locally. When initializing or unlocking the vault, it invokes:
*   **Algorithm**: Argon2id
*   **Memory Cost**: `32768 KB` (32 MB)
*   **Time Cost (Iterations)**: `2`
*   **Parallelism**: `2`
*   **Salt**: `16-byte` cryptographically secure random value (`crypto.getRandomValues`)
*   **Output Length**: `32-byte` (256-bit symmetric key)

### 2. Heap Audits & Zero-Wiping
To defend against heap-inspection attacks (where malicious processes attempt to scan the browser's JavaScript garbage-collected memory to extract keys):
*   Raw key bytes are immediately imported as a native browser **`CryptoKey`** object with **`extractable: false`**. The browser locks the key material inside its low-level cryptographic engine, rendering it unreadable to standard Javascript dumps.
*   Immediately after the `CryptoKey` is loaded, the temporary buffer array in JS memory is explicitly zeroed out: **`keyBytes.fill(0)`**.
*   Scope string variables containing raw passwords or confirmation pins are immediately overwritten with empty values (`''`) and set to `null` to facilitate rapid garbage collection.

---

## 🚀 Installation & Loading (Local Setup)

VaultX is ready for local previewing and packing:

1.  Clone this repository or download the source code locally.
2.  Open **Google Chrome** and navigate to the extensions page: `chrome://extensions/`.
3.  In the top-right corner, toggle **Developer mode** to **ON**.
4.  In the top-left corner of the toolbar, click **Load unpacked**.
5.  Select the folder containing this project (the directory containing `manifest.json`).
6.  VaultX is now loaded! Pinned the shield icon to your active extension bar for rapid previews.

---

## 🧪 Integration & Verification Testing

We have included a dedicated mock login page in the repository to let you test the extension's capabilities:

1.  Open Chrome and navigate to the test file in your browser:
    ```
    file:///C:/path/to/project/scratch/mock_login.html
    ```
2.  Open the VaultX extension, set your master password, and initialize the database.
3.  Click the `+` header icon to add a credential. Note that the website domain is automatically parsed and filled!
4.  Add a username (e.g. `test@acme.com`), expand the **Password Generator** drawer to generate a secure string, apply it, and click **Save**.
5.  Hover over the newly created suggested card and click the green checkmark **Autofill** button.
6.  The credential fields on the mock SaaS page will instantly populate with a premium success **violet glow**, bypassing DOM setters securely and updating state handlers!
7.  Verify copy clipboard timeouts by copying a password and watching it securely vanish from your system clipboard after 30 seconds.

---

## 📄 License

This project is open-source, fully transparent, and licensed under the **MIT License**. Audits, issues, and contributions are highly welcome.
