// VaultX - Secure Password Manager Controller

// Global State
let activeSessionKey = null; // Uint8Array (32 bytes)
let vaultData = { entries: [] };
let activeTabDomain = '';

// DOM Elements
const screens = {
  setup: document.getElementById('setup-screen'),
  unlock: document.getElementById('unlock-screen'),
  vault: document.getElementById('vault-screen'),
  form: document.getElementById('form-screen'),
  settings: document.getElementById('settings-screen')
};

const loader = {
  overlay: document.getElementById('loading-overlay'),
  text: document.getElementById('loading-text')
};

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
  initializeEventListeners();
  detectActiveTabDomain();
  checkVaultStatus();
});

// --- SCREEN ROUTING ---
function showScreen(screenId) {
  Object.entries(screens).forEach(([id, element]) => {
    if (id === screenId) {
      element.classList.remove('d-none');
    } else {
      element.classList.add('d-none');
    }
  });
}

function showLoading(message) {
  loader.text.textContent = message;
  loader.overlay.classList.remove('d-none');
}

function hideLoading() {
  loader.overlay.classList.add('d-none');
}

function showToast(message) {
  const toast = document.getElementById('toast');
  const toastMsg = document.getElementById('toast-message');
  toastMsg.textContent = message;
  toast.classList.remove('d-none');
  
  setTimeout(() => {
    toast.classList.add('d-none');
  }, 2500);
}

// --- SECURE DOMAIN PARSER ---
function extractBaseDomain(hostname) {
  if (!hostname) return '';
  
  // Check if hostname is an IP address (IPv4). If so, return as-is without splitting
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (ipRegex.test(hostname)) {
    return hostname;
  }

  let parts = hostname.split('.');
  if (parts.length > 2) {
    const suffix = parts.slice(-2).join('.');
    if (['co.uk', 'co.jp', 'com.br', 'com.mx', 'org.uk'].includes(suffix)) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }
  return hostname;
}

function detectActiveTabDomain() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      try {
        const url = new URL(tabs[0].url);
        if (!url.protocol.startsWith('chrome')) {
          activeTabDomain = extractBaseDomain(url.hostname);
        }
      } catch (e) {
        console.log("No clean URL detected on active tab:", e);
      }
    }
  });
}

// Check if vault initialized
function checkVaultStatus() {
  chrome.storage.local.get(['salt', 'vault'], (localData) => {
    if (localData.salt && localData.vault) {
      // Vault exists, check if session is active
      chrome.storage.session.get(['sessionKey'], (sessionData) => {
        if (sessionData.sessionKey) {
          const keyBytes = base64ToArray(sessionData.sessionKey);
          importSessionKey(keyBytes).then(cryptoKey => {
            activeSessionKey = cryptoKey;
            keyBytes.fill(0); // Wipe raw key material from memory!
            decryptAndLoadVault();
          }).catch(err => {
            console.error("Failed to import session key:", err);
            showScreen('unlock');
          });
        } else {
          showScreen('unlock');
        }
      });
    } else {
      showScreen('setup');
    }
  });
}

// --- BINARY ENCODING UTILS ---
function arrayToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArray(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

// --- CRYPTOGRAPHY ACTIONS ---
// --- KDF Argon2id ---
async function deriveKey(password, saltBytes) {
  // Uses hash-wasm preloaded globally
  const derivedKey = await hashwasm.argon2id({
    password: password,
    salt: saltBytes,
    iterations: 2,
    memorySize: 32768, // 32MB
    parallelism: 2,
    hashLength: 32,
    outputType: 'binary'
  });
  return derivedKey; // Returns Uint8Array (32 bytes)
}

// Import raw bytes into a non-extractable standard CryptoKey
async function importSessionKey(keyBytes) {
  return await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false, // extractable = false (CRITICAL FOR MEMORY AUDITING!)
    ["encrypt", "decrypt"]
  );
}

// Encrypt database using AES-GCM and CryptoKey
async function encryptData(plainText, cryptoKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(plainText);
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    cryptoKey,
    encodedText
  );

  return {
    iv: arrayToBase64(iv),
    data: arrayToBase64(ciphertext)
  };
}

// Decrypt database using AES-GCM and CryptoKey
async function decryptData(encryptedObj, cryptoKey) {
  const iv = base64ToArray(encryptedObj.iv);
  const ciphertext = base64ToArray(encryptedObj.data);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv },
    cryptoKey,
    ciphertext
  );

  return new TextDecoder().decode(decrypted);
}

// --- DATABASE HANDLERS ---
async function decryptAndLoadVault() {
  showLoading("Decrypting Vault...");
  try {
    const localData = await new Promise((resolve) => {
      chrome.storage.local.get(['vault'], resolve);
    });
    
    if (localData.vault) {
      const decryptedString = await decryptData(localData.vault, activeSessionKey);
      vaultData = JSON.parse(decryptedString);
    } else {
      vaultData = { entries: [] };
    }
    
    renderVaultEntries();
    showScreen('vault');
  } catch (err) {
    console.error("Vault decryption failed:", err);
    showScreen('unlock');
    showUnlockError("Failed to decrypt vault. Please ensure master password is correct.");
  } finally {
    hideLoading();
  }
}

async function saveVaultData() {
  if (!activeSessionKey) return;
  showLoading("Encrypting Vault...");
  try {
    const plainText = JSON.stringify(vaultData);
    const encryptedVault = await encryptData(plainText, activeSessionKey);
    
    await new Promise((resolve) => {
      chrome.storage.local.set({ vault: encryptedVault }, resolve);
    });
  } catch (err) {
    console.error("Failed to save vault:", err);
    showToast("Encryption failure. Changes not saved.");
  } finally {
    hideLoading();
  }
}

// --- RENDER FUNCTIONS ---
function renderVaultEntries(searchQuery = '') {
  const suggestedSection = document.getElementById('suggested-section');
  const suggestedList = document.getElementById('suggested-list');
  const allEntriesList = document.getElementById('all-entries-list');
  const emptyVaultMsg = document.getElementById('empty-vault-message');
  
  suggestedList.innerHTML = '';
  allEntriesList.innerHTML = '';

  const entries = vaultData.entries || [];
  
  if (entries.length === 0) {
    emptyVaultMsg.classList.remove('d-none');
    suggestedSection.classList.add('d-none');
    return;
  }
  
  emptyVaultMsg.classList.add('d-none');
  
  const query = searchQuery.trim().toLowerCase();
  
  // Filter entries based on search query
  const filteredEntries = entries.filter(entry => {
    return (
      entry.name.toLowerCase().includes(query) ||
      entry.domain.toLowerCase().includes(query) ||
      entry.username.toLowerCase().includes(query) ||
      (entry.notes && entry.notes.toLowerCase().includes(query))
    );
  });

  // Split into suggested vs normal
  const suggested = [];
  const standard = [];

  filteredEntries.forEach(entry => {
    const entryBaseDomain = extractBaseDomain(entry.domain);
    if (activeTabDomain && entryBaseDomain === activeTabDomain && !query) {
      suggested.push(entry);
    } else {
      standard.push(entry);
    }
  });

  // Render Suggested Segment
  if (suggested.length > 0) {
    suggestedSection.classList.remove('d-none');
    suggested.forEach(entry => {
      suggestedList.appendChild(createEntryCard(entry));
    });
  } else {
    suggestedSection.classList.add('d-none');
  }

  // Render Standard Segment
  if (standard.length > 0 || suggested.length > 0) {
    standard.forEach(entry => {
      allEntriesList.appendChild(createEntryCard(entry));
    });
  } else {
    allEntriesList.innerHTML = `<div class="empty-state"><p>No search matches found.</p></div>`;
  }
}

function createEntryCard(entry) {
  const card = document.createElement('div');
  card.className = 'entry-card';
  card.dataset.id = entry.id;

  const letter = entry.name ? entry.name.charAt(0).toUpperCase() : '?';
  
  card.innerHTML = `
    <div class="entry-meta">
      <div class="entry-avatar">${letter}</div>
      <div class="entry-info">
        <span class="entry-title">${escapeHtml(entry.name)}</span>
        <span class="entry-sub">${escapeHtml(entry.username)} • ${escapeHtml(entry.domain)}</span>
      </div>
    </div>
    <div class="entry-actions">
      <button class="btn-action btn-fill" title="Autofill Form">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg>
      </button>
      <button class="btn-action btn-copy-username" title="Copy Username">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
      </button>
      <button class="btn-action btn-copy-password" title="Copy Password">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
      </button>
      <button class="btn-action btn-edit" title="Edit Logins">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"></path><path d="M18.5 2.5a2.121 2.121 0 1 1 3 3L12 15l-4 1 1-4 9.5-9.5z"></path></svg>
      </button>
    </div>
  `;

  // Action listeners
  card.querySelector('.btn-fill').addEventListener('click', (e) => {
    e.stopPropagation();
    triggerAutofill(entry);
  });

  card.querySelector('.btn-copy-username').addEventListener('click', (e) => {
    e.stopPropagation();
    copyTextToClipboard(entry.username, "Username copied to clipboard!");
  });

  card.querySelector('.btn-copy-password').addEventListener('click', (e) => {
    e.stopPropagation();
    copyTextToClipboard(entry.password, "Password copied! Clears in 30 seconds.");
    triggerClipboardTimer();
  });

  card.querySelector('.btn-edit').addEventListener('click', (e) => {
    e.stopPropagation();
    openFormScreen(entry);
  });

  return card;
}

function escapeHtml(str) {
  if (!str) return '';
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// --- ACTIONS & UTILS ---
async function copyTextToClipboard(text, successMessage) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(successMessage);
  } catch (err) {
    showToast("Failed to copy clipboard.");
  }
}

function triggerClipboardTimer() {
  chrome.storage.local.get(['clipboardTimeout'], (data) => {
    const seconds = data.clipboardTimeout ? parseInt(data.clipboardTimeout) : 30;
    chrome.runtime.sendMessage({
      action: "startClipboardTimer",
      timeoutMs: seconds * 1000
    });
  });
}

function triggerAutofill(entry) {
  chrome.runtime.sendMessage({
    action: "autofillCredential",
    username: entry.username,
    password: entry.password,
    domain: entry.domain
  }, (response) => {
    if (response && response.success) {
      showToast("Form fields filled securely!");
    } else {
      showToast(response ? response.error : "Autofill failed. Try reloading the tab.");
    }
  });
}

// --- PASSWORD GENERATOR ---
function generateSecurePassword() {
  const length = parseInt(document.getElementById('gen-length').value);
  const uppercase = document.getElementById('gen-uppercase').checked;
  const lowercase = document.getElementById('gen-lowercase').checked;
  const numbers = document.getElementById('gen-numbers').checked;
  const symbols = document.getElementById('gen-symbols').checked;

  let charPool = '';
  if (uppercase) charPool += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (lowercase) charPool += 'abcdefghijklmnopqrstuvwxyz';
  if (numbers) charPool += '0123456789';
  if (symbols) charPool += '!@#$%^&*()_+-=[]{}|;:,.<>?';

  if (!charPool) {
    document.getElementById('gen-output').value = '';
    return;
  }

  // Cryptographically secure random character selection
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);
  
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charPool.charAt(randomValues[i] % charPool.length);
  }

  document.getElementById('gen-output').value = password;
}

// --- EVENT HANDLERS ---
function initializeEventListeners() {
  // 1. SETUP SCREEN
  document.getElementById('setup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    let password = document.getElementById('setup-password').value;
    let confirm = document.getElementById('setup-password-confirm').value;

    if (password !== confirm) {
      alert("Passwords do not match!");
      return;
    }

    showLoading("Generating cryptographically secure vault...");
    try {
      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const keyBytes = await deriveKey(password, saltBytes);
      activeSessionKey = await importSessionKey(keyBytes);
      vaultData = { entries: [] };

      // Encrypt empty initial database
      const encryptedVault = await encryptData(JSON.stringify(vaultData), activeSessionKey);

      // Save to local storage
      await new Promise((resolve) => {
        chrome.storage.local.set({
          salt: arrayToBase64(saltBytes),
          vault: encryptedVault
        }, resolve);
      });

      // Save key in memory session storage
      await new Promise((resolve) => {
        chrome.storage.session.set({
          sessionKey: arrayToBase64(keyBytes),
          lastActiveTime: Date.now()
        }, resolve);
      });

      // Secure Heap Cleanup: Clear fields and wipe transient arrays
      document.getElementById('setup-password').value = '';
      document.getElementById('setup-password-confirm').value = '';
      password = '';
      confirm = '';
      keyBytes.fill(0); // Zero out derived raw key material!

      renderVaultEntries();
      showScreen('vault');
      showToast("Vault initialized successfully.");
    } catch (err) {
      console.error(err);
      alert("Failed to initialize database: " + err.message);
    } finally {
      hideLoading();
    }
  });

  // 2. UNLOCK SCREEN
  document.getElementById('unlock-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    let password = document.getElementById('unlock-password').value;
    hideUnlockError();

    showLoading("Verifying master password...");
    try {
      const localData = await new Promise((resolve) => {
        chrome.storage.local.get(['salt'], resolve);
      });

      const saltBytes = base64ToArray(localData.salt);
      const keyBytes = await deriveKey(password, saltBytes);
      const testSessionKey = await importSessionKey(keyBytes);

      // Verify correctness by attempting decryption
      const vaultRes = await new Promise((resolve) => {
        chrome.storage.local.get(['vault'], resolve);
      });

      // Decrypt to test validation
      const decryptedString = await decryptData(vaultRes.vault, testSessionKey);
      
      // Success! Set session keys and load
      activeSessionKey = testSessionKey;
      vaultData = JSON.parse(decryptedString);

      await new Promise((resolve) => {
        chrome.storage.session.set({
          sessionKey: arrayToBase64(keyBytes),
          lastActiveTime: Date.now()
        }, resolve);
      });

      // Secure Heap Cleanup: Wiping sensitive inputs and raw byte arrays immediately
      document.getElementById('unlock-password').value = '';
      password = '';
      keyBytes.fill(0); // Clear key material from system RAM!

      renderVaultEntries();
      showScreen('vault');
      showToast("Vault unlocked.");
    } catch (err) {
      console.error("Wrong password or corrupted:", err);
      showUnlockError("Incorrect master password. Please verify spelling.");
    } finally {
      hideLoading();
    }
  });

  const toggleUnlockPw = document.getElementById('toggle-unlock-password');
  const unlockPwInput = document.getElementById('unlock-password');
  toggleUnlockPw.addEventListener('click', () => {
    const type = unlockPwInput.type === 'password' ? 'text' : 'password';
    unlockPwInput.type = type;
  });

  // 3. VAULT SCREEN ACTIONS
  document.getElementById('btn-add-entry').addEventListener('click', () => {
    openFormScreen();
  });

  document.getElementById('btn-create-first').addEventListener('click', () => {
    openFormScreen();
  });

  document.getElementById('btn-settings').addEventListener('click', () => {
    openSettingsScreen();
  });

  document.getElementById('btn-lock').addEventListener('click', () => {
    lockVaultManually();
  });

  // Search Action
  const searchInput = document.getElementById('search-input');
  const btnClearSearch = document.getElementById('btn-clear-search');

  searchInput.addEventListener('input', (e) => {
    const query = e.target.value;
    if (query) {
      btnClearSearch.classList.remove('d-none');
    } else {
      btnClearSearch.classList.add('d-none');
    }
    renderVaultEntries(query);
  });

  btnClearSearch.addEventListener('click', () => {
    searchInput.value = '';
    btnClearSearch.classList.add('d-none');
    renderVaultEntries();
  });

  // 4. FORM SCREEN ACTIONS
  document.getElementById('btn-form-back').addEventListener('click', () => {
    showScreen('vault');
  });
  
  document.getElementById('btn-form-cancel').addEventListener('click', () => {
    showScreen('vault');
  });

  const entryPwInput = document.getElementById('entry-password');
  const toggleEntryPw = document.getElementById('toggle-entry-password');
  toggleEntryPw.addEventListener('click', () => {
    entryPwInput.type = entryPwInput.type === 'password' ? 'text' : 'password';
  });

  // Toggle Password Generator
  const btnToggleGen = document.getElementById('btn-toggle-generator');
  const genDrawer = document.getElementById('generator-drawer');
  btnToggleGen.addEventListener('click', () => {
    genDrawer.classList.toggle('d-none');
    if (!genDrawer.classList.contains('d-none')) {
      generateSecurePassword();
    }
  });

  document.getElementById('gen-length').addEventListener('input', (e) => {
    document.getElementById('gen-len-val').textContent = e.target.value;
    generateSecurePassword();
  });

  ['gen-uppercase', 'gen-lowercase', 'gen-numbers', 'gen-symbols'].forEach(id => {
    document.getElementById(id).addEventListener('change', generateSecurePassword);
  });

  document.getElementById('btn-copy-gen').addEventListener('click', () => {
    const val = document.getElementById('gen-output').value;
    if (val) {
      copyTextToClipboard(val, "Generated password copied!");
    }
  });

  document.getElementById('btn-apply-gen').addEventListener('click', () => {
    const val = document.getElementById('gen-output').value;
    if (val) {
      document.getElementById('entry-password').value = val;
      genDrawer.classList.add('d-none');
      showToast("Generated password applied!");
    }
  });

  // Submit Credential Form
  document.getElementById('entry-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = document.getElementById('entry-id').value;
    const name = document.getElementById('entry-name').value;
    let domain = document.getElementById('entry-domain').value.trim();
    const username = document.getElementById('entry-username').value;
    const password = document.getElementById('entry-password').value;
    const notes = document.getElementById('entry-notes').value;

    // Standardize domain names
    try {
      if (domain.includes('://')) {
        domain = new URL(domain).hostname;
      }
    } catch (err) {}

    const entryData = {
      id: id || crypto.randomUUID(),
      name,
      domain,
      username,
      password,
      notes,
      createdAt: id ? (vaultData.entries.find(x => x.id === id)?.createdAt || Date.now()) : Date.now()
    };

    if (id) {
      // Edit mode
      const index = vaultData.entries.findIndex(x => x.id === id);
      if (index !== -1) {
        vaultData.entries[index] = entryData;
      }
    } else {
      // Add mode
      vaultData.entries.push(entryData);
    }

    await saveVaultData();
    renderVaultEntries();
    showScreen('vault');
    showToast(id ? "Credential modified." : "Credential stored safely.");
  });

  // 5. SETTINGS ACTIONS
  document.getElementById('btn-settings-back').addEventListener('click', () => {
    showScreen('vault');
  });

  // Auto lock timeouts
  const selectTimeout = document.getElementById('select-lock-timeout');
  selectTimeout.addEventListener('change', (e) => {
    const mins = parseInt(e.target.value);
    chrome.storage.session.set({ idleTimeout: mins });
    chrome.storage.local.set({ idleTimeout: mins });
    showToast("Auto-Lock timeout modified.");
  });

  // System idle lock
  const checkSystemIdle = document.getElementById('checkbox-system-idle');
  checkSystemIdle.addEventListener('change', (e) => {
    const val = e.target.checked;
    chrome.storage.session.set({ lockOnSystemIdle: val });
    chrome.storage.local.set({ lockOnSystemIdle: val });
    showToast(`Lock on system idle ${val ? 'enabled' : 'disabled'}.`);
  });

  // Clipboard Clear Timeouts
  const selectClip = document.getElementById('select-clipboard-timeout');
  selectClip.addEventListener('change', (e) => {
    const secs = parseInt(e.target.value);
    chrome.storage.local.set({ clipboardTimeout: secs });
    showToast("Clipboard timeout modified.");
  });

  // Export Backups
  document.getElementById('btn-export-vault').addEventListener('click', () => {
    exportEncryptedVault();
  });

  // Import Trigger
  const fileInput = document.getElementById('import-file-input');
  document.getElementById('btn-import-vault-trigger').addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      promptImportBackup(e.target.files[0]);
    }
  });

  // Factory Reset
  document.getElementById('btn-factory-reset').addEventListener('click', () => {
    openModal('modal-reset');
  });

  document.getElementById('btn-reset-cancel').addEventListener('click', closeModal);
  document.getElementById('btn-reset-confirm').addEventListener('click', () => {
    performFactoryReset();
  });

  // Forgot Password / Purge trigger
  document.getElementById('btn-reset-vault-trigger').addEventListener('click', () => {
    openModal('modal-purge-vault');
  });

  document.getElementById('btn-purge-cancel').addEventListener('click', closeModal);
  document.getElementById('btn-purge-confirm').addEventListener('click', () => {
    performFactoryReset();
  });

  // Import Dialog
  document.getElementById('btn-import-cancel').addEventListener('click', closeModal);

  // Alarm Lock messaging triggers
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === "vaultLocked") {
      activeSessionKey = null;
      vaultData = { entries: [] };
      showScreen('unlock');
    }
  });
}

// Unlock UI state alerts
function showUnlockError(message) {
  const err = document.getElementById('unlock-error');
  err.textContent = message;
  err.classList.remove('d-none');
}

function hideUnlockError() {
  document.getElementById('unlock-error').classList.add('d-none');
}

// Modals management
function openModal(modalId) {
  document.getElementById('modal-container').classList.remove('d-none');
  Array.from(document.getElementById('modal-container').children).forEach(box => {
    if (box.id === modalId) {
      box.classList.remove('d-none');
    } else {
      box.classList.add('d-none');
    }
  });
}

function closeModal() {
  document.getElementById('modal-container').classList.add('d-none');
  // Reset fields if import modal
  document.getElementById('import-password').value = '';
  document.getElementById('import-error').classList.add('d-none');
}

// Lock manually
function lockVaultManually() {
  activeSessionKey = null;
  vaultData = { entries: [] };
  chrome.storage.session.remove(['sessionKey', 'lastActiveTime'], () => {
    showScreen('unlock');
    showToast("Vault locked securely.");
  });
}

// Factory Reset / Purge DB
function performFactoryReset() {
  showLoading("Purging all local data...");
  chrome.storage.local.clear(() => {
    chrome.storage.session.clear(() => {
      activeSessionKey = null;
      vaultData = { entries: [] };
      closeModal();
      hideLoading();
      showScreen('setup');
      showToast("Database destroyed. Set up a new vault.");
    });
  });
}

// --- FORM LOAD ACTIONS ---
function openFormScreen(entry = null) {
  const title = document.getElementById('form-title');
  const idField = document.getElementById('entry-id');
  const nameField = document.getElementById('entry-name');
  const domainField = document.getElementById('entry-domain');
  const usernameField = document.getElementById('entry-username');
  const passwordField = document.getElementById('entry-password');
  const notesField = document.getElementById('entry-notes');

  // Reset password generator drawer
  document.getElementById('generator-drawer').classList.add('d-none');

  if (entry) {
    title.textContent = "Modify Credential";
    idField.value = entry.id;
    nameField.value = entry.name;
    domainField.value = entry.domain;
    usernameField.value = entry.username;
    passwordField.value = entry.password;
    notesField.value = entry.notes || '';
  } else {
    title.textContent = "Add Credential";
    idField.value = '';
    nameField.value = '';
    // Autopopulate domain based on active tab
    domainField.value = activeTabDomain || '';
    usernameField.value = '';
    passwordField.value = '';
    notesField.value = '';
  }

  showScreen('form');
}

function openSettingsScreen() {
  // Load current values
  chrome.storage.local.get(['idleTimeout', 'lockOnSystemIdle', 'clipboardTimeout'], (data) => {
    document.getElementById('select-lock-timeout').value = data.idleTimeout !== undefined ? data.idleTimeout : 15;
    document.getElementById('checkbox-system-idle').checked = data.lockOnSystemIdle !== false;
    document.getElementById('select-clipboard-timeout').value = data.clipboardTimeout || 30;
    showScreen('settings');
  });
}

// --- SECURE BACKUPS (JSON EXPORT/IMPORT) ---
async function exportEncryptedVault() {
  if (!activeSessionKey) return;
  showLoading("Encrypting backup...");
  try {
    // Generate secure backup schema: Contains salt, and vault encrypted blob
    const saltRes = await new Promise((resolve) => {
      chrome.storage.local.get(['salt'], resolve);
    });

    const exportData = {
      type: "VaultXBackup",
      version: 1,
      salt: saltRes.salt,
      vault: await encryptData(JSON.stringify(vaultData), activeSessionKey),
      exportedAt: Date.now()
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    // Save backup using anchor click downloader
    const a = document.createElement('a');
    a.href = url;
    a.download = `vaultx_backup_${new Date().toISOString().slice(0,10)}.json`;
    a.click();
    
    URL.revokeObjectURL(url);
    showToast("Backup exported successfully!");
  } catch (err) {
    console.error(err);
    showToast("Backup failed.");
  } finally {
    hideLoading();
  }
}

let pendingImportFile = null;

function promptImportBackup(file) {
  pendingImportFile = file;
  openModal('modal-import-password');
}

// Handle Backup file merge
document.getElementById('btn-import-confirm').addEventListener('click', async () => {
  const password = document.getElementById('import-password').value;
  const importError = document.getElementById('import-error');
  importError.classList.add('d-none');

  if (!password || !pendingImportFile) return;

  showLoading("Decrypting uploaded backup...");
  try {
    const fileContent = await new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => resolve(e.target.result);
      reader.onerror = (e) => reject(e);
      reader.readAsText(pendingImportFile);
    });

    const backupObj = JSON.parse(fileContent);
    
    if (backupObj.type !== "VaultXBackup" || !backupObj.salt || !backupObj.vault) {
      throw new Error("Invalid VaultX backup format.");
    }

    // Derive the key of the backup using the provided password and the backup's salt
    const backupSaltBytes = base64ToArray(backupObj.salt);
    const backupKeyBytes = await deriveKey(password, backupSaltBytes);
    const backupCryptoKey = await importSessionKey(backupKeyBytes);

    // Decrypt the backup's vault
    const decryptedBackupString = await decryptData(backupObj.vault, backupCryptoKey);
    const backupVaultData = JSON.parse(decryptedBackupString);
    
    // Secure Heap Cleanup
    backupKeyBytes.fill(0); // Wipe backup key material

    if (!backupVaultData.entries || !Array.isArray(backupVaultData.entries)) {
      throw new Error("Corrupted backup data entries.");
    }

    // Merge strategy: Add new ones, update matching IDs
    let newCount = 0;
    let updateCount = 0;

    backupVaultData.entries.forEach(backupEntry => {
      const existingIndex = vaultData.entries.findIndex(x => x.id === backupEntry.id);
      if (existingIndex !== -1) {
        // Overwrite existing with backup if backup is newer, or prompt-less merge
        vaultData.entries[existingIndex] = backupEntry;
        updateCount++;
      } else {
        vaultData.entries.push(backupEntry);
        newCount++;
      }
    });

    // Save newly merged database
    await saveVaultData();
    renderVaultEntries();
    
    closeModal();
    showScreen('vault');
    showToast(`Import Success: Added ${newCount}, Updated ${updateCount}`);
  } catch (err) {
    console.error("Backup import error:", err);
    importError.textContent = "Backup Decryption Failed. Check password or file integrity.";
    importError.classList.remove('d-none');
  } finally {
    hideLoading();
    pendingImportFile = null;
    document.getElementById('import-file-input').value = '';
  }
});
