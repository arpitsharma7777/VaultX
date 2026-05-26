// VaultX - Service Worker Session and Message Manager

let clipboardClearTimer = null;

// Configure session storage access levels on installation
chrome.runtime.onInstalled.addListener(() => {
  if (chrome.storage.session) {
    chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  }
  // Initialize default idle check alarms
  chrome.alarms.create("autoLockCheck", { periodInMinutes: 1 });
  console.log("VaultX background service worker initialized.");
});

// Alarm Listener: Run every minute to check if the session has expired
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "autoLockCheck") {
    checkActivityAndLock();
  }
});

// Idle State Listener: Lock if system goes idle or locks
chrome.idle.onStateChanged.addListener((state) => {
  if (state === "idle" || state === "locked") {
    chrome.storage.session.get(['sessionKey', 'lockOnSystemIdle'], (sessionData) => {
      if (sessionData.sessionKey && sessionData.lockOnSystemIdle !== false) {
        lockVault("system_idle");
      }
    });
  }
});

// Helper function to lock the vault securely
function lockVault(reason = "timeout") {
  chrome.storage.session.remove(['sessionKey', 'lastActiveTime'], () => {
    console.log(`Vault auto-locked: ${reason}`);
    // Notify open popup if any
    chrome.runtime.sendMessage({ action: "vaultLocked", reason }).catch(() => {
      // Ignore error if popup is not open
    });
  });
}

// Check last active time against session settings
function checkActivityAndLock() {
  chrome.storage.session.get(['sessionKey', 'lastActiveTime', 'idleTimeout'], (sessionData) => {
    if (!sessionData.sessionKey) return;

    const now = Date.now();
    const idleTimeoutMin = sessionData.idleTimeout !== undefined ? sessionData.idleTimeout : 15; // default 15 mins

    // -1 represents "Never lock"
    if (idleTimeoutMin === -1) return;

    const timeoutMs = idleTimeoutMin * 60 * 1000;
    const lastActive = sessionData.lastActiveTime || now;

    if (now - lastActive > timeoutMs) {
      lockVault("inactivity");
    }
  });
}

// Clean domains to ensure direct domain matching (e.g. www.example.com -> example.com)
function extractBaseDomain(hostname) {
  if (!hostname) return '';
  
  // Check if hostname is an IP address (IPv4). If so, return as-is without splitting
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (ipRegex.test(hostname)) {
    return hostname;
  }

  let parts = hostname.split('.');
  if (parts.length > 2) {
    // Check for common multi-part suffixes like .co.uk
    const suffix = parts.slice(-2).join('.');
    if (['co.uk', 'co.jp', 'com.br', 'com.mx', 'org.uk'].includes(suffix)) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }
  return hostname;
}

// Message listener for secure communications
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Update activity timestamp on any user-triggered extension messaging
  if (message.action !== "vaultLocked") {
    chrome.storage.session.get('sessionKey', (res) => {
      if (res.sessionKey) {
        chrome.storage.session.set({ lastActiveTime: Date.now() });
      }
    });
  }

  // Action: Trigger secure clipboard clear timer
  if (message.action === "startClipboardTimer") {
    const timeoutMs = message.timeoutMs || 30000;
    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);

    clipboardClearTimer = setTimeout(async () => {
      try {
        // Query active tab to clear clipboard using scripting
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url && !tab.url.startsWith("chrome://")) {
          // Standard tab, clear clipboard
          chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: () => {
              try {
                navigator.clipboard.writeText("");
                console.log("[VaultX] Clipboard cleared securely.");
              } catch (err) {
                // Clipboard API might need user gesture in target tab
              }
            }
          }).catch(err => console.log("Background clipboard clear execution bypassed:", err));
        }
      } catch (err) {
        console.log("Error during clipboard clearance:", err);
      }
    }, timeoutMs);

    sendResponse({ status: "timer_started" });
  }

  // Action: Request credential autofill
  if (message.action === "autofillCredential") {
    const { username, password, domain } = message;
    
    // Perform active tab verification for domain matching (anti-phishing measure)
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length === 0) {
        sendResponse({ success: false, error: "No active tab found" });
        return;
      }

      const activeTab = tabs[0];
      if (!activeTab.url) {
        sendResponse({ success: false, error: "No active URL accessible" });
        return;
      }

      try {
        const tabUrl = new URL(activeTab.url);
        const tabBaseDomain = extractBaseDomain(tabUrl.hostname);
        const credentialBaseDomain = extractBaseDomain(domain);

        let isMatch = tabBaseDomain === credentialBaseDomain;

        // Local file protocol exception to facilitate seamless offline dev testing
        if (tabUrl.protocol === "file:") {
          const cleanPath = decodeURIComponent(tabUrl.pathname).toLowerCase();
          const cleanDomain = credentialBaseDomain.toLowerCase();
          if (cleanDomain && cleanPath.includes(cleanDomain)) {
            isMatch = true;
          }
        }

        if (!isMatch) {
          console.warn(`Autofill blocked: Domain mismatch. Active: ${tabBaseDomain}, Credential: ${credentialBaseDomain}`);
          sendResponse({ success: false, error: "Domain mismatch" });
          return;
        }

        // Domain verification passed, inject into tab content script
        chrome.tabs.sendMessage(activeTab.id, {
          action: "fillLoginForm",
          username,
          password
        }, (response) => {
          if (chrome.runtime.lastError) {
            // Content script not ready or loaded yet
            sendResponse({ success: false, error: "Content script unresponsive. Please refresh the page." });
          } else {
            sendResponse({ success: true });
          }
        });
      } catch (e) {
        sendResponse({ success: false, error: "Security parser failure" });
      }
    });

    return true; // Keep message channel open for asynchronous sendResponse
  }
});
