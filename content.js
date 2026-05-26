// VaultX - Secure Form Detector and Autofill Injector

// Helper to verify element visibility
function isElementVisible(el) {
  if (!el) return false;
  const rect = el.getBoundingClientRect();
  const style = window.getComputedStyle(el);
  return (
    rect.width > 0 &&
    rect.height > 0 &&
    style.visibility !== 'hidden' &&
    style.display !== 'none' &&
    style.opacity !== '0'
  );
}

// Locate matching username input for a given password input
function findUsernameField(passwordInput) {
  const form = passwordInput.closest('form');
  
  if (form) {
    // Strategy 1: Check standard text or email inputs inside the same form
    const inputs = Array.from(form.querySelectorAll('input'));
    const pwdIndex = inputs.indexOf(passwordInput);
    
    // Look backwards in the form from the password field
    for (let i = pwdIndex - 1; i >= 0; i--) {
      const type = (inputs[i].getAttribute('type') || 'text').toLowerCase();
      if (['text', 'email', 'username'].includes(type) && isElementVisible(inputs[i])) {
        return inputs[i];
      }
    }
  }

  // Strategy 2: Scan globally for preceding visible text/email inputs
  const allInputs = Array.from(document.querySelectorAll('input'));
  const pwdIndex = allInputs.indexOf(passwordInput);
  if (pwdIndex > 0) {
    for (let i = pwdIndex - 1; i >= 0; i--) {
      const type = (allInputs[i].getAttribute('type') || 'text').toLowerCase();
      if (['text', 'email', 'username'].includes(type) && isElementVisible(allInputs[i])) {
        return allInputs[i];
      }
    }
  }

  return null;
}

// Safely set field values triggering standard framework handlers
function setFieldValue(inputField, value) {
  if (!inputField) return;
  
  // Bypass page-level setter modifications (anti-interception measure)
  try {
    const proto = inputField instanceof HTMLTextAreaElement 
      ? HTMLTextAreaElement.prototype 
      : HTMLInputElement.prototype;
      
    const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
    if (descriptor && descriptor.set) {
      descriptor.set.call(inputField, value);
    } else {
      inputField.value = value;
    }
  } catch (e) {
    inputField.value = value;
  }
  
  // Dispatch events to satisfy SPA state frameworks (React, Vue, Angular)
  inputField.dispatchEvent(new Event('input', { bubbles: true }));
  inputField.dispatchEvent(new Event('change', { bubbles: true }));
  
  // Highlight briefly with a subtle success glow to give a premium feel
  const originalTransition = inputField.style.transition;
  const originalBoxShadow = inputField.style.boxShadow;
  
  inputField.style.transition = 'box-shadow 0.3s ease';
  inputField.style.boxShadow = '0 0 10px rgba(139, 92, 246, 0.6)'; // violet success pulse
  
  setTimeout(() => {
    inputField.style.boxShadow = originalBoxShadow;
    setTimeout(() => {
      inputField.style.transition = originalTransition;
    }, 300);
  }, 1000);
}

// Listen for messages from background.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "fillLoginForm") {
    const { username, password } = message;
    
    // Scan DOM for password fields
    const passwordFields = Array.from(document.querySelectorAll('input[type="password"]'))
      .filter(isElementVisible);

    if (passwordFields.length === 0) {
      sendResponse({ success: false, error: "No visible login form detected on the page." });
      return;
    }

    // Populate all visible login password fields and their matching username fields
    let filledCount = 0;
    passwordFields.forEach(passwordField => {
      const usernameField = findUsernameField(passwordField);
      
      if (usernameField && username) {
        setFieldValue(usernameField, username);
      }
      setFieldValue(passwordField, password);
      filledCount++;
    });

    sendResponse({ success: true, filled: filledCount });
  }
});
