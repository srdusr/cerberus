// Content script: detects login/change-password forms and can fill them

function findLoginForms() {
  const forms = Array.from(document.querySelectorAll('form'));
  const results = [];
  for (const f of forms) {
    const inputs = Array.from(f.querySelectorAll('input'));
    const hasPassword = inputs.some(i => (i.type || '').toLowerCase() === 'password');
    const username = inputs.find(i => ['text','email','tel','username'].includes((i.type || '').toLowerCase()) || /user|email|login/i.test(i.name || i.id || ''));
    const password = inputs.find(i => (i.type || '').toLowerCase() === 'password');
    if (hasPassword && (username || password)) {
      results.push({
        action: f.getAttribute('action') || location.href,
        usernameName: username && (username.name || username.id) || null,
        passwordName: password && (password.name || password.id) || null,
      });
    }
  }
  return results;
}

function fillCredentials(payload) {
  const { username, password } = payload || {};
  if (!username && !password) return false;
  // Try to fill the first reasonable form
  const forms = Array.from(document.querySelectorAll('form'));
  for (const f of forms) {
    const inputs = Array.from(f.querySelectorAll('input'));
    const u = inputs.find(i => ['text','email','tel','username'].includes((i.type || '').toLowerCase()) || /user|email|login/i.test(i.name || i.id || ''));
    const p = inputs.find(i => (i.type || '').toLowerCase() === 'password');
    if (u || p) {
      if (u && username) {
        u.focus();
        u.value = username;
        u.dispatchEvent(new Event('input', { bubbles: true }));
      }
      if (p && password) {
        p.focus();
        p.value = password;
        p.dispatchEvent(new Event('input', { bubbles: true }));
      }
      return true;
    }
  }
  return false;
}

browser.runtime.onMessage.addListener((message) => {
  if (!message || !message.type) return;
  if (message.type === 'SCAN_FORMS') {
    return Promise.resolve({ forms: findLoginForms() });
  }
  if (message.type === 'FILL_CREDENTIALS') {
    const ok = fillCredentials(message.payload || {});
    return Promise.resolve({ ok });
  }
});
