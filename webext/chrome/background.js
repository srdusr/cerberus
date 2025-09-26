// Background service worker for Cerberus Chrome/Edge extension (MV3)

function connectNative() {
  try {
    return chrome.runtime.connectNative('com.cerberus.pm');
  } catch (e) {
    console.error('Native host connection failed', e);
    return null;
  }
}

function nativeRequest(payload) {
  return new Promise((resolve, reject) => {
    const port = connectNative();
    if (!port) {
      reject(new Error('no_native_host'));
      return;
    }
    const onMessage = (resp) => {
      port.onMessage.removeListener(onMessage);
      try { port.disconnect(); } catch {}
      resolve(resp);
    };
    const onDisconnect = () => {
      port.onMessage.removeListener(onMessage);
      reject(new Error('disconnected'));
    };
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
    port.postMessage(payload);
  });
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

async function getOriginForActiveTab() {
  const tab = await getActiveTab();
  try {
    const url = new URL(tab.url);
    return url.origin;
  } catch (e) {
    return tab.url;
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (!message || !message.type) return;
    if (message.type === 'GET_PAGE_FORMS') {
      const tab = await getActiveTab();
      chrome.tabs.sendMessage(tab.id, { type: 'SCAN_FORMS' }, sendResponse);
      return true;
    }
    if (message.type === 'FILL_CREDENTIALS') {
      const tab = await getActiveTab();
      chrome.tabs.sendMessage(tab.id, { type: 'FILL_CREDENTIALS', payload: message.payload }, sendResponse);
      return true;
    }
    if (message.type === 'GET_CREDENTIALS_FOR_TAB') {
      const origin = await getOriginForActiveTab();
      try {
        const resp = await nativeRequest({ type: 'get_for_origin', origin, include_password: true });
        sendResponse(resp);
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
      return true;
    }
    if (message.type === 'PING_NATIVE') {
      try {
        const resp = await nativeRequest({ type: 'ping' });
        sendResponse(resp);
      } catch (e) {
        sendResponse({ ok: false, error: String(e) });
      }
      return true;
    }
  })();
  return true; // keep channel open for async
});
