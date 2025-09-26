// Basic background script for Cerberus Firefox extension

browser.runtime.onInstalled.addListener(() => {
  console.log("Cerberus extension installed");
});

function connectNative() {
  try {
    return browser.runtime.connectNative('com.cerberus.pm');
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
      port.disconnect();
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

async function getOriginForTab(tabId) {
  const tab = await browser.tabs.get(tabId);
  try {
    const url = new URL(tab.url);
    return url.origin;
  } catch (e) {
    return tab.url;
  }
}

// Message router between popup/content and native host
browser.runtime.onMessage.addListener(async (message, sender) => {
  if (!message || !message.type) return;
  if (message.type === 'GET_PAGE_FORMS') {
    return browser.tabs.sendMessage(sender.tab.id, { type: 'SCAN_FORMS' });
  }
  if (message.type === 'FILL_CREDENTIALS') {
    return browser.tabs.sendMessage(sender.tab.id, {
      type: 'FILL_CREDENTIALS',
      payload: message.payload,
    });
  }
  if (message.type === 'GET_CREDENTIALS_FOR_TAB') {
    const origin = await getOriginForTab(sender.tab.id);
    const resp = await nativeRequest({ type: 'get_for_origin', origin, include_password: true }).catch(err => ({ ok: false, error: String(err) }));
    return resp;
  }
  if (message.type === 'PING_NATIVE') {
    const resp = await nativeRequest({ type: 'ping' }).catch(err => ({ ok: false, error: String(err) }));
    return resp;
  }
});
