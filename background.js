import { scanUrl, verifyApiKey } from './services/virustotal.js';
import { scanUrlWithMlModel } from './services/mlmodel.js';
import { storeUrlResult } from './services/storage.js';

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'POPUP_OPENED') {
    chrome.action.setBadgeText({ text: '' });
  }
  return true;
});

async function ensureApiKeyValidation() {
  const { apiKey } = await chrome.storage.local.get('apiKey');
  if (!apiKey) {
    await chrome.storage.local.set({ apiKeyValid: false });
    return;
  }
  const res = await verifyApiKey(apiKey);
  await chrome.storage.local.set({ apiKeyValid: Boolean(res.ok) });
}

chrome.runtime.onStartup.addListener(() => {
  ensureApiKeyValidation();
});

chrome.runtime.onInstalled.addListener(() => {
  ensureApiKeyValidation();
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.apiKey) {
    ensureApiKeyValidation();
  }
});

chrome.tabs.onActivated.addListener(() => {
  chrome.action.setBadgeText({ text: '' });
});

const activeScans = new Map();

const MAX_BANNER_INJECTION_RETRIES = 3;
const BANNER_RETRY_DELAY_MS = 500;

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;

  try {
    const { apiKeyValid } = await chrome.storage.local.get('apiKeyValid');
    if (!apiKeyValid) {
      return;
    }

    let url;
    try {
      url = new URL(details.url);
    } catch (e) {
      console.error(`Invalid URL:, ${details.url}\n\n${e}`);
      return;
    }

    if (!url.hostname) return;

    if (url.protocol === 'chrome:' ||
      url.protocol === 'chrome://extensions/:' ||
      url.protocol === 'about:' ||
      url.hostname.startsWith('devtools.') ||
      url.hostname.endsWith('.google.com') ||
      url.hostname.endsWith('.microsoft.com') ||
      url.protocol === 'file:' ||
      url.hostname === 'localhost' ||
      url.hostname.includes('127.0.0.1')) {
      return;
    }

    const storedResults = await chrome.storage.local.get(url.href);
    if (storedResults[url.href]) {
      const storedData = storedResults[url.href];
      const scanTime = new Date(storedData.scanTime);
      const now = new Date();
      const hoursSinceScan = (now - scanTime) / (1000 * 60 * 60);

      if (hoursSinceScan < 24) {
        if (storedData.isMalicious) {
          showAlert(url.href, storedData, details.tabId);
        } else {
          setBadge('SAFE_DETECTED', url.href, storedData);
        }
        return;
      }
    }

    const scanState = {
      url: url.href,
      tabId: details.tabId,
      virusTotal: null,
      mlModel: null,
      bannerShown: false
    };
    activeScans.set(url.href, scanState);

    const vtResult = await scanUrl(url.href).catch(error => {
      console.error('VirusTotal scan error:', error);
      return { isMalicious: false, scanSuccess: false, error: error.message };
    });

    const mlResult = await scanUrlWithMlModel(url.href).catch(error => {
      console.error('ML Model scan error:', error);
      return { isMalicious: false, scanSuccess: false, error: error.message };
    });

    scanState.virusTotal = vtResult;
    scanState.mlModel = mlResult;

    if (vtResult?.isMalicious) {
      showAlertImmediately(scanState, 'VirusTotal');
    }

    if (mlResult?.isMalicious) {
      showAlertImmediately(scanState, 'ML Model');
    }

    const combinedResult = {
      url: url.href,
      scanTime: new Date().toISOString(),
      virusTotal: vtResult,
      mlModel: mlResult,
      isMalicious: Boolean(vtResult?.isMalicious || mlResult?.isMalicious),
      scanSuccess: Boolean(vtResult?.scanSuccess || mlResult?.scanSuccess)
    };

    console.log("Combined Scan Result: \n", combinedResult);

    await storeUrlResult(url.href, combinedResult);

    chrome.runtime.sendMessage({
      type: 'SCAN_RESULT_RECEIVED',
      url: url.href,
      scanResult: combinedResult
    }).catch(() => {
      // Ignore errors if no listeners
    });

    if (combinedResult.isMalicious && scanState.bannerShown === false) {
      showAlert(url.href, combinedResult, details.tabId);
    } else if (combinedResult.isMalicious && scanState.bannerShown) {
      updateBanner(combinedResult, details.tabId);
    } else if (!combinedResult.isMalicious) {
      setBadge('SAFE_DETECTED', url.href, combinedResult);
    }

    setTimeout(() => {
      activeScans.delete(url.href);
    }, 60_000);

  } catch (error) {
    console.error('Error during URL scan:', error);
    activeScans.delete(url.href);
  }
});

// ------------------------ Checkpoint ------------------

function showAlertImmediately(scanState, detectedBy) {
  if (scanState.bannerShown) return;

  scanState.bannerShown = true;

  let alertMessage = '';
  if (detectedBy === 'VirusTotal') {
    const maliciousCount = scanState.virusTotal?.stats?.malicious || 0;
    const suspiciousCount = scanState.virusTotal?.stats?.suspicious || 0;
    if (maliciousCount > 0 || suspiciousCount > 0) {
      alertMessage = `⚠ Danger: This site has been flagged malicious by VirusTotal (${maliciousCount} security vendors detected threats). Hackers will likely attempt to steal your information.`;
    }
  } else if (detectedBy === 'ML Model') {
    alertMessage = '⚠ Danger: This site has been flagged malicious by ML Model analysis. Hackers will likely attempt to steal your information.';
  }

  if (alertMessage) {
    injectBanner(scanState.tabId, alertMessage, 'phishy-warning-banner');
  }
}

function buildAlertMessage(scanResult) {
  const maliciousCount = scanResult.virusTotal?.stats?.malicious || 0;
  const suspiciousCount = scanResult.virusTotal?.stats?.suspicious || 0;
  const mlModelFlagged = Boolean(scanResult.mlModel?.isMalicious);
  const vtFlagged = maliciousCount > 0 || suspiciousCount > 0;

  const detectors = [];
  if (vtFlagged) detectors.push(`VirusTotal (${maliciousCount} security vendors)`);
  if (mlModelFlagged) detectors.push('ML Model');

  if (detectors.length === 0) return null;
  return `⚠ Danger: This site has been flagged malicious by ${detectors.join(' and ')}. Hackers will likely attempt to steal your information.`;
}

function setBadge(type, url, scanResult) {
  if (type === 'PHISHING_DETECTED') {
    chrome.runtime.sendMessage({ type: 'PHISHING_DETECTED', url, scanResult });
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeTextColor({ color: '#FFFFFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#ff0000ff' });
  } else if (type === 'SAFE_DETECTED') {
    chrome.runtime.sendMessage({ type: 'SAFE_DETECTED', url, scanResult });
    chrome.action.setBadgeText({ text: '✓' });
    chrome.action.setBadgeTextColor({ color: '#FFFFFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#12a10d' });
  }
}

function showAlert(url, scanResult, tabId) {
  if (!tabId) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length > 0) showAlert(url, scanResult, tabs[0].id);
    });
    return;
  }

  const alertMessage = buildAlertMessage(scanResult);
  if (!alertMessage) return;

  setBadge('PHISHING_DETECTED', url, scanResult);
  injectBanner(tabId, alertMessage, 'phishy-warning-banner');
}

function updateBanner(scanResult, tabId) {
  if (!tabId) return;
  const alertMessage = buildAlertMessage(scanResult);
  if (!alertMessage) return;
  injectBanner(tabId, alertMessage, 'phishy-warning-banner');
}

function injectBanner(tabId, alertMessage, bannerId, attempts = 0) {
  chrome.scripting.executeScript({
    target: { tabId },
    func: (warningDetails) => {
      const createBanner = () => {
        const existingBanner = document.getElementById(warningDetails.bannerId);
        if (existingBanner) {
          existingBanner.remove();
        }

        const div = document.createElement('div');
        div.id = warningDetails.bannerId;
        div.style.position = 'fixed';
        div.style.top = '0';
        div.style.left = '0';
        div.style.right = '0';
        div.style.backgroundColor = '#ff1100';
        div.style.color = 'white';
        div.style.padding = '16px';
        div.style.zIndex = '9999999';
        div.style.fontFamily = 'system-ui, -apple-system, sans-serif';
        div.style.fontSize = '16px';
        div.style.fontWeight = 'bold';
        div.style.display = 'flex';
        div.style.justifyContent = 'center';
        div.style.alignItems = 'center';
        div.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.2)';

        div.textContent = warningDetails.alertMessage;

        const closeBtn = document.createElement('button');
        closeBtn.textContent = 'x';
        closeBtn.style.marginLeft = '12px';
        closeBtn.style.marginBottom = '8px';
        closeBtn.style.background = 'transparent';
        closeBtn.style.border = 'none';
        closeBtn.style.color = 'white';
        closeBtn.style.fontSize = '20px';
        closeBtn.style.cursor = 'pointer';
        closeBtn.style.padding = '0 7px';
        closeBtn.onclick = () => div.remove();

        div.appendChild(closeBtn);

        if (document.body) {
          document.body.prepend(div);
        } else {
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
              document.body.prepend(div);
            });
          } else {
            (document.documentElement || document.body).appendChild(div);
          }
        }
      };

      // Try to inject immediately
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', createBanner);
      } else {
        createBanner();
      }
    },
    args: [{ alertMessage, bannerId }]
  }).catch(error => {
    console.log('Banner injection failed (attempt ' + (attempts + 1) + '):', error);
    if (attempts + 1 < MAX_BANNER_INJECTION_RETRIES) {
      setTimeout(() => {
        injectBanner(tabId, alertMessage, bannerId, attempts + 1);
      }, BANNER_RETRY_DELAY_MS);
    } else {
      console.warn('Banner injection aborted after ' + (attempts + 1) + ' attempts.');
    }
  });
}
