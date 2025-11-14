import { scanUrl, verifyApiKey } from './services/virustotal.js';
import { scanUrlWithMlModel } from './services/mlmodel.js';
import { storeUrlResult } from './services/storage.js';

// Listen for navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only check main frame navigations
  if (details.frameId !== 0) return;

  try {
    const { apiKeyValid } = await chrome.storage.local.get('apiKeyValid');
    if (!apiKeyValid) {
      // Gate: do not scan until API key is verified
      return;
    }

    const url = new URL(details.url);

    // Skip local/internal URLs and browser pages
    if (url.protocol === 'chrome:' ||
      url.protocol === 'chrome://extensions/:' ||
      url.protocol === 'about:' ||
      url.protocol === 'file:' ||
      url.hostname === 'localhost' ||
      url.hostname.includes('127.0.0.1')) {
      return;
    }

    // Check if URL has already been scanned recently (within last 24 hours)
    const storedResults = await chrome.storage.local.get(url.href);
    if (storedResults[url.href]) {
      const storedData = storedResults[url.href];
      const scanTime = new Date(storedData.scanTime);
      const now = new Date();
      const hoursSinceScan = (now - scanTime) / (1000 * 60 * 60);

      // If url was scanned in the last 24 hours and was flagged as malicious, alert again
      if (hoursSinceScan < 24) {
        if (storedData.isMalicious) {
          showAlert(url.href, storedData);
        }
        return;
      }
    }

    // Scan the URL with both VirusTotal and ML Model APIs in parallel
    const [virusTotalResult, mlModelResult] = await Promise.allSettled([
      scanUrl(url.href),
      scanUrlWithMlModel(url.href)
    ]);

    // Extract results (handle potential rejections)
    const vtResult = virusTotalResult.status === 'fulfilled' ? virusTotalResult.value : null;
    const mlResult = mlModelResult.status === 'fulfilled' ? mlModelResult.value : null;

    // Combine results
    const combinedResult = {
      url: url.href,
      scanTime: new Date().toISOString(),
      virusTotal: vtResult,
      mlModel: mlResult,
      // Determine overall malicious status (if either API flags it as malicious)
      isMalicious: (vtResult?.isMalicious || false) || (mlResult?.isMalicious || false),
      // Overall scan success (at least one API succeeded)
      scanSuccess: (vtResult?.scanSuccess || false) || (mlResult?.scanSuccess || false)
    };

    console.log("Combined Scan Result: \n", combinedResult);

    // Store the combined result
    await storeUrlResult(url.href, combinedResult);

    // Show alert if the URL is malicious
    if (combinedResult.isMalicious) {
      showAlert(url.href, combinedResult);
    } else {
      console.log('No threats detected.');
    }
  } catch (error) {
    console.error('Error during URL scan:', error);
  }
});

// Function to show alert to the user
function showAlert(url, scanResult) {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length > 0) {
      const tabId = tabs[0].id;

      // Create notification with detailed info
      const maliciousCount = scanResult.virusTotal?.stats?.malicious || 0;
      const suspiciousCount = scanResult.virusTotal?.stats?.suspicious || 0;
      const mlModelFlagged = scanResult.mlModel?.isMalicious || false;
      
      // Build alert message
      let alertMessage = '';
      if (maliciousCount > 0 || suspiciousCount > 0) {
        alertMessage = `⚠ Danger: This site has been flagged malicious by ${maliciousCount} security vendors`;
        if (mlModelFlagged) {
          alertMessage += ' and by ML model analysis';
        }
        alertMessage += '. Hackers will likely attempt to steal your information.';
      } else if (mlModelFlagged) {
        alertMessage = '⚠ Danger: This site has been flagged as malicious by ML model analysis. Exercise caution.';
      }

      // Send message to popup if it's open
      chrome.runtime.sendMessage({
        type: 'PHISHING_DETECTED',
        url,
        scanResult
      });

      // Show a Chrome notification
      chrome.action.setBadgeText({ text: '!' });
      chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });

      // Inject warning banner into the page
      chrome.scripting.executeScript({
        target: { tabId },
        func: (warningDetails) => {
          const div = document.createElement('div');
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
          closeBtn.style.fontSize = '24px';
          closeBtn.style.cursor = 'pointer';
          closeBtn.style.padding = '0 7px';
          closeBtn.onclick = () => div.remove();

          div.appendChild(closeBtn);
          document.body.prepend(div);
        },
        args: [{ maliciousCount, suspiciousCount, alertMessage }]
      });
    }
  });
}

// Reset badge when the popup is opened
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'POPUP_OPENED') {
    chrome.action.setBadgeText({ text: '' });
  }
  return true;
});

// Verify API key on startup and when key changes
async function ensureApiKeyValidation() {
  const { apiKey } = await chrome.storage.local.get('apiKey');
  if (!apiKey) {
    await chrome.storage.local.set({ apiKeyValid: false });
    return;
  }
  const res = await verifyApiKey(apiKey);
  await chrome.storage.local.set({ apiKeyValid: !!res.ok });
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
