import { scanUrl } from './services/virustotal.js';
import { storeUrlResult } from './services/storage.js';

// Listen for navigation events
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only check main frame navigations
  if (details.frameId !== 0) return;

  try {
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

    // Scan the URL with VirusTotal
    const result = await scanUrl(url.href);
    console.log("Scan Result: \n", result);

    // Store the result
    await storeUrlResult(url.href, result);

    // Show alert if the URL is malicious
    if (result.isMalicious) {
      showAlert(url.href, result);
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
      const maliciousCount = scanResult.stats.malicious;
      const suspiciousCount = scanResult.stats.suspicious;

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

          div.textContent = `⚠ Danger: This site has been flagged malicious by ${warningDetails.maliciousCount} security vendors. Hackers will likely attempt to steal your information.`;

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
        args: [{ maliciousCount, suspiciousCount }]
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