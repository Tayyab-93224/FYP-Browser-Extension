import { scanUrl, verifyApiKey } from './services/virustotal.js';
import { scanUrlWithMlModel } from './services/mlmodel.js';
import { storeUrlResult } from './services/storage.js';

// Track active scans to avoid duplicate banners
const activeScans = new Map();

// Listen for navigation events - use onCommitted to start scanning earlier
chrome.webNavigation.onCommitted.addListener(async (details) => {
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
      url.hostname.endsWith('.google.com') ||
      url.hostname.endsWith('.microsoft.com') ||
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

      // If url was scanned in the last 24 hours and was flagged as malicious, alert immediately
      if (hoursSinceScan < 24) {
        if (storedData.isMalicious) {
          showAlert(url.href, storedData, details.tabId);
        }
        return;
      }
    }

    // Initialize scan state for this URL
    const scanState = {
      url: url.href,
      tabId: details.tabId,
      virusTotal: null,
      mlModel: null,
      bannerShown: false
    };
    activeScans.set(url.href, scanState);

    // Start both scans in parallel but handle results as they come
    const scanPromises = [
      scanUrl(url.href).then(result => {
        scanState.virusTotal = result;
        // Show banner immediately if VirusTotal detects threat
        if (result.isMalicious) {
          showAlertImmediately(url.href, scanState, 'VirusTotal');
        }
        return result;
      }).catch(error => {
        console.error('VirusTotal scan error:', error);
        scanState.virusTotal = { isMalicious: false, scanSuccess: false, error: error.message };
        return null;
      }),
      scanUrlWithMlModel(url.href).then(result => {
        scanState.mlModel = result;
        // Show banner immediately if ML Model detects threat
        if (result.isMalicious) {
          showAlertImmediately(url.href, scanState, 'ML Model');
        }
        return result;
      }).catch(error => {
        console.error('ML Model scan error:', error);
        scanState.mlModel = { isMalicious: false, scanSuccess: false, error: error.message };
        return null;
      })
    ];

    // Wait for both to complete for final result
    const [vtResult, mlResult] = await Promise.allSettled(scanPromises);
    const finalVtResult = vtResult.status === 'fulfilled' ? vtResult.value : null;
    const finalMlResult = mlResult.status === 'fulfilled' ? mlResult.value : null;

    // Combine results
    const combinedResult = {
      url: url.href,
      scanTime: new Date().toISOString(),
      virusTotal: finalVtResult || scanState.virusTotal,
      mlModel: finalMlResult || scanState.mlModel,
      // Determine overall malicious status (if either API flags it as malicious)
      isMalicious: (finalVtResult?.isMalicious || false) || (finalMlResult?.isMalicious || false),
      // Overall scan success (at least one API succeeded)
      scanSuccess: (finalVtResult?.scanSuccess || false) || (finalMlResult?.scanSuccess || false)
    };

    console.log("Combined Scan Result: \n", combinedResult);

    // Store the combined result
    await storeUrlResult(url.href, combinedResult);

    // Send message to popup that scan results are received (for any result)
    chrome.runtime.sendMessage({
      type: 'SCAN_RESULT_RECEIVED',
      url: url.href,
      scanResult: combinedResult
    }).catch(() => {
      // Ignore errors if popup is not open
    });

    // Update banner if not shown yet but threat detected
    if (combinedResult.isMalicious && !scanState.bannerShown) {
      showAlert(url.href, combinedResult, details.tabId);
    } else if (combinedResult.isMalicious && scanState.bannerShown) {
      // Update existing banner with complete information
      updateBanner(url.href, combinedResult, details.tabId);
    }

    // Clean up scan state after a delay
    setTimeout(() => {
      activeScans.delete(url.href);
    }, 60000); // Keep for 1 minute

  } catch (error) {
    console.error('Error during URL scan:', error);
    activeScans.delete(details.url);
  }
});

// Function to show alert immediately when first threat is detected
function showAlertImmediately(url, scanState, detectedBy) {
  if (scanState.bannerShown) return; // Already shown
  
  scanState.bannerShown = true;
  
  // Build immediate alert message
  let alertMessage = '';
  if (detectedBy === 'VirusTotal') {
    const maliciousCount = scanState.virusTotal?.stats?.malicious || 0;
    const suspiciousCount = scanState.virusTotal?.stats?.suspicious || 0;
    if (maliciousCount > 0 || suspiciousCount > 0) {
      alertMessage = `⚠ Danger: This site has been flagged malicious by VirusTotal (${maliciousCount} security vendors detected threats). Hackers will likely attempt to steal your information.`;
    }
  } else if (detectedBy === 'ML Model') {
    alertMessage = '⚠ Danger: This site has been flagged as malicious by ML Model analysis. Exercise caution.';
  }

  if (alertMessage) {
    injectBanner(scanState.tabId, alertMessage, 'phishy-warning-banner');
  }
}

// Function to show/update alert with complete information
function showAlert(url, scanResult, tabId) {
  if (!tabId) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length > 0) {
        showAlert(url, scanResult, tabs[0].id);
      }
    });
    return;
  }

  // Create notification with detailed info
  const maliciousCount = scanResult.virusTotal?.stats?.malicious || 0;
  const suspiciousCount = scanResult.virusTotal?.stats?.suspicious || 0;
  const mlModelFlagged = scanResult.mlModel?.isMalicious || false;
  const vtFlagged = (maliciousCount > 0 || suspiciousCount > 0);
  
  // Build alert message showing which API detected it
  let alertMessage = '';
  const detectors = [];
  
  if (vtFlagged) {
    detectors.push(`VirusTotal (${maliciousCount} security vendors)`);
  }
  if (mlModelFlagged) {
    detectors.push('ML Model');
  }
  
  if (detectors.length > 0) {
    alertMessage = `⚠ Danger: This site has been flagged malicious by ${detectors.join(' and ')}. Hackers will likely attempt to steal your information.`;
  }

  if (alertMessage) {
    // Send message to popup if it's open
    chrome.runtime.sendMessage({
      type: 'PHISHING_DETECTED',
      url,
      scanResult
    });

    // Show a Chrome notification
    chrome.action.setBadgeText({ text: '!' });
    chrome.action.setBadgeBackgroundColor({ color: '#EF4444' });

    // Inject or update warning banner
    injectBanner(tabId, alertMessage, 'phishy-warning-banner');
  }
}

// Function to update existing banner
function updateBanner(url, scanResult, tabId) {
  if (!tabId) return;
  
  const maliciousCount = scanResult.virusTotal?.stats?.malicious || 0;
  const suspiciousCount = scanResult.virusTotal?.stats?.suspicious || 0;
  const mlModelFlagged = scanResult.mlModel?.isMalicious || false;
  const vtFlagged = (maliciousCount > 0 || suspiciousCount > 0);
  
  let alertMessage = '';
  const detectors = [];
  
  if (vtFlagged) {
    detectors.push(`VirusTotal (${maliciousCount} security vendors)`);
  }
  if (mlModelFlagged) {
    detectors.push('ML Model');
  }
  
  if (detectors.length > 0) {
    alertMessage = `⚠ Danger: This site has been flagged malicious by ${detectors.join(' and ')}. Hackers will likely attempt to steal your information.`;
    injectBanner(tabId, alertMessage, 'phishy-warning-banner');
  }
}

// Function to inject banner into page
function injectBanner(tabId, alertMessage, bannerId) {
  chrome.scripting.executeScript({
    target: { tabId },
    func: (warningDetails) => {
      // Function to create and inject banner
      const createBanner = () => {
        // Remove existing banner if present
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
        closeBtn.style.fontSize = '24px';
        closeBtn.style.cursor = 'pointer';
        closeBtn.style.padding = '0 7px';
        closeBtn.onclick = () => div.remove();

        div.appendChild(closeBtn);
        
        // Try to prepend to body, if not ready, wait for DOM
        if (document.body) {
          document.body.prepend(div);
        } else {
          // Wait for DOM to be ready
          if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
              document.body.prepend(div);
            });
          } else {
            // Fallback: append to document
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
    // If injection fails (page not ready), retry after a short delay
    console.log('Banner injection failed, retrying...', error);
    setTimeout(() => {
      injectBanner(tabId, alertMessage, bannerId);
    }, 500);
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
