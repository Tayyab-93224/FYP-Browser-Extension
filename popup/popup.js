import { getAllUrls, clearHistory } from '../services/storage.js';
import { verifyApiKey } from '../services/virustotal.js';
import { checkAllApis } from '../services/healthcheck.js';

let currentUrl = '';
let apiKeySet = false;
let apiHealthCheckInterval = null;

const clearHistoryLink = document.getElementById('clear-history-link');
const currentDomainEl = document.getElementById('current-domain');
const currentPathEl = document.getElementById('current-path');
const statusTextEl = document.getElementById('status-text');
const scanStatusEl = document.querySelector('.scan-status');
const scanDetailsEl = document.getElementById('scan-details');
const maliciousCountEl = document.getElementById('malicious-count');
const suspiciousCountEl = document.getElementById('suspicious-count');
const cleanCountEl = document.getElementById('clean-count');
const lastScanTimeEl = document.getElementById('last-scan-time');
const historyListEl = document.getElementById('history-list');
const historyFilterEl = document.getElementById('history-filter');
const totalScansEl = document.getElementById('total-scans');
const threatsBlockedEl = document.getElementById('threats-blocked');
const scanProgressBarEl = document.getElementById('scan-progress-bar');
const scanRateValueEl = document.getElementById('scan-rate-value');

const mlPredictionEl = document.getElementById('ml-prediction');
const mlConfidenceEl = document.getElementById('ml-confidence');
const vtStatusIndicatorEl = document.getElementById('vt-status-indicator');
const mlStatusIndicatorEl = document.getElementById('ml-status-indicator');

const historyTabBtn = document.getElementById('history-tab-btn');
const statsTabBtn = document.getElementById('stats-tab-btn');
const historyTab = document.getElementById('history-tab');
const statsTab = document.getElementById('stats-tab');

const apiKeyModal = document.getElementById('api-key-modal');
const apiKeyInput = document.getElementById('api-key-input');
const saveApiKeyBtn = document.getElementById('save-api-key-btn');
const closeModalBtn = document.getElementById('close-modal-btn');
const settingsBtn = document.getElementById('settings-btn');

const apiKeyErrorEl = document.createElement('div');
apiKeyErrorEl.style.color = 'var(--color-danger)';
apiKeyErrorEl.style.fontSize = '13px';
apiKeyErrorEl.style.marginTop = '8px';
apiKeyErrorEl.className = 'api-key-error';
apiKeyInput.parentNode.appendChild(apiKeyErrorEl);

function isValidApiKey(key) {
  return /^[a-fA-F0-9]{64}$/.test(key) || /^[a-fA-F0-9]{32}$/.test(key);
}

async function checkApiKey() {
  const result = await chrome.storage.local.get(['apiKey', 'apiKeyValid']);
  const apiKey = result.apiKey ? result.apiKey.trim() : '';
  const validFormat = isValidApiKey(apiKey);
  apiKeySet = !!result.apiKeyValid && validFormat;

  if (!apiKeySet) {
    showApiKeyModal();
    apiKeyErrorEl.textContent = 'Please enter a valid API key.';
    vtStatusIndicatorEl.className = 'api-status-indicator error';
    mlStatusIndicatorEl.className = 'api-status-indicator error';
    vtStatusIndicatorEl.title = 'API key required';
    mlStatusIndicatorEl.title = 'API key required';
  } else {
    apiKeyErrorEl.textContent = '';
  }
}

clearHistoryLink.addEventListener('click', async (e) => {
  e.preventDefault();
  const confirmed = confirm('Are you sure you want to clear the scan history? This action cannot be undone.');

  if (confirmed) {
    await clearHistory();
    loadUrlHistory();
    loadStatistics();
    alert('Scan history cleared.');
  } else {
    alert('Clear history action canceled.');
  }
});

saveApiKeyBtn.addEventListener('click', async () => {
  const apiKey = apiKeyInput.value.trim();

  if (!isValidApiKey(apiKey)) {
    await chrome.storage.local.set({ apiKeyValid: false });
    apiKeyErrorEl.textContent = 'Please enter a valid API key.';
    apiKeyInput.focus();
    return;
  }

  apiKeyErrorEl.textContent = 'Verifying API key...';
  const verification = await verifyApiKey(apiKey);
  if (verification.ok) {
    await chrome.storage.local.set({ apiKey, apiKeyValid: true });
    apiKeySet = true;
    apiKeyModal.classList.add('hidden');
    apiKeyErrorEl.textContent = '';
    await initAfterKeyValid();
  } else {
    await chrome.storage.local.set({ apiKeyValid: false });
    apiKeyErrorEl.textContent = 'API key not accepted by VirusTotal.';
  }
});

closeModalBtn.addEventListener('click', () => {
  apiKeyModal.classList.add('hidden');
});

settingsBtn.addEventListener('click', () => {
  showApiKeyModal();
});

function showApiKeyModal() {
  chrome.storage.local.get('apiKey', (result) => {
    if (result.apiKey) {
      apiKeyInput.value = result.apiKey;
    }
    apiKeyModal.classList.remove('hidden');
  });
}

async function init() {
  chrome.runtime.sendMessage({ type: 'POPUP_OPENED' });
  
  await checkApiKey();
  
  if (apiKeySet) {
    await initAfterKeyValid();
  } else {
    scanDetailsEl.classList.add('hidden');
    const status = document.querySelector('.scan-status');
    if (status) {
      status.className = 'scan-status pending';
      statusTextEl.textContent = 'API key required';
    }
    // Clear history UI to appear empty
    historyListEl.innerHTML = `
      <div class="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-history">
          <path d="M3 3v5h5"></path>
          <path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"></path>
          <path d="M12 7v5l4 2"></path>
        </svg>
        <p>Enter a valid API key to begin</p>
      </div>
    `;
    // Zero out stats
    totalScansEl.textContent = '0';
    threatsBlockedEl.textContent = '0';
    scanProgressBarEl.style.width = '100%';
    scanRateValueEl.textContent = '100%';
  }
  
  // Set up tab navigation
  setupTabs();
  
  // Listen for history filter changes
  historyFilterEl.addEventListener('change', loadUrlHistory);
}

async function initAfterKeyValid() {
  // Check API health status
  await checkApiHealth();
  // Start periodic health checks (every 10 seconds)
  startApiHealthChecks();
  // Get current URL and update UI
  getCurrentTabUrl();
  // Load URL history
  await loadUrlHistory();
  // Load statistics
  await loadStatistics();
}

// Check API health and update UI
async function checkApiHealth() {
  try {
    const apiStatus = await checkAllApis();
    
    // Update VirusTotal status indicator
    if (apiStatus.virusTotal.running) {
      vtStatusIndicatorEl.className = 'api-status-indicator success';
      vtStatusIndicatorEl.title = apiStatus.virusTotal.message || 'VirusTotal API is running';
    } else {
      vtStatusIndicatorEl.className = 'api-status-indicator error';
      vtStatusIndicatorEl.title = apiStatus.virusTotal.error || 'VirusTotal API is not running';
    }
    
    // Update ML Model status indicator
    if (apiStatus.mlModel.running) {
      mlStatusIndicatorEl.className = 'api-status-indicator success';
      mlStatusIndicatorEl.title = apiStatus.mlModel.message || 'ML Model API is running';
    } else {
      mlStatusIndicatorEl.className = 'api-status-indicator error';
      mlStatusIndicatorEl.title = apiStatus.mlModel.error || 'ML Model API is not running';
    }
  } catch (error) {
    console.error('Error checking API health:', error);
    // Set both to error state if check fails
    vtStatusIndicatorEl.className = 'api-status-indicator error';
    mlStatusIndicatorEl.className = 'api-status-indicator error';
  }
}

// Start periodic API health checks
function startApiHealthChecks() {
  // Clear any existing interval
  if (apiHealthCheckInterval) {
    clearInterval(apiHealthCheckInterval);
  }
  
  // Check every 10 seconds
  apiHealthCheckInterval = setInterval(() => {
    if (apiKeySet) {
      checkApiHealth();
    }
  }, 10000);
}

// Stop API health checks
function stopApiHealthChecks() {
  if (apiHealthCheckInterval) {
    clearInterval(apiHealthCheckInterval);
    apiHealthCheckInterval = null;
  }
}

// Get current tab URL
function getCurrentTabUrl() {
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (tabs.length > 0) {
      currentUrl = tabs[0].url;
      
      try {
        const url = new URL(currentUrl);
        currentDomainEl.textContent = url.hostname;
        currentPathEl.textContent = url.pathname + url.search;
        
        // Check if we have a scan result for this URL
        const results = await chrome.storage.local.get(currentUrl);
        if (results[currentUrl]) {
          updateCurrentUrlStatus(results[currentUrl]);
        } else {
          // Show checking status
          scanStatusEl.className = 'scan-status pending';
          statusTextEl.textContent = 'Checking...';
          scanDetailsEl.classList.add('hidden');
        }
      } catch (error) {
        console.error('Error parsing URL:', error);
      }
    }
  });
}

// Update current URL status
function updateCurrentUrlStatus(result) {
  scanDetailsEl.classList.remove('hidden');
  
  // Handle both old format (direct stats) and new format (combined results)
  const virusTotalResult = result.virusTotal || result;
  const mlModelResult = result.mlModel;
  
  // Update VirusTotal results
  if (virusTotalResult && virusTotalResult.stats) {
    maliciousCountEl.textContent = virusTotalResult.stats.malicious || 0;
    suspiciousCountEl.textContent = virusTotalResult.stats.suspicious || 0;
    cleanCountEl.textContent = (virusTotalResult.stats.harmless || 0) + (virusTotalResult.stats.undetected || 0);
    
    // Update VirusTotal status indicator
    if (virusTotalResult.scanSuccess) {
      vtStatusIndicatorEl.className = 'api-status-indicator success';
      vtStatusIndicatorEl.title = 'VirusTotal API is running and responding';
    } else {
      vtStatusIndicatorEl.className = 'api-status-indicator error';
      vtStatusIndicatorEl.title = 'VirusTotal scan failed';
    }
  } else {
    maliciousCountEl.textContent = '-';
    suspiciousCountEl.textContent = '-';
    cleanCountEl.textContent = '-';
    vtStatusIndicatorEl.className = 'api-status-indicator error';
    vtStatusIndicatorEl.title = 'No VirusTotal results available';
  }
  
  // Update ML Model results
  if (mlModelResult) {
    const prediction = mlModelResult.prediction || 'unknown';
    const confidence = mlModelResult.confidence || 0;
    
    // Format prediction text
    let predictionText = prediction;
    if (prediction === 'malicious' || prediction === 'phishing') {
      predictionText = 'Malicious';
    } else if (prediction === 'benign' || prediction === 'safe') {
      predictionText = 'Safe';
    } else {
      predictionText = prediction.charAt(0).toUpperCase() + prediction.slice(1);
    }
    
    mlPredictionEl.textContent = predictionText;
    mlConfidenceEl.textContent = typeof confidence === 'number' 
      ? `${(confidence * 100).toFixed(1)}%` 
      : `${confidence}%`;
    
    // Update ML Model status indicator
    if (mlModelResult.scanSuccess) {
      mlStatusIndicatorEl.className = 'api-status-indicator success';
      mlStatusIndicatorEl.title = 'ML Model API is running and responding';
    } else {
      mlStatusIndicatorEl.className = 'api-status-indicator error';
      mlStatusIndicatorEl.title = 'ML Model scan failed';
    }
  } else {
    mlPredictionEl.textContent = '-';
    mlConfidenceEl.textContent = '-';
    mlStatusIndicatorEl.className = 'api-status-indicator error';
    mlStatusIndicatorEl.title = 'No ML Model results available';
  }
  
  // Update last scan time
  const scanDate = new Date(result.scanTime || new Date());
  lastScanTimeEl.textContent = `Last scanned: ${formatDate(scanDate)}`;
  
  // Update overall status indicator (combine both results)
  const isMalicious = result.isMalicious || false;
  const hasSuspicious = virusTotalResult?.stats?.suspicious > 0;
  
  if (isMalicious) {
    scanStatusEl.className = 'scan-status danger';
    statusTextEl.textContent = 'Malicious';
    scanStatusEl.innerHTML = `
      <span class="status-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-alert">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          <path d="M12 8v4"></path>
          <path d="M12 16h.01"></path>
        </svg>
      </span>
      <span id="status-text">Malicious</span>
    `;
  } else if (hasSuspicious) {
    scanStatusEl.className = 'scan-status warning';
    statusTextEl.textContent = 'Suspicious';
    scanStatusEl.innerHTML = `
      <span class="status-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-alert-triangle">
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path>
          <path d="M12 9v4"></path>
          <path d="M12 17h.01"></path>
        </svg>
      </span>
      <span id="status-text">Suspicious</span>
    `;
  } else {
    scanStatusEl.className = 'scan-status safe';
    statusTextEl.textContent = 'Safe';
    scanStatusEl.innerHTML = `
      <span class="status-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-shield-check">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          <path d="m9 12 2 2 4-4"></path>
        </svg>
      </span>
      <span id="status-text">Safe</span>
    `;
  }
}

// Load URL history
async function loadUrlHistory() {
  // Gate UI when API key is not validated
  const { apiKeyValid } = await chrome.storage.local.get('apiKeyValid');
  if (!apiKeyValid) {
    historyListEl.innerHTML = `
      <div class="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-history">
          <path d="M3 3v5h5"></path>
          <path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"></path>
          <path d="M12 7v5l4 2"></path>
        </svg>
        <p>Enter a valid API key to begin</p>
      </div>
    `;
    return;
  }

  const filter = historyFilterEl.value;
  const urls = await getAllUrls();
  
  // Clear history list
  historyListEl.innerHTML = '';
  
  if (urls.length === 0) {
    // Show empty state
    historyListEl.innerHTML = `
      <div class="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-history">
          <path d="M3 3v5h5"></path>
          <path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"></path>
          <path d="M12 7v5l4 2"></path>
        </svg>
        <p>No scan history yet</p>
      </div>
    `;
    return;
  }
  
  // Sort URLs by scan time (newest first)
  urls.sort((a, b) => new Date(b.scanTime) - new Date(a.scanTime));
  
  // Filter URLs
  const filteredUrls = filter === 'all' 
    ? urls 
    : filter === 'malicious' 
      ? urls.filter(url => url.isMalicious) 
      : urls.filter(url => !url.isMalicious);
  
  // Create history items
  filteredUrls.forEach(urlData => {
    const historyItem = document.createElement('div');
    historyItem.className = 'history-item';
    
    try {
      const url = new URL(urlData.url);
      const displayUrl = url.hostname + url.pathname.substring(0, 15) + (url.pathname.length > 15 ? '...' : '');
      
      historyItem.innerHTML = `
        <div class="history-item-content">
          <div class="history-url" title="${urlData.url}">${displayUrl}</div>
          <div class="history-time">${formatDate(new Date(urlData.scanTime))}</div>
        </div>
        <div class="history-status ${urlData.isMalicious ? 'malicious' : 'safe'}">
          ${urlData.isMalicious ? 'Malicious' : 'Safe'}
        </div>
      `;
      
      historyListEl.appendChild(historyItem);
      
      // Add click event to show details
      historyItem.addEventListener('click', () => {
        showUrlDetails(urlData);
      });
    } catch (error) {
      console.error('Error parsing URL:', error);
    }
  });
}

// Show URL details on the console
function showUrlDetails(urlData) {
  // Implementation for showing detailed view of a URL scan
  console.log('Show details for:', urlData);
  // This could open a modal or navigate to a detail view
}

// Load statistics
async function loadStatistics() {
  const urls = await getAllUrls();
  const totalScans = urls.length;
  const maliciousScans = urls.filter(url => url.isMalicious).length;
  const successfulScans = urls.filter(url => url.scanSuccess).length;
  const scanRate = totalScans > 0 ? Math.round((successfulScans / totalScans) * 100) : 100;
  
  totalScansEl.textContent = totalScans;
  threatsBlockedEl.textContent = maliciousScans;
  scanProgressBarEl.style.width = `${scanRate}%`;
  scanRateValueEl.textContent = `${scanRate}%`;
}

// Format date
function formatDate(date) {
  const now = new Date();
  const diff = Math.floor((now - date) / 1000); // Difference in seconds
  
  if (diff < 60) {
    return 'Just now';
  } else if (diff < 3600) {
    const minutes = Math.floor(diff / 60);
    return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
  } else if (diff < 86400) {
    const hours = Math.floor(diff / 3600);
    return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  } else if (diff < 604800) {
    const days = Math.floor(diff / 86400);
    return `${days} day${days > 1 ? 's' : ''} ago`;
  } else {
    return date.toLocaleDateString();
  }
}

// Setup tab navigation
function setupTabs() {
  // History tab
  historyTabBtn.addEventListener('click', () => {
    historyTabBtn.classList.add('active');
    statsTabBtn.classList.remove('active');
    historyTab.classList.add('active');
    statsTab.classList.remove('active');
  });
  
  // Stats tab
  statsTabBtn.addEventListener('click', () => {
    statsTabBtn.classList.add('active');
    historyTabBtn.classList.remove('active');
    statsTab.classList.add('active');
    historyTab.classList.remove('active');
    
    // Refresh statistics when tab is shown
    loadStatistics();
  });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'PHISHING_DETECTED' && message.url === currentUrl) {
    updateCurrentUrlStatus(message.scanResult);
  }
  
  if (message.type === 'SCAN_RESULT_RECEIVED') {
    // Alert user that scan results are received
    showScanResultAlert(message.scanResult);
    // Update current URL status if it matches
    if (message.url === currentUrl) {
      updateCurrentUrlStatus(message.scanResult);
    }
  }
  
  // Refresh history list and statistics when a new URL is scanned
  loadUrlHistory();
  loadStatistics();
});

// Show alert when scan results are received
function showScanResultAlert(scanResult) {
  // Create a notification-style alert
  const alertDiv = document.createElement('div');
  alertDiv.className = 'scan-result-alert';
  alertDiv.style.cssText = `
    position: fixed;
    top: 10px;
    right: 10px;
    background: var(--color-primary);
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    z-index: 10000;
    font-size: 14px;
    max-width: 300px;
    animation: slideIn 0.3s ease-out;
  `;
  
  const hasVtResult = scanResult.virusTotal?.scanSuccess;
  const hasMlResult = scanResult.mlModel?.scanSuccess;
  
  let message = 'Scan results received: ';
  const results = [];
  if (hasVtResult) results.push('VirusTotal');
  if (hasMlResult) results.push('ML Model');
  
  message += results.join(' & ') || 'No results';
  
  alertDiv.textContent = message;
  document.body.appendChild(alertDiv);
  
  // Remove after 3 seconds
  setTimeout(() => {
    alertDiv.style.animation = 'slideOut 0.3s ease-out';
    setTimeout(() => alertDiv.remove(), 300);
  }, 3000);
}


// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', init);

// Cleanup when popup is closed
window.addEventListener('beforeunload', () => {
  stopApiHealthChecks();
});
