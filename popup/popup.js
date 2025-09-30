import { getAllUrls, clearHistory } from '../services/storage.js';

// Initialize variables
let currentUrl = '';
let apiKeySet = false;

// DOM Elements
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

// Tab Elements
const historyTabBtn = document.getElementById('history-tab-btn');
const statsTabBtn = document.getElementById('stats-tab-btn');
const historyTab = document.getElementById('history-tab');
const statsTab = document.getElementById('stats-tab');

// Modal Elements
const apiKeyModal = document.getElementById('api-key-modal');
const apiKeyInput = document.getElementById('api-key-input');
const saveApiKeyBtn = document.getElementById('save-api-key-btn');
const closeModalBtn = document.getElementById('close-modal-btn');
const settingsBtn = document.getElementById('settings-btn');

// Check if API key is set
async function checkApiKey() {
  const result = await chrome.storage.local.get('apiKey');
  apiKeySet = result.apiKey ? true : false;
  
  if (!apiKeySet) {
    showApiKeyModal();
  }
}

// Save API key
saveApiKeyBtn.addEventListener('click', async () => {
  const apiKey = apiKeyInput.value.trim();
  
  if (apiKey) {
    await chrome.storage.local.set({ apiKey });
    apiKeySet = true;
    apiKeyModal.classList.add('hidden');
    
    // Reload current tab data with the new API key
    getCurrentTabUrl();
  } else {
    apiKeyInput.focus();
  }
});

// Close modal
closeModalBtn.addEventListener('click', () => {
  apiKeyModal.classList.add('hidden');
});

// Show settings modal
settingsBtn.addEventListener('click', () => {
  showApiKeyModal();
});

// Show API key modal
function showApiKeyModal() {
  chrome.storage.local.get('apiKey', (result) => {
    if (result.apiKey) {
      apiKeyInput.value = result.apiKey;
    }
    apiKeyModal.classList.remove('hidden');
  });
}

// Initialize popup
async function init() {
  // Notify background script that popup is opened
  chrome.runtime.sendMessage({ type: 'POPUP_OPENED' });
  
  // Check if API key is set
  await checkApiKey();
  
  // Get current URL and update UI
  getCurrentTabUrl();
  
  // Load URL history
  loadUrlHistory();
  
  // Load statistics
  loadStatistics();
  
  // Set up tab navigation
  setupTabs();
  
  // Listen for history filter changes
  historyFilterEl.addEventListener('change', loadUrlHistory);
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

// Update current URL status      // iss ko change karna hai yaad rakheen
function updateCurrentUrlStatus(result) {
  scanDetailsEl.classList.remove('hidden');
  
  // Update scan stats
  maliciousCountEl.textContent = result.stats.malicious;
  suspiciousCountEl.textContent = result.stats.suspicious;
  cleanCountEl.textContent = result.stats.harmless + result.stats.undetected;
  
  // Update last scan time
  const scanDate = new Date(result.scanTime);
  lastScanTimeEl.textContent = `Last scanned: ${formatDate(scanDate)}`;
  
  // Update status indicator
  if (result.isMalicious) {
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
  } else if (result.stats.suspicious > 0) {
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
  
  // Refresh history list and statistics when a new URL is scanned
  loadUrlHistory();
  loadStatistics();
});


// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', init);