// API Health Check Service
// Checks if both VirusTotal and ML Model APIs are running

const ML_MODEL_API_URL = 'http://127.0.0.1:5000';
const VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3';

/**
 * Check if ML Model API is running
 * @returns {Promise<{running: boolean, error?: string}>}
 */
export async function checkMlModelApi() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3000);
  
  try {
    const response = await fetch(`${ML_MODEL_API_URL}/health`, {
      method: 'GET',
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    
    if (response.ok) {
      const data = await response.json();
      return {
        running: true,
        status: data.status || 'running',
        message: data.message || 'ML Model API is running'
      };
    } else {
      return {
        running: false,
        error: `API returned status ${response.status}`
      };
    }
  } catch (error) {
    clearTimeout(timeoutId);
    // Network error, API not running, or timeout
    return {
      running: false,
      error: error.name === 'AbortError' || error.name === 'TimeoutError' ? 'Connection timeout' : 'API not reachable'
    };
  }
}

/**
 * Check if VirusTotal API is accessible
 * @returns {Promise<{running: boolean, error?: string}>}
 */
export async function checkVirusTotalApi() {
  let timeoutId = null;
  
  try {
    const { apiKey } = await chrome.storage.local.get('apiKey');
    
    if (!apiKey) {
      return {
        running: false,
        error: 'API key not configured'
      };
    }

    // Try to verify the API key (lightweight check)
    const controller = new AbortController();
    timeoutId = setTimeout(() => controller.abort(), 5000);
    
    const response = await fetch(`${VIRUSTOTAL_API_URL}/users/me`, {
      method: 'GET',
      headers: { 'x-apikey': apiKey },
      signal: controller.signal
    });
    
    clearTimeout(timeoutId);
    timeoutId = null;
    
    if (response.ok || response.status === 401) {
      // 401 means API is reachable but key might be invalid
      // We consider it "running" if we get a response
      return {
        running: true,
        status: response.ok ? 'running' : 'key_invalid',
        message: response.ok ? 'VirusTotal API is running' : 'VirusTotal API is reachable but API key may be invalid'
      };
    } else {
      return {
        running: false,
        error: `API returned status ${response.status}`
      };
    }
  } catch (error) {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    return {
      running: false,
      error: error.name === 'AbortError' || error.name === 'TimeoutError' ? 'Connection timeout' : 'API not reachable'
    };
  }
}

/**
 * Check both APIs
 * @returns {Promise<{mlModel: Object, virusTotal: Object}>}
 */
export async function checkAllApis() {
  const [mlModelStatus, virusTotalStatus] = await Promise.allSettled([
    checkMlModelApi(),
    checkVirusTotalApi()
  ]);
  
  return {
    mlModel: mlModelStatus.status === 'fulfilled' ? mlModelStatus.value : { running: false, error: 'Check failed' },
    virusTotal: virusTotalStatus.status === 'fulfilled' ? virusTotalStatus.value : { running: false, error: 'Check failed' }
  };
}

