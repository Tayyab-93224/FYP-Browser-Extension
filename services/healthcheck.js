const ML_MODEL_API_URL = 'http://127.0.0.1:8000';
const VIRUSTOTAL_API_URL = 'https://www.virustotal.com/api/v3';


export async function checkMlModelApi() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 3000);

  try {
    const response = await fetch(`${ML_MODEL_API_URL}/health`, {
      signal: controller.signal   // controller.signal contains the abort signal that can be true or false
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
        error: `Server Error: ${response.status}`
      };
    }
  } catch (error) {
    clearTimeout(timeoutId);  // clearing the timeout is essential to stop the request if it takes too long
    if (error.name === 'AbortError') {
      return {
        running: false,
        error: 'Connection timeout (No Response)'
      };
    } else {
      return {
        running: false,
        error: 'API not reachable (Network Error)'
      };
    }
  }
}


export async function checkVirusTotalApi() {
  let timeoutId = null;
  const controller = new AbortController();

  try {
    // Check if an API key is configured in backend
    const apiKeyRes = await fetch('http://127.0.0.1:8000/api/storage/api-key');

    if (!apiKeyRes.ok) {
      return {
        running: false,
        error: 'API key not configured'
      };
    }

    const apiKeyData = await apiKeyRes.json();
    const apiKey = apiKeyData.apiKey;

    if (!apiKey) {
      return {
        running: false,
        error: 'API key not configured'
      };
    }

    timeoutId = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(`${VIRUSTOTAL_API_URL}/users/me`, {
      headers: { 'x-apikey': apiKey },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.ok) {
      return {
        running: true,
        status: 'running',
        message: 'VirusTotal API is running'
      };
    }

    if (response.status === 401) {
      return {
        running: true,
        status: 'invalid_key',
        message: 'VirusTotal API is reachable but API key may be invalid'
      }

    } else {
      return {
        running: false,
        error: `API responded with status: ${response.status}`
      };
    }
  } catch (error) {
    if (timeoutId) clearTimeout(timeoutId);
    return {
      running: false,
      error: error.name === 'AbortError'
        ? 'Connection timeout'
        : 'API not reachable'
    };
  }
}


export async function checkAllApis() {
  const [mlModelStatus, virusTotalStatus] = await Promise.allSettled([
    checkMlModelApi(),
    checkVirusTotalApi()
  ]);

  return {
    mlModel: mlModelStatus.status === 'fulfilled'
      ? mlModelStatus.value
      : { running: false, error: 'ML Model API Check failed' },

    virusTotal: virusTotalStatus.status === 'fulfilled'
      ? virusTotalStatus.value
      : { running: false, error: 'VirusTotal API Check failed' }
  };
}
