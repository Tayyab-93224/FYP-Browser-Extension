// ML Model API service
// ML Model API is configured to use localhost (127.0.0.1)

// ML Model API endpoint (hardcoded to localhost)
const ML_MODEL_API_URL = 'http://127.0.0.1:5000/predict'; // Update port if your ML model uses a different one

// Scan URL with ML model
export async function scanUrlWithMlModel(url) {
  try {
    // Prepare request headers
    const headers = {
      'Content-Type': 'application/json'
    };

    // Make API request to ML model (localhost)
    const response = await fetch(ML_MODEL_API_URL, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`ML Model API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    
    // Parse ML model response
    // The API returns: { prediction: 1 (phishing) or 0 (safe), status: 'phishing' or 'safe' }
    const prediction = data.prediction !== undefined ? data.prediction : (data.result || data.class || data.label);
    const status = data.status || '';
    const confidence = data.confidence || data.score || data.probability || 0;
    
    // Determine if malicious: prediction === 1 means phishing/malicious
    const isMalicious = prediction === 1 || 
                       prediction === 'malicious' || 
                       prediction === 'phishing' || 
                       status === 'phishing' ||
                       (typeof prediction === 'number' && prediction > 0.5) ||
                       (typeof confidence === 'number' && confidence > 0.5 && (prediction === 'malicious' || prediction === 'phishing' || status === 'phishing'));

    return {
      url,
      scanTime: new Date().toISOString(),
      prediction: status || (prediction === 1 ? 'phishing' : prediction === 0 ? 'safe' : 'unknown'),
      confidence: typeof confidence === 'number' ? confidence : parseFloat(confidence) || 0,
      isMalicious: !!isMalicious,
      scanSuccess: true,
      rawResponse: data // Store raw response for debugging
    };
  } catch (error) {
    console.error('Error scanning URL with ML model:', error);
    return {
      url,
      scanTime: new Date().toISOString(),
      prediction: 'unknown',
      confidence: 0,
      isMalicious: false,
      scanSuccess: false,
      error: error.message
    };
  }
}

