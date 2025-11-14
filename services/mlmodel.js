// ML Model API service
// ML Model API is configured to use localhost (127.0.0.1)

// ML Model API endpoint (hardcoded to localhost)
const ML_MODEL_API_URL = 'http://127.0.0.1:8000/predict'; // Update port if your ML model uses a different one

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
    // Adjust these fields based on your ML model's actual response format
    const prediction = data.prediction || data.result || data.class || data.label;
    const confidence = data.confidence || data.score || data.probability || 0;
    const isMalicious = prediction === 'malicious' || 
                       prediction === 'phishing' || 
                       prediction === 1 || 
                       (typeof prediction === 'number' && prediction > 0.5) ||
                       (typeof confidence === 'number' && confidence > 0.5 && (prediction === 'malicious' || prediction === 'phishing'));

    return {
      url,
      scanTime: new Date().toISOString(),
      prediction: prediction || 'unknown',
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

