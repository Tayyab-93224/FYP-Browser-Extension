const ML_MODEL_API_URL = 'http://127.0.0.1:5000/predict';

export async function scanUrlWithMlModel(url) {
  try {
    const headers = {
      'Content-Type': 'application/json'
    };

    const response = await fetch(ML_MODEL_API_URL, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      throw new Error(`ML Model API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();

    const prediction = data.prediction || 'unknown';
    const status = data.status || '';
    const confidence = data.confidence || 0;

    const isMalicious = prediction === 1 || status === 'phishing' || (typeof confidence === 'number' && confidence > 50.0);

    return {
      url,
      scanTime: new Date(),
      prediction: status || 'unknown',
      confidence: confidence,
      isMalicious: Boolean(isMalicious),
      scanSuccess: true,
      rawResponse: data
    };
  } catch (error) {
    console.error('Error scanning URL with ML model:', error);
    return {
      url,
      scanTime: new Date(),
      prediction: 'unknown',
      confidence: 0,
      isMalicious: false,
      scanSuccess: false,
      error: error.message
    };
  }
}

