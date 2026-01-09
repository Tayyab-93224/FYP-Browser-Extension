const BACKEND_BASE_URL = 'http://127.0.0.1:8000';

// Store the combined scan result  in the backend 
export async function storeUrlResult(combinedResult) {
  try {
    const response = await fetch(`${BACKEND_BASE_URL}/api/storage/url-result`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(combinedResult)
    });

    if (!response.ok) {
      throw new Error(`Failed to store URL result: ${response.status} ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error('Error storing URL result:', error);
    return { success: false, message: 'Failed to store URL result' };
  }
}


export async function getAllUrls() {
  try {
    const response = await fetch(`${BACKEND_BASE_URL}/api/storage/urls`);

    if (!response.ok) {
      throw new Error(`Failed to fetch URLs: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    // data should match UrlHistoryResponse { urls: [...], total: number }
    return data.urls || [];
  } catch (error) {
    console.error('Error getting all the URLs:', error);
    return [];
  }
}


export async function clearHistory() {
  try {
    const response = await fetch(`${BACKEND_BASE_URL}/api/storage/url-result`, {
      method: 'DELETE'
    });

    if (!response.ok) {
      throw new Error(`Failed to clear history: ${response.status} ${response.statusText}`);
    }

    return true;
  } catch (error) {
    console.error('Error clearing history:', error);
    return false;
  }
}
