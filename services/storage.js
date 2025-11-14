// Store URL scan result
export async function storeUrlResult(url, result) {
  try {
    // Store result with URL as key
    await chrome.storage.local.set({ [url]: result });
    
    // Update URL list
    const urlListData = await chrome.storage.local.get('urlList');
    let urlList = urlListData.urlList || [];
    
    // Check if URL already exists in the list
    const existingIndex = urlList.findIndex(item => item.url === url);
    
    if (existingIndex !== -1) {
      // Update existing entry
      urlList[existingIndex] = {
        url,
        scanTime: result.scanTime || new Date().toISOString(),
        isMalicious: result.isMalicious,
        scanSuccess: result.scanSuccess,
        hasVirusTotal: !!result.virusTotal,
        hasMlModel: !!result.mlModel
      };
    } else {
      // Add new entry
      urlList.push({
        url,
        scanTime: result.scanTime || new Date().toISOString(),
        isMalicious: result.isMalicious,
        scanSuccess: result.scanSuccess,
        hasVirusTotal: !!result.virusTotal,
        hasMlModel: !!result.mlModel
      });
    }
    
    // Limit list to most recent 100 entries
    if (urlList.length > 100) {
      urlList = urlList.sort((a, b) => new Date(b.scanTime) - new Date(a.scanTime)).slice(0, 100);
    }
    
    // Save updated list
    await chrome.storage.local.set({ urlList });
    
    return true;
  } catch (error) {
    console.error('Error storing URL result:', error);
    return false;
  }
}

// Get all scanned URLs
export async function getAllUrls() {
  try {
    const result = await chrome.storage.local.get('urlList');
    return result.urlList || [];
  } catch (error) {
    console.error('Error getting all URLs:', error);
    return [];
  }
}

// Get URL by ID
export async function getUrlById(id) {
  try {
    const result = await chrome.storage.local.get(id);
    return result[id] || null;
  } catch (error) {
    console.error('Error getting URL by ID:', error);
    return null;
  }
}

// Clear history
export async function clearHistory() {
  try {
    // Get all URLs
    const urlListData = await chrome.storage.local.get('urlList');
    const urlList = urlListData.urlList || [];
    
    // Create array of keys to remove
    const keysToRemove = urlList.map(item => item.url);
    
    // Add urlList to keys to remove
    keysToRemove.push('urlList');
    
    // Remove all keys
    await chrome.storage.local.remove(keysToRemove);
    
    return true;
  } catch (error) {
    console.error('Error clearing history:', error);
    return false;
  }
}
