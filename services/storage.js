export async function storeUrlResult(currentUrl, result) {
  try {
    await chrome.storage.local.set({ [currentUrl]: result });

    const urlListData = await chrome.storage.local.get('urlList');
    let urlList;
    if (urlListData.urlList) {
      urlList = urlListData.urlList;
    } else {
      urlList = [];
    }

    let existingIndex = -1;
    for (let i = 0; i < urlList.length; i++) {
      if (urlList[i].url === currentUrl) {
        existingIndex = i;
        break;
      }
    }

    if (existingIndex === -1) {
      urlList.push({
        url: currentUrl,
        scanTime: result.scanTime || new Date(),
        isMalicious: result.isMalicious,
        scanSuccess: result.scanSuccess,
        hasVirusTotal: Boolean(result.virusTotal),
        hasMlModel: Boolean(result.mlModel)
      });
    }

    if (urlList.length > 100) {
      urlList.sort((a, b) => {
        const TimeA = new Date(a.scanTime);
        const TimeB = new Date(b.scanTime);
        return TimeB.getTime() - TimeA.getTime();
      });
      urlList = urlList.slice(0, 100);
    }

    await chrome.storage.local.set({ urlList });

    return true;
  } catch (error) {
    console.error('Error storing URL result:', error);
    return false;
  }
}

export async function getAllUrls() {
  try {
    const result = await chrome.storage.local.get('urlList');
    return result.urlList || [];
  } catch (error) {
    console.error('Error getting all URLs:', error);
    return [];
  }
}

export async function clearHistory() {
  try {
    const urlListData = await chrome.storage.local.get('urlList');
    const urlList = urlListData.urlList || [];

    const keysToRemove = urlList.map(item => item.url);
    keysToRemove.push('urlList');
    await chrome.storage.local.remove(keysToRemove);

    return true;
  } catch (error) {
    console.error('Error clearing history:', error);
    return false;
  }
}
