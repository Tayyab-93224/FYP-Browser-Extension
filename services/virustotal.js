export async function scanUrl(url) {
  try {
      const res = await chrome.storage.local.get('apiKey');
      const apiKey = res.apiKey;

      if (!apiKey) {
          throw new Error('API key not found');
      }

      // Submit URL for analysis
      const response = await fetch('https://www.virustotal.com/api/v3/urls', {
          method: 'POST',
          headers: {
              'x-apikey': apiKey,
              'Content-Type': 'application/x-www-form-urlencoded'
          },
          body: `url=${url}`
      });

      if (!response.ok) {
          throw new Error(`VirusTotal API error: ${response.status}`);
      }

      const submitData = await response.json();
      const analysisId = submitData.data.id;

      // Wait 13 seconds, then fetch the result
      const result = await new Promise((resolve, reject) => {
          setTimeout(async () => {
              try {
                  const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                      method: 'GET',
                      headers: {
                          'x-apikey': apiKey
                      }
                  });

                  const analysisData = await analysisResponse.json();
                  const stats = analysisData.data.attributes.stats;
                  const isMalicious = stats.malicious > 0 || stats.suspicious > 0;

                  resolve({
                      url,
                      scanTime: new Date().toISOString(),
                      stats,
                      isMalicious,
                      scanSuccess: true,
                      analysisId
                  });
              } catch (err) {
                  reject(err);
              }
          }, 15000);
      });

      return result;

  } catch (error) {
      console.error('Error scanning URL:', error);
      return {
          url,
          scanTime: new Date().toISOString(),
          stats: {
              malicious: 0,
              suspicious: 0,
              harmless: 0,
              undetected: 0
          },
          isMalicious: false,
          scanSuccess: false,
          error: error.message
      };
  }
}

