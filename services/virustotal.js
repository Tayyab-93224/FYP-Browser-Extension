export async function verifyApiKey(apiKeyOverride) {
    try {
        const res = await chrome.storage.local.get('apiKey');
        const apiKey = (apiKeyOverride || res.apiKey || '').trim();
        if (!apiKey) {
            return { ok: false, status: 0 };
        }

        const response = await fetch('https://www.virustotal.com/api/v3/users/me', {
            method: 'GET',
            headers: { 'x-apikey': apiKey }
        });

        return { ok: response.ok, status: response.status };
    } catch (e) {
        return { ok: false, status: -1 };
    }
}

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

        // Poll for the analysis result with exponential backoff (max 5 tries, up to ~10s)
        let tries = 0;
        const maxTries = 5;
        let wait = 1500;

        while (tries < maxTries) {
            await new Promise(res => setTimeout(res, wait));
            tries++;
            const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                method: 'GET',
                headers: {
                    'x-apikey': apiKey
                }
            });
            const analysisData = await analysisResponse.json();
            let stats = analysisData?.data?.attributes?.stats;
            // If stats are available, break early
            if (stats && typeof stats.malicious === 'number') {
                let isMalicious = stats.malicious > 0 || stats.suspicious > 0;
                return {
                    url,
                    scanTime: new Date().toISOString(),
                    stats,
                    isMalicious,
                    scanSuccess: true,
                    analysisId
                };
            }
            // Increase wait time for next try (exponential backoff)
            wait *= 1.7;
        }

        // If no stats after polling, return as unsuccessful
        return {
            url,
            scanTime: new Date().toISOString(),
            stats: stats || {
                malicious: 0,
                suspicious: 0,
                harmless: 0,
                undetected: 0
            },
            isMalicious: false,
            scanSuccess: false,
            analysisId,
            error: 'Scan result not ready in time'
        };

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
