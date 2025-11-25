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

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function scanUrl(url) {
    try {
        const res = await chrome.storage.local.get('apiKey');
        const apiKey = res.apiKey?.trim();

        if (!apiKey) {
            throw new Error('API key not found');
        }

        const response = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}`
        });

        if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
        }

        const submitData = await response.json();
        const analysisId = submitData.data.id;

        let tries = 0;
        const maxTries = 5;
        let wait = 1500;

        while (tries < maxTries) {
            await sleep(wait);
            tries++;

            const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                method: 'GET',
                headers: {
                    'x-apikey': apiKey
                }
            });

            if (!analysisResponse.ok) {
                throw new Error(`Failed to retrieve analysis: ${analysisResponse.status}`);
            }

            const analysisData = await analysisResponse.json();
            const stats = analysisData?.data?.attributes?.stats;

            if (stats && typeof stats.malicious === 'number') {
                const isMalicious = stats.malicious > 0 || stats.suspicious > 0;
                return {
                    url,
                    scanTime: new Date().toISOString(),
                    stats,
                    isMalicious,
                    scanSuccess: true,
                    analysisId
                };
            }
            wait *= 1.7;
        }

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
