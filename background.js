const OPENPHISH_API_URL = "https://openphish.com/feed.txt";
const UPDATE_INTERVAL = 3600000; // 1 hour

class PhishingDetector {
    constructor() {
        this.cachedPhishingDomains = new Set();
        this.lastUpdateTime = 0;
        this.updatePhishingDatabase();
    }

    computePhishScore(url) {
        try { // Fixing typo in computePhishScore
            const u = new URL(url);

            // === Feature 1: URL Length (normalized, cap at 200)
            const f1 = Math.min(url.length / 200, 1);

            // === Feature 2: Subdomain Depth
            const domainParts = u.hostname.split('.');
            const subdomainCount = domainParts.length - 2; // e.g. sub.domain.com → 1
            const f2 = Math.min(subdomainCount / 5, 1);

            // === Feature 3: Suspicious Characters
            const suspiciousCharMatch = url.match(/[-@?%=&\\/]/g);
            const f3 = suspiciousCharMatch ? suspiciousCharMatch.length / url.length : 0;

            // === Feature 4: IP Address in Host
            const ipRegex = /^\d{1,3}(\.\d{1,3}){3}$/;
            const f4 = ipRegex.test(u.hostname) ? 1 : 0;

            // === Feature 5: Insecure Protocol (HTTP)
            const f5 = u.protocol === 'http:' ? 1 : 0;

            // === Feature 6: Entropy (complexity of URL)
            const charFreq = {};
            for (let char of url) charFreq[char] = (charFreq[char] || 0) + 1;
            let entropy = 0;
            for (let char in charFreq) {
                const p = charFreq[char] / url.length;
                entropy -= p * Math.log2(p);
            }
            const f6 = Math.min(entropy / 5, 1); // Normalize to [0,1]

            // === Feature 7: Uncommon TLD
            const commonTLDs = ['com', 'org', 'net', 'edu', 'gov', 'in'];
            const tld = domainParts[domainParts.length - 1].toLowerCase();
            const f7 = commonTLDs.includes(tld) ? 0 : 1;

            // === Feature 8: Suspicious Keywords in Domain
            const suspiciousKeywords = ['login', 'secure', 'account', 'update', 'verify', 'bank', 'paypal', 'signin'];
            // Ensure suspicious keywords are checked in the full URL, not just the hostname
            const f8 = suspiciousKeywords.some(kw => url.toLowerCase().includes(kw)) ? 1 : 0;

            // === Combine All Features
            const features = [f1, f2, f3, f4, f5, f6, f7, f8];
            // Adjusted weights to increase sensitivity to suspicious keywords and subdomain depth
            const weights =  [0.10, 0.15, 0.20, 0.10, 0.10, 0.15, 0.05, 0.15]; // Must sum to 1

            const score = features.reduce((sum, fi, i) => sum + weights[i] * fi, 0);
            console.log('Feature values:', { f1, f2, f3, f4, f5, f6, f7, f8 });
            console.log('Final phishing score:', score);
            return score; // Value between 0 and 1
        } catch (e) {
            return 1; // If parsing fails, treat as phishing
        }
    }

    async fetchPhishingData() {
        try {
            const response = await fetch(OPENPHISH_API_URL, {
                method: "GET",
                headers: {
                    "User-Agent": "Phishing-Detector-Extension/1.0",
                    "Accept": "text/plain",
                    "Cache-Control": "no-cache"
                }
            });

            if (!response.ok) {
                throw new Error(`Failed to fetch from OpenPhish: ${response.status}`);
            }

            const data = await response.text();
            return data;
        } catch (error) {
            console.error('Error fetching from OpenPhish:', error);
            return null;
        }
    }

    async updatePhishingDatabase() {
        try {
            const database = await this.fetchPhishingData();
            
            if (database) {
                this.cachedPhishingDomains.clear();
                const domains = this.extractDomainsFromDatabase(database);
                domains.forEach(domain => {
                    if (domain && domain.trim()) {
                        this.cachedPhishingDomains.add(domain.toLowerCase().trim());
                    }
                });
                this.lastUpdateTime = Date.now();
                console.log(`Updated phishing database. Total domains: ${this.cachedPhishingDomains.size}`);
            }
        } catch (error) {
            console.error('Database update failed:', error);
        }

        // Schedule next update
        setTimeout(() => this.updatePhishingDatabase(), UPDATE_INTERVAL);
    }

    extractDomainsFromDatabase(database) {
        const domains = new Set();
        const lines = database.split('\n');
        
        lines.forEach(line => {
            try {
                const url = new URL(line.trim());
                domains.add(url.hostname.toLowerCase());
            } catch (error) {
                // Skip invalid URLs
            }
        });
        
        return domains;
    }

    async checkURL(url) {
        try {
            if (!url || typeof url !== 'string') return { isPhishing: false };
            
            // Basic URL format validation
            let formattedUrl = url.trim();
            
            // Check if it's a search query rather than a URL
            if (!formattedUrl.includes('.') || formattedUrl.includes(' ')) {
                return { isPhishing: false };
            }

            // Add protocol if missing
            if (!formattedUrl.startsWith('http://') && !formattedUrl.startsWith('https://')) {
                formattedUrl = `https://${formattedUrl}`;
            }

            try {
                const urlObj = new URL(formattedUrl);
                const domain = urlObj.hostname.toLowerCase();
                
                // Check if domain is in our database
                if (this.cachedPhishingDomains.has(domain)) {
                    return {
                        isPhishing: true,
                        confidence: "High",
                        reason: `Matched phishing domain: ${domain}`,
                        score: 1, // 100% phishing
                        features: ["impersonation"], // Example feature, adjust as needed
                        timestamp: Date.now()
                    };
                }

                // Compute heuristic phishing score
                const score = this.computePhishScore(formattedUrl);
                // Example: extract features (customize as needed)
                const features = [];
                if (score >= 0.45) {
                    // Example feature extraction (customize logic as needed)
                    if (formattedUrl.match(/\d{1,3}(\.\d{1,3}){3}/)) features.push("ipInUrl");
                    if ((new URL(formattedUrl)).hostname.split('.').length - 2 > 2) features.push("suspiciousSubdomain");
                    if (formattedUrl.match(/[-@?%=&\\/]/g)) features.push("specialChars");
                    // Add more feature extraction as needed
                    console.log('URL is unsafe: %d', score);
                    return {
                        isPhishing: true,
                        confidence: "Medium",
                        reason: `Heuristic phishing score: ${score.toFixed(2)}`,
                        score,
                        features,
                        timestamp: Date.now()
                    };
                }
                else {
                    console.log('URL is safe: %d', score);
                    return { isPhishing: false };
                }
            } catch (urlError) {
                console.log('Invalid URL format:', formattedUrl);
                return { isPhishing: false };
            }
            
            return { isPhishing: false };
        } catch (error) {
            console.error('URL checking error:', error);
            return { isPhishing: false };
        }
    }

    getStats() {
        return {
            domainCount: this.cachedPhishingDomains.size,
            lastUpdated: this.lastUpdateTime,
            nextUpdate: this.lastUpdateTime + UPDATE_INTERVAL
        };
    }
}

const phishingDetector = new PhishingDetector();

// Listen for messages from content script and popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "checkURL") {
        phishingDetector.checkURL(request.url)
            .then(result => sendResponse(result))
            .catch(error => {
                console.error('Error processing request:', error);
                sendResponse({ isPhishing: false });
            });
        return true; // Keep the message channel open for async response
    }
    
    if (request.action === "getStats") {
        sendResponse({ stats: phishingDetector.getStats() });
    }
});

// Block navigation to phishing sites
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
    if (details.frameId === 0) { // Only check main frame
        const result = await phishingDetector.checkURL(details.url);
        if (result.isPhishing) {
            const urlParam = encodeURIComponent(details.url);
            const score = result.score !== undefined ? result.score : 0;
            const features = result.features && result.features.length > 0 ? encodeURIComponent(result.features.join(',')) : '';
            const query = `?url=${urlParam}&score=${score}${features ? `&features=${features}` : ''}`;
            chrome.tabs.update(details.tabId, {
                url: chrome.runtime.getURL('blocked.html') + query
            });
        }
    }
});
