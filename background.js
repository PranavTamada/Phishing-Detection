const OPENPHISH_API_URL = "https://openphish.com/feed.txt";
const UPDATE_INTERVAL = 3600000; // 1 hour

class PhishingDetector {
    constructor() {
        this.cachedPhishingDomains = new Set();
        this.lastUpdateTime = 0;
        this.updatePhishingDatabase();
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
                        timestamp: Date.now()
                    };
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
            chrome.tabs.update(details.tabId, {
                url: chrome.runtime.getURL('blocked.html')
            });
        }
    }
});
