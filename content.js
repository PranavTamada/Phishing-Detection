// content.js
class SearchBarPhishingDetector {
    constructor() {
        this.searchBar = null;
        this.warningElement = null;
        this.debounceTimer = null;
        this.observer = null;
        
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.init());
        } else {
            this.init();
        }
    }

    init() {
        this.initializeSearchBarDetection();
        this.setupMutationObserver();
    }

    setupMutationObserver() {
        // Make sure body exists before observing
        if (!document.body) {
            window.addEventListener('load', () => this.setupMutationObserver());
            return;
        }

        this.observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                if (mutation.addedNodes.length) {
                    this.initializeSearchBarDetection();
                }
            });
        });

        // Start observing with proper configuration
        this.observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    initializeSearchBarDetection() {
        const inputSelectors = [
            'input[type="text"]',
            'input[type="url"]',
            'input[type="search"]',
            'input[name="q"]',
            'input[name="search"]',
            'input[name="url"]',
            'input[placeholder*="search"]',
            'input[placeholder*="url"]',
            'input[placeholder*="address"]'
        ];

        const searchBars = document.querySelectorAll(inputSelectors.join(','));
        
        searchBars.forEach(bar => {
            if (!bar.hasPhishingListener) {
                bar.addEventListener('input', this.handleSearchInput.bind(this));
                bar.addEventListener('keydown', this.handleKeyDown.bind(this));
                bar.addEventListener('paste', this.handlePaste.bind(this));
                bar.hasPhishingListener = true;
            }
        });
    }

    createWarningElement() {
        if (this.warningElement) return this.warningElement;

        const warning = document.createElement('div');
        warning.style.cssText = `
            position: fixed;
            background-color: #ff4444;
            color: white;
            padding: 15px;
            border-radius: 8px;
            z-index: 999999;
            display: none;
            max-width: 400px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            font-family: Arial, sans-serif;
        `;
        document.body.appendChild(warning);
        return warning;
    }

    handleKeyDown(event) {
        if (event.key === 'Enter') {
            const url = event.target.value;
            this.checkUrlBeforeSubmit(url, event);
        }
    }

    handlePaste(event) {
        const pastedText = event.clipboardData.getData('text');
        if (pastedText) {
            this.checkUrlBeforeSubmit(pastedText, event);
        }
    }

    async checkUrlBeforeSubmit(url, event) {
        try {
            if (!url || typeof url !== 'string') return;

            const response = await new Promise((resolve, reject) => {
                chrome.runtime.sendMessage(
                    { action: 'checkURL', url: url },
                    (response) => {
                        if (chrome.runtime.lastError) {
                            reject(chrome.runtime.lastError);
                        } else {
                            resolve(response);
                        }
                    }
                );
            });

            if (response && response.isPhishing) {
                if (event) event.preventDefault();
                this.displayWarning(response, event.target);
                this.notifyUser(response);
            }
        } catch (error) {
            console.error('URL check failed:', error);
        }
    }

    handleSearchInput(event) {
        const url = event.target.value;
        
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => {
            if (!url || typeof url !== 'string') return;

            try {
                chrome.runtime.sendMessage(
                    { action: 'checkURL', url: url },
                    (response) => {
                        if (chrome.runtime.lastError) {
                            console.error('Message sending error:', chrome.runtime.lastError);
                            return;
                        }
                        if (response && response.isPhishing) {
                            this.displayWarning(response, event.target);
                        } else {
                            this.hideWarning();
                        }
                    }
                );
            } catch (error) {
                console.error('URL check failed:', error);
            }
        }, 300);
    }

    displayWarning(result, targetElement) {
        if (!this.warningElement) {
            this.warningElement = this.createWarningElement();
        }

        if (result && result.isPhishing) {
            const rect = targetElement.getBoundingClientRect();
            const warningContent = `
                <div style="margin-bottom: 10px;">
                    <strong>⚠️ Warning: Potential Phishing Site</strong>
                </div>
                <div style="margin-bottom: 10px;">
                    ${result.reason || 'This URL has been identified as a potential phishing site.'}
                </div>
                <div style="font-size: 0.9em; color: #ffebee;">
                    Last updated: ${new Date(result.timestamp).toLocaleString()}
                </div>
            `;
            
            this.warningElement.innerHTML = warningContent;
            this.warningElement.style.top = `${rect.bottom + window.scrollY + 5}px`;
            this.warningElement.style.left = `${rect.left + window.scrollX}px`;
            this.warningElement.style.display = 'block';
        }
    }

    hideWarning() {
        if (this.warningElement) {
            this.warningElement.style.display = 'none';
        }
    }

    notifyUser(result) {
        chrome.runtime.sendMessage({
            action: 'showNotification',
            title: '⚠️ Phishing Site Detected',
            message: result.reason || 'This URL has been identified as a potential phishing site.'
        });
    }
}

// Initialize the detector
new SearchBarPhishingDetector();