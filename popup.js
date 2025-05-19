// popup.js
document.addEventListener('DOMContentLoaded', () => {
    // Get stats from background script
    chrome.runtime.sendMessage({ action: 'getStats' }, (response) => {
        if (chrome.runtime.lastError) {
            console.error('Error in sendMessage:', chrome.runtime.lastError); // Adding detailed error logging
            document.getElementById('statusText').textContent = 'Error: Could not get status';
            return;
        }

        const stats = response.stats;
        document.getElementById('domainCount').textContent = `Domains in database: ${stats.domainCount}`;
        document.getElementById('lastUpdate').textContent = `Last update: ${new Date(stats.lastUpdated).toLocaleString()}`;
        document.getElementById('statusText').textContent = 'Protection Active';
    });
});