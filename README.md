# Phishing Link Detection Browser Extension

## Overview
This browser extension helps users stay safe from phishing attacks by detecting and blocking malicious links in real-time. The extension works by analyzing URLs against a database of known phishing sites and alerting users before they can access a harmful website.

## Features
-  **Real-time URL scanning** to detect phishing links.
-  **Warning notifications** when a malicious link is detected.
-  **Automated checks** against phishing databases (Google Safe Browsing, OpenPhish, etc.).
-  **Privacy-focused** with no user data tracking.
-  **Works across multiple websites and web apps.**

##  Installation
1. **Download the extension files** or clone this repository:
   ```sh
   git clone https://github.com/PranavTamada/Phishing-Detection.git
   ```
2. **Open Chrome and navigate to the Extensions page:**
   - Go to `chrome://extensions/`
   - Enable **Developer Mode** (toggle on the top right).
   - Click **Load Unpacked** and select the extension folder.
3. The extension is now installed and running!

## How It Works
1. The extension monitors all links that the user clicks.
2. It extracts the URL and checks it against known phishing databases.
3. If a link is detected as malicious:
   - The extension prevents navigation.
   - A warning popup alerts the user.
4. The user can choose to proceed at their own risk or return to safety.

## Technologies Used
- **JavaScript (ES6+)**
- **Manifest V3 (Chrome Extensions API)**
- **Fetch API** for phishing database lookups
- **Background Scripts & Content Scripts**

## Future Enhancements
-  Support for more browsers (Firefox, Edge, Safari)
-  AI-based phishing detection
-  Mobile browser extension compatibility
-  Automatic updates to phishing databases

 **Stay safe from phishing attacks with this browser extension!** 

