# Phishy - Browser Extension for Phishing URL Detection

Phishy is a browser extension that detects potentially malicious or phishing websites in real-time using the VirusTotal API. It provides immediate alerts when visiting suspicious sites and maintains a history of all scanned URLs.

## Features

- Real-time phishing detection using VirusTotal API
- Immediate visual alerts for suspicious websites
- Comprehensive URL history with scan results
- Clean, intuitive popup interface
- Scan statistics and protection metrics

## Installation

1. Download or clone this repository
2. Navigate to `chrome://extensions` in your Chrome browser
3. Enable "Developer mode" in the top-right corner
4. Click "Load unpacked" and select the extension directory
5. The Phishy extension should now be installed and visible in your extensions list

## Usage

1. Click on the Phishy icon in your browser toolbar to open the popup
2. Enter your VirusTotal API key when prompted
   - You can get a free API key by signing up at [VirusTotal](https://www.virustotal.com/gui/join-us)
3. Browse the web normally - Phishy will automatically scan URLs as you visit them
4. If a malicious site is detected, you'll see an alert banner at the top of the page
5. View your scan history and statistics in the popup interface

## Development

The extension is built using vanilla JavaScript and follows Chrome's extension manifest v3 format. The main components are:

- `manifest.json`: Extension configuration
- `background.js`: Handles URL monitoring and VirusTotal API calls
- `popup/`: Contains the user interface files
- `services/`: Contains API and storage service modules

## License

MIT License