# Phishy: AI-Powered Phishing URL Detection

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Backend-Flask-000000?logo=flask&logoColor=white)
![Chrome](https://img.shields.io/badge/Extension-Manifest%20V3-4285F4?logo=google-chrome&logoColor=white)
![ML](https://img.shields.io/badge/ML-Random%20Forest-F7931E?logo=scikit-learn&logoColor=white)

> **A real-time, hybrid browser extension that combines local Machine Learning (Random Forest) with the VirusTotal API to detect zero-day phishing attacks and known malicious sites.**

---

## Table of Contents
- [Project Overview](#-project-overview)
- [Key Features](#-key-features)
- [System Architecture](#️-system-architecture)
- [Directory Structure](#-directory-structure)
- [Installation & Setup](#-installation--setup)
  - [1. Backend Setup (Flask + ML)](#1-backend-setup-flask--ml)
  - [2. Extension Setup (Chrome)](#2-extension-setup-chrome)
- [Usage Guide](#-usage-guide)
- [Tech Stack](#-tech-stack)
- [Limitations](#-limitations)
- [License](#-license)

---

## Project Overview

**Phishy** solves the latency vs. accuracy issue in web security. Unlike standard extensions that rely solely on ML APIs or slow external APIs, Phishy uses a **Dual-Engine Parallel Architecture**.

It "races" two detection engines against each other:
1.  **Local ML Engine:** A Python-based Random Forest model that instantly analyzes URL features (length, special characters, subdomains) to catch **zero-day threats**.
2.  **VirusTotal API:** A cloud-based check against global threat intelligence to catch **known malicious domains**.

The user receives a warning from whichever engine responds *first*.

---

## Key Features

- **Hybrid Parallel Scanning:** Simultaneous execution of local ML heuristic analysis and cloud API checks.
- **Zero-Day Protection:** Detects never-before-seen phishing links using feature extraction logic.
- **Verified Threat Intelligence:** Cross-references URLs with over 70 security vendors via VirusTotal.
- **Low Latency:** "Race condition" logic ensures the user isn't stuck waiting for a slow API response.
- **Immediate Visual Alerts:** On-page banners and browser icon badges (🔴) for dangerous sites.
- **Comprehensive History:** Logs scan results locally with details on which engine flagged the threat.

---

## System Architecture

The system follows a **Client-Server-API** hybrid model:

1.  **Browser Extension (Client):** Captures the URL and sends asynchronous requests to both backends.
2.  **Flask Server (Local Backend):** Receives the URL, extracts lexical features, and runs the Random Forest model.
3.  **VirusTotal (External Backend):** Validates the URL against global blacklists.

---

## Directory Structure

```text
├── 📂 assets/              # Icons and images for the extension
├── 📂 popup/               # Extension popup UI (HTML/CSS/JS)
├── 📂 services/            # Helper scripts for API handling
├── app.py                  # Flask API Server (The ML Backend)
├── background.js           # Core extension logic (Parallel Scanning)
├── manifest.json           # Chrome Extension Configuration (Manifest V3)
├── train_model.py          # Script to train the Random Forest model
├── test_the_model.py       # Script to test model on single URLs
├── phishing_model.joblib   # Saved Machine Learning Model
├── model_features.joblib   # Saved List of Model Features
├── requirements.txt        # Python dependencies
└── README.md               # Project Documentation
````

-----

## Installation & Setup

### Prerequisites

  - **Python 3.8+** installed.
  - **Google Chrome** browser.

### 1\. Backend Setup (Flask + ML)

The Python backend must be running for the Machine Learning detection to work.

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Tayyab-Khurram/FYP-Project.git
    cd phishy-extension
    ```

2.  **Install Python dependencies:**

    ```bash
    pip install flask flask-cors pandas scikit-learn tldextract joblib
    ```

3.  **Train the Model (First Time Only):**
    *Ensure `phishing_urls.csv` and `benign_urls.csv` are in the root folder.*

    ```bash
    python train_model.py
    ```

4.  **Start the Server:**

    ```bash
    python app.py
    ```

    *You should see: `Running on http://127.0.0.1:5000`*

### 2\. Extension Setup (Chrome)

1.  Open Chrome and navigate to `chrome://extensions/`.
2.  Toggle **Developer mode** (top right corner).
3.  Click **Load unpacked**.
4.  Select the **root folder** of this project.
5.  The Phishy icon should appear in your toolbar.

-----

## Usage Guide

1.  **Keep the Server Running:** The terminal running `python app.py` must remain open while you browse.
2.  **API Key Setup:** Click the extension icon and enter your VirusTotal API Key (optional but recommended for full protection).
3.  **Browse Normally:** - If a site is safe, nothing happens.
      - If a site is **Phishing**, a red banner will appear at the top of the page.
4.  **Check History:** Click the extension icon to view a log of recent scans and see which engine (ML or VirusTotal) flagged the site.

-----

## Tech Stack

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Frontend** | HTML, CSS, JavaScript | Browser Extension UI & Logic |
| **Backend** | Python, Flask | Host ML Model & API Endpoint |
| **ML Engine** | Scikit-Learn (Random Forest) | Zero-day Threat Detection |
| **API** | VirusTotal v3 | Verified Threat Intelligence |
| **Storage** | Chrome Storage API | Local History Management |

-----

## Limitations

  - **Local Server Required:** The `app.py` script must be running locally for ML detection to function.
  - **API Rate Limits:** The standard VirusTotal free API has a request limit (4 requests/minute). The extension handles this gracefully by relying on the ML model if the API quota is exceeded.

-----

## License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.
