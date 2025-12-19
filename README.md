# Phishy: AI-Powered Phishing URL Detection

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi&logoColor=white)
![Chrome](https://img.shields.io/badge/Extension-Manifest%20V3-4285F4?logo=google-chrome&logoColor=white)
![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?logo=sqlite&logoColor=white)

> **A real-time, hybrid browser extension that combines local Machine Learning (Random Forest) with the VirusTotal API to detect zero-day phishing attacks, backed by a high-performance FastAPI server.**

---

## Table of Contents
- [Project Overview](#-project-overview)
- [Key Features](#-key-features)
- [System Architecture](#️-system-architecture)
- [Directory Structure](#-directory-structure)
- [Installation & Setup](#-installation--setup)
  - [1. Backend Setup (FastAPI + ML)](#1-backend-setup-fastapi--ml)
  - [2. Extension Setup (Chrome)](#2-extension-setup-chrome)
- [Usage Guide](#-usage-guide)
- [Tech Stack](#-tech-stack)
- [Limitations](#-limitations)
- [License](#-license)
---

## Project Overview

**Phishy** solves the latency vs. accuracy trade-off in web security. Unlike standard extensions that rely solely on slow external APIs, Phishy uses a **Dual-Engine Parallel Architecture**.

It "races" two detection engines against each other:
1.  **Local ML Engine:** A Python-based Random Forest model served via **FastAPI** that instantly analyzes URL features (length, special characters, subdomains) to catch **zero-day threats**.
2.  **VirusTotal API:** A cloud-based check against global threat intelligence to catch **known malicious domains**.

The system persists all scan history and user logs in a structured **SQLite database** for analysis and auditing.

---

## Key Features

- **High-Performance Backend:** Built on **FastAPI** for asynchronous, non-blocking request handling.
- **Zero-Day Protection:** Detects never-before-seen phishing links using feature extraction logic.
- **Verified Threat Intelligence:** Cross-references URLs with over 70 security vendors via VirusTotal.
- **Structured Persistence:** Automatically saves scan logs and user data to a local **SQLite database**.
- **Low Latency:** "Race condition" logic ensures the user isn't stuck waiting for a slow API response.
- **Immediate Visual Alerts:** On-page banners and browser icon badges (❗) for dangerous sites and (✔️) for safe sites.

---

## System Architecture

The system follows a **Client-Server-Database** hybrid model:

1.  **Browser Extension (Client):** Captures the URL and sends asynchronous requests to the local server.
2.  **FastAPI Server (Local Backend):** Receives the URL, runs the Random Forest model, and handles concurrent API validation.
3.  **SQLite Database:** Stores scan history, API keys, and threat logs for persistent access.
4.  **VirusTotal (External Service):** Validates the URL against global blacklists.

---

## Directory Structure

```text
├── 📂 assets/              # Icons and images for the extension
├── 📂 popup/               # Extension popup UI (HTML/CSS/JS)
├── 📂 services/            # Helper scripts for API handling
├── main.py                 # FastAPI Server (Replaces app.py)
├── background.js           # Core extension logic (Parallel Scanning)
├── manifest.json           # Chrome Extension Configuration (Manifest V3)
├── train_model.py          # Script to train the Random Forest model
├── test_the_model.py       # Script to test model on single URLs
├── phishing_model.joblib   # Saved Machine Learning Model
├── model_features.joblib   # Saved List of Model Features
├── phishy.db               # SQLite Database (Auto-generated)
├── requirements.txt        # Python dependencies
└── README.md               # Project Documentation
