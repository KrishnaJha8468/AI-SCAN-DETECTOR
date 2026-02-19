#  AI Scam Detector

##  Project Files

### Main Application
- `app.py` - Main Streamlit web application
- `ai_detector.py` - AI content detection engine
- `scoring_engine.py` - Unified risk scoring system
- `text_analyzer.py` - Text analysis for scams
- `url_analyzer.py` - URL analysis with brand detection
- `visual_detector.py` - Visual spoofing detection

### Browser Extension
- `browser-extension/` - Chrome/Brave/Firefox extension
  - `background.js` - Extension service worker
  - `content.js` - Page content script
  - `manifest.json` - Extension configuration
  - `popup.html/css/js` - Extension popup interface
  - `icons/` - Icon files for different risk levels

### Email Forwarding System
- `email_forwarding/` - Email-based scam detection
  - `email_server.py` - Email server
  - `email_config.py` - Email configuration
  - `test_email_forwarding.py` - Test script
  - `templates/` - Dashboard HTML template

##  Quick Start

1. Install requirements:
   ```bash
   pip install -r requirements.txt
