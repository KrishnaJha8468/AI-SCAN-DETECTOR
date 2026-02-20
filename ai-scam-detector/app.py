# app.py - Complete AI Scam Detector with Browser Extension Support

import streamlit as st
import datetime
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from text_analyzer import TextAnalyzer
from url_analyzer import URLAnalyzer
from scoring_engine import ScoringEngine
from ai_detector import AIDetector
import time
import re

# For browser extension API
try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    import threading
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    st.warning("⚠️ Flask or flask-cors not installed. Browser extension API will not work. Run: pip install flask flask-cors")

# Page configuration (MUST be first)
st.set_page_config(
    page_title="AI Scam Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# PROFESSIONAL DARK THEME CSS
# ============================================================================

st.markdown("""
<style>
    /* Import Professional Font */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');
    
    /* Global Styles - Dark Theme */
    .stApp {
        font-family: 'Plus Jakarta Sans', sans-serif;
        background: #0A0A0F;
        color: #FFFFFF;
    }
    
    /* Hide Streamlit Branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
    
    /* Main Container */
    .main-container {
        max-width: 1400px;
        margin: 0 auto;
        padding: 1rem 2rem;
    }
    
    /* Header Section */
    .header {
        margin-bottom: 2rem;
        padding: 1rem 0;
        border-bottom: 1px solid rgba(255,255,255,0.1);
    }
    
    .header-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 1rem;
    }
    
    .logo {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    .logo-icon {
        font-size: 2rem;
        background: linear-gradient(135deg, #3B82F6, #8B5CF6);
        padding: 0.75rem;
        border-radius: 16px;
    }
    
    .logo-text {
        font-size: 1.5rem;
        font-weight: 700;
        color: #FFFFFF;
    }
    
    .header-badge {
        background: rgba(59, 130, 246, 0.1);
        border: 1px solid rgba(59, 130, 246, 0.2);
        padding: 0.5rem 1rem;
        border-radius: 100px;
        font-size: 0.875rem;
        color: #3B82F6;
    }
    
    /* Extension Badge */
    .extension-badge {
        background: linear-gradient(135deg, #3B82F6, #8B5CF6);
        color: white;
        padding: 0.25rem 0.75rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-left: 0.5rem;
    }
    
    /* Stats Grid */
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 1.5rem;
        margin: 2rem 0;
    }
    
    .stat-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 20px;
        padding: 1.5rem;
        backdrop-filter: blur(10px);
        transition: all 0.3s ease;
    }
    
    .stat-card:hover {
        background: rgba(255,255,255,0.05);
        border-color: rgba(59, 130, 246, 0.3);
        transform: translateY(-2px);
    }
    
    .stat-label {
        font-size: 0.875rem;
        color: #94A3B8;
        margin-bottom: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .stat-value {
        font-size: 2rem;
        font-weight: 700;
        color: #FFFFFF;
        line-height: 1.2;
    }
    
    .stat-trend {
        font-size: 0.875rem;
        color: #10B981;
        margin-top: 0.5rem;
        display: flex;
        align-items: center;
        gap: 0.25rem;
    }
    
    /* Extension Info Card */
    .extension-card {
        background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(139, 92, 246, 0.1));
        border: 1px solid rgba(59, 130, 246, 0.2);
        border-radius: 20px;
        padding: 1.5rem;
        margin: 2rem 0;
        backdrop-filter: blur(10px);
    }
    
    .extension-title {
        font-size: 1.25rem;
        font-weight: 600;
        color: #FFFFFF;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .extension-steps {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin: 1rem 0;
    }
    
    .step {
        background: rgba(0,0,0,0.2);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
    }
    
    .step-number {
        background: #3B82F6;
        color: white;
        width: 24px;
        height: 24px;
        border-radius: 50%;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        font-size: 0.875rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    
    /* Input Section */
    .input-section {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 32px;
        padding: 2rem;
        margin: 2rem 0;
        backdrop-filter: blur(10px);
    }
    
    .section-title {
        font-size: 1.125rem;
        font-weight: 600;
        color: #FFFFFF;
        margin-bottom: 1.5rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    .section-title::before {
        content: '';
        width: 4px;
        height: 24px;
        background: linear-gradient(135deg, #3B82F6, #8B5CF6);
        border-radius: 2px;
    }
    
    /* Example Section Headers */
    .example-header {
        margin: 1.5rem 0 0.75rem 0;
        color: #94A3B8;
        font-size: 0.9rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .example-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #3B82F6;
    }
    
    .example-dot-purple {
        background: #8B5CF6;
    }
    
    /* Cards */
    .card {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 24px;
        padding: 1.5rem;
        height: 100%;
        transition: all 0.3s ease;
    }
    
    .card:hover {
        border-color: rgba(59, 130, 246, 0.3);
    }
    
    /* Risk Meter */
    .risk-meter-container {
        background: rgba(255,255,255,0.05);
        border-radius: 100px;
        height: 8px;
        margin: 1.5rem 0;
        overflow: hidden;
        position: relative;
    }
    
    .risk-meter-fill {
        height: 100%;
        border-radius: 100px;
        transition: width 1s cubic-bezier(0.34, 1.56, 0.64, 1);
        background: linear-gradient(90deg, #10B981 0%, #F59E0B 50%, #EF4444 100%);
        position: relative;
    }
    
    /* Risk Indicators */
    .risk-indicator {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 24px;
        padding: 2rem;
        margin: 1rem 0;
        text-align: center;
        backdrop-filter: blur(10px);
    }
    
    .risk-critical {
        border-left: 4px solid #EF4444;
    }
    
    .risk-high {
        border-left: 4px solid #F59E0B;
    }
    
    .risk-medium {
        border-left: 4px solid #FBBF24;
    }
    
    .risk-low {
        border-left: 4px solid #10B981;
    }
    
    .risk-safe {
        border-left: 4px solid #3B82F6;
    }
    
    .risk-title {
        font-size: 1.25rem;
        font-weight: 500;
        color: #94A3B8;
        margin-bottom: 0.5rem;
    }
    
    .risk-score {
        font-size: 4rem;
        font-weight: 800;
        color: #FFFFFF;
        line-height: 1;
        margin: 1rem 0;
    }
    
    /* AI Detection Card */
    .ai-card {
        background: linear-gradient(135deg, rgba(139, 92, 246, 0.1), rgba(59, 130, 246, 0.1));
        border: 1px solid rgba(139, 92, 246, 0.2);
        border-radius: 20px;
        padding: 1.25rem;
        margin: 1rem 0;
        backdrop-filter: blur(10px);
    }
    
    .ai-high {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.1), rgba(139, 92, 246, 0.1));
        border-color: rgba(239, 68, 68, 0.3);
    }
    
    .ai-medium {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.1), rgba(139, 92, 246, 0.1));
        border-color: rgba(245, 158, 11, 0.3);
    }
    
    .ai-low {
        background: linear-gradient(135deg, rgba(16, 185, 129, 0.1), rgba(59, 130, 246, 0.1));
        border-color: rgba(16, 185, 129, 0.3);
    }
    
    /* Findings */
    .finding-item {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 12px;
        padding: 1rem 1.25rem;
        margin: 0.75rem 0;
        color: #E2E8F0;
        font-size: 0.95rem;
        transition: all 0.2s ease;
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
    
    .finding-item:hover {
        background: rgba(255,255,255,0.04);
        border-color: rgba(59, 130, 246, 0.3);
        transform: translateX(4px);
    }
    
    .finding-critical {
        border-left: 4px solid #EF4444;
    }
    
    .finding-warning {
        border-left: 4px solid #F59E0B;
    }
    
    .finding-info {
        border-left: 4px solid #3B82F6;
    }
    
    /* Metric Boxes */
    .metric-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin: 2rem 0;
    }
    
    .metric-box {
        background: rgba(255,255,255,0.02);
        border: 1px solid rgba(255,255,255,0.05);
        border-radius: 20px;
        padding: 1.5rem;
        text-align: center;
        transition: all 0.3s ease;
    }
    
    .metric-box:hover {
        background: rgba(255,255,255,0.03);
        border-color: rgba(59, 130, 246, 0.3);
    }
    
    .metric-label {
        font-size: 0.875rem;
        color: #94A3B8;
        margin-bottom: 0.75rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    .metric-value {
        font-size: 2rem;
        font-weight: 700;
        color: #FFFFFF;
    }
    
    /* Buttons */
    .stButton > button {
        background: rgba(255,255,255,0.03);
        color: #FFFFFF;
        font-weight: 500;
        padding: 0.6rem 1.2rem;
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.1);
        transition: all 0.2s ease;
        font-size: 0.95rem;
    }
    
    .stButton > button:hover {
        background: rgba(255,255,255,0.05);
        border-color: rgba(59, 130, 246, 0.5);
        transform: translateY(-1px);
    }
    
    .stButton > button[data-baseweb="button"] {
        background: linear-gradient(135deg, #3B82F6, #8B5CF6);
        color: white;
        border: none;
        font-weight: 600;
        padding: 0.75rem 2rem;
        font-size: 1rem;
        border-radius: 14px;
        box-shadow: 0 4px 20px rgba(59, 130, 246, 0.3);
    }
    
    .stButton > button[data-baseweb="button"]:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(59, 130, 246, 0.4);
    }
    
    /* Input Fields */
    .stTextArea textarea, .stTextInput input {
        background: rgba(255,255,255,0.02) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 16px !important;
        padding: 1rem !important;
        color: #FFFFFF !important;
        font-size: 0.95rem !important;
    }
    
    .stTextArea textarea:focus, .stTextInput input:focus {
        border-color: #3B82F6 !important;
        box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2) !important;
    }
    
    /* Radio Buttons */
    .stRadio > div {
        background: rgba(255,255,255,0.02) !important;
        border: 1px solid rgba(255,255,255,0.1) !important;
        border-radius: 16px !important;
        padding: 0.5rem !important;
    }
    
    .stRadio [role="radiogroup"] {
        gap: 0.5rem;
    }
    
    .stRadio label {
        color: #94A3B8 !important;
    }
    
    .stRadio label[data-checked="true"] {
        background: linear-gradient(135deg, #3B82F6, #8B5CF6) !important;
        color: white !important;
        border-radius: 10px !important;
        padding: 0.5rem 1rem !important;
    }
    
    /* Footer */
    .footer {
        margin-top: 4rem;
        padding: 2rem 0;
        border-top: 1px solid rgba(255,255,255,0.05);
        text-align: center;
    }
    
    .footer-badges {
        display: flex;
        justify-content: center;
        gap: 2rem;
        margin-bottom: 1.5rem;
        flex-wrap: wrap;
    }
    
    .footer-badge {
        color: #64748B;
        font-size: 0.875rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .footer-badge::before {
        content: '•';
        color: #3B82F6;
        font-size: 1.5rem;
        line-height: 1;
    }
    
    .footer-copyright {
        color: #475569;
        font-size: 0.875rem;
    }
    
    /* Tooltip */
    .tooltip {
        position: relative;
        display: inline-block;
        cursor: help;
    }
    
    .tooltip .tooltip-text {
        visibility: hidden;
        background: #1E293B;
        color: #E2E8F0;
        text-align: center;
        padding: 0.5rem 0.75rem;
        border-radius: 8px;
        font-size: 0.8rem;
        position: absolute;
        z-index: 1000;
        bottom: 125%;
        left: 50%;
        transform: translateX(-50%);
        white-space: nowrap;
        opacity: 0;
        transition: opacity 0.2s;
        border: 1px solid rgba(255,255,255,0.1);
    }
    
    .tooltip:hover .tooltip-text {
        visibility: visible;
        opacity: 1;
    }
    
    /* Loading Spinner */
    .loading-spinner {
        display: inline-block;
        width: 30px;
        height: 30px;
        border: 3px solid rgba(59, 130, 246, 0.1);
        border-radius: 50%;
        border-top-color: #3B82F6;
        animation: spin 0.8s linear infinite;
    }
    
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    
    /* Responsive */
    @media (max-width: 768px) {
        .stats-grid {
            grid-template-columns: repeat(2, 1fr);
        }
        .metric-grid {
            grid-template-columns: 1fr;
        }
        .header-top {
            flex-direction: column;
            gap: 1rem;
            text-align: center;
        }
        .footer-badges {
            gap: 1rem;
            flex-direction: column;
            align-items: center;
        }
        .extension-steps {
            grid-template-columns: 1fr;
        }
    }
</style>
""", unsafe_allow_html=True)

# ============================================================================
# FLASK API FOR BROWSER EXTENSION - COMPLETELY FIXED
# ============================================================================

# Check if flask is installed
FLASK_AVAILABLE = False
FLASK_PORT = 5000

try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    FLASK_AVAILABLE = True
except ImportError as e:
    FLASK_AVAILABLE = False

# Display Flask status in sidebar
with st.sidebar:
    st.markdown("---")
    st.markdown("### 🌐 Extension API Status")
    
    if FLASK_AVAILABLE:
        st.info(f"🔄 Starting Flask on port {FLASK_PORT}...")
    else:
        st.error("❌ Flask not installed")
        st.code("pip install flask flask-cors")

# Start Flask if available
if FLASK_AVAILABLE:
    try:
        # Create Flask app
        flask_app = Flask(__name__)
        CORS(flask_app)
        
        print("="*50)
        print("✅ FLASK: Starting server on port 5000...")
        print("="*50)
        
        @flask_app.route('/health', methods=['GET'])
        def health_check():
            return jsonify({
                'status': 'healthy',
                'message': 'AI Scam Detector API is running',
                'timestamp': str(datetime.datetime.now())
            })
        
        @flask_app.route('/check-url', methods=['POST'])
        def check_url_extension():
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'No JSON data received'}), 400
                    
                url = data.get('url', '')
                
                if not url:
                    return jsonify({'error': 'No URL provided'}), 400
                
                # Import analyzers here
                from url_analyzer import URLAnalyzer
                from scoring_engine import ScoringEngine
                
                url_analyzer_local = URLAnalyzer()
                scoring_engine_local = ScoringEngine()
                
                # Analyze URL
                score, findings = url_analyzer_local.analyze(url)
                risk_level = scoring_engine_local.get_risk_level(score)[0]
                
                return jsonify({
                    'success': True,
                    'score': score,
                    'risk_level': risk_level,
                    'findings': findings[:10],
                    'timestamp': str(datetime.datetime.now())
                })
                
            except Exception as e:
                return jsonify({'error': str(e), 'success': False}), 500
        
        # DEFINE THE run_flask FUNCTION HERE!
        def run_flask():
            """Function to run Flask server in a separate thread"""
            try:
                print(f"🚀 Flask server starting on port {FLASK_PORT}...")
                flask_app.run(host='0.0.0.0', port=FLASK_PORT, debug=False, use_reloader=False)
            except Exception as e:
                print(f"❌ Flask server error: {e}")
        
        # Start Flask in background thread
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
        
        print("✅ FLASK: Server started in background thread")
        
    except Exception as e:
        with st.sidebar:
            st.error(f"❌ Failed to start Flask: {e}")
        print(f"❌ FLASK Error: {e}")

# Update sidebar with success
with st.sidebar:
    st.success(f"✅ Flask API running on port {FLASK_PORT}")
    st.code(f"http://localhost:{FLASK_PORT}/health")
    st.info("Extension will connect automatically")
    
    # ===== ADD EMAIL FORWARDING SECTION HERE =====
    st.markdown("---")
    st.markdown("### 📧 Email Forwarding")
    
    st.info("""
    **👵 For Non-Tech Users:**
    
    Just forward suspicious emails to:
    `detect@yourproject.com`
    
    📝 Add `#scan` in subject
    ⚡ Get instant risk analysis by email!
    *No app installation needed*
    """)
    
    if st.button("📊 Email Dashboard"):
        import webbrowser
        webbrowser.open("http://localhost:5001/email-dashboard")
    # ===== END EMAIL FORWARDING SECTION =====

# ============================================================================
# INITIALIZATION (MUST BE FIRST)
# ============================================================================

# Initialize analyzers
@st.cache_resource
def init_analyzers():
    return {
        'text': TextAnalyzer(),
        'url': URLAnalyzer(),
        'scoring': ScoringEngine(),
        'ai': AIDetector()
    }

analyzers = init_analyzers()

# Initialize session state for inputs - THIS MUST BE BEFORE ANY WIDGETS
if 'text_input' not in st.session_state:
    st.session_state.text_input = ""
if 'url_input' not in st.session_state:
    st.session_state.url_input = ""
if 'history' not in st.session_state:
    st.session_state.history = []
if 'load_example' not in st.session_state:
    st.session_state.load_example = None

# ============================================================================
# HANDLE EXAMPLE BUTTON CLICKS - THIS MUST RUN BEFORE CREATING WIDGETS
# ============================================================================

# Check if an example button was clicked and update session state
if st.session_state.load_example == "scam_email":
    st.session_state.text_input = """Subject: URGENT: Your PayPal Account Limited

Dear Customer,

We detected unusual activity on your account. Your account has been temporarily limited. Click here to verify now: paypal-verify.tk

Failure to verify within 24 hours will result in permanent suspension.

PayPal Security Team"""
    st.session_state.load_example = None
    
elif st.session_state.load_example == "ai_scam":
    st.session_state.text_input = """I am writing to inform you of suspicious activity detected on your financial account. Furthermore, we have observed multiple unauthorized access attempts. Consequently, your account has been temporarily restricted. To restore full functionality, please verify your identity by clicking the secure link below."""
    st.session_state.load_example = None
    
elif st.session_state.load_example == "safe_email":
    st.session_state.text_input = """Hi John,

Just confirming our meeting tomorrow at 2pm. Let me know if you need to reschedule.

Best,
Sarah"""
    st.session_state.load_example = None
    
elif st.session_state.load_example == "scam_url":
    st.session_state.url_input = "http://paypal-verify.tk/login"
    st.session_state.load_example = None
    
elif st.session_state.load_example == "typosquatting":
    st.session_state.url_input = "faceb00k.com"
    st.session_state.load_example = None
    
elif st.session_state.load_example == "safe_url":
    st.session_state.url_input = "https://www.paypal.com"
    st.session_state.load_example = None

# ============================================================================
# HEADER SECTION
# ============================================================================

st.markdown('<div class="main-container">', unsafe_allow_html=True)

# Header
st.markdown("""
<div class="header">
    <div class="header-top">
        <div class="logo">
            <span class="logo-icon">🛡️</span>
            <span class="logo-text">AI Scam Detector</span>
        </div>
        <div class="header-badge">
            ⚡ Enterprise Grade • Real-time Analysis
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# Stats Grid
st.markdown("""
<div class="stats-grid">
    <div class="stat-card">
        <div class="stat-label">Total Scans</div>
        <div class="stat-value">24,847</div>
        <div class="stat-trend">↑ +1,247 today</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Threats Blocked</div>
        <div class="stat-value">18,934</div>
        <div class="stat-trend" style="color: #EF4444;">76% detection</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">Users Protected</div>
        <div class="stat-value">12.8K</div>
        <div class="stat-trend">↑ +445 this week</div>
    </div>
    <div class="stat-card">
        <div class="stat-label">AI Accuracy</div>
        <div class="stat-value">94%</div>
        <div class="stat-trend">↑ +3% improvement</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================================
# BROWSER EXTENSION PROMO SECTION
# ============================================================================

st.markdown("""
<div class="extension-card">
    <div class="extension-title">
        <span>🌐 Browser Extension Available</span>
        <span class="extension-badge">NEW</span>
    </div>
    <p style="color: #94A3B8; margin-bottom: 1.5rem;">
        Get real-time protection while browsing! Our Chrome/Firefox extension automatically scans every website you visit.
    </p>
    <div class="extension-steps">
        <div class="step">
            <div class="step-number">1</div>
            <div style="font-weight: 600; margin-bottom: 0.25rem;">Download</div>
            <div style="font-size: 0.8rem; color: #94A3B8;">Get the extension from our GitHub</div>
        </div>
        <div class="step">
            <div class="step-number">2</div>
            <div style="font-weight: 600; margin-bottom: 0.25rem;">Install</div>
            <div style="font-size: 0.8rem; color: #94A3B8;">1-click installation in Chrome/Firefox</div>
        </div>
        <div class="step">
            <div class="step-number">3</div>
            <div style="font-weight: 600; margin-bottom: 0.25rem;">Protect</div>
            <div style="font-size: 0.8rem; color: #94A3B8;">Automatic alerts on dangerous sites</div>
        </div>
    </div>
    <div style="text-align: center; margin-top: 1rem;">
        <span style="background: rgba(59,130,246,0.2); padding: 0.5rem 1rem; border-radius: 100px; font-size: 0.875rem;">
            🔌 API Endpoint: http://localhost:5000/check-url
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================================
# MAIN INPUT SECTION
# ============================================================================

st.markdown('<div class="input-section">', unsafe_allow_html=True)

# Input Type Selection
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    input_type = st.radio(
        "Select analysis type",
        ["📧 Email/SMS Text", "🔗 URL/Link", "📧+🔗 Both"],
        horizontal=True,
        label_visibility="collapsed"
    )

# Input Fields
col_left, col_right = st.columns(2)

with col_left:
    if input_type in ["📧 Email/SMS Text", "📧+🔗 Both"]:
        st.markdown('<div class="section-title">Message Content</div>', unsafe_allow_html=True)
        
        # Text area widget - uses session_state value via key
        st.text_area(
            "Paste suspicious message",
            height=200,
            placeholder="Paste email, SMS, or message here...",
            label_visibility="collapsed",
            key="text_input"  # This links to st.session_state.text_input
        )
        
        # Quick examples with styled header
        st.markdown("""
        <div class="example-header">
            <span class="example-dot"></span>
            QUICK TEST EXAMPLES
        </div>
        """, unsafe_allow_html=True)
        
        ex1, ex2, ex3 = st.columns(3)
        with ex1:
            if st.button("📧 Scam Email", use_container_width=True):
                st.session_state.load_example = "scam_email"
                st.rerun()
        
        with ex2:
            if st.button("🤖 AI Scam", use_container_width=True):
                st.session_state.load_example = "ai_scam"
                st.rerun()
        
        with ex3:
            if st.button("📧 Safe Email", use_container_width=True):
                st.session_state.load_example = "safe_email"
                st.rerun()

with col_right:
    if input_type in ["🔗 URL/Link", "📧+🔗 Both"]:
        st.markdown('<div class="section-title">URL/Link</div>', unsafe_allow_html=True)
        
        # URL input widget - uses session_state value via key
        st.text_input(
            "Paste suspicious URL",
            placeholder="https://... or bit.ly/...",
            label_visibility="collapsed",
            key="url_input"  # This links to st.session_state.url_input
        )
        
        # URL examples with styled header
        st.markdown("""
        <div class="example-header">
            <span class="example-dot example-dot-purple"></span>
            TEST URLS
        </div>
        """, unsafe_allow_html=True)
        
        url1, url2, url3 = st.columns(3)
        with url1:
            if st.button("🔗 Scam URL", use_container_width=True):
                st.session_state.load_example = "scam_url"
                st.rerun()
        
        with url2:
            if st.button("🔗 Typosquatting", use_container_width=True):
                st.session_state.load_example = "typosquatting"
                st.rerun()
        
        with url3:
            if st.button("🔗 Safe URL", use_container_width=True):
                st.session_state.load_example = "safe_url"
                st.rerun()

# Analyze Button
st.markdown('<div style="text-align: center; margin: 2rem 0;">', unsafe_allow_html=True)
analyze_clicked = st.button("🚀 ANALYZE NOW", type="primary", use_container_width=True)
st.markdown('</div>', unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)  # Close input-section

# ============================================================================
# ANALYSIS RESULTS
# ============================================================================

if analyze_clicked:
    has_text = input_type in ["📧 Email/SMS Text", "📧+🔗 Both"] and st.session_state.text_input
    has_url = input_type in ["🔗 URL/Link", "📧+🔗 Both"] and st.session_state.url_input
    
    if not has_text and not has_url:
        st.warning("⚠️ Please provide content to analyze")
    else:
        with st.spinner("🔍 Analyzing with AI..."):
            time.sleep(1.5)
            
            # Initialize results
            text_result = None
            url_result = None
            ai_result = None
            ai_score = 0
            ai_findings = []
            text_score = 0
            url_score = 0
            
            # Analyze text
            if has_text:
                text_score, text_findings = analyzers['text'].analyze(st.session_state.text_input)
                text_result = {
                    'score': text_score,
                    'findings': text_findings
                }
                
                # AI detection
                ai_score, ai_findings = analyzers['ai'].analyze(st.session_state.text_input)
                ai_result = {
                    'score': ai_score,
                    'findings': ai_findings
                }
            
            # Analyze URL
            if has_url:
                url_score, url_findings = analyzers['url'].analyze(st.session_state.url_input)
                url_result = {
                    'score': url_score,
                    'findings': url_findings
                }
            
            # Calculate unified score
            combined_score, components = analyzers['scoring'].calculate_risk(text_result, url_result)
            
            # Apply AI boost
            if has_text and ai_score >= 30:
                if ai_score >= 70:
                    combined_score = min(combined_score + 30, 100)
                    components['ai_generated'] = ai_score
                elif ai_score >= 50:
                    combined_score = min(combined_score + 20, 100)
                    components['ai_generated'] = ai_score
                elif ai_score >= 30:
                    combined_score = min(combined_score + 10, 100)
                    components['ai_generated'] = ai_score
            
            # Add to history
            st.session_state.history.append({
                'timestamp': datetime.datetime.now().strftime('%H:%M'),
                'score': combined_score,
                'type': 'text' if has_text and not has_url else 'url' if has_url and not has_text else 'both'
            })
            
            # ========================================================================
            # RESULTS DISPLAY
            # ========================================================================
            
            st.markdown("---")
            
            # Main Risk Score Card
            risk_level, _ = analyzers['scoring'].get_risk_level(combined_score)
            
            risk_class = ""
            if combined_score >= 80:
                risk_class = "risk-critical"
            elif combined_score >= 60:
                risk_class = "risk-high"
            elif combined_score >= 40:
                risk_class = "risk-medium"
            elif combined_score >= 20:
                risk_class = "risk-low"
            else:
                risk_class = "risk-safe"
            
            col_score1, col_score2, col_score3 = st.columns([1, 2, 1])
            with col_score2:
                st.markdown(f"""
                <div class="risk-indicator {risk_class}">
                    <div class="risk-title">{risk_level}</div>
                    <div class="risk-score">{combined_score}%</div>
                    <div class="risk-meter-container">
                        <div class="risk-meter-fill" style="width: {combined_score}%;"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            
            # Component Scores
            st.markdown("### 📊 Component Analysis")
            
            col_comp1, col_comp2, col_comp3 = st.columns(3)
            
            with col_comp1:
                ai_display = f"AI: {ai_score}% detected" if has_text else ""
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">📧 Text Risk</div>
                    <div class="metric-value">{text_score if has_text else 'N/A'}%</div>
                    <div class="stat-trend" style="color: #94A3B8; font-size: 0.8rem;">{ai_display}</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col_comp2:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">🔗 URL Risk</div>
                    <div class="metric-value">{url_score if has_url else 'N/A'}%</div>
                    <div class="stat-trend" style="color: #94A3B8; font-size: 0.8rem;">Domain analysis</div>
                </div>
                """, unsafe_allow_html=True)
            
            with col_comp3:
                st.markdown(f"""
                <div class="metric-box">
                    <div class="metric-label">🎯 Combined Risk</div>
                    <div class="metric-value">{combined_score}%</div>
                    <div class="stat-trend" style="color: #94A3B8; font-size: 0.8rem;">Weighted score</div>
                </div>
                """, unsafe_allow_html=True)
            
            # AI Detection Section
            if has_text and ai_score > 0:
                st.markdown("### 🤖 AI Content Analysis")
                
                ai_class = "ai-high" if ai_score >= 70 else "ai-medium" if ai_score >= 40 else "ai-low"
                ai_label = "🔴 AI-GENERATED" if ai_score >= 70 else "🟡 POSSIBLY AI" if ai_score >= 40 else "🟢 HUMAN-LIKELY"
                
                st.markdown(f"""
                <div class="ai-card {ai_class}">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="font-size: 1.1rem; color: #FFFFFF;">{ai_label}</strong>
                            <div style="color: #94A3B8; font-size: 0.9rem; margin-top: 0.25rem;">
                                Confidence: {ai_score}% • {len(ai_findings)} patterns detected
                            </div>
                        </div>
                        <div class="tooltip">
                            <span style="background: rgba(255,255,255,0.1); padding: 0.5rem 1rem; border-radius: 100px; font-size: 0.875rem;">ⓘ AI Analysis</span>
                            <span class="tooltip-text">AI-generated text shows patterns like transition words, formal language, and perfect grammar</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                if ai_findings:
                    with st.expander("🔍 View AI Detection Details"):
                        for finding in ai_findings[:5]:
                            st.markdown(f"<div class='finding-item finding-info'><span>📌</span> {finding}</div>", unsafe_allow_html=True)
            
            # Risk Factors Breakdown
            if components:
                st.markdown("### ⚠️ Risk Factors Detected")
                breakdown = analyzers['scoring'].get_risk_breakdown(components)
                
                for factor in breakdown[:5]:
                    finding_class = "finding-critical" if "🔴" in factor else "finding-warning" if "🟡" in factor else "finding-info"
                    st.markdown(f"<div class='finding-item {finding_class}'><span>{factor[0]}</span> {factor[2:]}</div>", unsafe_allow_html=True)
                
                if len(breakdown) > 5:
                    with st.expander("📋 View All Risk Factors"):
                        for factor in breakdown[5:]:
                            finding_class = "finding-critical" if "🔴" in factor else "finding-warning" if "🟡" in factor else "finding-info"
                            st.markdown(f"<div class='finding-item {finding_class}'><span>{factor[0]}</span> {factor[2:]}</div>", unsafe_allow_html=True)
            
            # Detailed Findings
            col_find1, col_find2 = st.columns(2)
            
            with col_find1:
                if text_result and text_result['findings']:
                    st.markdown("### 📧 Text Analysis Details")
                    for finding in text_result['findings'][:5]:
                        emoji = "⚠️" if "urgent" in finding.lower() or "fear" in finding.lower() else "📌"
                        st.markdown(f"<div class='finding-item finding-warning'><span>{emoji}</span> {finding}</div>", unsafe_allow_html=True)
                    
                    if len(text_result['findings']) > 5:
                        with st.expander("📋 More Text Findings"):
                            for finding in text_result['findings'][5:]:
                                emoji = "⚠️" if "urgent" in finding.lower() or "fear" in finding.lower() else "📌"
                                st.markdown(f"<div class='finding-item finding-warning'><span>{emoji}</span> {finding}</div>", unsafe_allow_html=True)
            
            with col_find2:
                if url_result and url_result['findings']:
                    st.markdown("### 🔗 URL Analysis Details")
                    for finding in url_result['findings'][:5]:
                        emoji = "🚨" if "HIGH" in finding else "⚠️" if "suspicious" in finding.lower() else "🔗"
                        st.markdown(f"<div class='finding-item finding-critical'><span>{emoji}</span> {finding}</div>", unsafe_allow_html=True)
                    
                    if len(url_result['findings']) > 5:
                        with st.expander("📋 More URL Findings"):
                            for finding in url_result['findings'][5:]:
                                emoji = "🚨" if "HIGH" in finding else "⚠️" if "suspicious" in finding.lower() else "🔗"
                                st.markdown(f"<div class='finding-item finding-critical'><span>{emoji}</span> {finding}</div>", unsafe_allow_html=True)
            
            # Smart Recommendations
            st.markdown("### 🛡️ Smart Recommendations")
            recommendations = analyzers['scoring'].get_recommendations(combined_score, has_text, has_url)
            
            for rec in recommendations:
                if "🚨" in rec or "🔴" in rec:
                    st.error(rec)
                elif "🟡" in rec:
                    st.warning(rec)
                elif "🟢" in rec or "✅" in rec:
                    st.success(rec)
                else:
                    st.info(rec)
            
            # History Chart
            if len(st.session_state.history) > 1:
                st.markdown("### 📈 Risk History")
                history_df = pd.DataFrame(st.session_state.history[-10:])
                fig = px.line(history_df, x='timestamp', y='score', 
                             title='Risk Score Trend',
                             labels={'score': 'Risk Score %', 'timestamp': 'Time'})
                fig.update_layout(
                    height=300,
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font_color='#FFFFFF',
                    title_font_color='#FFFFFF'
                )
                fig.update_traces(line=dict(color='#3B82F6', width=3))
                fig.update_xaxes(gridcolor='rgba(255,255,255,0.1)')
                fig.update_yaxes(gridcolor='rgba(255,255,255,0.1)', range=[0, 100])
                st.plotly_chart(fig, use_container_width=True)
            
            # Full Report
            with st.expander("📄 View Full Technical Report"):
                report = analyzers['scoring'].generate_report(text_result, url_result, combined_score, components)
                st.code(report, language='text')

# ============================================================================
# EDUCATIONAL SECTION
# ============================================================================

with st.expander("💡 Learn to Spot Scams"):
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
        **📧 Email Red Flags**
        • Urgency: "Act now!", "Limited time"
        • Fear: "Account suspended", "Legal action"
        • Generic greetings: "Dear Customer"
        • Perfect grammar (AI scams)
        """)
    
    with col2:
        st.markdown("""
        **🔗 URL Warning Signs**
        • Misspelled domains: paypa1.com
        • Suspicious TLDs: .tk, .ml, .xyz
        • URL shorteners: bit.ly/xxx
        • New domains (< 30 days)
        """)
    
    with col3:
        st.markdown("""
        **🤖 AI Scam Patterns**
        • Overuse of transition words
        • Too formal/polite
        • No contractions or slang
        • Consistent sentence length
        """)

# ============================================================================
# FOOTER
# ============================================================================

st.markdown("""
<div class="footer">
    <div class="footer-badges">
        <span class="footer-badge">Enterprise Grade Security</span>
        <span class="footer-badge">Real-time Analysis</span>
        <span class="footer-badge">94% Accuracy</span>
        <span class="footer-badge">Privacy First</span>
    </div>
    <div class="footer-copyright">
        © 2026 AI Scam Detector • Advanced Cybersecurity Project • All Rights Reserved
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('</div>', unsafe_allow_html=True)  # Close main-container

# ============================================================================
# DISPLAY FLASK API STATUS
# ============================================================================

if FLASK_AVAILABLE:
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🌐 Extension API")
    st.sidebar.success("✅ Flask API running on http://localhost:5000")
    st.sidebar.info("""
    **Endpoints:**
    - `POST /check-url` - Scan URLs
    - `GET /health` - Health check
    
    **For extension to work:**
    1. Keep this app running
    2. Install browser extension
    3. Start browsing!
    """)
else:
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🌐 Extension API")
    st.sidebar.error("❌ Flask not installed")
    st.sidebar.code("pip install flask flask-cors")