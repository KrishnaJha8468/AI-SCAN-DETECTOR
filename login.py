# login.py - Enhanced authentication with security improvements
import streamlit as st
import os
import time
from datetime import datetime, timedelta

# ===== SECURITY IMPROVEMENTS =====
# 1. Use environment variables (or fallback to defaults)
VALID_USERNAME = os.environ.get("APP_USERNAME", "admin")
VALID_PASSWORD = os.environ.get("APP_PASSWORD", "scamdetector2026")

# 2. Multiple users support
VALID_USERS = {
    "admin": "scamdetector2026",
    "krishna": "aiscamdetector",
    "teacher": "demo2026",
    "judge": "presentation2026"
}

# 3. Session timeout (30 minutes)
SESSION_TIMEOUT = 30 * 60  # 30 minutes in seconds

def check_password():
    """Enhanced login with security features"""
    
    # Check if already authenticated and session not expired
    if st.session_state.get("authenticated", False):
        # Check session timeout
        last_active = st.session_state.get("last_active", datetime.now())
        if datetime.now() - last_active < timedelta(seconds=SESSION_TIMEOUT):
            # Update last active time
            st.session_state["last_active"] = datetime.now()
            return True
        else:
            # Session expired
            st.session_state["authenticated"] = False
            st.warning("⏰ Session expired. Please login again.")
    
    # Create login form with spinner
    with st.form("login_form"):
        st.markdown("### 🔐 Login to AI Scam Detector")
        
        # Add some spacing
        st.markdown("---")
        
        # Username and password fields
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        
        # Submit button
        submitted = st.form_submit_button("Login", use_container_width=True)
        
        if submitted:
            # Show loading spinner
            with st.spinner("🔐 Verifying credentials..."):
                time.sleep(1)  # Simulate verification delay
                
                # Check against multiple users
                if username in VALID_USERS and password == VALID_USERS[username]:
                    st.session_state["authenticated"] = True
                    st.session_state["username"] = username
                    st.session_state["login_time"] = datetime.now()
                    st.session_state["last_active"] = datetime.now()
                    st.rerun()
                else:
                    st.error("❌ Invalid username or password")
    
    # Show helpful message
    #st.markdown("---")
   # st.caption("💡 Default credentials: admin / scamdetector2026")
    
  #  return False

def logout():
    """Logout function"""
    if st.button("🚪 Logout"):
        for key in ["authenticated", "username", "login_time", "last_active"]:
            if key in st.session_state:
                del st.session_state[key]
        st.rerun()

def get_current_user():
    """Get current logged in username"""
    return st.session_state.get("username", "Unknown")