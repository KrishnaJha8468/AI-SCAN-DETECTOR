# alert_network.py - Community-Powered Scam Alert Network

from flask import Flask, request, jsonify, render_template
import sqlite3
import datetime
import hashlib
import json
import os
import threading
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__, template_folder='templates', static_folder='static')

# Database setup
DATABASE = 'alert_network.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE,
                  phone TEXT,
                  whatsapp TEXT,
                  location TEXT,
                  verified BOOLEAN DEFAULT 0,
                  join_date DATETIME,
                  reputation INTEGER DEFAULT 0)''')
    
    # Scam reports table
    c.execute('''CREATE TABLE IF NOT EXISTS reports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  scam_type TEXT,
                  content TEXT,
                  url TEXT,
                  phone_number TEXT,
                  email_sender TEXT,
                  description TEXT,
                  risk_score INTEGER,
                  timestamp DATETIME,
                  location TEXT,
                  verified BOOLEAN DEFAULT 0,
                  votes INTEGER DEFAULT 0,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Alerts table
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  report_id INTEGER,
                  title TEXT,
                  message TEXT,
                  severity TEXT,
                  affected_regions TEXT,
                  timestamp DATETIME,
                  active BOOLEAN DEFAULT 1,
                  FOREIGN KEY (report_id) REFERENCES reports (id))''')
    
    # User votes table
    c.execute('''CREATE TABLE IF NOT EXISTS votes
                 (user_id INTEGER,
                  report_id INTEGER,
                  vote_type TEXT,
                  timestamp DATETIME,
                  PRIMARY KEY (user_id, report_id))''')
    
    # Scam patterns database
    c.execute('''CREATE TABLE IF NOT EXISTS patterns
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  pattern TEXT,
                  pattern_type TEXT,
                  severity TEXT,
                  occurrences INTEGER DEFAULT 1,
                  first_seen DATETIME,
                  last_seen DATETIME)''')
    
    conn.commit()
    conn.close()
    print("✅ Alert Network Database initialized")

init_db()

# ============================================================================
# USER MANAGEMENT
# ============================================================================

def register_user(email, phone=None, whatsapp=None, location=None):
    """Register a new user in the network"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    try:
        c.execute('''INSERT INTO users 
                     (email, phone, whatsapp, location, join_date, reputation)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (email, phone, whatsapp, location, datetime.datetime.now(), 0))
        conn.commit()
        user_id = c.lastrowid
        print(f"✅ New user registered: {email} (ID: {user_id})")
        return user_id
    except sqlite3.IntegrityError:
        # User already exists
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        user_id = c.fetchone()[0]
        return user_id
    finally:
        conn.close()

def get_user_reputation(user_id):
    """Get user reputation score"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT reputation FROM users WHERE id = ?', (user_id,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else 0

def update_reputation(user_id, change):
    """Update user reputation"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('UPDATE users SET reputation = reputation + ? WHERE id = ?', (change, user_id))
    conn.commit()
    conn.close()

# ============================================================================
# SCAM REPORTING
# ============================================================================

def report_scam(user_id, scam_data):
    """Submit a new scam report"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Extract data
    scam_type = scam_data.get('type', 'unknown')
    content = scam_data.get('content', '')
    url = scam_data.get('url', '')
    phone = scam_data.get('phone', '')
    email = scam_data.get('email', '')
    description = scam_data.get('description', '')
    risk_score = scam_data.get('risk_score', 50)
    location = scam_data.get('location', 'unknown')
    
    # Insert report
    c.execute('''INSERT INTO reports 
                 (user_id, scam_type, content, url, phone_number, email_sender, 
                  description, risk_score, timestamp, location, verified, votes)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (user_id, scam_type, content, url, phone, email, description,
               risk_score, datetime.datetime.now(), location, 0, 0))
    
    report_id = c.lastrowid
    conn.commit()
    
    # Check for patterns
    check_patterns(content, url, phone, email)
    
    # If high risk, create alert
    if risk_score >= 70:
        create_alert(report_id, scam_data)
    
    conn.close()
    print(f"🚨 New scam report #{report_id} (Risk: {risk_score}%)")
    return report_id

def check_patterns(content, url, phone, email):
    """Check for recurring scam patterns"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Extract potential patterns
    patterns = []
    
    # URL patterns
    if url:
        domain = url.split('/')[2] if '://' in url else url.split('/')[0]
        patterns.append(('url_domain', domain))
    
    # Phone patterns
    if phone:
        # Normalize phone number
        phone_clean = ''.join(filter(str.isdigit, phone))
        if len(phone_clean) >= 10:
            patterns.append(('phone_prefix', phone_clean[:6]))
    
    # Email patterns
    if email:
        if '@' in email:
            domain = email.split('@')[1]
            patterns.append(('email_domain', domain))
    
    # Content patterns (keywords)
    keywords = ['urgent', 'suspended', 'paypal', 'amazon', 'bank', 'irs', 'lottery']
    for keyword in keywords:
        if keyword in content.lower():
            patterns.append(('keyword', keyword))
    
    # Update patterns database
    now = datetime.datetime.now()
    for pattern_type, pattern in patterns:
        c.execute('''SELECT id, occurrences FROM patterns 
                     WHERE pattern = ? AND pattern_type = ?''', (pattern, pattern_type))
        result = c.fetchone()
        
        if result:
            # Update existing pattern
            c.execute('''UPDATE patterns 
                         SET occurrences = occurrences + 1, last_seen = ?
                         WHERE id = ?''', (now, result[0]))
        else:
            # New pattern
            c.execute('''INSERT INTO patterns 
                         (pattern, pattern_type, severity, occurrences, first_seen, last_seen)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (pattern, pattern_type, 'medium', 1, now, now))
    
    conn.commit()
    conn.close()

def create_alert(report_id, scam_data):
    """Create a community alert for high-risk scams"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Generate alert title and message
    scam_type = scam_data.get('type', 'unknown')
    
    if scam_type == 'url':
        title = f"⚠️ Dangerous URL Detected: {scam_data.get('url', '')}"
        message = f"Multiple users reported this URL as a scam. Risk score: {scam_data.get('risk_score', 0)}%"
    elif scam_type == 'phone':
        title = f"📞 Scam Call Alert: {scam_data.get('phone', '')}"
        message = f"This phone number is being used in scam calls. Do not answer or call back."
    elif scam_type == 'email':
        title = f"📧 Phishing Email Alert: {scam_data.get('email', '')}"
        message = f"Emails from this sender are fraudulent. Do not click any links."
    else:
        title = f"🚨 New Scam Alert: {scam_data.get('title', 'Unknown Scam')}"
        message = scam_data.get('description', 'A new scam has been reported in your area.')
    
    c.execute('''INSERT INTO alerts 
                 (report_id, title, message, severity, affected_regions, timestamp, active)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
              (report_id, title, message, 'high', scam_data.get('location', 'all'),
               datetime.datetime.now(), 1))
    
    alert_id = c.lastrowid
    conn.commit()
    conn.close()
    
    # Notify users
    notify_users(alert_id)
    
    return alert_id

# ============================================================================
# NOTIFICATIONS
# ============================================================================

def notify_users(alert_id):
    """Send notifications to users about new alerts"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Get alert details
    c.execute('''SELECT title, message, severity, affected_regions FROM alerts WHERE id = ?''', (alert_id,))
    alert = c.fetchone()
    
    if not alert:
        return
    
    title, message, severity, region = alert
    
    # Get users to notify
    if region == 'all':
        c.execute('SELECT email, phone, whatsapp FROM users WHERE verified = 1')
    else:
        c.execute('''SELECT email, phone, whatsapp FROM users 
                     WHERE verified = 1 AND location = ?''', (region,))
    
    users = c.fetchall()
    conn.close()
    
    # Send notifications (in background thread)
    for email, phone, whatsapp in users:
        if email:
            thread = threading.Thread(target=send_email_alert, args=(email, title, message))
            thread.daemon = True
            thread.start()
        
        if whatsapp:
            # You can integrate with your WhatsApp bot here
            pass

def send_email_alert(to_email, title, message):
    """Send email alert to user"""
    try:
        # Use your existing email config
        from email_config import EMAIL_SETTINGS
        
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SETTINGS['email_address']
        msg['To'] = to_email
        msg['Subject'] = f"🚨 Scam Alert: {title}"
        
        body = f"""
        🚨 SCAM ALERT
        
        {title}
        
        {message}
        
        Severity: HIGH
        Time: {datetime.datetime.now()}
        
        Stay safe!
        - AI Scam Detector Community Network
        """
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(EMAIL_SETTINGS['smtp_server'], EMAIL_SETTINGS['smtp_port'])
        server.starttls()
        server.login(EMAIL_SETTINGS['email_address'], EMAIL_SETTINGS['email_password'])
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Alert email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

# ============================================================================
# VOTING SYSTEM
# ============================================================================

def vote_report(user_id, report_id, vote_type):
    """Vote on a scam report (upvote/downvote)"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Check if already voted
    c.execute('''SELECT vote_type FROM votes 
                 WHERE user_id = ? AND report_id = ?''', (user_id, report_id))
    existing = c.fetchone()
    
    if existing:
        # Update vote
        old_vote = existing[0]
        c.execute('''UPDATE votes SET vote_type = ?, timestamp = ?
                     WHERE user_id = ? AND report_id = ?''',
                  (vote_type, datetime.datetime.now(), user_id, report_id))
        
        # Update report votes count
        if vote_type == 'up':
            change = 2 if old_vote == 'down' else 1
        else:
            change = -2 if old_vote == 'up' else -1
        
        c.execute('UPDATE reports SET votes = votes + ? WHERE id = ?', (change, report_id))
    else:
        # New vote
        c.execute('''INSERT INTO votes (user_id, report_id, vote_type, timestamp)
                     VALUES (?, ?, ?, ?)''',
                  (user_id, report_id, vote_type, datetime.datetime.now()))
        
        # Update report votes
        change = 1 if vote_type == 'up' else -1
        c.execute('UPDATE reports SET votes = votes + ? WHERE id = ?', (change, report_id))
        
        # Update user reputation
        rep_change = 1 if vote_type == 'up' else -1
        c.execute('UPDATE users SET reputation = reputation + ? WHERE id = ?', (rep_change, user_id))
    
    conn.commit()
    conn.close()
    
    # Check if report should be verified
    check_verification(report_id)

def check_verification(report_id):
    """Auto-verify reports with enough upvotes"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT votes FROM reports WHERE id = ?', (report_id,))
    votes = c.fetchone()[0]
    
    if votes >= 5:
        c.execute('UPDATE reports SET verified = 1 WHERE id = ?', (report_id,))
        print(f"✅ Report #{report_id} verified by community ({votes} votes)")
        
        # If high risk, create alert
        c.execute('SELECT risk_score FROM reports WHERE id = ?', (report_id,))
        risk_score = c.fetchone()[0]
        
        if risk_score >= 70:
            c.execute('''SELECT scam_type, content, url, phone_number, email_sender, description, location 
                         FROM reports WHERE id = ?''', (report_id,))
            report = c.fetchone()
            
            scam_data = {
                'type': report[0],
                'content': report[1],
                'url': report[2],
                'phone': report[3],
                'email': report[4],
                'description': report[5],
                'location': report[6],
                'risk_score': risk_score
            }
            create_alert(report_id, scam_data)
    
    conn.commit()
    conn.close()

# ============================================================================
# API ROUTES
# ============================================================================

@app.route('/')
def index():
    """Alert Network Dashboard"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # Get active alerts
    c.execute('''SELECT id, title, message, severity, timestamp 
                 FROM alerts WHERE active = 1 
                 ORDER BY timestamp DESC LIMIT 10''')
    active_alerts = c.fetchall()
    
    # Get recent reports
    c.execute('''SELECT r.id, u.email, r.scam_type, r.risk_score, r.timestamp, r.votes, r.verified
                 FROM reports r
                 JOIN users u ON r.user_id = u.id
                 ORDER BY r.timestamp DESC LIMIT 20''')
    recent_reports = c.fetchall()
    
    # Get statistics
    c.execute('SELECT COUNT(*) FROM reports')
    total_reports = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM reports WHERE verified = 1')
    verified_reports = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM alerts WHERE active = 1')
    active_alerts_count = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    
    # Get top patterns
    c.execute('''SELECT pattern, pattern_type, occurrences 
                 FROM patterns 
                 ORDER BY occurrences DESC LIMIT 10''')
    top_patterns = c.fetchall()
    
    conn.close()
    
    return render_template('alert_dashboard.html',
                         active_alerts=active_alerts,
                         recent_reports=recent_reports,
                         total_reports=total_reports,
                         verified_reports=verified_reports,
                         active_alerts_count=active_alerts_count,
                         total_users=total_users,
                         top_patterns=top_patterns)

@app.route('/api/report', methods=['POST'])
def api_report():
    """API endpoint to submit scam reports"""
    try:
        data = request.json
        
        # Get or create user
        user_email = data.get('user_email', 'anonymous@reporter.com')
        user_id = register_user(user_email)
        
        # Submit report
        report_id = report_scam(user_id, data)
        
        return jsonify({
            'success': True,
            'report_id': report_id,
            'message': 'Thank you for reporting! Your report helps protect others.'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/vote', methods=['POST'])
def api_vote():
    """API endpoint to vote on reports"""
    try:
        data = request.json
        user_email = data.get('user_email')
        report_id = data.get('report_id')
        vote_type = data.get('vote_type')
        
        if not user_email or not report_id or not vote_type:
            return jsonify({'success': False, 'error': 'Missing data'}), 400
        
        user_id = register_user(user_email)
        vote_report(user_id, report_id, vote_type)
        
        return jsonify({'success': True, 'message': 'Vote recorded'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get active alerts"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    region = request.args.get('region', 'all')
    
    if region == 'all':
        c.execute('''SELECT id, title, message, severity, timestamp 
                     FROM alerts WHERE active = 1 
                     ORDER BY timestamp DESC''')
    else:
        c.execute('''SELECT id, title, message, severity, timestamp 
                     FROM alerts WHERE active = 1 AND affected_regions = ?
                     ORDER BY timestamp DESC''', (region,))
    
    alerts = [{
        'id': row[0],
        'title': row[1],
        'message': row[2],
        'severity': row[3],
        'timestamp': row[4]
    } for row in c.fetchall()]
    
    conn.close()
    return jsonify({'success': True, 'alerts': alerts})

@app.route('/api/patterns', methods=['GET'])
def api_patterns():
    """Get top scam patterns"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('''SELECT pattern, pattern_type, occurrences, last_seen 
                 FROM patterns 
                 ORDER BY occurrences DESC LIMIT 20''')
    
    patterns = [{
        'pattern': row[0],
        'type': row[1],
        'occurrences': row[2],
        'last_seen': row[3]
    } for row in c.fetchall()]
    
    conn.close()
    return jsonify({'success': True, 'patterns': patterns})

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get network statistics"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    c.execute('SELECT COUNT(*) FROM users')
    total_users = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM reports')
    total_reports = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM reports WHERE verified = 1')
    verified_reports = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM alerts WHERE active = 1')
    active_alerts = c.fetchone()[0]
    
    c.execute('SELECT COUNT(*) FROM reports WHERE timestamp > datetime("now", "-24 hours")')
    reports_24h = c.fetchone()[0]
    
    conn.close()
    
    return jsonify({
        'success': True,
        'stats': {
            'total_users': total_users,
            'total_reports': total_reports,
            'verified_reports': verified_reports,
            'active_alerts': active_alerts,
            'reports_last_24h': reports_24h
        }
    })

if __name__ == '__main__':
    print("="*60)
    print("🌐 ALERT NETWORK - Community Scam Detection")
    print("="*60)
    print("✅ Server starting on port 5003...")
    print("🌍 Dashboard: http://localhost:5003")
    print("📊 API: http://localhost:5003/api/stats")
    print("="*60)
    app.run(host='0.0.0.0', port=5003, debug=True)