# email_server.py - Complete Email Forwarding Server with Permanent Duplicate Prevention

import imaplib
import smtplib
import email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header
import time
import sqlite3
import datetime
import re
import os
import sys
from bs4 import BeautifulSoup

# Add parent directory to path to import analyzers
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from text_analyzer import TextAnalyzer
from url_analyzer import URLAnalyzer
from scoring_engine import ScoringEngine
from ai_detector import AIDetector
from email_config import EMAIL_SETTINGS, RESPONSE_TEMPLATES

print("="*60)
print("📧 EMAIL FORWARDING SERVER STARTING...")
print("="*60)

class EmailForwardingServer:
    def __init__(self):
        """Initialize the email forwarding server"""
        self.settings = EMAIL_SETTINGS
        self.templates = RESPONSE_TEMPLATES
        self.processed_file = 'processed_msgs.txt'
        self.processed_uids = set()
        
        # Initialize analyzers
        self.text_analyzer = TextAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.scoring_engine = ScoringEngine()
        self.ai_detector = AIDetector()
        
        # Setup database
        self.setup_database()
        
        # Load previously processed message IDs
        self.load_processed_ids()
        
        print("✅ Email Forwarding Server Initialized")
        print(f"📧 Listening for emails at: {self.settings['email_address']}")
        print(f"📧 Use '#scan' in subject to trigger analysis")
        print(f"📋 Tracking {len(self.processed_uids)} already processed emails")
        print("="*60)
    
    def load_processed_ids(self):
        """Load previously processed message IDs from file"""
        if os.path.exists(self.processed_file):
            try:
                with open(self.processed_file, 'r') as f:
                    self.processed_uids = set(line.strip() for line in f if line.strip())
                print(f"✅ Loaded {len(self.processed_uids)} processed message IDs")
            except Exception as e:
                print(f"⚠️ Could not load processed IDs: {e}")
                self.processed_uids = set()
        else:
            self.processed_uids = set()
    
    def save_processed_id(self, msg_id):
        """Save a processed message ID to file"""
        try:
            with open(self.processed_file, 'a') as f:
                f.write(msg_id + '\n')
            self.processed_uids.add(msg_id)
        except Exception as e:
            print(f"⚠️ Could not save processed ID: {e}")
    
    def setup_database(self):
        """Create database to store scan history"""
        conn = sqlite3.connect(self.settings['database_file'])
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT,
                subject TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                timestamp DATETIME,
                findings TEXT,
                reply_sent BOOLEAN
            )
        ''')
        
        conn.commit()
        conn.close()
        print("✅ Database initialized")
    
    def extract_email_content(self, msg):
        """Extract text content from email"""
        content = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                # Get text content
                if content_type == "text/plain":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        content += payload.decode(charset, errors='ignore')
                    except:
                        continue
                        
                elif content_type == "text/html":
                    try:
                        payload = part.get_payload(decode=True)
                        charset = part.get_content_charset() or 'utf-8'
                        html = payload.decode(charset, errors='ignore')
                        soup = BeautifulSoup(html, 'html.parser')
                        content += soup.get_text()
                    except:
                        continue
        else:
            # Not multipart
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                content = payload.decode(charset, errors='ignore')
            except:
                content = str(msg.get_payload())
        
        return content.strip()
    
    def extract_urls(self, content):
        """Extract URLs from email content"""
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        urls = re.findall(url_pattern, content)
        return list(set(urls))
    
    def analyze_forwarded_email(self, sender, subject, content):
        """Analyze the forwarded email content"""
        print(f"\n🔍 Analyzing email from: {sender}")
        print(f"📝 Subject: {subject}")
        
        # Extract URLs from content
        urls = self.extract_urls(content)
        
        # Initialize results
        text_result = None
        url_result = None
        ai_result = None
        
        # Analyze text content
        text_score, text_findings = self.text_analyzer.analyze(content)
        text_result = {
            'score': text_score,
            'findings': text_findings
        }
        
        # Analyze for AI content
        ai_score, ai_findings = self.ai_detector.analyze(content)
        ai_result = {
            'score': ai_score,
            'findings': ai_findings
        }
        
        # Analyze first URL if present
        url_score = 0
        url_findings = []
        if urls:
            url_score, url_findings = self.url_analyzer.analyze(urls[0])
            url_result = {
                'score': url_score,
                'findings': url_findings
            }
            print(f"🔗 Found URL: {urls[0]}")
        
        # Calculate combined score
        combined_score, components = self.scoring_engine.calculate_risk(text_result, url_result)
        
        # Apply AI boost
        if ai_score >= 30:
            if ai_score >= 70:
                combined_score = min(combined_score + 30, 100)
                components['ai_generated'] = ai_score
            elif ai_score >= 50:
                combined_score = min(combined_score + 20, 100)
                components['ai_generated'] = ai_score
            elif ai_score >= 30:
                combined_score = min(combined_score + 10, 100)
                components['ai_generated'] = ai_score
        
        # Get risk level
        risk_level, _ = self.scoring_engine.get_risk_level(combined_score)
        
        # Prepare findings summary
        all_findings = []
        if text_findings:
            all_findings.extend(text_findings[:3])
        if url_findings:
            all_findings.extend(url_findings[:2])
        if ai_findings and ai_score >= 40:
            all_findings.append(f"🤖 AI Detection: {ai_score}%")
        
        findings_text = "\n".join([f"• {f}" for f in all_findings[:5]])
        
        # Store in database
        self.save_scan_result(sender, subject, combined_score, risk_level, findings_text)
        
        return {
            'score': combined_score,
            'risk_level': risk_level,
            'findings': findings_text,
            'has_url': len(urls) > 0,
            'url_count': len(urls),
            'ai_score': ai_score,
            'timestamp': datetime.datetime.now().isoformat()
        }
    
    def save_scan_result(self, sender, subject, score, risk_level, findings):
        """Save scan result to database"""
        conn = sqlite3.connect(self.settings['database_file'])
        cursor = conn.cursor()
        
        # Fix for DeprecationWarning - use ISO format string instead of datetime object
        timestamp = datetime.datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO scans (sender_email, subject, risk_score, risk_level, timestamp, findings, reply_sent)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            sender,
            subject[:100],
            score,
            risk_level,
            timestamp,  # Use string instead of datetime object
            findings,
            False
        ))
        
        conn.commit()
        conn.close()
    
    def generate_reply(self, result):
        """Generate reply email based on risk score"""
        score = result['score']
        findings = result['findings']
        
        if score >= 70:
            template = self.templates['high_risk']
        elif score >= 40:
            template = self.templates['medium_risk']
        else:
            template = self.templates['low_risk']
        
        return template.format(score=score, findings=findings)
    
    def send_reply(self, to_address, original_subject, reply_body):
        """Send reply email"""
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.settings['email_address']
            msg['To'] = to_address
            msg['Subject'] = f"Re: {original_subject} [Scam Analysis]"
            
            # Add body
            msg.attach(MIMEText(reply_body, 'plain'))
            
            # Send via SMTP
            server = smtplib.SMTP(self.settings['smtp_server'], self.settings['smtp_port'])
            server.starttls()
            server.login(self.settings['email_address'], self.settings['email_password'])
            server.send_message(msg)
            server.quit()
            
            print(f"✅ Reply sent to: {to_address}")
            return True
            
        except Exception as e:
            print(f"❌ Failed to send reply: {e}")
            return False
    
    def process_folder(self, imap, folder_name):
        """Process a single folder for emails"""
        try:
            imap.select(folder_name)
            print(f"📁 Checking folder: {folder_name}")
            
            search_criteria = f'(SUBJECT "{self.settings["scan_prefix"]}")'
            result, data = imap.search(None, search_criteria)
            
            if result != 'OK' or not data[0]:
                return 0
            
            processed_count = 0
            for num in data[0].split():
                # Get unique message ID
                result, msg_data = imap.fetch(num, '(BODY[HEADER.FIELDS (MESSAGE-ID)])')
                if result == 'OK' and msg_data[0]:
                    msg_id = msg_data[0][1].decode('utf-8', errors='ignore').strip()
                else:
                    msg_id = str(num)
                
                # Skip if already processed
                if msg_id in self.processed_uids:
                    print(f"⏭️ Skipping already processed: {msg_id[:30]}...")
                    continue
                
                # Fetch full email
                result, email_data = imap.fetch(num, '(RFC822)')
                if result != 'OK':
                    continue
                    
                raw_email = email_data[0][1]
                msg = email.message_from_bytes(raw_email)
                
                # Extract sender
                from_header = msg.get('From', '')
                sender_match = re.search(r'<(.+?)>', from_header)
                sender_email = sender_match.group(1) if sender_match else from_header
                
                # Extract subject
                subject = msg.get('Subject', 'No Subject')
                
                # Extract content
                content = self.extract_email_content(msg)
                
                if content:
                    # Analyze the email
                    result = self.analyze_forwarded_email(sender_email, subject, content)
                    
                    # Generate and send reply
                    reply_body = self.generate_reply(result)
                    self.send_reply(sender_email, subject, reply_body)
                    
                    # Mark as processed
                    self.save_processed_id(msg_id)
                    processed_count += 1
                    
                    # Mark as read
                    imap.store(num, '+FLAGS', '\\Seen')
                    
                    # Move to processed folder (optional)
                    try:
                        imap.copy(num, 'Processed')
                        imap.store(num, '+FLAGS', '\\Deleted')
                    except:
                        pass
                    
                    time.sleep(1)  # Prevent rate limiting
            
            return processed_count
            
        except Exception as e:
            print(f"⚠️ Error processing folder {folder_name}: {e}")
            return 0
    
    def check_forwarded_emails(self):
        """Check all folders for forwarded emails"""
        try:
            # Connect to IMAP server
            imap = imaplib.IMAP4_SSL(self.settings['imap_server'], self.settings['imap_port'])
            imap.login(self.settings['email_address'], self.settings['email_password'])
            
            total_processed = 0
            
            # Check INBOX
            total_processed += self.process_folder(imap, 'INBOX')
            
            # Check SPAM folder (sometimes emails go there)
            try:
                total_processed += self.process_folder(imap, '[Gmail]/Spam')
            except:
                pass
            
            # Check ALL MAIL (Gmail's archive)
            try:
                total_processed += self.process_folder(imap, '[Gmail]/All Mail')
            except:
                pass
            
            imap.close()
            imap.logout()
            
            if total_processed > 0:
                print(f"📊 Processed {total_processed} new emails this cycle")
            else:
                print("📭 No new forwarded emails found")
            
        except Exception as e:
            print(f"❌ Error checking emails: {e}")
    
    def run(self, check_interval=30):
        """Run the email forwarding server continuously"""
        print(f"\n🚀 Email forwarding server started")
        print(f"📧 Checking for new emails every {check_interval} seconds")
        print(f"💾 Permanent duplicate prevention enabled")
        print("="*60)
        
        try:
            while True:
                self.check_forwarded_emails()
                time.sleep(check_interval)
        except KeyboardInterrupt:
            print("\n\n👋 Server stopped by user")
        except Exception as e:
            print(f"\n❌ Server error: {e}")

# ============================================================================
# WEB INTERFACE FOR EMAIL FORWARDING
# ============================================================================

from flask import Flask, render_template, request, jsonify

app = Flask(__name__, template_folder='templates')

@app.route('/email-dashboard', methods=['GET'])
def email_dashboard():
    """Dashboard for email forwarding statistics"""
    conn = sqlite3.connect(EMAIL_SETTINGS['database_file'])
    cursor = conn.cursor()
    
    # Get recent scans
    cursor.execute('''
        SELECT sender_email, subject, risk_score, risk_level, timestamp, findings
        FROM scans
        ORDER BY timestamp DESC
        LIMIT 20
    ''')
    
    recent_scans = cursor.fetchall()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) FROM scans')
    total_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_score >= 70')
    high_risk = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_score >= 40 AND risk_score < 70')
    medium_risk = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scans WHERE risk_score < 40')
    low_risk = cursor.fetchone()[0]
    
    conn.close()
    
    # Pass email address to template
    email_address = EMAIL_SETTINGS.get('email_address', 'krishnaeclipsee@gmail.com')
    
    return render_template('email_dashboard.html',
                         recent_scans=recent_scans,
                         total_scans=total_scans,
                         high_risk=high_risk,
                         medium_risk=medium_risk,
                         low_risk=low_risk,
                         email_address=email_address)

if __name__ == '__main__':
    # Start email server in background thread
    import threading
    email_server = EmailForwardingServer()
    
    def run_email_server():
        email_server.run(check_interval=30)
    
    email_thread = threading.Thread(target=run_email_server, daemon=True)
    email_thread.start()
    
    # Start Flask web interface
    print("\n🌐 Starting web dashboard on http://localhost:5001/email-dashboard")
    app.run(host='0.0.0.0', port=5001, debug=False)