# whatsapp_bot.py - Complete WhatsApp Scam Detector Bot

from flask import Flask, request, jsonify, render_template
from twilio.twiml.messaging_response import MessagingResponse
import sys
import os
import re
import datetime
import sqlite3

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import analyzers, use mock if not available
try:
    from text_analyzer import TextAnalyzer
    from url_analyzer import URLAnalyzer
    from ai_detector import AIDetector
    from scoring_engine import ScoringEngine
    ANALYZERS_AVAILABLE = True
    print("✅ Analyzers imported successfully")
except Exception as e:
    print(f"⚠️ Using mock analyzers: {e}")
    ANALYZERS_AVAILABLE = False
    
    # Mock classes
    class TextAnalyzer:
        def analyze(self, text):
            score = 30 if any(w in text.lower() for w in ['urgent', 'suspended', 'paypal', 'account']) else 5
            findings = ['⚠️ Urgency detected'] if score > 20 else []
            return score, findings
    
    class URLAnalyzer:
        def analyze(self, url):
            score = 85 if any(x in url for x in ['bit.ly', 'tinyurl', '.tk', '.ml']) else 10
            findings = ['🔗 Suspicious link'] if score > 50 else []
            return score, findings
    
    class AIDetector:
        def analyze(self, text):
            score = 40 if len(text.split()) > 15 else 10
            findings = ['🤖 AI pattern detected'] if score > 30 else []
            return score, findings
    
    class ScoringEngine:
        def calculate_risk(self, text_result, url_result):
            score = (text_result.get('score', 0) if text_result else 0)
            if url_result:
                score = (score + url_result.get('score', 0)) // 2
            return min(score, 100), {}
        
        def get_risk_level(self, score):
            if score >= 70:
                return "🔴 HIGH RISK", "#FF4444"
            elif score >= 40:
                return "🟡 MEDIUM RISK", "#FFA500"
            else:
                return "🟢 LOW RISK", "#00FF00"

# Initialize analyzers
text_analyzer = TextAnalyzer()
url_analyzer = URLAnalyzer()
ai_detector = AIDetector()
scoring_engine = ScoringEngine()

app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect('whatsapp_scans.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  phone TEXT,
                  message TEXT,
                  score INTEGER,
                  risk_level TEXT,
                  timestamp DATETIME)''')
    conn.commit()
    conn.close()

init_db()

# Twilio WhatsApp credentials
TWILIO_ACCOUNT_SID = 'AC416a37c5eb2ff3dfba89ef9ba2c56411'  # You'll update this
TWILIO_AUTH_TOKEN = '7380f418667fe0d730411be96208f21f'  # You'll update this
TWILIO_WHATSAPP_NUMBER = 'whatsapp:+14155238886'            # Sandbox number (DO NOT CHANGE)
TWILIO_PHONE_NUMBER = '+18783091374'                         # Your trial number

@app.route('/')
def index():
    return render_template('whatsapp.html')

@app.route('/webhook', methods=['POST'])
def webhook():
    """Handle incoming WhatsApp messages"""
    try:
        # Get message details from Twilio
        incoming_msg = request.values.get('Body', '').strip()
        sender = request.values.get('From', '')
        
        print(f"\n📱 WhatsApp from {sender}: {incoming_msg[:50]}")
        
        # Create response
        response = MessagingResponse()
        reply = response.message()
        
        # Analyze the message
        result = analyze_content(incoming_msg, sender)
        
        # Format response
        response_text = format_whatsapp_response(result)
        reply.body(response_text)
        
        # Save to database
        save_scan(sender, incoming_msg, result['score'], result['risk_level'])
        
        return str(response)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        response = MessagingResponse()
        reply = response.message()
        reply.body("⚠️ Sorry, I couldn't analyze that. Please try again.")
        return str(response)

@app.route('/api/analyze', methods=['POST'])
def analyze_api():
    """API endpoint for testing"""
    try:
        data = request.json
        message = data.get('message', '')
        
        result = analyze_content(message, 'api_user')
        
        return jsonify({
            'success': True,
            'score': result['score'],
            'risk_level': result['risk_level'],
            'findings': result['findings'],
            'ai_score': result['ai_score']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def analyze_content(message, sender):
    """Analyze message for scams"""
    # Extract URLs
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    urls = re.findall(url_pattern, message)
    
    text_result = None
    url_result = None
    
    # Analyze text
    text_score, text_findings = text_analyzer.analyze(message)
    text_result = {'score': text_score, 'findings': text_findings}
    
    # Analyze for AI
    ai_score, ai_findings = ai_detector.analyze(message)
    
    # Analyze URLs if present
    url_score = 0
    url_findings = []
    if urls:
        url_score, url_findings = url_analyzer.analyze(urls[0])
        url_result = {'score': url_score, 'findings': url_findings}
    
    # Calculate combined score
    combined_score, _ = scoring_engine.calculate_risk(text_result, url_result)
    
    # Apply AI boost
    if ai_score >= 30:
        if ai_score >= 70:
            combined_score = min(combined_score + 30, 100)
        elif ai_score >= 50:
            combined_score = min(combined_score + 20, 100)
        else:
            combined_score = min(combined_score + 10, 100)
    
    # Get risk level
    risk_level, _ = scoring_engine.get_risk_level(combined_score)
    
    # Prepare findings
    all_findings = []
    if text_findings:
        all_findings.extend(text_findings[:2])
    if url_findings:
        all_findings.extend(url_findings[:2])
    if ai_findings and ai_score >= 40:
        all_findings.append(f"🤖 AI Detection: {ai_score}%")
    
    return {
        'score': round(combined_score, 1),
        'risk_level': risk_level,
        'findings': all_findings,
        'has_url': len(urls) > 0,
        'ai_score': ai_score
    }

def format_whatsapp_response(result):
    """Format response for WhatsApp"""
    score = result['score']
    
    if score >= 70:
        emoji = "🔴"
        title = "*🚨 HIGH RISK SCAM DETECTED!*"
    elif score >= 40:
        emoji = "🟡"
        title = "*⚠️ MEDIUM RISK - SUSPICIOUS*"
    else:
        emoji = "🟢"
        title = "*✅ SAFE - LOW RISK*"
    
    response = f"{title}\n\n"
    response += f"{emoji} Risk Score: *{score}%*\n"
    
    if result['has_url']:
        response += "🔗 *URL detected*\n"
    
    if result['findings']:
        response += "\n*Findings:*\n"
        for f in result['findings'][:3]:
            response += f"• {f}\n"
    
    response += "\n*Recommendations:*\n"
    if score >= 70:
        response += "• ❌ DO NOT click any links\n"
        response += "• ❌ DO NOT reply\n"
        response += "• 🗑️ Delete message"
    elif score >= 40:
        response += "• 👀 Verify carefully\n"
        response += "• 🔍 Check before clicking"
    else:
        response += "• 👍 Stay vigilant"
    
    response += "\n\n🛡️ *AI Scam Detector*"
    return response

def save_scan(phone, message, score, risk_level):
    """Save scan to database"""
    try:
        conn = sqlite3.connect('whatsapp_scans.db')
        c = conn.cursor()
        c.execute("INSERT INTO scans (phone, message, score, risk_level, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (phone, message[:200], score, risk_level, datetime.datetime.now()))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ Database error: {e}")

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'message': 'WhatsApp Bot is running',
        'time': str(datetime.datetime.now())
    })

if __name__ == '__main__':
    print("="*60)
    print("📱 WHATSAPP SCAM DETECTOR BOT")
    print("="*60)
    print("✅ Server starting...")
    print("🌐 Web Interface: http://localhost:5002")
    print("📞 Webhook URL: http://localhost:5002/webhook")
    print("📊 API: http://localhost:5002/api/analyze")
    print("="*60)
    app.run(host='0.0.0.0', port=5002, debug=True)