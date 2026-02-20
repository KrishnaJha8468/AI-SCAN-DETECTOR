# whatsapp_bot.py 

from flask import Flask, request, jsonify, render_template
from twilio.twiml.messaging_response import MessagingResponse
import sys
import os
import re
import datetime
import sqlite3

# ===== ENHANCED CONTEXTUAL DETECTION =====
from datetime import datetime

class SocialEngineeringDetector:
    """Detects social engineering scams that don't use urgency words"""
    
    def __init__(self):
        # Patterns that scammers use (no urgency words)
        self.social_patterns = [
            # Lost/found items
            (r'(found|have).+?(wallet|phone|keys|bag|purse|id|card)', 35, "Found item scam"),
            (r'(lost|missing).+?(wallet|phone|keys)', 30, "Lost item bait"),
            
            # Package delivery (no urgency)
            (r'(package|parcel|delivery).+?(ready|arrived|waiting)', 40, "Fake delivery"),
            (r'(courier|fedex|ups|dhl|usps).+?(delivery|package)', 45, "Courier impersonation"),
            
            # Social engineering
            (r'call me (back|at).+?\d{3,}', 50, "Callback scam"),
            (r'text me (back|at).+?\d{3,}', 50, "Text back scam"),
            (r'whatsapp me (back|at)', 45, "WhatsApp redirect"),
            
            # Personal information
            (r'(verify|confirm).+?(identity|account|information)', 40, "Identity verification"),
            (r'(update|check).+?(details|info|profile)', 35, "Profile update scam"),
            
            # Money requests (no urgency)
            (r'(send|transfer).+?(money|cash|funds)', 60, "Money request"),
            (r'(gift|google play|itunes).+?card', 65, "Gift card scam"),
            
            # Prize scams (no urgency)
            (r'(won|winner|selected|chosen).+?(prize|lotto|lottery)', 55, "Fake prize"),
            (r'(gift|free).+?(iphone|ipad|macbook)', 50, "Free gift scam"),
        ]
        
        # Sender behavior tracking
        self.sender_history = {}
        
    def analyze_message(self, message, sender, timestamp):
        """Analyze message for social engineering"""
        message_lower = message.lower()
        score = 0
        findings = []
        
        # Check against social patterns
        for pattern, weight, description in self.social_patterns:
            if re.search(pattern, message_lower):
                score += weight
                findings.append(f"🎭 {description}")
        
        # Check sender behavior
        behavior_score, behavior_findings = self.analyze_sender_behavior(sender, timestamp)
        score += behavior_score
        findings.extend(behavior_findings)
        
        # Check for unusual requests
        if '?' in message and any(word in message_lower for word in ['you', 'your', 'ur']):
            score += 10
            findings.append("❓ Question about you - information fishing")
        
        # Check for link + personal message combo
        if 'http' in message_lower and len(message.split()) > 5:
            score += 15
            findings.append("🔗 Link in personal message - suspicious")
        
        return min(score, 100), findings
    
    def analyze_sender_behavior(self, sender, timestamp):
        """Track sender behavior patterns"""
        score = 0
        findings = []
        
        if sender not in self.sender_history:
            self.sender_history[sender] = {
                'first_seen': timestamp,
                'message_count': 0,
                'last_message': timestamp
            }
            findings.append("👤 New sender")
            score += 10
        
        history = self.sender_history[sender]
        history['message_count'] += 1
        
        # Check message frequency
        time_diff = (timestamp - history['last_message']).seconds
        if time_diff < 60 and history['message_count'] > 3:
            score += 20
            findings.append("⚡ Rapid messaging - automated")
        
        history['last_message'] = timestamp
        return min(score, 100), findings

class ContextualAnalyzer:
    """Combines all detection methods"""
    
    def __init__(self):
        self.social_detector = SocialEngineeringDetector()
        
    def analyze(self, message, sender=None):
        """Complete contextual analysis"""
        timestamp = datetime.now()
        
        # Get regular analysis first
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+])+|www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', message)
        
        text_score, text_findings = text_analyzer.analyze(message)
        ai_score, ai_findings = ai_detector.analyze(message)
        
        # Social engineering analysis
        social_score, social_findings = self.social_detector.analyze_message(message, sender, timestamp)
        
        # URL analysis
        url_score = 0
        url_findings = []
        if urls:
            url_score, url_findings = url_analyzer.analyze(urls[0])
        
        # Combine scores with weights
        total_score = (
            text_score * 0.2 +      # Traditional urgency (lower weight)
            ai_score * 0.15 +        # AI detection
            social_score * 0.6 +     # Social engineering (higher weight)
            url_score * 0.3           # URL risk
        )
        
        # Combine findings
        all_findings = []
        all_findings.extend(text_findings[:2])
        all_findings.extend(social_findings[:3])
        all_findings.extend(url_findings[:2])
        if ai_score >= 40:
            all_findings.append(f"🤖 AI Analysis: {ai_score}%")
        
        return round(total_score, 1), all_findings, bool(urls)

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
TWILIO_ACCOUNT_SID = 'TWILIO_ACCOUNT_SID'  
TWILIO_AUTH_TOKEN = 'TWILIO_AUTH_TOKEN'  
TWILIO_WHATSAPP_NUMBER = 'whatsapp:+14155238886'         
TWILIO_PHONE_NUMBER = '+18783091374'                        

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
    """Enhanced analysis with social engineering detection"""
    
    # Initialize contextual analyzer
    contextual_analyzer = ContextualAnalyzer()
    
    # Get enhanced analysis
    combined_score, findings, has_url = contextual_analyzer.analyze(message, sender)
    
    # Get risk level
    if combined_score >= 70:
        risk_level = "🔴 HIGH RISK"
    elif combined_score >= 40:
        risk_level = "🟡 MEDIUM RISK"
    else:
        risk_level = "🟢 LOW RISK"
    
    # Get AI score from existing detector
    ai_score, _ = ai_detector.analyze(message)
    
    return {
        'score': combined_score,
        'risk_level': risk_level,
        'findings': findings,
        'has_url': has_url,
        'ai_score': ai_score
    }

def format_whatsapp_response(result):
    """Enhanced response with detailed findings"""
    score = result['score']
    findings = result['findings']
    
    # Header based on risk
    if score >= 70:
        header = "🚨 *HIGH RISK SCAM DETECTED!*\n"
        emoji = "🔴"
        recommendations = [
            "• ❌ DO NOT reply to this message",
            "• ❌ DO NOT call any numbers mentioned",
            "• ❌ DO NOT click any links",
            "• 🚫 Block this sender immediately",
            "• 📞 Verify independently if concerned"
        ]
    elif score >= 40:
        header = "⚠️ *MEDIUM RISK - BE CAREFUL*\n"
        emoji = "🟡"
        recommendations = [
            "• 👀 Verify the sender's identity",
            "• 🔍 Don't share personal information",
            "• 📞 Contact the company directly",
            "• ⚠️ Be cautious with any links"
        ]
    else:
        header = "✅ *SAFE - LOW RISK*\n"
        emoji = "🟢"
        recommendations = [
            "• 👍 Message appears safe",
            "• 🔒 Still practice caution",
            "• 📱 Trust your instincts"
        ]
    
    # Build response
    response = header
    response += f"\n{emoji} Risk Score: *{score}%*\n"
    
    if result['has_url']:
        response += "🔗 *Link detected in message*\n"
    
    if findings:
        response += "\n*Why this score:*\n"
        for finding in findings[:5]:
            response += f"• {finding}\n"
    
    response += "\n*Recommendations:*\n"
    for rec in recommendations[:4]:
        response += f"{rec}\n"
    
    response += "\n🛡️ *AI Scam Detector*"
    
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
    print("✅ Enhanced with Social Engineering Detection")
    print("="*60)
    app.run(host='0.0.0.0', port=5002, debug=True)