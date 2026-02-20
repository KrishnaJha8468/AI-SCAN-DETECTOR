# text_analyzer.py - Text analysis for scam detection

import re
from collections import Counter

class TextAnalyzer:
    def __init__(self):
        # Define word categories
        self.urgency_words = [
            'urgent', 'immediately', 'asap', 'act now', 'limited time',
            'expires', 'deadline', 'hurry', 'don\'t miss', 'last chance',
            'verify now', 'update now', 'confirm now', 'click here',
            'instant', 'now', 'today only', 'while supplies last',
            'expiration', 'expiring', 'suspended', 'suspension'
        ]
        
        self.fear_words = [
            'suspended', 'terminated', 'blocked', 'locked', 'security alert',
            'unauthorized', 'unusual activity', 'breach', 'compromised',
            'legal action', 'lawsuit', 'arrest', 'police', 'criminal',
            'fraud alert', 'identity theft', 'hacked', 'virus', 'malware',
            'account limited', 'restricted', 'deactivated', 'closed permanently',
            'you owe', 'debt', 'collection', 'court', 'penalty', 'fine'
        ]
        
        self.greetings = [
            'dear customer', 'dear user', 'dear member', 'valued customer',
            'hello customer', 'dear sir/madam', 'to whom it may concern',
            'dear friend', 'hello friend', 'dear account holder',
            'dear email user', 'dear gmail user', 'dear paypal user',
            'dear amazon customer', 'dear netflix user', 'dear bank customer'
        ]
        
    def analyze(self, text):
        """Main analysis function - returns score and findings"""
        if not text:
            return 0, []
        
        text_lower = text.lower()
        findings = []
        score = 0
        
        # Check urgency
        for word in self.urgency_words:
            if word in text_lower:
                score += 5
                findings.append(f"⚠️ Urgency word: '{word}'")
        
        # Check fear
        for word in self.fear_words:
            if word in text_lower:
                score += 6
                findings.append(f"😨 Fear word: '{word}'")
        
        # Check greetings
        for greeting in self.greetings:
            if greeting in text_lower:
                score += 5
                findings.append(f"👤 Generic greeting: '{greeting}'")
                break
        
        # Check ALL CAPS
        caps_words = re.findall(r'\b[A-Z]{4,}\b', text)
        if caps_words:
            score += len(caps_words) * 2
            findings.append(f"🔊 SHOUTING: {', '.join(caps_words[:3])}")
        
        # Cap at 100
        score = min(score, 100)
        
        return score, findings