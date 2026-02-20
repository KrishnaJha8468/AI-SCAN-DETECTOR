# ai_detector.py - AI-generated text detection (Enhanced version)

import re
import math

class AIDetector:
    def __init__(self):
        # AI-generated text patterns (EXPANDED)
        self.ai_patterns = {
            'transition_phrases': [
                'in conclusion', 'furthermore', 'moreover', 'additionally',
                'consequently', 'hence', 'thus', 'therefore', 'nonetheless',
                'nevertheless', 'conversely', 'in contrast', 'on the other hand',
                'as a result', 'for instance', 'for example', 'in addition',
                'accordingly', 'subsequently', 'alternatively', 'specifically',
                'notably', 'particularly', 'conversely', 'likewise'
            ],
            
            'formal_words': [
                'utilize', 'leverage', 'facilitate', 'implement', 'optimize',
                'streamline', 'innovate', 'paradigm', 'synergy', 'ecosystem',
                'holistic', 'proactive', 'seamless', 'robust', 'scalable',
                'commence', 'terminate', 'endeavor', 'ascertain', 'delineate',
                'expedite', 'ameliorate', 'commensurate', 'delineate',
                'henceforth', 'heretofore', 'herein', 'therein'
            ],
            
            'hedging_words': [
                'perhaps', 'maybe', 'possibly', 'presumably', 'seemingly',
                'apparently', 'arguably', 'debatably', 'theoretically',
                'hypothetically', 'purportedly', 'allegedly', 'putatively',
                'ostensibly', 'reportedly', 'supposedly'
            ],
            
            'overly_polite': [
                'I hope this message finds you well',
                'I trust this email finds you well',
                'I am writing to you today',
                'Thank you for your time and consideration',
                'Please do not hesitate to contact me',
                'I look forward to hearing from you',
                'Thank you for your prompt attention',
                'I appreciate your assistance',
                'I apologize for any inconvenience',
                'Please accept our apologies',
                'We value your business',
                'Thank you for your cooperation'
            ],
            
            'ai_sentence_starters': [
                'I am writing to', 'This email is to', 'The purpose of this',
                'I would like to', 'I wanted to', 'I am reaching out',
                'I hope you are', 'Thank you for', 'I appreciate your',
                'I am contacting you', 'This serves as', 'This is to',
                'I am pleased to', 'I regret to', 'We are writing to'
            ],
            
            'scam_phrases': [
                'verify your identity', 'confirm your details', 'secure your account',
                'unauthorized access', 'suspicious activity', 'temporarily restricted',
                'account limited', 'verify now', 'click the link', 'secure link',
                'immediate action', 'failure to respond', 'permanently suspended'
            ]
        }
        
        # Human-like patterns (lack of these suggests AI)
        self.human_patterns = [
            r'\b(hey|hi|hello|yo|sup)\b',  # Casual greetings
            r'\b(yeah|nah|okay|ok|k|sure|ya|yep|nope)\b',  # Informal words
            r'\.{2,}',  # Ellipsis (thinking...)
            r'\b(um|uh|er|ah|hmm|oof|oh)\b',  # Filler words
            r'!{2,}',  # Multiple exclamation marks
            r'\?{2,}',  # Multiple question marks
            r'\b(gonna|wanna|gotta|ain\'t|dunno|kinda|sorta)\b',  # Contractions
            r'\b(lol|lmao|rofl|idk|tbh|btw|imo|imho)\b',  # Internet slang
            r'\b(cool|awesome|amazing|great|nice)\b',  # Casual adjectives
            r'\b(thanks|thx|ty)\b',  # Casual thanks
            r'\b(btw|fyi|asap)\b'  # Common abbreviations
        ]
        
    def analyze(self, text):
        """Analyze text for AI-generated patterns"""
        if not text or len(text) < 50:
            return 0, ["⚠️ Text too short for AI analysis (min 50 characters)"]
        
        findings = []
        score = 0
        text_lower = text.lower()
        
        # Check 1: Transition phrases (AI overuses these)
        transition_count = 0
        transition_found = []
        for phrase in self.ai_patterns['transition_phrases']:
            if phrase in text_lower:
                transition_count += 1
                if len(transition_found) < 3:
                    transition_found.append(phrase)
        
        if transition_count > 0:
            score += transition_count * 8
            findings.append(f"🤖 Transition phrases ({transition_count}): {', '.join(transition_found)}")
        
        # Check 2: Formal business words (AI loves these)
        formal_count = 0
        formal_found = []
        for word in self.ai_patterns['formal_words']:
            if word in text_lower:
                formal_count += 1
                if len(formal_found) < 3:
                    formal_found.append(word)
        
        if formal_count > 0:
            score += formal_count * 6
            findings.append(f"📊 Formal AI words ({formal_count}): {', '.join(formal_found)}")
        
        # Check 3: Hedging words
        hedge_count = 0
        for word in self.ai_patterns['hedging_words']:
            if word in text_lower:
                hedge_count += 1
                score += 5
        
        if hedge_count > 0:
            findings.append(f"🤔 Hedging words: {hedge_count}")
        
        # Check 4: Overly polite phrases
        polite_count = 0
        for phrase in self.ai_patterns['overly_polite']:
            if phrase in text_lower:
                polite_count += 1
                score += 7
        
        if polite_count > 0:
            findings.append(f"🎩 Overly polite phrases: {polite_count}")
        
        # Check 5: AI sentence starters
        starter_count = 0
        for starter in self.ai_patterns['ai_sentence_starters']:
            if starter in text_lower:
                starter_count += 1
                score += 6
        
        if starter_count > 0:
            findings.append(f"📝 AI-style sentence starters: {starter_count}")
        
        # Check 6: Scam phrases (often used in AI scams)
        scam_phrase_count = 0
        for phrase in self.ai_patterns['scam_phrases']:
            if phrase in text_lower:
                scam_phrase_count += 1
                score += 5
        
        if scam_phrase_count > 0:
            findings.append(f"⚠️ Scam-related phrases: {scam_phrase_count}")
        
        # Check 7: Lack of human elements
        human_count = 0
        human_found = []
        for pattern in self.human_patterns:
            matches = re.findall(pattern, text_lower)
            if matches:
                human_count += len(matches)
                if len(human_found) < 3:
                    human_found.extend(matches[:2])
        
        if human_count == 0:
            score += 30
            findings.append("🤖 NO human elements detected - text is too perfect")
        elif human_count < 3:
            score += 15
            findings.append(f"⚠️ Very few human elements ({human_count})")
        else:
            score -= 10  # Reduce score for human-like text
            findings.append(f"👤 Human elements detected: {', '.join(str(h) for h in human_found[:3])}")
        
        # Check 8: Sentence length consistency
        sentences = re.split(r'[.!?]+', text)
        if len(sentences) > 3:
            lengths = [len(s.strip().split()) for s in sentences if s.strip()]
            if lengths:
                avg_length = sum(lengths) / len(lengths)
                variance = sum((l - avg_length) ** 2 for l in lengths) / len(lengths)
                
                if variance < 3:  # Very consistent = AI
                    score += 25
                    findings.append(f"📏 UNUSUALLY consistent sentence length - AI pattern")
                elif variance < 6:
                    score += 10
                    findings.append("📏 Somewhat consistent sentences")
        
        # Check 9: Vocabulary repetition
        words = text_lower.split()
        if len(words) > 30:
            word_freq = {}
            for word in words:
                if len(word) > 3:  # Skip small words
                    word_freq[word] = word_freq.get(word, 0) + 1
            
            repeated_words = [word for word, count in word_freq.items() if count > 2]
            if len(repeated_words) > 3:
                score += 10
                findings.append(f"🔄 Repetitive vocabulary: {', '.join(repeated_words[:3])}")
        
        # Check 10: Perfect grammar (no contractions, no slang)
        has_contractions = any(word in text_lower for word in ["'t", "'s", "'m", "'re", "'ve", "'ll"])
        if not has_contractions and len(words) > 30:
            score += 15
            findings.append("✨ No contractions used - unusually formal")
        
        # Calculate AI probability (cap at 100)
        ai_probability = min(score, 100)
        
        # Add summary
        if ai_probability >= 70:
            findings.insert(0, f"🤖 **HIGH AI PROBABILITY: {ai_probability}%**")
            findings.insert(1, "   This text shows strong AI-generated patterns")
        elif ai_probability >= 50:
            findings.insert(0, f"⚖️ **MEDIUM-HIGH AI PROBABILITY: {ai_probability}%**")
            findings.insert(1, "   Very likely AI-generated or heavily AI-assisted")
        elif ai_probability >= 30:
            findings.insert(0, f"🟡 **MEDIUM AI PROBABILITY: {ai_probability}%**")
            findings.insert(1, "   Could be AI-generated or AI-assisted")
        elif ai_probability >= 15:
            findings.insert(0, f"🟢 **LOW AI PROBABILITY: {ai_probability}%**")
            findings.insert(1, "   Probably written by a human")
        else:
            findings.insert(0, f"✅ **VERY LOW AI PROBABILITY: {ai_probability}%**")
            findings.insert(1, "   Almost certainly human-written")
        
        return ai_probability, findings
    
    def get_ai_risk_level(self, score):
        """Get risk level for AI detection"""
        if score >= 70:
            return "🔴 HIGH AI RISK", "Very likely AI-generated (common in modern scams)"
        elif score >= 50:
            return "🟡 MEDIUM-HIGH AI RISK", "Probably AI-generated"
        elif score >= 30:
            return "🟡 MEDIUM AI RISK", "Could be AI-generated or AI-assisted"
        elif score >= 15:
            return "🟢 LOW AI RISK", "Probably human-written"
        else:
            return "✅ VERY LOW AI RISK", "Almost certainly human-written"