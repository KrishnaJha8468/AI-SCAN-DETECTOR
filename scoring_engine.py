# scoring_engine.py - Unified scoring system with AI detection

class ScoringEngine:
    def __init__(self):
        # Weights for different components
        self.weights = {
            'text_urgency': 0.15,
            'text_fear': 0.20,
            'text_greeting': 0.10,
            'text_grammar': 0.10,
            'text_trust': 0.05,
            'url_tld': 0.10,
            'url_typosquatting': 0.15,
            'url_shortener': 0.08,
            'url_age': 0.07
        }
        
        # Risk level thresholds
        self.thresholds = {
            'critical': 80,
            'high': 60,
            'medium': 40,
            'low': 20,
            'safe': 0
        }
        
    def calculate_risk(self, text_result=None, url_result=None):
        """
        Calculate overall risk score from text and URL analysis
        """
        risk_score = 0
        components = {}
        
        # If only URL is present, just use URL score
        if url_result and not text_result:
            risk_score = url_result.get('score', 0)
            # Process components for breakdown
            url_components = self._process_url_results(url_result)
            components.update(url_components)
            return round(risk_score, 1), components
        
        # If only text is present, just use text score
        if text_result and not url_result:
            risk_score = text_result.get('score', 0)
            # Process components for breakdown
            text_components = self._process_text_results(text_result)
            components.update(text_components)
            return round(risk_score, 1), components
        
        # If both are present, calculate weighted score
        if text_result and url_result:
            text_score = text_result.get('score', 0)
            url_score = url_result.get('score', 0)
            
            # URL should have higher weight for scam detection
            if url_score >= 70:
                # URL is clearly malicious - score should be at least 70%
                risk_score = (url_score * 0.8) + (text_score * 0.2)
                # Ensure minimum of 70% for high-risk URLs
                if risk_score < 70:
                    risk_score = 70
            elif url_score >= 40:
                # URL is suspicious - moderate weight
                risk_score = (url_score * 0.7) + (text_score * 0.3)
            else:
                # URL seems safe - text dominates
                risk_score = (text_score * 0.6) + (url_score * 0.4)
            
            # Boost if both are suspicious
            if text_score > 40 and url_score > 40:
                risk_score = risk_score * 1.15  # 15% boost
                components['combined_boost'] = 15
            
            # Process components for breakdown
            text_components = self._process_text_results(text_result)
            components.update(text_components)
            
            url_components = self._process_url_results(url_result)
            components.update(url_components)
        
        # Ensure score is between 0-100
        risk_score = min(max(risk_score, 0), 100)
        
        return round(risk_score, 1), components
    
    def _process_text_results(self, text_result):
        """Extract and normalize text components"""
        components = {}
        
        if not text_result:
            return components
        
        findings = text_result.get('findings', [])
        raw_score = text_result.get('score', 0)
        
        # Initialize component scores
        urgency_score = 0
        fear_score = 0
        greeting_score = 0
        grammar_score = 0
        trust_score = 0
        
        # Analyze each finding
        for finding in findings:
            finding_lower = finding.lower()
            
            # Urgency detection
            if any(word in finding_lower for word in ['urgent', '⏰', 'immediately', 'asap', 'act now']):
                urgency_score += 25
            elif '⚠️ urgency' in finding_lower or 'urgency word' in finding_lower:
                urgency_score += 20
            
            # Fear detection
            if any(word in finding_lower for word in ['😨', 'fear', 'suspended', 'blocked', 'limited']):
                fear_score += 20
            elif 'fear word' in finding_lower:
                fear_score += 15
            
            # Greeting detection
            if any(word in finding_lower for word in ['👤', 'generic', 'dear customer', 'valued customer']):
                greeting_score = 70
            
            # Grammar issues
            if any(word in finding_lower for word in ['🔊', '📢', '📝', 'all caps', 'shouting']):
                grammar_score += 20
            elif 'grammar' in finding_lower:
                grammar_score += 15
            
            # Trust phrases
            if any(word in finding_lower for word in ['🤔', 'trust', 'legitimate', 'not a scam']):
                trust_score += 25
        
        # Cap scores at 100
        components['text_urgency'] = min(urgency_score, 100)
        components['text_fear'] = min(fear_score, 100)
        components['text_greeting'] = min(greeting_score, 100)
        components['text_grammar'] = min(grammar_score, 100)
        components['text_trust'] = min(trust_score, 100)
        
        # If no specific findings but raw score exists, distribute raw score
        if all(v == 0 for v in components.values()) and raw_score > 0:
            components['text_urgency'] = raw_score * 0.3
            components['text_fear'] = raw_score * 0.3
            components['text_grammar'] = raw_score * 0.2
            components['text_greeting'] = raw_score * 0.1
            components['text_trust'] = raw_score * 0.1
        
        return components
    
    def _process_url_results(self, url_result):
        """Extract and normalize URL components"""
        components = {}
        
        if not url_result:
            return components
        
        findings = url_result.get('findings', [])
        raw_score = url_result.get('score', 0)
        
        # Initialize component scores
        tld_score = 0
        typosquat_score = 0
        shortener_score = 0
        age_score = 0
        
        # Analyze each finding
        for finding in findings:
            finding_lower = finding.lower()
            
            # TLD detection
            if any(word in finding_lower for word in ['.tk', '.ml', '.ga', '.cf', '.xyz', 'suspicious tld']):
                tld_score = 85
            elif 'trusted tld' in finding_lower:
                tld_score = 10
            
            # Typosquatting detection
            if any(word in finding_lower for word in ['typo', 'squat', 'contains', 'brand', 'paypa1', 'faceb00k']):
                typosquat_score = 90
            elif 'looks like' in finding_lower:
                typosquat_score = 80
            
            # URL shortener detection
            if any(word in finding_lower for word in ['shortener', 'bit.ly', 'tinyurl', 'short link']):
                shortener_score = 85
            
            # Domain age detection
            if 'created' in finding_lower and 'days' in finding_lower:
                if 'only' in finding_lower or '7 days' in finding_lower:
                    age_score = 90
                elif '30 days' in finding_lower:
                    age_score = 70
                else:
                    age_score = 50
            elif 'whois lookup failed' in finding_lower:
                age_score = 60
        
        # If URL score is high but we didn't catch specific components
        if raw_score >= 70 and all(v == 0 for v in [tld_score, typosquat_score, shortener_score, age_score]):
            tld_score = raw_score * 0.3
            typosquat_score = raw_score * 0.4
            shortener_score = raw_score * 0.15
            age_score = raw_score * 0.15
        
        components['url_tld'] = tld_score
        components['url_typosquatting'] = typosquat_score
        components['url_shortener'] = shortener_score
        components['url_age'] = age_score
        
        return components
    
    def get_risk_level(self, score):
        """Get risk level based on score"""
        if score >= 80:
            return "🔴 CRITICAL RISK", "#8B0000"
        elif score >= 60:
            return "🔴 HIGH RISK", "#FF4444"
        elif score >= 40:
            return "🟡 MEDIUM RISK", "#FFA500"
        elif score >= 20:
            return "🟢 LOW RISK", "#32CD32"
        else:
            return "✅ SAFE", "#228B22"
    
    def get_recommendations(self, score, has_text=True, has_url=True):
        """Get personalized recommendations based on risk score"""
        if score >= 80:
            return [
                "🚨 **CRITICAL: DO NOT interact with this content!**",
                "❌ Do not click any links",
                "❌ Do not reply or provide information",
                "❌ Delete this message immediately",
                "✅ If concerned, visit official website DIRECTLY"
            ]
        elif score >= 60:
            return [
                "🔴 **HIGH RISK: Strong scam indicators detected**",
                "⚠️ Do not click any links",
                "⚠️ Verify sender/URL carefully",
                "⚠️ Contact company using official contact info",
                "✅ Hover over links to see real destination"
            ]
        elif score >= 40:
            return [
                "🟡 **MEDIUM RISK: Multiple suspicious patterns**",
                "👀 Verify sender email address carefully",
                "👀 Check for spelling errors in URLs",
                "👀 Don't provide personal information",
                "✅ When in doubt, contact directly"
            ]
        elif score >= 20:
            return [
                "🟢 **LOW RISK: Some minor indicators**",
                "👍 Still verify sender address",
                "👍 Be cautious with links",
                "👍 Stay vigilant"
            ]
        else:
            return [
                "✅ **SAFE: Appears legitimate**",
                "👍 Always practice safe browsing",
                "👍 Keep your software updated",
                "👍 Use 2-factor authentication"
            ]
    
    def get_risk_breakdown(self, components):
        """Get visual breakdown of risk factors"""
        breakdown = []
        
        # Define component labels (UPDATED WITH AI DETECTION)
        labels = {
            'text_urgency': '⏰ Urgency',
            'text_fear': '😨 Fear Tactics',
            'text_greeting': '👤 Generic Greeting',
            'text_grammar': '📝 Grammar Issues',
            'text_trust': '🤔 Trust Phrases',
            'url_tld': '🌐 Domain TLD',
            'url_typosquatting': '🎭 Typosquatting',
            'url_shortener': '🔗 URL Shortener',
            'url_age': '📅 Domain Age',
            'combined_boost': '🚨 Combined Risk Boost',
            'ai_generated': '🤖 AI-Generated Content'  # ADDED THIS LINE
        }
        
        for comp, score in components.items():
            if comp in labels and score > 0:
                if score >= 70:
                    level = "🔴"
                elif score >= 40:
                    level = "🟡"
                else:
                    level = "🟢"
                breakdown.append(f"{level} {labels[comp]}: {score:.0f}%")
        
        return breakdown
    
    def generate_report(self, text_result, url_result, combined_score, components):
        """Generate a complete risk report"""
        report = []
        
        risk_level, color = self.get_risk_level(combined_score)
        report.append(f"📊 **RISK ASSESSMENT REPORT**")
        report.append(f"{'='*40}")
        report.append(f"Overall Risk: {risk_level} ({combined_score}%)")
        report.append("")
        
        if combined_score >= 80:
            report.append("⚠️ **CRITICAL - This is definitely a scam!**")
        elif combined_score >= 60:
            report.append("⚠️ **Strong scam indicators detected!**")
        elif combined_score >= 40:
            report.append("⚠️ **Multiple suspicious patterns detected**")
        else:
            report.append("✅ **This content appears legitimate**")
        report.append("")
        
        if components:
            report.append("**🔍 Risk Factor Breakdown:**")
            breakdown = self.get_risk_breakdown(components)
            report.extend(breakdown)
            report.append("")
        
        if text_result:
            report.append(f"**📧 Text Analysis:** {text_result.get('score', 0)}% risk")
            report.append(f"   • Found {len(text_result.get('findings', []))} patterns")
        
        if url_result:
            report.append(f"**🔗 URL Analysis:** {url_result.get('score', 0)}% risk")
            report.append(f"   • Found {len(url_result.get('findings', []))} patterns")
        
        report.append("")
        report.append("**🛡️ Recommendations:**")
        recommendations = self.get_recommendations(combined_score, bool(text_result), bool(url_result))
        for r in recommendations:
            report.append(f"   • {r}")
        
        return "\n".join(report)