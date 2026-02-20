# visual_detector.py - Detects visually similar characters (homoglyphs)

import re

class VisualDetector:  # Make sure this is EXACTLY "VisualDetector" (capital V, capital D)
    def __init__(self):
        # Homoglyph maps - characters that look alike
        self.homoglyphs = {
            'a': ['а', 'à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'α', '⍺'],
            'b': ['Ь', 'ḃ', 'ƅ', 'β', 'ⲃ'],
            'c': ['с', 'ç', 'ć', 'č', 'ċ', 'ς', 'ⲥ'],
            'd': ['ԁ', 'ɗ', 'đ', 'ⅾ'],
            'e': ['е', 'è', 'é', 'ê', 'ë', 'ē', 'ė', 'ę', 'ϵ', 'ⲉ'],
            'f': ['ſ', 'ƒ', 'ḟ'],
            'g': ['ɡ', 'ġ', 'ǵ', 'ģ'],
            'h': ['һ', 'ḣ', 'ħ', 'ℎ'],
            'i': ['і', 'í', 'ì', 'ï', 'î', 'ī', 'į', 'ı', 'ɨ'],
            'j': ['ј', 'ĵ', 'ǰ'],
            'k': ['ķ', 'ḳ', 'ƙ', 'κ'],
            'l': ['ӏ', 'ḷ', 'ĺ', 'ļ', 'ⅼ'],
            'm': ['м', 'ṃ', 'ṁ', 'ⅿ'],
            'n': ['п', 'ņ', 'ṇ', 'ń', 'ň', 'ñ'],
            'o': ['о', 'ο', 'σ', 'ọ', 'ỏ', 'õ', 'ö', 'ø', '0'],
            'p': ['р', 'ṗ', 'ṕ', 'ρ'],
            'q': ['ԛ', 'ɋ'],
            'r': ['г', 'ŕ', 'ř', 'ṙ', 'ṛ'],
            's': ['ѕ', 'ş', 'š', 'ṡ', 'ṣ', 'ς'],
            't': ['т', 'ţ', 'ť', 'ṫ', 'ṭ', 'ƭ'],
            'u': ['υ', 'ü', 'ù', 'ú', 'û', 'ū', 'ų'],
            'v': ['ν', 'ṿ', 'ṽ', 'ⅴ'],
            'w': ['ѡ', 'ŵ', 'ẇ', 'ẉ', 'ω'],
            'x': ['х', 'χ', 'ẋ', 'ẍ'],
            'y': ['у', 'ÿ', 'ý', 'ŷ', 'ẏ', 'γ'],
            'z': ['ž', 'ż', 'ẓ', 'ẕ', 'ζ'],
        }
        
        # Common brand names to check
        self.brands = [
            'microsoft', 'apple', 'google', 'facebook', 'amazon',
            'paypal', 'netflix', 'chase', 'wellsfargo', 'bankofamerica',
            'instagram', 'twitter', 'linkedin', 'whatsapp', 'spotify',
            'youtube', 'gmail', 'outlook', 'yahoo', 'ebay', 'github'
        ]
        
    def analyze_domain(self, domain):
        """Analyze domain for homoglyph attacks"""
        if not domain:
            return 0, []
        
        findings = []
        score = 0
        domain_lower = domain.lower()
        
        # Check for suspicious Unicode characters
        suspicious_chars = []
        for char in domain:
            if ord(char) > 127:  # Non-ASCII
                suspicious_chars.append(f"{char} (U+{ord(char):04X})")
                score += 15
        
        if suspicious_chars:
            findings.append(f"🔣 Suspicious Unicode: {', '.join(suspicious_chars[:3])}")
        
        # Check for homoglyphs of brand names
        for brand in self.brands:
            if self._contains_homoglyph(domain_lower, brand):
                score += 40
                findings.append(f"🎭 Visual spoofing: '{domain}' looks like '{brand}'")
                break
        
        # Check for mixed scripts
        scripts = self._detect_scripts(domain)
        if len(scripts) > 1:
            score += 25
            findings.append(f"🔄 Mixed scripts: {', '.join(scripts)}")
        
        # Check for zero-width characters
        if any(ord(c) in [0x200B, 0x200C, 0x200D, 0xFEFF] for c in domain):
            score += 50
            findings.append("👻 Zero-width characters detected")
        
        # Check for repeated characters
        for brand in self.brands:
            for i in range(2, 4):
                repeated = brand[0] * i
                if repeated in domain_lower and brand not in domain_lower:
                    score += 20
                    findings.append(f"🔁 Repeated pattern: '{repeated}' in '{domain}'")
                    break
        
        return min(score, 100), findings
    
    def _contains_homoglyph(self, domain, brand):
        """Check if domain contains homoglyph version of brand"""
        if brand in domain:
            return False
        
        if len(domain) < len(brand) - 2 or len(domain) > len(brand) + 3:
            return False
        
        matches = 0
        total = min(len(domain), len(brand))
        
        for i in range(total):
            d_char = domain[i]
            b_char = brand[i]
            
            if d_char == b_char:
                matches += 1
            elif d_char in self.homoglyphs.get(b_char, []):
                matches += 0.8
        
        similarity = matches / total if total > 0 else 0
        return similarity > 0.7 and similarity < 1.0
    
    def _detect_scripts(self, text):
        """Detect Unicode scripts in text"""
        scripts = set()
        
        for char in text:
            code = ord(char)
            if code < 0x80:
                scripts.add("Latin")
            elif 0x0400 <= code <= 0x04FF:
                scripts.add("Cyrillic")
            elif 0x0370 <= code <= 0x03FF:
                scripts.add("Greek")
            elif 0x0590 <= code <= 0x05FF:
                scripts.add("Hebrew")
            elif 0x0600 <= code <= 0x06FF:
                scripts.add("Arabic")
            elif 0x4E00 <= code <= 0x9FFF:
                scripts.add("CJK")
        
        return list(scripts)