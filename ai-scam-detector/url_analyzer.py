# url_analyzer.py - Complete URL analysis with brand impersonation and subdomain detection

import re
import whois
import datetime
import tldextract
from urllib.parse import urlparse
from visual_detector import VisualDetector

class URLAnalyzer:
    def __init__(self):
        # Initialize visual detector
        self.visual_detector = VisualDetector()
        
        # Risky TLDs (top-level domains)
        self.risky_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club', 
            '.work', '.date', '.men', '.loan', '.download', '.bid',
            '.win', '.review', '.trade', '.webcam', '.science',
            '.party', '.racing', '.online', '.site', '.website',
            '.space', '.tech', '.store', '.shop', '.click', '.gq',
            '.cfd', '.stream', '.gdn', '.mom', '.work', '.bond',
            '.repl', '.host', '.press', '.cam', '.life'
        ]
        
        # URL shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl', 'tiny.cc', 'ow.ly', 'is.gd',
            'buff.ly', 'short.link', 'rb.gy', 'shorturl', 'cutt.ly',
            'shorte.st', 'bc.vc', 'adf.ly', 'goo.gl',
            'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv'
        ]
        
        # Legitimate domains that should get 0% risk
        self.legitimate_domains = [
            'microsoft.com', 'google.com', 'amazon.com', 'apple.com', 
            'facebook.com', 'twitter.com', 'github.com', 'linkedin.com',
            'youtube.com', 'netflix.com', 'paypal.com', 'chase.com',
            'wellsfargo.com', 'bankofamerica.com', 'instagram.com',
            'whatsapp.com', 'spotify.com', 'yahoo.com', 'gmail.com',
            'outlook.com', 'ebay.com', 'bing.com', 'msn.com',
            'live.com', 'office.com', 'microsoftonline.com'
        ]
        
        # ========== BRAND IMPERSONATION DETECTION ==========
        # Brand protection list with common typos and variations
        self.brands = {
            'microsoft': ['microsoft', 'micr0soft', 'micros0ft', 'micr0s0ft', 'rnicrosoft', 'mlcrosoft', 'microsfot'],
            'google': ['google', 'g00gle', 'go0gle', 'g0ogle', 'googl', 'goog1e', 'googIe', 'g00g1e'],
            'paypal': ['paypal', 'paypa1', 'paypall', 'pay-pal', 'paypaI', 'paypaI', 'paypaI', 'paypa1'],
            'amazon': ['amazon', 'amaz0n', 'amazn', 'amzon', 'amaz0n', 'arnazon', 'amaz0n'],
            'facebook': ['facebook', 'faceb00k', 'face-book', 'faceb00k', 'faceb0ok', 'faceb00k', 'faceb00k'],
            'apple': ['apple', 'app1e', 'appple', 'appIe', 'appIe', 'app1e'],
            'netflix': ['netflix', 'netfl1x', 'netfllx', 'netfIix', 'netfl1x', 'netfIix'],
            'chase': ['chase', 'chase-bank', 'chaseonline', 'chaseonIine', 'chase0nline'],
            'wellsfargo': ['wellsfargo', 'wellsfarg0', 'wells-fargo', 'weIIsfargo', 'wellsfarg0'],
            'instagram': ['instagram', 'instagrarn', 'instagrarn', 'instagrarn'],
            'linkedin': ['linkedin', 'linkedln', 'linkedin', 'linkedln', 'linked1n'],
            'twitter': ['twitter', 'twltter', 'twltter', 'tw1tter'],
            'github': ['github', 'gitbub', 'gitbub', 'g1thub'],
            'yahoo': ['yahoo', 'yah00', 'yaho0', 'yah0o'],
            'gmail': ['gmail', 'grnail', 'gmaIl', 'gma1l'],
            'outlook': ['outlook', 'outIook', 'outIook', '0utlook'],
            'ebay': ['ebay', 'ebay', 'ebay', 'ebay'],
        }
        
        # Visual similarity mappings for homograph attacks
        self.visual_replacements = {
            '0': 'o',     # zero looks like o
            '1': 'l',     # one looks like l
            '3': 'e',     # three looks like e
            '4': 'a',     # four looks like a
            '5': 's',     # five looks like s
            '7': 't',     # seven looks like t
            '8': 'b',     # eight looks like b
            'rn': 'm',    # rn looks like m
            'vv': 'w',    # vv looks like w
            'cl': 'd',    # cl looks like d
            'I': 'l',     # capital I looks like l
            '|': 'l',     # pipe looks like l
            '€': 'e',     # Euro sign looks like e
        }
        
        print("✅ URLAnalyzer initialized with brand impersonation and subdomain detection")
    
    def check_brand_impersonation(self, domain, subdomain):
        """Check if domain is impersonating a known brand"""
        domain_lower = domain.lower()
        subdomain_lower = subdomain.lower()
        full_domain = f"{subdomain}.{domain}" if subdomain else domain
        full_domain_lower = full_domain.lower()
        
        score = 0
        findings = []
        
        # ========== CHECK 1: SUSPICIOUS SUBDOMAINS ==========
        # Check if subdomain contains brand names (phishing tactic)
        if subdomain_lower:
            for brand in self.brands.keys():
                if brand in subdomain_lower:
                    score += 50
                    findings.append(f"🚨 Suspicious subdomain: '{subdomain}' contains '{brand}' - common phishing tactic")
                    break
            
            # Check for multiple hyphens in subdomain
            if subdomain_lower.count('-') > 2:
                score += 20
                findings.append(f"⚠️ Multiple hyphens in subdomain: '{subdomain}' - unusual")
        
        # ========== CHECK 2: MULTIPLE BRAND REFERENCES ==========
        brand_count = 0
        brands_found = []
        for brand in self.brands.keys():
            if brand in full_domain_lower:
                brand_count += 1
                brands_found.append(brand)
        
        if brand_count > 1:
            score += 60
            findings.append(f"⚠️ Multiple brand references ({', '.join(brands_found)}) - highly suspicious")
        
        # ========== CHECK 3: BRAND IN DOMAIN WITH SUBDOMAIN ==========
        # If domain has subdomain and contains brand, it's suspicious
        if subdomain_lower and any(brand in domain_lower for brand in self.brands.keys()):
            score += 40
            findings.append(f"⚠️ Brand name in main domain with subdomain - potential phishing")
        
        # ========== CHECK 4: DIRECT BRAND IMPERSONATION ==========
        # Remove common prefixes/suffixes for cleaner matching
        clean_domain = re.sub(r'^(www\.|secure\.|login\.|account\.|verify\.|my\.|auth\.)', '', domain_lower)
        clean_domain = re.sub(r'\.(com|org|net|tk|ml|ga|cf|xyz|top|club|online|site)$', '', clean_domain)
        
        for brand, variations in self.brands.items():
            # DIRECT CHECK: If brand name appears in domain but it's not the exact official domain
            if brand in clean_domain and brand != clean_domain:
                # Calculate how much it looks like the brand
                similarity = len(brand) / len(clean_domain) if len(clean_domain) > 0 else 0
                if similarity > 0.5:  # At least 50% similar
                    score += 45
                    findings.append(f"🎭 Brand impersonation: '{domain}' contains '{brand}' but is not official site")
                    continue
            
            # VARIATION CHECK: Check against known typos
            for variation in variations:
                if variation in clean_domain:
                    score += 55
                    findings.append(f"🔍 Known typosquat: '{domain}' uses '{variation}' to mimic '{brand}'")
                    break
            
            # CHARACTER SUBSTITUTION CHECK: Replace visual tricks and check again
            normalized = clean_domain
            for char, replacement in self.visual_replacements.items():
                normalized = normalized.replace(char, replacement)
            
            # If after normalization it matches a brand but original doesn't, it's a spoof
            if normalized != clean_domain:
                for brand_name in self.brands.keys():
                    if brand_name in normalized and brand_name not in clean_domain:
                        # Calculate similarity to avoid false positives
                        similarity = len(brand_name) / len(clean_domain) if len(clean_domain) > 0 else 0
                        if similarity > 0.6:
                            score += 65
                            findings.append(f"👁️ Homograph attack: '{domain}' uses visual tricks to look like '{brand_name}'")
                            break
        
        # ========== CHECK 5: NUMBER SUBSTITUTION PATTERNS ==========
        for brand_name in self.brands.keys():
            # Create a version with common substitutions
            substituted = brand_name
            substituted = substituted.replace('o', '0')
            substituted = substituted.replace('l', '1')
            substituted = substituted.replace('e', '3')
            substituted = substituted.replace('a', '4')
            substituted = substituted.replace('s', '5')
            substituted = substituted.replace('t', '7')
            
            if substituted in clean_domain and brand_name not in clean_domain:
                score += 70
                findings.append(f"🔢 Number substitution: '{domain}' uses numbers to mimic '{brand_name}'")
                break
        
        return min(score, 100), findings
    
    def analyze(self, url):
        """Main URL analysis function"""
        if not url:
            return 0, ["❌ No URL provided"]
        
        findings = []
        score = 0
        
        # Clean the URL
        url = url.strip()
        findings.append(f"🔗 Analyzing: {url}")
        
        # Add protocol if missing for parsing
        if not url.startswith(('http://', 'https://')):
            url_with_proto = 'http://' + url
        else:
            url_with_proto = url
        
        try:
            # Parse URL
            parsed = urlparse(url_with_proto)
            extracted = tldextract.extract(url_with_proto)
            
            domain_full = f"{extracted.domain}.{extracted.suffix}"
            domain_name = extracted.domain.lower()
            subdomain = extracted.subdomain.lower()
            tld = extracted.suffix.lower()
            
            findings.append(f"📌 Domain: {domain_full}")
            if subdomain:
                findings.append(f"📌 Subdomain: {subdomain}")
            
            # ===== EARLY EXIT FOR LEGITIMATE DOMAINS =====
            # If this is a known legitimate domain, return 0% immediately
            for legit in self.legitimate_domains:
                if legit == domain_full:  # Exact match only
                    findings.append(f"✅ Verified legitimate domain: {legit}")
                    findings.insert(0, f"✅ SAFE SCORE: 0% - LEGITIMATE DOMAIN")
                    return 0, findings
            
            # ========== CHECK 1: IP ADDRESS ==========
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain_name):
                score += 40
                findings.append("🔴 HIGH: Uses IP address instead of domain name")
            
            # ========== CHECK 2: SUSPICIOUS TLD ==========
            if f".{tld}" in self.risky_tlds:
                score += 40
                findings.append(f"🔴 HIGH: Suspicious TLD .{tld} (commonly used in scams)")
            
            # ========== CHECK 3: URL SHORTENER ==========
            for shortener in self.url_shorteners:
                if shortener in domain_full:
                    score += 50
                    findings.append(f"🔴 HIGH: URL shortener ({shortener}) - hides real destination")
                    break
            
            # ========== CHECK 4: BRAND IMPERSONATION (WITH SUBDOMAIN) ==========
            brand_score, brand_findings = self.check_brand_impersonation(domain_full, subdomain)
            if brand_score > 0:
                score += brand_score
                findings.extend([f"⚠️ {f}" for f in brand_findings])
            
            # ========== CHECK 5: TYPOSQUATTING (Legacy) ==========
            # Only run if brand detection didn't already catch it
            if brand_score < 40:
                for brand, typos in self.brands.items():
                    # Check for common typos
                    for typo in typos:
                        if typo in domain_name and brand not in domain_name:
                            score += 40
                            findings.append(f"🔴 HIGH: Typosquatting detected - '{typo}' looks like '{brand}'")
                            break
                    
                    # Check for leetspeak (paypa1, amaz0n, etc.)
                    leet_version = brand.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0')
                    if leet_version in domain_name and brand not in domain_name:
                        score += 45
                        findings.append(f"🔢 Numbers replacing letters - common scam tactic")
                        break
            
            # ========== CHECK 6: HYPHENS IN DOMAIN ==========
            if '-' in domain_name and len(domain_name.split('-')) > 2:
                score += 15
                findings.append(f"⚠️ Multiple hyphens in domain - unusual for legitimate sites")
            elif '-' in domain_name and any(brand in domain_name for brand in self.brands.keys()):
                score += 20
                findings.append(f"⚠️ Hyphenated domain with brand name - suspicious")
            
            # ========== CHECK 7: DOMAIN AGE ==========
            try:
                w = whois.whois(domain_full)
                if w.creation_date:
                    if isinstance(w.creation_date, list):
                        creation_date = w.creation_date[0]
                    else:
                        creation_date = w.creation_date
                    
                    if isinstance(creation_date, datetime.datetime):
                        age_days = (datetime.datetime.now() - creation_date).days
                        
                        if age_days < 7:
                            score += 50
                            findings.append(f"🔴 HIGH: Domain created ONLY {age_days} days ago!")
                        elif age_days < 30:
                            score += 40
                            findings.append(f"🔴 HIGH: Domain created {age_days} days ago (very new)")
                        elif age_days < 90:
                            score += 20
                            findings.append(f"⚠️ Domain age: {age_days} days (relatively new)")
                        elif age_days < 365:
                            findings.append(f"📅 Domain age: {age_days} days (less than a year)")
                        else:
                            findings.append(f"✅ Domain age: {age_days//365} years (established)")
                else:
                    score += 30
                    findings.append("⚠️ Could not determine domain age - suspicious")
                    
            except Exception as e:
                score += 35
                findings.append("⚠️ Domain WHOIS lookup failed - often means domain is suspicious")
            
            # ========== CHECK 8: HTTPS ==========
            if not url.startswith('https://'):
                score += 15
                findings.append("⚠️ No HTTPS - connection not encrypted")
            else:
                findings.append("✅ HTTPS secure connection")
            
            # ========== CHECK 9: SUSPICIOUS PATTERNS ==========
            if '@' in url:
                score += 30
                findings.append("⚠️ Contains '@' - could redirect to different site")
            
            # Count dots in full domain (including subdomains)
            dot_count = (subdomain + '.' + domain_full).count('.')
            if dot_count > 3:
                score += 20
                findings.append(f"⚠️ Excessive subdomains ({dot_count} dots) - unusual for legitimate sites")
            elif dot_count > 2:
                score += 10
                findings.append(f"⚠️ Multiple subdomains ({dot_count} dots)")
            
            # Long URL
            if len(url) > 100:
                score += 5
                findings.append(f"📏 Unusually long URL ({len(url)} chars)")
            
            # ========== CHECK 10: VISUAL SPOOFING / HOMOGLYPHS ==========
            visual_score, visual_findings = self.visual_detector.analyze_domain(domain_full)
            if visual_score > 0:
                score += visual_score
                for finding in visual_findings:
                    findings.append(f"👁️ {finding}")
            
        except Exception as e:
            score += 30
            findings.append(f"❌ Error analyzing URL: {str(e)[:50]}")
        
        # ========== FINAL SAFETY NET ==========
        # Check for obvious brand impersonation patterns
        full_domain_for_check = f"{subdomain}.{domain_name}.{tld}" if subdomain else f"{domain_name}.{tld}"
        
        for brand in self.brands.keys():
            # Check for brand in subdomain
            if subdomain and brand in subdomain:
                score = max(score, 75)
                if not any("Suspicious subdomain" in f for f in findings):
                    findings.append(f"🔴 CRITICAL: Subdomain contains '{brand}' - definite phishing attempt")
            
            # Check for multiple brand appearances
            brand_occurrences = full_domain_for_check.lower().count(brand)
            if brand_occurrences > 1:
                score = max(score, 80)
                findings.append(f"🔴 CRITICAL: Multiple '{brand}' references - definite scam")
            
            # Check for brand with character substitution
            brand_with_zeros = brand.replace('o', '0').replace('i', '1').replace('e', '3')
            if brand_with_zeros in full_domain_for_check and brand not in full_domain_for_check:
                score = max(score, 85)
                findings.append(f"🔴 CRITICAL: '{full_domain_for_check}' strongly resembles '{brand}' - likely phishing")
        
        # Cap score at 100
        score = min(score, 100)
        
        # Add summary at top based on score
        if score >= 80:
            findings.insert(0, f"🔴 CRITICAL RISK: {score}% - DEFINITE SCAM!")
        elif score >= 60:
            findings.insert(0, f"🔴 HIGH RISK: {score}% - VERY LIKELY SCAM")
        elif score >= 40:
            findings.insert(0, f"🟡 MEDIUM RISK: {score}% - SUSPICIOUS")
        elif score >= 20:
            findings.insert(0, f"🟢 LOW RISK: {score}% - PROBABLY SAFE")
        else:
            findings.insert(0, f"✅ SAFE: {score}% - LEGITIMATE DOMAIN")
        
        return score, findings
    
    def get_risk_level(self, score):
        """Get risk level text"""
        if score >= 80:
            return "🔴 CRITICAL RISK"
        elif score >= 60:
            return "🔴 HIGH RISK"
        elif score >= 40:
            return "🟡 MEDIUM RISK"
        elif score >= 20:
            return "🟢 LOW RISK"
        else:
            return "✅ SAFE"