import json
import hashlib
import datetime
import os
from pathlib import Path
from typing import Dict, List, Optional, Any
import pandas as pd
from collections import Counter

class AlertNetwork:
    """Community-powered scam alert system"""
    
    def __init__(self, data_dir: str = "alert_data"):
        """Initialize the alert network with a data directory"""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        # File paths
        self.alerts_file = self.data_dir / "scam_alerts.json"
        self.blocklist_file = self.data_dir / "community_blocklist.json"
        self.stats_file = self.data_dir / "alert_stats.json"
        
        # Initialize files if they don't exist
        self._initialize_files()
        
        # Load existing data
        self.alerts = self._load_json(self.alerts_file, [])
        self.blocklist = self._load_json(self.blocklist_file, {})
        self.stats = self._load_json(self.stats_file, self._get_default_stats())
    
    def _initialize_files(self):
        """Create data files if they don't exist"""
        if not self.alerts_file.exists():
            self._save_json(self.alerts_file, [])
        if not self.blocklist_file.exists():
            self._save_json(self.blocklist_file, {})
        if not self.stats_file.exists():
            self._save_json(self.stats_file, self._get_default_stats())
    
    def _get_default_stats(self):
        """Return default statistics structure"""
        return {
            "total_reports": 0,
            "unique_scams": 0,
            "top_scam_types": {},
            "top_targeted_platforms": {},
            "reports_by_day": {},
            "last_updated": str(datetime.datetime.now())
        }
    
    def _load_json(self, filepath, default):
        """Load JSON data from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return default
    
    def _save_json(self, filepath, data):
        """Save JSON data to file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def _generate_scam_hash(self, scam_data: Dict) -> str:
        """Generate unique hash for a scam based on its content"""
        # Create a string from key identifying features
        identifying_string = f"{scam_data.get('url', '')}|{scam_data.get('title', '')}|{scam_data.get('content', '')[:200]}"
        return hashlib.sha256(identifying_string.encode()).hexdigest()[:16]
    
    def report_scam(self, 
                    reporter_id: str,
                    scam_type: str,
                    url: str = "",
                    title: str = "",
                    content: str = "",
                    platform: str = "unknown",
                    screenshot: Optional[str] = None,
                    additional_info: Dict = None) -> Dict:
        """
        Report a new scam to the community network
        
        Args:
            reporter_id: Anonymous user ID or email
            scam_type: Type of scam (phishing, fake store, impersonation, etc.)
            url: URL where scam was found
            title: Title of the scam content
            content: Description or content of the scam
            platform: Platform where scam was found (email, website, social media)
            screenshot: Base64 encoded screenshot (optional)
            additional_info: Any additional information
            
        Returns:
            Dict with report status and scam hash
        """
        if additional_info is None:
            additional_info = {}
            
        # Generate unique hash for this scam
        scam_hash = self._generate_scam_hash({
            'url': url,
            'title': title,
            'content': content
        })
        
        # Check if this scam was already reported
        existing_alert = self._find_existing_alert(scam_hash, url)
        
        if existing_alert:
            # Update existing alert with new report
            existing_alert['report_count'] += 1
            existing_alert['last_reported'] = str(datetime.datetime.now())
            existing_alert['reporter_ids'].append(reporter_id)
            
            # Update confidence score based on reports
            confidence = min(existing_alert['report_count'] * 10, 99)
            existing_alert['community_confidence'] = confidence
            
            # Add to blocklist if confidence is high
            if confidence >= 70 and url and url not in self.blocklist:
                self._add_to_blocklist(url, scam_hash, scam_type, confidence)
            
            status = "updated"
            scam_id = existing_alert['scam_id']
        else:
            # Create new alert
            scam_id = scam_hash
            new_alert = {
                'scam_id': scam_id,
                'scam_type': scam_type,
                'url': url,
                'title': title,
                'content': content,
                'platform': platform,
                'first_reported': str(datetime.datetime.now()),
                'last_reported': str(datetime.datetime.now()),
                'report_count': 1,
                'reporter_ids': [reporter_id],
                'community_confidence': 10,  # Start with 10% confidence
                'screenshot': screenshot,
                'additional_info': additional_info,
                'status': 'active'  # active, confirmed, false_positive
            }
            self.alerts.append(new_alert)
            
            # If URL is provided, add to blocklist with initial confidence
            if url:
                self._add_to_blocklist(url, scam_id, scam_type, 10)
            
            status = "new"
        
        # Update statistics
        self._update_stats(scam_type, platform)
        
        # Save all data
        self._save_json(self.alerts_file, self.alerts)
        self._save_json(self.blocklist_file, self.blocklist)
        self._save_json(self.stats_file, self.stats)
        
        return {
            'status': status,
            'scam_id': scam_id,
            'message': f"Scam reported successfully! Community confidence: {self._get_confidence(scam_id)}%",
            'community_confidence': self._get_confidence(scam_id)
        }
    
    def _find_existing_alert(self, scam_hash: str, url: str) -> Optional[Dict]:
        """Find if a scam already exists in the database"""
        # First try by hash
        for alert in self.alerts:
            if alert.get('scam_id') == scam_hash:
                return alert
        
        # If URL is provided, try by URL
        if url:
            for alert in self.alerts:
                if alert.get('url') == url and url:
                    return alert
        
        return None
    
    def _add_to_blocklist(self, url: str, scam_id: str, scam_type: str, confidence: int):
        """Add a URL to the community blocklist"""
        self.blocklist[url] = {
            'scam_id': scam_id,
            'scam_type': scam_type,
            'confidence': confidence,
            'added': str(datetime.datetime.now()),
            'report_count': self._get_report_count(scam_id)
        }
    
    def _update_stats(self, scam_type: str, platform: str):
        """Update statistics with new report"""
        today = datetime.datetime.now().strftime('%Y-%m-%d')
        
        # Update total reports
        self.stats['total_reports'] += 1
        self.stats['unique_scams'] = len(self.alerts)
        
        # Update scam type counts
        self.stats['top_scam_types'][scam_type] = self.stats['top_scam_types'].get(scam_type, 0) + 1
        
        # Update platform counts
        self.stats['top_targeted_platforms'][platform] = self.stats['top_targeted_platforms'].get(platform, 0) + 1
        
        # Update daily reports
        self.stats['reports_by_day'][today] = self.stats['reports_by_day'].get(today, 0) + 1
        
        # Keep only last 30 days of daily stats
        if len(self.stats['reports_by_day']) > 30:
            oldest = min(self.stats['reports_by_day'].keys())
            del self.stats['reports_by_day'][oldest]
        
        self.stats['last_updated'] = str(datetime.datetime.now())
    
    def _get_report_count(self, scam_id: str) -> int:
        """Get the number of reports for a specific scam"""
        for alert in self.alerts:
            if alert['scam_id'] == scam_id:
                return alert['report_count']
        return 0
    
    def _get_confidence(self, scam_id: str) -> int:
        """Get community confidence for a scam"""
        for alert in self.alerts:
            if alert['scam_id'] == scam_id:
                return alert['community_confidence']
        return 0
    
    def check_url(self, url: str) -> Dict:
        """Check if a URL is in the community blocklist"""
        if url in self.blocklist:
            block_info = self.blocklist[url]
            return {
                'blocked': True,
                'confidence': block_info['confidence'],
                'scam_type': block_info['scam_type'],
                'report_count': block_info['report_count'],
                'message': f"This URL has been reported {block_info['report_count']} times as a {block_info['scam_type']} scam"
            }
        return {'blocked': False}
    
    def check_content(self, content: str) -> Dict:
        """Check if content matches any reported scams"""
        content_lower = content.lower()
        matches = []
        
        for alert in self.alerts:
            # Simple content matching (can be enhanced with ML later)
            alert_content = alert.get('content', '').lower()
            if alert_content and len(alert_content) > 50:  # Only check substantial content
                # Check for significant overlap
                words = set(alert_content.split())
                content_words = set(content_lower.split())
                common_words = words.intersection(content_words)
                
                if len(common_words) >= 5:  # If 5+ words match
                    match_score = len(common_words) / len(words) * 100
                    if match_score > 30:  # If more than 30% content matches
                        matches.append({
                            'scam_id': alert['scam_id'],
                            'scam_type': alert['scam_type'],
                            'match_score': round(match_score, 2),
                            'confidence': alert['community_confidence']
                        })
        
        if matches:
            # Sort by match score
            matches.sort(key=lambda x: x['match_score'], reverse=True)
            return {
                'matches_found': True,
                'matches': matches[:3],  # Return top 3 matches
                'warning': "This content matches previously reported scams"
            }
        
        return {'matches_found': False}
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """Get most recent scam alerts"""
        sorted_alerts = sorted(self.alerts, 
                             key=lambda x: x['last_reported'], 
                             reverse=True)
        return sorted_alerts[:limit]
    
    def get_top_scams(self, limit: int = 5) -> List[Dict]:
        """Get scams with most reports"""
        sorted_by_reports = sorted(self.alerts, 
                                  key=lambda x: x['report_count'], 
                                  reverse=True)
        return sorted_by_reports[:limit]
    
    def get_statistics(self) -> Dict:
        """Get community statistics"""
        return {
            'total_reports': self.stats['total_reports'],
            'unique_scams': self.stats['unique_scams'],
            'active_protections': len(self.blocklist),
            'top_scam_types': dict(Counter(self.stats['top_scam_types']).most_common(5)),
            'top_platforms': dict(Counter(self.stats['top_targeted_platforms']).most_common(5)),
            'reports_today': self.stats['reports_by_day'].get(
                datetime.datetime.now().strftime('%Y-%m-%d'), 0
            ),
            'last_updated': self.stats['last_updated']
        }

# Initialize global alert network instance
alert_network = AlertNetwork()