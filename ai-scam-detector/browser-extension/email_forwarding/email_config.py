# email_config.py - Email configuration settings

# Email server settings
EMAIL_SETTINGS = {
    'imap_server': 'imap.gmail.com',
    'imap_port': 993,
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'email_address': 'krishnaeclipsee@gmail.com',
    'email_password': 'pldq pywt fbpx qrhe',
    'scan_prefix': '#scan',
    'database_file': 'email_scans.db'
}

# Response templates (without emojis)
RESPONSE_TEMPLATES = {
    'high_risk': '''
HIGH RISK SCAM DETECTED!

Risk Score: {score}%
Confidence: CRITICAL

This email appears to be a SCAM!
DO NOT click any links or reply.

Risk Factors:
{findings}

Recommendations:
• Delete this email immediately
• Do not click any links
• If concerned about an account, visit the official website directly

Stay safe!
- AI Scam Detector Team
''',

    'medium_risk': '''
MEDIUM RISK DETECTED

Risk Score: {score}%
Confidence: SUSPICIOUS

This email shows suspicious patterns.

Risk Factors:
{findings}

Recommendations:
• Verify sender carefully
• Hover over links before clicking
• Don't provide personal information
• Contact the company directly if unsure

Stay vigilant!
- AI Scam Detector Team
''',

    'low_risk': '''
LOW RISK - APPEARS SAFE

Risk Score: {score}%
Confidence: SAFE

This email appears legitimate.

Risk Factors:
{findings}

Recommendations:
• Still verify sender address
• Be cautious with links
• Stay vigilant

Stay safe!
- AI Scam Detector Team
''',

    'error': '''
ERROR PROCESSING EMAIL

Sorry, we couldn't analyze your email.

Possible reasons:
• Email format not supported
• Technical error
• Empty content

Please try forwarding the complete email including headers.

- AI Scam Detector Team
'''
}
