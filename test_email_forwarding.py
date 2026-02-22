# test_email_forwarding.py
from email_server import EmailForwardingServer

server = EmailForwardingServer()

# Test with fake job scam
test_content = """
From: hr@globalcareers-hiring.tk
Job Offer - Work From Home $5000/Month
Congratulations! Data entry position.
Pay security deposit of $100 via gift card.
Send Google Play gift card codes.
Visit: jobs-globalcareers.tk/register
"""

result = server.analyze_forwarded_email(
    "krishnaeclipsee@gmail.com",
    "#scan Test",
    test_content
)

print(f"Score: {result['score']}")
print(f"Risk: {result['risk_level']}")
print(f"Findings: {result['findings']}")