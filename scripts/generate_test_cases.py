# generate_test_cases.py
import sys
import os
# Forces Python to recognize the parent directory as the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import email.message
import email.utils
import time

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'test_emails', 'v50'))
os.makedirs(OUTPUT_DIR, exist_ok=True)

def create_eml(filename, sender, to, subject, body, origin_ip, attachment_name=None, attachment_payload=None):
    msg = email.message.EmailMessage()
    msg['From'] = sender
    msg['To'] = to
    msg['Subject'] = subject
    msg['Date'] = email.utils.formatdate(localtime=True)
    msg['Message-ID'] = email.utils.make_msgid()
    
    # Inject the origin IP into the Received header to test our MaxMind/GeoIP routing
    msg.add_header('Received', f'from mail.server.com ([{origin_ip}]) by mx.yourorg.com with ESMTP id 12345; {email.utils.formatdate(localtime=True)}')
    
    msg.set_content(body)
    
    if attachment_name and attachment_payload:
        msg.add_attachment(
            attachment_payload,
            maintype='application',
            subtype='octet-stream',
            filename=attachment_name
        )
        
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, 'wb') as f:
        f.write(bytes(msg))
    print(f"[+] Generated: {filepath}")

print("Generating Forensic Test Cases...\n")

# 1. Benign Corporate Email (Control)
create_eml(
    "01_benign_newsletter.eml",
    "HR Department <hr@yourorg.com>",
    "employee@yourorg.com",
    "Weekly Corporate Newsletter - Q3 Update",
    "Hello team, please find the standard updates for this week on the intranet. Have a great weekend!",
    "198.51.100.44"
)

# 2. Executive Display Name Spoofing
create_eml(
    "02_spoof_ceo_wire.eml",
    '"Satya Nadella" <attacker-domain-77@freemail.ru>',
    "finance@yourorg.com",
    "URGENT: Wire Transfer Required",
    "I am in a meeting. Process a wire transfer of $50,000 to the attached vendor immediately. Do not call me.",
    "45.33.32.156" # Random suspicious IP
)

# 3. Malicious Payload (.exe extension)
create_eml(
    "03_malicious_payload.eml",
    "Vendor Invoicing <no-reply@vendor-billing-update.com>",
    "accounts@yourorg.com",
    "OVERDUE: Invoice #99482",
    "Your account is past due. Please review the attached invoice immediately to avoid service suspension.",
    "103.45.67.89",
    attachment_name="invoice_99482.pdf.exe",
    attachment_payload=b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00" # Fake Windows executable header
)

# 4 & 5. Coordinated Attack Campaign (Phase 10 Correlation Trigger)
# Both of these emails come from DIFFERENT senders, but share the EXACT same origin IP (A known Tor Exit Node).
# Your Graph Correlation engine will detect this and link them together in the UI!
TOR_EXIT_IP = "185.220.101.5"

create_eml(
    "04_campaign_alpha.eml",
    "IT Support <helpdesk-alert@it-verify-login.com>",
    "user1@yourorg.com",
    "Password Expiry Notice",
    "Your password expires in 2 hours. Click here to verify your credentials: http://it-verify-login.com/auth",
    TOR_EXIT_IP
)

create_eml(
    "05_campaign_beta.eml",
    "Security Team <sec-ops@it-verify-login.com>",
    "user2@yourorg.com",
    "Unusual Login Detected",
    "We detected a login from Russia. If this wasn't you, secure your account: http://it-verify-login.com/auth",
    TOR_EXIT_IP
)

print("\nDone! Test suite ready in the 'test_emails' folder.")