# generate_50_test_cases.py
"""
Batch Forensic EML Generator (50 Synthetic Cases)
Generates 50 varied RFC 5322 compliant emails covering multiple threat vectors,
benign traffic, and multi-incident campaign clusters.
"""
import sys
import os
# Forces Python to recognize the parent directory as the project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import random
import hashlib
import email.message
import email.utils

OUTPUT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'test_emails', 'v50'))
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------
# INDICATOR POOLS & SHARED CAMPAIGN INFRASTRUCTURE
# ---------------------------------------------------------
# Shared IPs to trigger Phase 10 Graph Correlation clusters
CAMPAIGN_IPS = {
    "CAMP_TOR_01": "185.220.101.5",       # Tor Exit Node cluster
    "CAMP_BULLET_02": "91.240.118.172",   # Bulletproof hosting cluster
    "CAMP_BOTNET_03": "103.145.12.89",    # Compromised Asian ISP
    "CAMP_CLOUD_04": "45.33.32.156"       # Cloud VPS infrastructure
}

SHARED_PAYLOAD_HASHES = {
    "ransomware_dropper.exe": b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00" + b"A" * 128,
    "invoice_macro.xlsm": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"MACRO_VBA_PAYLOAD" * 8,
    "credentials_stealer.scr": b"MZ\x00\x00\x00\x00\x00\x00" + b"KEYLOGGER_STUB" * 16
}

EMPLOYEES = [
    "vikram.sharma@yourorg.com", "sneha.patel@yourorg.com", "arjun.nair@yourorg.com",
    "priya.iyer@yourorg.com", "rohit.verma@yourorg.com", "finance-desk@yourorg.com",
    "accounts-payable@yourorg.com", "hr-ops@yourorg.com", "compliance@yourorg.com"
]

BENIGN_SENDERS = [
    ("HR Operations", "hr-notifications@yourorg.com"),
    ("IT Helpdesk", "it-support@yourorg.com"),
    ("Vendor Billing", "invoicing@trustedpartner.in"),
    ("All-Hands Announcements", "internal-news@yourorg.com"),
    ("Meeting Scheduler", "calendar-notify@yourorg.com")
]

BENIGN_TOPICS = [
    ("Monthly All-Hands Meeting Agenda", "Team, please find the meeting agenda attached for Friday's town hall. Join via the internal portal link."),
    ("Updated Q3 Leave Policy", "HR has posted the updated leaves guidelines. Review the internal employee handbook for details."),
    ("Scheduled Server Maintenance Window", "IT will perform scheduled network updates Saturday between 02:00 and 04:00 UTC. Expect minor downtime."),
    ("Reimbursement Claims Deadline", "All travel expense reports for the current cycle must be submitted by EOD Wednesday."),
    ("Quarterly Team Lunch Planning", "Please vote on the preferred restaurant in the internal team poll before end of day.")
]

ATTACK_TEMPLATES = [
    # CEO Fraud / BEC
    {
        "type": "BEC_SPOOF",
        "sender_name": "Executive Director",
        "sender_addr": "director-exec@fastmail-secure.ru",
        "subject": "CONFIDENTIAL: Immediate Offshore Wire Transfer",
        "body": "I am traveling for an acquisition discussion. Need an urgent payment of INR 4,850,000 processed to the audit firm today. Keep this confidential and do not call me.",
        "risk_attachment": None
    },
    # Credential Harvesting
    {
        "type": "CRED_HARVEST",
        "sender_name": "Microsoft 365 Admin",
        "sender_addr": "security-update@ms-portal-auth365.net",
        "subject": "CRITICAL: Password Expiry & MFA Sync Failure",
        "body": "Your single sign-on token has expired. Session will be terminated within 60 minutes. Re-authenticate immediately via: https://login-microsoft-auth365.net/sync",
        "risk_attachment": None
    },
    # Malicious Payload Dropper
    {
        "type": "MALWARE_DROPPER",
        "sender_name": "Invoicing Clearinghouse",
        "sender_addr": "billing@tax-invoice-gateway.cc",
        "subject": "OVERDUE PAYMENT: Formal Legal Notice #INV-9812",
        "body": "Your outstanding tax payment is overdue. Attached is the certified demand notice. Open the document to verify transaction reconciliation.",
        "risk_attachment": ("Demand_Notice_INV9812.pdf.exe", "ransomware_dropper.exe")
    },
    # Invoice Fraud / Payment Diversion
    {
        "type": "INVOICE_FRAUD",
        "sender_name": "Logistics Dispatch Desk",
        "sender_addr": "accounts@freight-logistics-corp.com",
        "subject": "RE: Updated Banking Credentials for Wire Dispatch",
        "body": "Please note that our settlement banking credentials have changed due to mid-year compliance migration. Route all upcoming payments to the newly attached banking mandate.",
        "risk_attachment": ("New_Banking_Mandate.xlsm", "invoice_macro.xlsm")
    },
    # Quishing / Obfuscated Link
    {
        "type": "QUISHING_LINK",
        "sender_name": "Payroll Services",
        "sender_addr": "salary-disbursal@internal-payroll-gov.org",
        "subject": "Tax Deduction Revision Statement (Form 16/Annexure)",
        "body": "Discrepancy detected in your monthly income tax deduction. View your revised payslip and tax calculation statement: http://185.220.101.5/payroll/tax_audit.php",
        "risk_attachment": ("Payslip_Audit.scr", "credentials_stealer.scr")
    }
]

def make_random_ip():
    return f"{random.randint(11, 210)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def generate_batch(count=50):
    print("=" * 60)
    print(f"Generating {count} Synthetic RFC 5322 Forensic Test Cases...")
    print("=" * 60)

    generated = []

    for i in range(1, count + 1):
        msg = email.message.EmailMessage()
        target_employee = random.choice(EMPLOYEES)
        msg['To'] = target_employee
        msg['Date'] = email.utils.formatdate(localtime=True)
        msg['Message-ID'] = email.utils.make_msgid(domain="forensic-lab.local")

        # 30% Benign, 70% Malicious / Correlated Attacks
        is_benign = (i <= 15)

        if is_benign:
            name, addr = random.choice(BENIGN_SENDERS)
            subj, body = random.choice(BENIGN_TOPICS)
            origin_ip = f"192.168.1.{random.randint(20, 200)}"
            filename = f"case_{i:02d}_benign_{name.lower().replace(' ', '_')}.eml"
            
            msg['From'] = f'"{name}" <{addr}>'
            msg['Subject'] = f"{subj} [Ref #{random.randint(100, 999)}]"
            msg.add_header('Received', f'from mail.yourorg.com ([{origin_ip}]) by mx.yourorg.com; {email.utils.formatdate(localtime=True)}')
            msg.set_content(body)

        else:
            tpl = random.choice(ATTACK_TEMPLATES)
            # Assign to one of the 4 shared campaign infrastructure clusters to feed Phase 10 Graph Correlation
            cluster_key = random.choice(list(CAMPAIGN_IPS.keys()))
            origin_ip = CAMPAIGN_IPS[cluster_key] if random.random() < 0.65 else make_random_ip()
            
            filename = f"case_{i:02d}_{tpl['type'].lower()}_{cluster_key.lower()}.eml"
            
            msg['From'] = f'"{tpl["sender_name"]}" <{tpl["sender_addr"]}>'
            msg['Subject'] = f"{tpl['subject']} - Notice {i:03d}"
            msg.add_header('Received', f'from mailhost.threat-relay.net ([{origin_ip}]) by mx.yourorg.com with ESMTP id {random.randint(10000, 99999)}; {email.utils.formatdate(localtime=True)}')
            
            msg.set_content(tpl['body'])

            # Attach payload if template requires it
            if tpl["risk_attachment"]:
                att_name, payload_key = tpl["risk_attachment"]
                payload_bytes = SHARED_PAYLOAD_HASHES[payload_key]
                msg.add_attachment(
                    payload_bytes,
                    maintype="application",
                    subtype="octet-stream",
                    filename=att_name
                )

        filepath = os.path.join(OUTPUT_DIR, filename)
        with open(filepath, "wb") as f:
            f.write(bytes(msg))

        generated.append(filename)

    print(f"\n[✓] Successfully written 50 cases to '{OUTPUT_DIR}/':")
    print(f"    • 15 Benign Baseline Cases (Safe control group)")
    print(f"    • 35 Attack Cases spanning BEC, Ransomware, Credential Harvesting, and Quishing")
    print(f"    • Multi-target Campaign Clusters pre-wired to trigger Graph Correlation across shared IPs and payload hashes.")
    print("=" * 60)

if __name__ == "__main__":
    generate_batch(50)