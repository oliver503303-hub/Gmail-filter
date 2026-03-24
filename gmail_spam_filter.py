"""
Gmail Spam Filter
-----------------
Scans your Gmail inbox and separates emails into:
  - IMPORTANT: kept/starred in inbox
  - SPAM: moved to spam folder

Setup:
1. Go to https://console.cloud.google.com/
2. Create a project → Enable Gmail API
3. Create OAuth 2.0 credentials (Desktop App)
4. Download as 'credentials.json' and place in this directory
5. Run: python gmail_spam_filter.py
"""

import os
import json
import re
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

SCOPES = ['https://mail.google.com/']

# --- Spam detection rules ---
SPAM_KEYWORDS = [
    'win', 'winner', 'prize', 'lottery', 'free money', 'click here',
    'unsubscribe', 'limited offer', 'act now', 'earn cash', 'make money',
    'weight loss', 'diet pill', 'viagra', 'casino', 'crypto investment',
    'nigerian prince', 'inheritance', 'claim your reward', 'you have been selected',
    'congratulations you', 'dear friend', 'hot singles', 'enlargement',
    'risk free', '100% free', 'satisfaction guaranteed', 'no credit check',
    'work from home', 'be your own boss', 'multi-level', 'mlm',
]

IMPORTANT_KEYWORDS = [
    'invoice', 'receipt', 'payment', 'order', 'shipping', 'delivery',
    'appointment', 'meeting', 'calendar', 'schedule', 'interview',
    'job offer', 'contract', 'agreement', 'urgent', 'important',
    'password reset', 'verification', 'security alert', 'bank', 'tax',
    'doctor', 'hospital', 'prescription', 'insurance', 'legal',
    'github', 'gitlab', 'jira', 'slack', 'zoom',
]

SPAM_SENDER_PATTERNS = [
    r'no.?reply@.*\.(xyz|top|click|bid|loan|work|gq|tk|ml|ga|cf)',
    r'.*@.*\.(xyz|top|click|bid|loan|work)',
    r'noreply@bulk.*',
    r'promo@.*',
    r'marketing@.*',
    r'newsletter@.*',
    r'offers@.*',
    r'deals@.*',
]


def get_gmail_service():
    """Authenticate and return Gmail service."""
    creds = None

    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials.json'):
                print("\n ERROR: credentials.json not found!")
                print("\nTo get credentials:")
                print("1. Go to https://console.cloud.google.com/")
                print("2. Create a project and enable the Gmail API")
                print("3. Go to APIs & Services > Credentials")
                print("4. Create OAuth 2.0 Client ID (Desktop App)")
                print("5. Download JSON and save as 'credentials.json' here")
                raise FileNotFoundError("credentials.json required")

            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())
        print("Authentication saved to token.json")

    return build('gmail', 'v1', credentials=creds)


def get_message_details(service, msg_id):
    """Fetch subject, sender, and snippet for a message."""
    msg = service.users().messages().get(
        userId='me', id=msg_id, format='metadata',
        metadataHeaders=['Subject', 'From']
    ).execute()

    headers = {h['name']: h['value'] for h in msg['payload']['headers']}
    return {
        'id': msg_id,
        'subject': headers.get('Subject', '(no subject)'),
        'sender': headers.get('From', ''),
        'snippet': msg.get('snippet', ''),
        'labels': msg.get('labelIds', []),
    }


def is_spam(email):
    """Heuristic spam detection. Returns (is_spam: bool, reason: str)."""
    text = f"{email['subject']} {email['snippet']}".lower()
    sender = email['sender'].lower()

    # Already labeled by Gmail
    if 'SPAM' in email['labels']:
        return True, "already in spam"
    if 'IMPORTANT' in email['labels']:
        return False, "marked important by Gmail"

    # Check important keywords first (higher priority)
    for kw in IMPORTANT_KEYWORDS:
        if kw in text:
            return False, f"important keyword: '{kw}'"

    # Check spam sender patterns
    for pattern in SPAM_SENDER_PATTERNS:
        if re.search(pattern, sender, re.IGNORECASE):
            return True, f"spam sender pattern: {pattern}"

    # Check spam keywords
    matches = [kw for kw in SPAM_KEYWORDS if kw in text]
    if len(matches) >= 2:
        return True, f"spam keywords: {matches[:3]}"

    return False, "no spam signals"


def move_to_spam(service, msg_id):
    """Move a message to the spam folder."""
    service.users().messages().modify(
        userId='me',
        id=msg_id,
        body={
            'addLabelIds': ['SPAM'],
            'removeLabelIds': ['INBOX'],
        }
    ).execute()


def star_message(service, msg_id):
    """Star an important message."""
    service.users().messages().modify(
        userId='me',
        id=msg_id,
        body={'addLabelIds': ['STARRED']},
    ).execute()


def scan_inbox(service, max_emails=50, dry_run=True):
    """Scan inbox and classify emails."""
    print(f"\nScanning inbox (max {max_emails} emails)...")
    print(f"Mode: {'DRY RUN (no changes)' if dry_run else 'LIVE (will move spam)'}\n")

    results = service.users().messages().list(
        userId='me',
        labelIds=['INBOX'],
        maxResults=max_emails
    ).execute()

    messages = results.get('messages', [])
    if not messages:
        print("No messages found in inbox.")
        return

    important = []
    spam = []

    for i, msg_ref in enumerate(messages, 1):
        email = get_message_details(service, msg_ref['id'])
        spam_flag, reason = is_spam(email)

        if spam_flag:
            spam.append((email, reason))
        else:
            important.append((email, reason))

        print(f"[{i}/{len(messages)}] {email['subject'][:50]:<50} → {'SPAM' if spam_flag else 'IMPORTANT'}")

    print(f"\n{'='*60}")
    print(f"RESULTS: {len(important)} important | {len(spam)} spam")
    print(f"{'='*60}")

    print(f"\n IMPORTANT emails ({len(important)}):")
    for email, reason in important[:10]:
        print(f"  From: {email['sender'][:40]}")
        print(f"  Subj: {email['subject'][:55]}")
        print(f"  Why:  {reason}\n")

    print(f"\n SPAM emails ({len(spam)}):")
    for email, reason in spam[:10]:
        print(f"  From: {email['sender'][:40]}")
        print(f"  Subj: {email['subject'][:55]}")
        print(f"  Why:  {reason}\n")

    if not dry_run and spam:
        print(f"\nMoving {len(spam)} spam emails to spam folder...")
        for email, _ in spam:
            move_to_spam(service, email['id'])
        print(f"Done! Moved {len(spam)} emails to spam.")

        print(f"\nStarring {len(important)} important emails...")
        for email, _ in important:
            if 'STARRED' not in email['labels']:
                star_message(service, email['id'])
        print(f"Done! Starred {len(important)} important emails.")

    elif dry_run and spam:
        print("\nDRY RUN — no changes made.")
        print("Run with --apply to actually move spam and star important emails.")

    # Save report
    report = {
        'scanned': len(messages),
        'important': [{'subject': e['subject'], 'sender': e['sender'], 'reason': r} for e, r in important],
        'spam': [{'subject': e['subject'], 'sender': e['sender'], 'reason': r} for e, r in spam],
    }
    with open('spam_filter_report.json', 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to spam_filter_report.json")


if __name__ == '__main__':
    import sys

    apply_changes = '--apply' in sys.argv
    max_emails = 50
    for arg in sys.argv:
        if arg.startswith('--max='):
            max_emails = int(arg.split('=')[1])

    service = get_gmail_service()
    scan_inbox(service, max_emails=max_emails, dry_run=not apply_changes)
