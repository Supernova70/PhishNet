"""Generate data/hard_negatives.csv — curated modern samples the 2016-2018
Kaggle corpus lacks.

Two classes of hard cases:
  label 0 — legitimate notification/newsletter/digest/receipt traffic that
            the model false-positives on in the wild (Reddit digests,
            GitLab marketing, GitHub alerts, calendar invites, receipts).
  label 1 — modern phishing patterns the old corpus predates (QR-code
            scams, wallet drainers, MFA fatigue, payroll-change BEC).

Committed on purpose: these are synthetic samples, no user data.

Usage: python scripts/make_hard_negatives.py
"""

import csv
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "hard_negatives.csv"

LEGIT = [
    # ── Reddit / forum style digests ──────────────────────────────
    '''Your daily digest from Reddit: 12 new posts in communities you follow.
Top post today: "I finally understand the hype around Patel Neck" with 842 upvotes
and 96 comments. Reply directly from this email or open the app to join the
discussion. Manage your email preferences in account settings to choose how often
you hear from us.''',
    '''New comments on a thread you follow: user mountain_hiker replied "this fixed
my build issue, thanks!" See the full conversation on Reddit. You are receiving
this because you subscribed to comment notifications. Unsubscribe any time from
the notification settings page.''',
    '''Trending in r/webdev today: a thread about debugging CSS grid layouts reached
1.2k upvotes. Tap through to read the top answers, or browse your home feed for
more from the communities you care about.''',
    # ── Developer tool notifications ───────────────────────────────
    '''[GitLab] Get started with the Duo Agent Platform
Your complete 8-part implementation guide is ready. Learn how to embed specialized
AI agents throughout your DevSecOps lifecycle: refactoring routine tasks, running
security scans, integrating external tools through the Model Context Protocol, and
setting up event-driven triggers to automate workflows. Read the guide, then tell
us what you think. This email was sent because you opted in to product marketing.
Update your preferences or unsubscribe at any time.''',
    '''Dependabot alert: your repository has a medium severity advisory in lodash.
A patched release is available. Review the alert in the Security tab, merge the
proposed version bump, and the advisory will auto-close. You are receiving this
because you are the code owner for package.json.''',
    '''[GitHub] Review requested: pull request #482 "Fix flaky session refresh test"
in your repository. 3 files changed with 24 additions and 11 deletures. CI passed
on all required checks. Leave a review or merge when you are ready.''',
    '''New release published: v2.14.0 of your project is now available. Changes
include faster cold starts, a refreshed settings page, and 6 bug fixes. Full
release notes are on the releases page. This notification was sent to repository
maintainers.''',
    # ── Security / account notices ─────────────────────────────────
    '''Google: security alert. A new sign-in on Chrome OS was detected in Bengaluru,
India. If this was you, nothing to do. If not, review recent activity and change
your password immediately. This is an automated security notice sent to the
account recovery address.''',
    '''Your password was changed successfully. The change was made from a trusted
device on 2 October. If you did not make this change, contact support within
24 hours. Do not reply to this message.''',
    '''Two-factor authentication is now enabled on your account. Backup codes were
generated once and stored by you. Download new codes from the security settings
page if you have lost them.''',
    '''Your monthly account statement is ready to view. No payment is due this cycle.
Statements remain available online for 7 years. This is a service notification,
not a marketing email.''',
    # ── Calendar / meetings ────────────────────────────────────────
    '''Invitation: Quarterly planning review. Thursday, 9 October, 10:00-11:00 AM.
Location: Conference Room B / video link included. Please accept or decline so
the organiser can confirm catering. Agenda attached.''',
    '''Your meeting has been rescheduled: "Design sync" moved from Tuesday 2 PM to
Wednesday 11 AM at the same link. The organiser updated the time. No action is
needed unless the new slot conflicts with your calendar.''',
    '''Reminder: your 1:1 with your manager starts in 30 minutes. Notes document was
shared with you before the meeting. Reschedule from the calendar event if you
cannot attend.''',
    # ── Receipts / commerce ────────────────────────────────────────
    '''Order confirmation: your package has shipped. Estimated delivery Friday.
Tracking updates will follow by email and in the app. Items in this order:
one wireless keyboard, one USB-C hub. Thank you for shopping with us.''',
    '''Receipt from your ride: total charged 420.50 to your default card. Trip from
Indiranagar to Koramangala, 11.2 km, 28 minutes. Rate your driver in the app.
View trip details or request a fare review within 7 days.''',
    '''Payment received: invoice 00931 was paid in full. Balance due: 0.00. A copy
of the receipt is attached for your records. Your subscription renews on 14
November unless cancelled.''',
    '''Your seat is confirmed: flight 6E 214, Bengaluru to Hyderabad, 18 October,
boarding pass available in the app. Check-in opens 48 hours before departure.
Baggage allowance: 15 kg checked, 7 kg cabin.''',
    '''Booking confirmed: 2 nights, check-in 12 October, check-out 14 October.
Confirmation number 774129. Free cancellation until 10 October. Manage your
booking from the trips section of your account.''',
    # ── Newsletters ────────────────────────────────────────────────
    '''This week in your newsletter: five essays on distributed systems, a short
interview with a database internals engineer, and one job listing from a team
hiring backend engineers. Forward this to a friend if you enjoyed it. The web
version has all links.''',
    '''Issue 214: what we learned migrating off a monolith, a guide to writing
better incident reports, and three tools our readers recommend. Read online or
in your favorite feed reader. You are subscribed because you signed up on our
site.''',
    '''Your weekly learning digest: 3 new courses in your chosen track, one article
picked for you, and a reminder that your deadline for the current module is
Sunday. Continue where you left off from the dashboard.''',
    '''New episode: "The physics of cache invalidation" is now live, 47 minutes.
Listen in the app or on the web. New episodes arrive every Tuesday morning.
Follow the show to get notifications.''',
    '''Product update: search is now 3x faster, dark mode follows your system
setting, and offline drafts save automatically. See the changelog for the full
list of fixes in this release.''',
    # ── Notifications / reminders ──────────────────────────────────
    '''Your document has 3 new comments. Priya mentioned you: "can we simplify this
step?" Open the file to reply. Mentions notify you even when the document is not
shared with you directly.''',
    '''A file was shared with you: "Q4 roadmap draft". Open to view or request edit
access. Files you open are added to your recent list for quick access later.''',
    '''Your download is ready. The link expires in 7 days. If the download stops,
retry from the transfers page. Downloads from your account are logged for
security.''',
    '''Class starts tomorrow at 6 PM. Bring your notebook; we will cover regex
fundamentals and practice with live exercises. A recording will be posted for
people who cannot attend.''',
    '''Your library hold is ready for pickup: "Designing Data-Intensive Applications".
Collect it by 9 October from the central branch. Late fees are waived for holds
picked up on time.''',
    '''Flu shot reminder: appointments are available this week at your clinic.
Walk-ins welcome between 9 AM and 5 PM. This reminder is based on your recorded
preferences, you can turn it off in communication settings.''',
    '''Your vehicle service is due in 500 km. Book a slot from the app; pick-up and
drop-off are available at no extra cost inside city limits.''',
    '''Meter reading submitted successfully for period ending 30 September. Units
consumed: 214. Amount will be added to your next bill. View history in the usage
section.''',
    '''Exam results published: you scored 84 percent in Module 3. The certificate
unlocks once all modules are complete. Review the answer key before the next
attempt window opens.''',
    '''Welcome aboard! Your onboarding checklist has 4 steps left. Complete your
profile, read the handbook, set your goals, and say hello in the team channel.
Your manager has been notified of your start date.''',
    # ── HTML-flavored legit samples (entities, tables, tracking) ───
    '''<html><head><style>body{margin:0;font-family:Arial}.btn{width:120px}</style></head>
<body><p>&nbsp;&nbsp;Hi there,</p><p>Your weekly roundup is ready &mdash; 8 new
stories picked for you.</p><table><tr><td width="600">Featured: how small teams
ship faster with boring technology</td></tr></table><p>Read the full issue online.
You are receiving this because you subscribed to the digest.</p></body></html>''',
    '''<html><body style="font:14px sans-serif"><h1>Thanks for your order</h1>
<p>Order #A-5581 shipped via express courier.</p><p width="100%">Track it with
the link in your account under &quot;Orders&quot;.</p><p>&copy; 2026 Storefront.
You can <a>unsubscribe</a> from transactional notices in settings.</p></body></html>''',
    '''MIME-Version: 1.0
Subject: Your weekly usage report
Content-Type: text/plain; charset=utf-8

Usage is up 12 percent week over week. Storage used: 3.4 GB of 15 GB.
No action required; this report is generated every Monday. Open the dashboard
for per-project breakdowns.''',
    # ── Corporate / HR / internal ──────────────────────────────────
    '''Please complete your mandatory security training by 20 October. The module
takes about 25 minutes and can be paused. Completion is tracked by your manager.
Access the course from the learning portal.''',
    '''Timesheet approval reminder: your timesheet for last week is awaiting
submission. Approvals close Tuesday at noon. Edit entries in the workforce system
before the deadline to avoid delayed payment.''',
    '''Office will be closed on Monday for the public holiday. Emergency IT support
remains reachable on the on-call number. Normal service resumes Tuesday.''',
    # ── Indian market notifications ────────────────────────────────
    '''Your electricity bill for September is 1,842. Due date: 18 October. Pay from
the app, net banking, or any UPI app. Late payment charges apply after the due
date. Consumption was 214 units, 8 percent lower than last month.''',
    '''Order placed successfully: 2 kg basmati rice and 1 L sunflower oil. Delivery
expected tomorrow between 7 and 9 AM. You can track the rider live in the app.
Pay on delivery is enabled for this order.''',
    '''Mutual fund statement: your SIP of 5,000 was processed on 1 October into the
flexi cap fund, 312.44 units allotted at NAV 16.00. This is a transaction
acknowledgement from your broker.''',
]

PHISH = [
    '''URGENT: Your parcel could not be delivered due to unpaid customs fee of 99.
Scan the QR code in the attached image to pay immediately or the package will be
returned to sender. Pay within 12 hours to avoid cancellation.''',
    '''Claim your airdrop reward before it expires. Connect your wallet to verify
eligibility and receive up to 2.5 ETH in free tokens. Reward ends in 3 hours.
Never share your seed phrase with anyone.''',
    '''Unusual sign-in attempt detected. Approve the pending MFA request to block
the attacker, or your account will be locked. If you did not initiate this,
approve anyway to secure the account immediately.''',
    '''From the CEO: I am in a meeting and cannot talk. Process an urgent salary
change for a new contractor today and send the confirmation to my personal
address. Keep this confidential until the board meeting ends.''',
    '''You have a secure document awaiting signature. Open the attachment and review
it now; the link expires today. Sign with your email password to access the
document viewer.''',
    '''Your package is on hold: verify your address and pay the small redelivery fee
of $1.99 to release it. Failure to confirm within 24 hours means the item is
destroyed at the depot.''',
    '''The IRS owes you a refund of 286. Confirm your bank details within 24 hours
to receive the deposit. Refunds not claimed this week are forfeited to the
treasury.''',
    '''Your one-time password is 493021. Share this code with our verification agent
to complete your login. Do not delay — the code expires in 60 seconds and
repeated failures lock your account.''',
    '''Your account will be suspended: unusual login activity requires identity
verification. Confirm your credentials at the verification page to keep access.
All pending transfers will be cancelled if you ignore this notice.''',
    '''Your cloud storage is full: files will be deleted in 24 hours. Upgrade now at
a 90 percent discount to keep your photos and documents. Payment details are
requested on the next screen.''',
    '''Your WhatsApp number will be deactivated today unless you verify ownership.
Complete verification with the attached form or lose all chat history
permanently.''',
    '''Salary revision approved: sign the attached offer revision to activate your
new compensation effective this month. Unsigned revisions are cancelled after 48
hours. HR will not resend this notice.''',
    '''We noticed an unauthorized transaction of $499 on your card. If this was not
you, verify your identity immediately using the link below to reverse the charge.
Unverified disputes are auto-rejected.''',
    '''You have 1 new voicemail: "This is your bank, urgent matter, call back or log
in to listen." Transcription is attached. Listening requires your account number
for identity confirmation.''',
    '''Final notice: unpaid invoice 88213 will be sent to collections tomorrow.
Settle immediately by transferring to the account below or face legal action.
Reply for wire instructions.''',
]


def main() -> None:
    rows = [(t, 0) for t in LEGIT] + [(t, 1) for t in PHISH]
    OUT.parent.mkdir(exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["text", "label"])
        writer.writerows(rows)
    print(f"Wrote {len(rows)} rows to {OUT} ({len(LEGIT)} legit, {len(PHISH)} phish)")


if __name__ == "__main__":
    sys.exit(main())
