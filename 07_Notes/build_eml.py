from email.message import EmailMessage
import pathlib

sim = pathlib.Path.home() / "DF-2026-006/00_Simulation"
out = pathlib.Path.home() / "DF-2026-006/01_Original_Evidence/EV-001_phishing_email.eml"
zip_path = sim / "Invoice_INV-2026-0914.zip"

msg = EmailMessage()
msg["Return-Path"] = "<bounce@mailer-service.example>"
msg["Received"] = ("from mail.orion-supplies-invoices.example ([203.0.113.45]) "
                   "by mx.nimbuslogistics.example; Mon, 14 Sep 2026 09:42:11 +0530")
msg["From"] = "Orion Office Supplies <billing@orion-supplies-invoices.example>"
msg["To"] = "accounts.exec@nimbuslogistics.example"
msg["Reply-To"] = "orion.payments@freemail.example"
msg["Subject"] = "URGENT: Overdue Invoice INV-2026-0914 - Payment Required Within 24 Hours"
msg["Date"] = "Mon, 14 Sep 2026 09:42:11 +0530"
msg["Message-ID"] = "<20260914094211.1A2B3C@orion-supplies-invoices.example>"
msg["X-Mailer"] = "BulkMailer 2.1"
msg.set_content("""Dear Sir/Madam,

Our records show that invoice INV-2026-0914 remains unpaid.

Please open the attached invoice and confirm payment within 24 hours,
failing which your account will be suspended without further notice.

Regards,
Accounts Department
Orion Office Supplies
""")
msg.add_attachment(zip_path.read_bytes(), maintype="application",
                   subtype="zip", filename=zip_path.name)
out.write_bytes(msg.as_bytes())
print("EV-001 written:", out.name, out.stat().st_size, "bytes")
