#!/bin/bash
# =====================================================================
# Case DF-2026-006 - Forensic Investigation of a Phishing Email
#                    Containing a Malicious Attachment
# Group 6 - Kashvi Vora (16010123167), Rushabh Vora (16010123280)
#
# Builds the SIMULATED phishing evidence set, then preserves and
# acquires it using proper forensic procedure.
#
# SAFETY: nothing here is malicious. The "dropper" is a harmless C
# program that prints a line of text, and the "payload" is the EICAR
# industry-standard antivirus test file. Neither is ever executed.
#
# Run with:  bash build_case_evidence.sh
# =====================================================================

set -e
CASE=~/DF-2026-006

echo "=== STEP 1: case workspace ==============================="
mkdir -p $CASE/{00_Simulation,01_Original_Evidence,02_Working_Copy,03_Hashes,04_Tool_Output/{ClamAV,radare2,YARA},05_YARA_Rules,06_Screenshots,07_Notes}
echo "workspace ready at $CASE"

echo
echo "=== STEP 2: build the disguised dropper =================="
cat > $CASE/00_Simulation/invoice_stub.c <<'EOF'
#include <stdio.h>

const char *g_campaign = "INV-2026-0914";
const char *g_source   = "hxxp://orion-supplies-invoices.example/update";
const char *g_builder  = "NimbusInvoiceViewer/1.0";

int main(void) {
    printf("Invoice viewer could not open %s (%s) [%s]\n",
           g_campaign, g_source, g_builder);
    return 0;
}
EOF

cd $CASE/00_Simulation
if command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1; then
    x86_64-w64-mingw32-gcc invoice_stub.c -o Invoice_INV-2026-0914.pdf.exe
    DROPPER="Invoice_INV-2026-0914.pdf.exe"
    echo "built Windows PE: $DROPPER"
else
    gcc invoice_stub.c -o Invoice_INV-2026-0914.pdf
    DROPPER="Invoice_INV-2026-0914.pdf"
    echo "mingw not found - built Linux ELF fallback: $DROPPER"
fi
file "$DROPPER"

echo
echo "=== STEP 3: EICAR test file =============================="
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > Invoice_Helper.dll
SIZE=$(wc -c < Invoice_Helper.dll)
echo "Invoice_Helper.dll is $SIZE bytes (must be 68)"
[ "$SIZE" -eq 68 ] || { echo "ERROR: wrong size, ClamAV may not detect it"; exit 1; }

echo
echo "=== STEP 4: package the attachment ======================="
rm -f Invoice_INV-2026-0914.zip
zip -jq Invoice_INV-2026-0914.zip "$DROPPER" Invoice_Helper.dll
unzip -l Invoice_INV-2026-0914.zip | tail -5

echo
echo "=== STEP 5: build the phishing email ====================="
cat > $CASE/07_Notes/build_eml.py <<'EOF'
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
EOF
python3 $CASE/07_Notes/build_eml.py

echo
echo ">>> SIMULATION ENDS HERE. From this point you are the investigator."
echo

echo "=== STEP 6: preservation (hash + write-protect) =========="
cd $CASE/01_Original_Evidence
sha256sum EV-001_phishing_email.eml | tee $CASE/03_Hashes/EV-001_sha256.txt
md5sum    EV-001_phishing_email.eml | tee $CASE/03_Hashes/EV-001_md5.txt
chmod 444 EV-001_phishing_email.eml
ls -l

echo
echo "=== STEP 7: working copy + integrity check ==============="
cp -p EV-001_phishing_email.eml $CASE/02_Working_Copy/
cd $CASE/02_Working_Copy
chmod 644 EV-001_phishing_email.eml
echo "original:    $(cut -d' ' -f1 $CASE/03_Hashes/EV-001_sha256.txt)"
echo "working copy:$(sha256sum EV-001_phishing_email.eml | cut -d' ' -f1)"
echo "(these two MUST be identical - that is your proof of copy integrity)"

echo
echo "=== STEP 8: acquisition (extract attachment) ============="
cat > $CASE/07_Notes/extract_attachment.py <<'EOF'
import email, email.policy, pathlib

src = pathlib.Path.home() / "DF-2026-006/02_Working_Copy/EV-001_phishing_email.eml"
outdir = pathlib.Path.home() / "DF-2026-006/02_Working_Copy"
msg = email.message_from_bytes(src.read_bytes(), policy=email.policy.default)

for part in msg.iter_attachments():
    name = part.get_filename()
    data = part.get_payload(decode=True)
    dest = outdir / f"EV-002_{name}"
    dest.write_bytes(data)
    print("extracted:", dest.name, len(data), "bytes")
EOF
python3 $CASE/07_Notes/extract_attachment.py

mkdir -p EV-003_extracted
unzip -oq EV-002_Invoice_INV-2026-0914.zip -d EV-003_extracted
ls -l EV-003_extracted
sha256sum EV-002_* EV-003_extracted/* | tee $CASE/03_Hashes/derived_artefacts_sha256.txt

echo
echo "=========================================================="
echo "EVIDENCE SET READY"
echo "  EV-001  the phishing email      (01_Original_Evidence, read-only)"
echo "  EV-002  the ZIP attachment      (02_Working_Copy)"
echo "  EV-003  the two extracted files (02_Working_Copy/EV-003_extracted)"
echo
echo "Next: ClamAV scan, then radare2 analysis, then YARA matching."
echo "=========================================================="
