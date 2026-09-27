# Forensic Investigation of a Phishing Email Containing a Malicious Attachment

**Case reference:** DF-2026-006

Digital forensic investigation of a simulated phishing email carrying a weaponised
attachment, performed in an isolated Kali Linux environment using three Kali tools
from three different categories.

Submitted for **LAB CA Component 2**, Cyber Security, Forensics & Cyber Law
(216U01E734), B.Tech Computer Engineering, Semester VII,
K. J. Somaiya School of Engineering, Somaiya Vidyavihar University.

| Group 6 | Roll Number | Role |
|---|---|---|
| Kashvi Vora | 16010123167 | Lead Examiner |
| Rushabh Vora | 16010123280 | Evidence Custodian |

---

## Safety notice

**No real malware is present in this repository, and none was used in the investigation.**

- The "known-malicious component" is the [EICAR Standard Anti-Virus Test File](https://www.eicar.org/download-anti-malware-testfile/) — a 68-byte text string with no malicious capability, which antivirus vendors agree to flag by convention.
- The "dropper" is a benign C program, compiled in the laboratory, that prints one line of text. Its source is in `07_Notes/`. It was never executed.
- All email addresses use the `.example` suffix, reserved for documentation. The IP address is from the documentation range. No real person, organisation, mailbox or system is involved.

The evidence files themselves are **deliberately not committed** (see `.gitignore`).
They can be regenerated exactly by running the build script below.

---

## Tools demonstrated

| Tool | Kali Category | Investigative question |
|---|---|---|
| ClamAV 1.4.6 | Protect | Does the file contain anything already known to be malicious? |
| radare2 6.0.5 | Reverse Engineering | What is this file really, and what does its code do? |
| YARA 4.5.8 | Forensics | Does it match the indicators defined for this campaign? |

Categories are as published on <https://www.kali.org/tools/>.
Nmap was excluded because it is covered in Laboratory Experiment 6.

---

## Key finding

ClamAV, loaded with **3,628,083 signatures**, scanned the disguised attachment
`Invoice_INV-2026-0914.pdf.exe` and reported **OK — not detected**, at every
container layer, even with `--allmatch` enabled.

radare2 established the same file to be an **unsigned Windows PE32+ executable**
whose `sym.main` function loads the phishing campaign's own spoofed domain into an
argument register. A three-string YARA rule, written from those recovered
indicators, matched it at byte offsets radare2 independently confirmed
(`0x8400`, `0x8417`, `0x843e`).

**Signature-based antivirus alone was insufficient for this investigation.**
Each of the three tools covered a blind spot of the others.

---

## Repository structure

```
.
├── README.md
├── .gitignore
├── Report/            Full forensic investigation report (.docx)
├── Presentation/      Slide deck (.pptx)
├── Documentation/     Command sheet, command explanations, complete command log
├── 03_Hashes/         SHA-256 and MD5 registers for all artefacts
├── 04_Tool_Output/    Captured output: ClamAV/, radare2/, YARA/
├── 05_YARA_Rules/     phish_campaign.yar — custom detection rules
├── 06_Screenshots/    Evidential screenshots referenced in the report
├── 07_Notes/          build_case_evidence.sh and supporting scripts
└── Video/             Link to the recorded presentation
```

---

## Reproducing the investigation

Tested on Kali GNU/Linux Rolling 2026.2.

**1. Install the tools**

```bash
sudo apt update
sudo apt install -y clamav clamav-freshclam yara radare2 mingw-w64 zip unzip git
sudo systemctl stop clamav-freshclam
sudo freshclam
```

**2. Build the evidence set**

```bash
bash 07_Notes/build_case_evidence.sh
```

This creates `~/DF-2026-006/` containing the phishing email (EV-001), the ZIP
attachment (EV-002) and the two extracted artefacts (EV-003), hashes the original,
write-protects it with `chmod 444`, and extracts the attachment to a working copy.

Verify the EICAR artefact hashes to the published value:

```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

**3. Run the examination**

The full command sequence is in `Documentation/3_Complete_Command_Log.docx`.
Summary:

```bash
cd ~/DF-2026-006

# ClamAV (Protect)
clamscan -r 02_Working_Copy/EV-003_extracted/
clamscan 02_Working_Copy/EV-001_phishing_email.eml
clamscan --scan-mail=no 02_Working_Copy/EV-001_phishing_email.eml
clamscan -a -z 02_Working_Copy/EV-001_phishing_email.eml

# radare2 (Reverse Engineering)
cd 02_Working_Copy/EV-003_extracted
file *
rabin2 -I Invoice_INV-2026-0914.pdf.exe
rabin2 -S Invoice_INV-2026-0914.pdf.exe | head -8
rabin2 -z Invoice_INV-2026-0914.pdf.exe | head -5
rahash2 -a sha256 Invoice_INV-2026-0914.pdf.exe
r2 -A -qc "pdf @ sym.main" Invoice_INV-2026-0914.pdf.exe 2>/dev/null | head -20

# YARA (Forensics)
cd ~/DF-2026-006
yara -r 05_YARA_Rules/phish_campaign.yar 02_Working_Copy/EV-003_extracted/
yara -s 05_YARA_Rules/phish_campaign.yar 02_Working_Copy/EV-003_extracted/Invoice_INV-2026-0914.pdf.exe
yara -r 05_YARA_Rules/phish_campaign.yar 02_Working_Copy/EV-002_Invoice_INV-2026-0914.zip
```

Note: the dropper's hash will differ from the one recorded here, because MinGW
embeds a compile timestamp in the PE header. Identical source, different hash —
which is itself part of why signature-based detection struggles with freshly
compiled binaries.

---

## Forensic procedure

Identification → Preservation → Acquisition → Examination → Analysis →
Documentation → Reporting → Conclusion.

Evidence was hashed (SHA-256 and MD5) and write-protected before any tool was
applied. Examination was performed on verified working copies. Hashes were
independently reproduced with `rahash2`. No suspect file was executed at any
point — all analysis is static. The chain of custody, evidence forms, examination
log and investigation timeline are in the report.

---

## Limitations

- Synthetic evidence; findings about detection behaviour transfer to real samples, but no claim is made about real malware behaviour.
- Static analysis only; no dynamic or sandbox execution was performed.
- The Windows API imports observed (`GetProcAddress`, `VirtualProtect`, `Sleep`) originate from the MinGW C runtime rather than author-written code.
- YARA rules authored from a single sample generalise poorly.

---

## References

1. [Kali Linux Tools — clamav](https://www.kali.org/tools/clamav/)
2. [Kali Linux Tools — radare2](https://www.kali.org/tools/radare2/)
3. [Kali Linux Tools — yara](https://www.kali.org/tools/yara/)
4. [ClamAV Documentation](https://docs.clamav.net/)
5. [YARA Documentation](https://yara.readthedocs.io/)
6. [radare2 Book](https://book.rada.re/)
7. [MITRE ATT&CK T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
8. [EICAR Anti-Malware Test File](https://www.eicar.org/download-anti-malware-testfile/)
9. [NIST SP 800-86 — Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final)

---

*Academic submission. Faculty in-charge: Ms. Poonam Bhogle, Ms. Shivani Deosthale.*
