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
