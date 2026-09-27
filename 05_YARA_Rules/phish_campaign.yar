/*
   Case DF-2026-006 - Phishing Email with Malicious Attachment
   Group 6 - Kashvi Vora (16010123167), Rushabh Vora (16010123280)

   These rules detect the indicators of the simulated phishing campaign
   used in this investigation. They contain no malicious code: a YARA
   rule is only a description of patterns to look for.

   Usage (YARA scans ONE file or directory per run):
     yara -s phish_campaign.yar <file>
     yara -r -s phish_campaign.yar <directory>
*/

rule Nimbus_Phish_Campaign_INV20260914
{
    meta:
        author      = "Group 6, K. J. Somaiya School of Engineering"
        case_id     = "DF-2026-006"
        description = "Indicators of the INV-2026-0914 phishing campaign"
        reference   = "https://attack.mitre.org/techniques/T1566/001/"

    strings:
        $invoice_ref  = "INV-2026-0914" ascii
        $lookalike    = "orion-supplies-invoices.example" ascii
        $builder_tag  = "NimbusInvoiceViewer" ascii

    condition:
        2 of them
}

rule EICAR_Test_File_Present
{
    meta:
        author      = "Group 6, K. J. Somaiya School of Engineering"
        case_id     = "DF-2026-006"
        description = "Flags the EICAR antivirus test file (harmless)"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $eicar
}

rule Windows_PE_Executable_Artifact
{
    meta:
        author      = "Group 6, K. J. Somaiya School of Engineering"
        case_id     = "DF-2026-006"
        description = "Any Windows PE executable - a match on a file named .pdf or .pdf.exe proves the attachment is an executable disguised as a document"

    strings:
        $mz = { 4D 5A }                      // 'MZ' DOS header magic
        $pe = "PE" fullword ascii            // PE signature

    condition:
        $mz at 0 and $pe
}
