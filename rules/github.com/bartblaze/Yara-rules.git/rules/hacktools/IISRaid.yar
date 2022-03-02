rule IISRaid
{
    meta:
        id = "40tj9tn6FNrr4xE042IPIm"
        fingerprint = "521b0798e25a620534f8e04c8fd62fd42c90ea5b785968806cb7538986dedac6"
        version = "1.0"
        creation_date = "2021-08-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IISRaid."
        category = "MALWARE"
        malware = "IISRAID"
        malware_type = "BACKDOOR"
        reference = "https://github.com/0x09AL/IIS-Raid"


    strings:
        $pdb1 = "\\IIS-Raid-master\\" ascii wide
        $pdb2 = "\\IIS-Backdoor.pdb" ascii wide
        $s1 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
        $s2 = "C:\\Windows\\Temp\\creds.db" ascii wide
        $s3 = "CHttpModule::" ascii wide
        $s4 = "%02d/%02d/%04d %02d:%02d:%02d | %s" ascii wide

    condition:
        any of ($pdb*) or 3 of ($s*)
}