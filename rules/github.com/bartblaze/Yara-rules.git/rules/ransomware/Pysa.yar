rule Pysa
{
    meta:
        id = "240byxdCwyzaTk3xgjzbEa"
        fingerprint = "7f8819e9f76b9c97e90cd5da7ea788c9bb1eb135d8e1cb8974d6f17ecf51b3c3"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Pysa aka Mespinoza ransomware."
        category = "MALWARE"
        malware = "PYSA"
        malware_type = "RANSOMWARE"
        mitre_att = "S0583"

    strings:
        $code = { 8a 0? 41 84 c0 75 ?? 2b ce 8b 35 ?? ?? ?? ?? 8d 41 01 50 5? 6a 07 6a 00 68 ?? ?? ?? 
    ?? ff 7? ?? ff d? 6a 05 68 ?? ?? ?? ?? 6a 07 6a 00 68 ?? ?? ?? ?? ff 7? ?? ff d? ff 7? ?? ff 
    15 ?? ?? ?? ?? 8b 4? ?? 33 cd 5e e8 ?? ?? ?? ?? 8b e5 5d c3 }
        $s1 = "n.pysa" ascii wide fullword
        $s2 = "%s\\Readme.README" ascii wide
        $s3 = "Every byte on any types of your devices was encrypted." ascii wide

    condition:
        $code or 2 of ($s*)
}