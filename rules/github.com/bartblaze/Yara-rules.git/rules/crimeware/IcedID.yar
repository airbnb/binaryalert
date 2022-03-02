rule IcedID_init_loader
{
    meta:
        id = "1GXBmGKG0zu5DhEKiZK0Kx"
        fingerprint = "b86460e97101c23cf11ff9fb43f6fcdce444fcfa301b1308c2f4d6aa2f01986a"
        version = "1.0"
        creation_date = "2021-01-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IcedID (stage 1 and 2, initial loaders)."
        category = "MALWARE"
        malware = "ICEDID"
        malware_type = "LOADER"
        mitre_att = "S0483"

    strings:
        $s1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" ascii wide
        $s2 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii wide
        $s3 = "/image/?id=%0.2X%0.8X%0.8X%s" ascii wide
        $x1 = "; _gat=" ascii wide
        $x2 = "; _ga=" ascii wide
        $x3 = "; _u=" ascii wide
        $x4 = "; __io=" ascii wide
        $x5 = "; _gid=" ascii wide
        $x6 = "Cookie: __gads=" ascii wide

    condition:
        2 of ($s*) or 3 of ($x*)
}

rule IcedID_core_loader
{
    meta:
        id = "682uTswieW7dk3i644FZ9F"
        fingerprint = "ffcfe3a1d5f0aad41892faf41c986a9601596d14f43985708f9bf4eb7d63a6b9"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies IcedID core loader."
        category = "MALWARE"
        malware = "ICEDID"
        malware_type = "LOADER"
        mitre_att = "S0483"

    strings:
        $code = { 4? 33 d2 4? 85 f6 0f 84 ?? ?? ?? ?? 4? 83 fe 04 0f 
    82 ?? ?? ?? ?? 4? 83 c6 fc 4? 89 74 ?? ?? 4? 85 db 75 ?? 4? 
    85 f6 0f 84 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4? 8b c8 4? 8d 46 
    01 8d 53 08 ff 15 ?? ?? ?? ?? 4? 89 44 ?? ?? 4? 8b d8 4? 85 
    c0 0f 84 ?? ?? ?? ?? 4? 8b b? ?? ?? ?? ?? 4? ba 01 00 00 00 }

    condition:
        $code
}