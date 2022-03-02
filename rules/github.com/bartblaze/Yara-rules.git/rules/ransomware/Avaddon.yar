rule Avaddon
{
    meta:
        id = "gzIxctaiGZf4jXkwWO0BR"
        fingerprint = "ab5c7c5ea9d7d0587e8b2b327c138b2ba21ad6fbbef63f67935dab60f116088f"
        version = "1.0"
        creation_date = "2021-05-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Avaddon ransomware."
        category = "MALWARE"
        malware = "AVADDON"
        malware_type = "RANSOMWARE"
        mitre_att = "S0640"

    strings:
        $s1 = "\"ext\":" ascii wide
        $s2 = "\"rcid\":" ascii wide
        $s3 = "\"hdd\":" ascii wide
        $s4 = "\"name\":" ascii wide
        $s5 = "\"size\":" ascii wide
        $s6 = "\"type\":" ascii wide
        $s7 = "\"lang\":" ascii wide
        $s8 = "\"ip\":" ascii wide
        $code = { 83 7f 14 10 8b c7 c7 4? ?? 00 00 00 00 72 ?? 8b 07 6a 00 6a 00 
    8d ?? f8 51 6a 00 6a 01 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 56 
        8b 7? ?? ff 15 ?? ?? ?? ?? 56 6a 00 50 ff 15 ?? ?? ?? ?? 8b f0 85 
        f6 74 ?? 83 7f 14 10 72 ?? 8b 3f }

    condition:
        uint16(0)==0x5a4d and (5 of ($s*) or $code)
}