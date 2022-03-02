rule REvil_Dropper
{
    meta:
        id = "77UKzYTt79Q5WVUpRQgOiK"
        fingerprint = "0b55e00e07c49e450fa643b5c8f4c1c03697c0f15d8f95c709e9b1a3cf2340ed"
        version = "1.0"
        creation_date = "2021-07-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies the dropper used by REvil in the Kaseya supply chain attack."
        category = "MALWARE"
        malware = "REVIL"
        malware_type = "RANSOMWARE"
        mitre_att = "S0496"
        reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
        hash = "d55f983c994caa160ec63a59f6b4250fe67fb3e8c43a388aec60a4a6978e9f1e"

    strings:
        $ = { 55 8b ec 56 8b 35 24 d0 40 00 68 04 1c 41 00 6a 65 6a 00 ff 
     d6 85 c0 0f 84 98 00 00 00 50 6a 00 ff 15 20 d0 40 00 85 c0 0f 84 
      87 00 00 00 50 ff 15 18 d0 40 00 68 14 1c 41 00 6a 66 6a 00 a3 a0 
      43 41 00 ff d6 85 c0 74 6c 50 33 f6 56 ff 15 20 d0 40 00 85 c0 74 
      5e 50 ff 15 18 d0 40 00 68 24 1c 41 00 ba 88 55 0c 00 a3 a4 43 41 
      00 8b c8 e8 9a fe ff ff 8b 0d a0 43 41 00 ba d0 56 00 00 c7 04 ?4 
      38 1c 41 00 e8 83 fe ff ff c7 04 ?4 ec 43 41 00 68 a8 43 41 00 56 
      56 68 30 02 00 00 56 56 56 ff 75 10 c7 05 a8 43 41 00 44 00 00 00 
      50 ff 15 28 d0 40 00 }
        $ = { 55 8b ec 83 ec 08 e8 55 ff ff ff 85 c0 75 04 33 c0 eb 67 68 
    98 27 41 00 68 68 b7 0c 00 a1 f4 32 41 00 50 e8 58 fe ff ff 83 c4 
    0c 89 45 f8 68 80 27 41 00 68 d0 56 00 00 8b 0d f0 32 41 00 51 e8 
    3c fe ff ff 83 c4 0c 89 45 fc c7 05 f8 32 41 00 44 00 00 00 68 3c 
    33 41 00 68 f8 32 41 00 6a 00 6a 00 6a 08 6a 00 6a 00 6a 00 8b 55 
    10 52 8b 45 fc 50 ff 15 28 c0 40 00 33 c0 }

    condition:
        any of them
}