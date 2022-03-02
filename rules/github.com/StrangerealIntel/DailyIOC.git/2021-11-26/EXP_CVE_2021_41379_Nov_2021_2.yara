rule EXP_CVE_2021_41379_Nov_2021_2
{
    meta:
        description = "Detect exploit tool using CVE-2021-41379 (variant 2)"
        author = "Arkbird_SOLG"
        date = "2021-11-26"
        reference = "Internal Research"
        // base ref -> https://valhalla.nextron-systems.com/info/rule/EXPL_Windows_InstallerFileTakeOver_CVE_2021_41379_Nov21_1
        hash1 = "13fe508e7efb50378eb8e0225221283756bf482d51be7837f850ef2b7f3281f0"
        hash2 = "402722d95d468ddef049e1079c882bb9a316841b9695a15783fc23bbd3b33aed"
        hash3 = "d025564e6dc872cff32f2295e0b5a2d8e3a21fbef1957facb69a493fa8a995fb"
        hash4 = "dc65cd6311fd764a89d0761932bef61a89fd979510bd9ff23cde8c001de316b8"
        tlp = "white"
        adversary = "-"
    strings:
       $s1 = { 4c 89 6c 24 38 44 89 6c 24 30 44 89 6c 24 28 44 89 6c 24 20 [1-2] 01 00 00 00 ?? 8b ?? 45 33 c0 ba 03 00 08 00 48 8d 0d [3] 00 ff 15 [3] 00 48 8b d8 48 83 f8 ff 0f 84 ?? 01 00 00 33 d2 48 8b c8 ff 15 [3] 00 44 89 6d 10 48 8d 55 10 48 8b cb ff 15 [3] 00 48 8b cb ff 15 [3] 00 ff 15 [3] 00 44 8b c0 33 d2 b9 00 10 10 00 ff 15 [3] 00 48 8b d8 4c 89 }
       $s2 = { 4c 89 6c 24 30 c7 44 24 28 80 00 00 04 c7 44 24 20 04 00 00 00 45 33 c9 [1-2] 01 00 00 00 ?? 8b ?? ba 00 00 01 80 48 8d 4d 20 ff 15 [3] 00 48 89 05 [3] 00 44 89 6d 14 48 8d 45 14 48 89 44 24 28 44 89 6c 24 20 45 33 c9 4c 8d 05 [2] ff ff 33 d2 33 c9 ff 15 [3] 00 48 8b d8 ?? 8b ?? ba 04 01 00 00 49 8d ?? 10 02 00 00 [4] 00 } 
       $s3 = { 40 53 48 81 ec 30 08 00 00 48 8b 05 [3] 00 48 33 c4 48 89 84 24 20 08 00 00 0f 10 05 [3] 00 48 8b d9 33 d2 0f 10 0d [3] 00 48 8d 4c 24 50 41 b8 d0 07 00 00 0f 29 44 24 20 0f 10 05 [3] 00 0f 29 4c 24 30 0f 29 44 24 40 e8 [2] 00 00 4c 8b 0b 48 8d 44 24 20 41 b8 00 04 00 00 41 8b c8 66 83 38 00 74 0a 48 83 c0 02 48 83 e9 01 75 f0 45 33 d2 49 8b c0 48 2b c1 48 85 c9 49 0f 44 c2 74 47 4c 2b c0 48 8d 44 44 20 74 2e b9 fe ff ff 7f 4c 2b c8 0f 1f 80 00 00 00 00 48 85 c9 74 1a 41 0f b7 14 01 66 85 d2 74 10 66 89 10 48 ff c9 48 83 c0 02 49 83 e8 01 75 e1 4d 85 c0 48 8d 50 fe 48 0f 45 d0 66 44 89 12 33 d2 8d 4a 02 ff 15 [3] 00 48 8b 4b 08 48 8d 54 24 20 ff 15 [3] 00 33 c0 48 8b 8c 24 20 08 00 00 48 33 cc e8 [2] 00 00 48 81 c4 30 08 00 00 5b }
       $s4 = { 48 8b c8 ff 15 [3] 00 33 c9 ff 15 [3] 00 48 8b c8 41 b8 04 01 00 00 48 8d 95 30 02 00 00 ff 15 [3] 00 e8 [2] ff ff 48 8b d0 45 33 c0 48 8d 8d 30 02 00 00 ff 15 [3] 00 33 c9 ff 15 [3] 00 48 8d } 
    condition:
       uint16(0) == 0x5A4D and filesize > 25KB and all of ($s*) 
} 
