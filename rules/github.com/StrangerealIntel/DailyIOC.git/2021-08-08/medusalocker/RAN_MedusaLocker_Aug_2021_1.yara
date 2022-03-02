rule RAN_MedusaLocker_Aug_2021_1
{
    meta:
        description = "Detect MedusaLocker ransomware"
        author = "Arkbird_SOLG"
        date = "2021-08-08"
        reference = "Internal Research"
        hash1 = "4f9a833e79092006c06203a66b41fc9250bcebcee148fea404db75d52035131c"
        hash2 = "212e7f5ed4a581b4d778dfef226738c6db56b4b4006526259392d03062587887"
        hash3 = "a25c0227728878c386ab6dba139976cb10e853dd3cd1eb3623f236ee8e1df212"
        hash4 = "c2a0a317d73c96428ab088a8f0636ec4ccace7ca691c84ed66a83a70183f40dc"
        hash5 = "0abb4a302819cdca6c9f56893ca2b52856b55a0aa68a3cb8bdcd55dcc1fad9ad"
        hash6 = "f5fb7fa5231c18f0951c755c4cb0ec07b0889b5e320f42213cbf6bbbe499ad31"
        tlp = "white"
        adversary = "RaaS"
    strings:
        $s1 = "{8761ABBD-7F85-42EE-B272-A76179687C63}" fullword wide
        $s2 = { 83 c4 08 8d 8d ?? fe ff ff e8 [2] ff ff 8d 8d ?? fe ff ff e8 [2] ff ff 68 [2] 48 00 8d 8d ?? ff ff ff e8 [2] ff ff 8b c8 e8 [2] ff ff 68 [2] 48 00 8d 8d [2] ff ff e8 [2] 00 00 8d 8d [2] ff ff 51 e8 ?? f9 ff ff 83 c4 04 88 85 2b ff ff ff 8d 8d [2] ff ff e8 [2] 00 00 0f b6 95 2b ff ff ff 85 d2 74 1e 68 [2] 48 00 8d 8d ?? ff ff ff e8 [2] ff ff 8b c8 e8 [2] ff ff 33 c0 e9 [2] 00 00 8d 4d fa e8 [2] ff ff 8d 4d fa e8 [2] 01 00 8d 4d fa e8 [2] 01 00 8d 4d fa e8 [2] 01 00 0f b6 c0 85 c0 74 0c c7 85 ?? fe ff ff [2] 48 00 eb 0a c7 85 ?? fe ff ff [2] 48 00 8b 8d ?? fe ff ff 89 8d ?? fe ff ff 8d 95 ?? fe ff ff 52 8d 8d ?? ff ff ff e8 [2] ff ff 8b c8 e8 [2] ff ff e8 ?? f8 ff ff 8d 4d 8c e8 [2] 00 00 68 [2] 48 00 8d 8d ?? ff ff ff e8 [2] ff ff 8b c8 e8 [2] ff ff b9 [2] 4a 00 e8 [2] ff ff 50 e8 [2] ff ff 83 c4 04 50 8d 4d 8c e8 [2] 00 00 0f b6 c0 85 c0 75 41 68 [2] 48 00 8d 8d ?? ff ff ff e8 [2] ff ff 8b c8 e8 [2] ff ff e8 ?? c6 ff ff c7 85 ?? fe ff ff 00 00 00 00 8d 4d 8c e8 [2] 00 00 8d 4d fa e8 [2] ff ff 8b 85 ?? fe ff ff e9 [2] 00 00 68 [2] 48 00 8d 8d ?? ff ff ff e8 [2] ff ff 8b c8 e8 [2] ff ff 68 [2] 48 00 8d 8d ?? fe ff ff e8 [2] 00 00 8d 8d ?? fd ff ff 51 8d 4d 8c e8 [2] 00 00 50 e8 [2] ff ff 83 c4 04 50 8d 95 ?? fe ff ff 52 b9 [2] 4a 00 e8 [2] 00 00 0f b6 c0 85 c0 75 0c c7 85 ?? fe ff ff 01 00 00 00 eb 0a c7 85 ?? fe ff ff 00 00 00 00 8a 8d ?? fe ff ff 88 8d 2a ff ff ff 8d 8d ?? fd ff ff e8 [2] 00 00 8d 8d ?? fe ff ff }
        $s3 = { 62 00 63 00 64 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 73 00 65 00 74 00 20 00 7b 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 7d 00 20 00 62 00 6f 00 6f 00 74 00 73 00 74 00 61 00 74 00 75 00 73 00 70 00 6f 00 6c 00 69 00 63 00 79 00 20 00 69 00 67 00 6e 00 6f 00 72 00 65 00 61 00 6c 00 6c 00 66 00 61 00 69 00 6c 00 75 00 72 00 65 00 73 }
        $s4 = { 42 67 49 41 41 41 43 6b 41 41 42 53 55 30 45 78 }
        $s5 = "wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest" fullword wide
        $s6 = { 62 00 63 00 64 00 65 00 64 00 69 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 73 00 65 00 74 00 20 00 7b 00 64 00 65 00 66 00 61 00 75 00 6c 00 74 00 7d 00 20 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 20 00 4e 00 6f }
        $s7 = { 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 20 00 44 00 65 00 6c 00 65 00 74 00 65 00 20 00 53 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 41 00 6c 00 6c 00 20 00 2f 00 51 00 75 00 69 00 65 00 74 }
        $s8 = { 77 00 6d 00 69 00 63 00 2e 00 65 00 78 00 65 00 20 00 53 00 48 00 41 00 44 00 4f 00 57 00 43 00 4f 00 50 00 59 00 20 00 2f 00 6e 00 6f 00 69 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 76 00 65 }
        $s9 = { 77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 20 00 44 00 45 00 4c 00 45 00 54 00 45 00 20 00 53 00 59 00 53 00 54 00 45 00 4d 00 53 00 54 00 41 00 54 00 45 00 42 00 41 00 43 00 4b 00 55 00 50 }
        $s10 = { 33 c0 48 89 44 24 40 48 c7 44 24 48 07 00 00 00 66 89 44 24 30 44 8d 40 26 48 8d 15 [2] 09 00 48 8d 4c 24 30 e8 [2] ff ff 48 83 7c 24 40 00 74 42 4c 8d 44 24 30 48 83 7c 24 48 08 4c 0f 43 44 24 30 33 d2 b9 01 00 1f 00 ff 15 [2] 07 00 48 85 c0 75 1f 4c 8d 44 24 30 48 83 7c 24 48 08 4c 0f 43 44 24 30 33 d2 33 c9 ff 15 [2] 07 00 32 db eb 02 b3 01 48 8b 54 24 48 48 83 fa 08 72 37 48 8d 14 55 02 00 00 00 48 8b 4c 24 30 48 8b c1 48 81 fa 00 10 00 00 72 19 48 83 c2 27 48 8b 49 f8 48 2b c1 48 83 c0 f8 48 83 f8 1f 0f 87 d3 00 00 00 e8 [2] 03 00 84 db 0f 85 ad 00 00 00 e8 3e 36 00 00 84 c0 75 05 e8 c5 36 00 00 e8 ?? 94 ff ff 48 8d 1d [2] 0d 00 48 8d 4c 24 30 e8 [2] ff ff 48 8b f8 48 8d 35 [2] 0d 00 0f 1f }
    condition:
       uint16(0) == 0x5A4D  and filesize > 150KB and 9 of ($s*) 
} 
