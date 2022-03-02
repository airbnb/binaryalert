rule RAN_AvosLocker_July_2021_1
{
    meta:
        description = "Detect AvosLocker ransomware"
        author = "Arkbird_SOLG"
        date = "2021-07-23"
        reference = "https://blog.malwarebytes.com/threat-analysis/2021/07/avoslocker-enters-the-ransomware-scene-asks-for-partners/"
        hash1 = "43b7a60c0ef8b4af001f45a0c57410b7374b1d75a6811e0dfc86e4d60f503856"
        hash2 = "fb544e1f74ce02937c3a3657be8d125d5953996115f65697b7d39e237020706f"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 64 72 69 76 65 20 25 73 20 74 6f 6f 6b 20 25 66 20 73 65 63 6f 6e 64 73 0a 00 00 00 25 63 3a 00 64 72 69 76 65 3a 20 25 73 }
        $s2 = { 63 6c 69 65 6e 74 5f 72 73 61 5f 70 72 69 76 3a 20 25 73 0a }
        $s3 = { 2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 0a 2d 2d 2d 2d 2d 45 4e 44 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d }
        $s4 = { ff 35 b8 2c 46 00 88 9d 7c ef ff ff e8 3c 56 02 00 50 8d 85 71 ef ff ff 50 e8 c5 9e ff ff 83 c4 0c 8d 85 94 ef ff ff 50 53 53 68 14 01 00 00 ff 35 b8 2c 46 00 ff b5 90 ef ff ff ff 15 00 a0 44 00 85 c0 0f 85 cd 00 00 00 8b 35 48 a0 44 00 8d 85 98 fe ff ff 53 68 ff 00 00 00 50 68 00 04 00 00 ff d6 50 53 68 00 10 00 00 ff 15 44 a0 44 00 b1 3e c7 85 70 ef ff ff 3e 7b 6c 6c c7 85 74 ef ff ff 71 6c 04 1e 8b c3 c7 85 78 ef ff ff 1b 4d 34 00 30 8c 05 71 ef ff ff 40 83 f8 0a 73 08 8a 8d 70 ef ff ff eb eb 8d 85 98 fe ff ff 88 9d 7b ef ff ff 50 8d 85 71 ef ff ff 50 e8 23 9e ff ff 0f 28 05 00 8b 45 00 59 0f 11 85 48 ef ff ff 59 0f 28 05 40 8b 45 00 8b cb 0f 11 85 58 ef ff ff 66 c7 }
        $s5 = { 38 9d a0 fd ff ff 74 0c ff b5 94 fd ff ff e8 a6 ca ff ff 59 8d 85 ac fd ff ff 50 56 ff 15 48 a1 44 00 85 c0 0f 85 4d ff ff ff 8b 85 a4 fd ff ff 8b 8d 84 fd ff ff 8b 10 8b 40 04 2b c2 c1 f8 02 3b }
        $s6 = { 4d 61 70 3a 20 25 73 0a 00 00 00 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 25 00 6c 00 73 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 }
        $s7 = { 44 6f 6e 65 21 21 0a 00 25 66 20 73 65 63 6f 6e 64 73 0a }
        $s8 = { 56 68 01 00 00 08 6a 01 52 ff 15 14 a0 44 00 85 c0 0f 84 97 00 00 00 8d 45 f8 50 53 53 6a 06 53 ff 36 8b 1d 20 a0 44 00 ff d3 85 c0 74 73 ff 75 f8 e8 3b a7 01 00 a3 b8 2c 46 00 59 85 c0 }
    condition:
       uint16(0) == 0x5A4D  and filesize > 50KB and 6 of ($s*) 
}  
