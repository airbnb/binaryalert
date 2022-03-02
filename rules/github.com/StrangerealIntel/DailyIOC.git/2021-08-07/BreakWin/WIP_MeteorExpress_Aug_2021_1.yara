rule WIP_MeteorExpress_Aug_2021_1
{
    meta:
        description = "Detect MeteorExpress/BreakWin wiper"
        author = "Arkbird_SOLG"
        date = "2021-08-06"
        reference = "https://labs.sentinelone.com/meteorexpress-mysterious-wiper-paralyzes-iranian-trains-with-epic-troll/"
        hash1 = "2aa6e42cb33ec3c132ffce425a92dfdb5e29d8ac112631aec068c8a78314d49b"
        hash2 = "074bcc51b77d8e35b96ed444dc479b2878bf61bf7b07e4d7bd4cf136cc3c0dce"
        hash3 = "6709d332fbd5cde1d8e5b0373b6ff70c85fee73bd911ab3f1232bb5db9242dd4"
        hash4 = "9b0f724459637cec5e9576c8332bca16abda6ac3fbbde6f7956bc3a97a423473"
        tlp = "white"
        adversary = "-"
    strings:
        $s1 = { 8d 04 2a 8b f1 3b c8 0f 42 f0 33 c9 8b c6 83 c0 01 0f 92 c1 f7 d9 0b c8 e8 42 00 00 00 53 68 18 2c 41 00 50 89 44 24 1c 89 5f 10 89 77 14 e8 aa 20 00 00 8b 74 24 1c 83 c4 0c c6 04 1e 00 83 fd 10 72 0a 8b 0f 8d 55 01 e8 50 00 00 00 5d 89 37 8b c7 5f 5e 5b 59 }
        $s2 = { 68 cc 00 00 00 b8 [3] 00 e8 [2] 00 00 8b f1 89 75 8c 83 4d d4 ff 33 c0 83 4d d8 ff 6a 44 5f 57 50 89 45 dc 89 45 e0 8d 45 90 50 e8 [3] 00 8d 46 1c 89 7d 90 83 c4 0c 83 78 14 08 72 02 8b 00 89 45 98 8d 7d e4 33 c0 83 c6 04 ab 8b ce 83 7e 14 08 ab ab 72 02 8b 0e 8b 46 10 8d 04 41 8b ce 72 02 8b 0e ff 75 8c 33 d2 50 51 8d 4d e4 89 55 e4 89 55 e8 89 55 ec e8 [2] fd ff 33 d2 89 55 fc 8b 45 e8 89 55 88 39 45 ec 74 0d 33 c9 66 89 08 83 c0 02 89 45 e8 eb 0f 8d 4d 88 51 50 8d 4d e4 e8 3c 02 00 00 33 d2 8b 7d 8c 8d 4d d4 51 8d 4d 90 51 8b 47 34 52 52 52 52 52 52 ff 75 e4 52 ff 70 04 ff 15 08 [2] 00 85 c0 74 28 ff 75 d8 8d 4f 3c e8 [2] ff ff ff 75 d4 8d }
        $s3 = { 8b ec 83 e4 f8 83 ec 7c a1 14 50 41 00 33 c4 89 44 24 78 8b 45 0c 8b 4d 08 89 0c 24 53 56 57 83 e8 01 0f 84 05 01 00 00 83 e8 01 0f 84 23 01 00 00 83 e8 0d 74 15 ff 75 14 ff 75 10 ff 75 0c 51 ff 15 2c e1 40 00 e9 0b 01 00 00 8d 44 24 40 c6 05 f4 63 41 00 01 50 51 ff 15 30 e1 40 00 8b d8 6a 00 89 5c 24 18 ff 15 10 e0 40 00 8b f0 8d 44 24 48 56 50 53 ff 15 28 e1 40 00 56 ff 15 0c e0 40 00 83 3d f8 63 41 00 00 0f 84 8d 00 00 00 53 ff 15 04 e0 40 00 ff 35 f8 63 41 00 89 44 24 14 50 ff 15 00 e0 40 00 8b d8 8d 44 24 18 50 6a 18 ff 35 f8 63 41 00 ff 15 14 e0 40 00 8b 7c 24 20 8d 44 24 30 8b 74 24 1c 50 ff 74 24 10 ff 15 44 e1 40 00 8b 44 24 38 2b c6 8b 74 24 10 68 20 00 cc 00 99 2b c2 6a 00 8b c8 8b 44 24 44 6a 00 56 ff 74 24 30 2b c7 d1 f9 ff 74 24 30 99 2b c2 d1 f8 50 51 ff 74 24 34 ff 15 18 e0 40 00 53 56 ff 15 00 e0 40 00 56 ff 15 08 e0 40 00 8d 44 24 40 }
        $s4 = { 38 1b 38 26 38 2e 38 39 38 3f 38 4a 38 50 38 5e 38 67 38 6c 38 79 38 7e 38 ec 38 }
        $s5 = { 55 8b ec 51 a1 60 57 41 00 83 f8 fe 75 0a e8 8e 0d 00 00 a1 60 57 41 00 83 f8 ff 75 07 b8 ff ff 00 00 eb 1b 6a 00 8d 4d fc 51 6a 01 8d 4d 08 51 50 ff 15 50 e0 40 00 85 c0 74 e2 66 8b 45 08 8b }
        $s6 = { 69 63 61 63 6c 73 2e 65 78 65 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 44 61 74 61 5c 53 2d 31 2d 35 2d 31 38 5c 52 65 61 64 4f 6e 6c 79 22 20 2f 72 65 73 65 74 20 2f 54 }
        $s7 = { 77 6d 69 63 20 63 6f 6d 70 75 74 65 72 73 79 73 74 65 6d 20 77 68 65 72 65 20 6e 61 6d 65 3d 22 25 63 6f 6d 70 75 74 65 72 6e 61 6d 65 25 22 20 63 61 6c 6c 20 75 6e 6a 6f 69 6e 64 6f 6d 61 69 6e 6f 72 77 6f 72 6b 67 72 6f 75 70 }
        $s8 = { 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 68 [3] 00 e8 [2] 03 00 59 c3 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 68 [3] 00 e8 [2] 03 00 59 c3 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 68 [3] 00 e8 [2] 03 00 59 c3 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 68 [3] 00 e8 [2] 03 00 59 c3 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 68 [3] 00 e8 [2] 03 00 59 c3 6a ?? 68 [3] 00 b9 [3] 00 e8 [2] 00 00 68 [3] 00 e8 [2] 03 00 59 c3 }
        $s9 = { 8b 55 ?? 8d 4d ?? e8 ?? ?? fe ff c6 45 fc 08 ff 15 ?? ?? 47 00 8b d0 8d 4d ?? e8 ?? ?? fe ff c6 45 fc 09 8d 45 ?? 50 8d 45 ?? 50 8d 4d ?? e8 ?? ?? ?? ff 83 ec 0c 8b cc 89 65 ?? 51 ff 70 04 ff 30 e8 ?? ?? ?? ff c6 45 fc 0a 83 ec 18 8b cc 89 65 ?? 68 ?? ?? 48 00 e8 ?? ?? ?? ff c6 45 fc 0b c6 45 fc 09 8d }
    condition:
       uint16(0) == 0x5A4D and filesize > 25KB and 4 of ($s*) 
}  
