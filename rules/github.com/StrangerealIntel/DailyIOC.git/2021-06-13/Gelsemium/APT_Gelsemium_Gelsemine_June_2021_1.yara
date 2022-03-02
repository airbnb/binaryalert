rule APT_Gelsemium_Gelsemine_June_2021_1 {
   meta:
        description = "Detect Gelsemine malware (Dropper - Variant 1)"
        author = "Arkbird_SOLG"
        reference = "https://www.welivesecurity.com/wp-content/uploads/2021/06/eset_gelsemium.pdf"
        date = "2021-06-12"
        hash1 = "00b701e3ef29912c1fcd8c2154c4ae372cfe542cfa54ffcce9fb449883097cec"
        hash2 = "109d4b8878b8c8f3b7015f6b3ae573a6799296becce0f32ca3bd216bee0ab473"
        hash3 = "fe71b66d65d5ff9d03a47197c99081d9ec8d5f6e95143bdc33f5ea2ac0ae5762"
        hash3 = "29e78ca3cb49dd2985a29e74cafb1a0a15515670da0f4881f6095fb2926bfefd"
        tlp = "white"
        adversary = "Gelsemium"
   strings:      
            $s1 = { 8b 44 24 04 83 ec 40 85 c0 53 55 56 57 0f 84 ec 15 00 00 8b 58 1c 85 db 0f 84 e1 15 00 00 8b 48 0c 85 c9 0f 84 d6 15 00 00 83 38 00 75 0b 8b 48 04 85 c9 0f 85 c6 15 00 00 83 3b 0b 75 06 c7 03 0c 00 00 00 8b 48 0c 8b 30 8b 78 04 8b 53 38 8b 6b 3c 89 4c 24 28 8b 48 10 8b 03 83 f8 1e 89 4c 24 20 89 74 24 14 89 7c 24 18 89 54 24 10 89 7c 24 38 89 4c 24 2c c7 44 24 34 00 00 00 }
            $s2 = { 33 c0 33 d2 8a 06 8a 56 01 03 c8 33 c0 8a 46 02 03 f9 03 ca 33 d2 8a 56 03 03 f9 03 c8 33 c0 8a 46 04 03 f9 03 ca 33 d2 8a 56 05 03 f9 03 c8 33 c0 8a 46 06 03 f9 03 ca 33 d2 8a 56 07 03 f9 03 c8 33 c0 8a 46 08 03 f9 03 ca 33 d2 8a 56 09 03 f9 03 c8 33 c0 8a 46 0a 03 f9 03 ca 33 d2 8a 56 0b 03 f9 03 c8 33 c0 8a 46 0c 03 f9 03 ca 33 d2 8a 56 0d 03 f9 03 c8 33 c0 8a 46 0e 03 f9 03 ca 33 d2 8a 56 0f 03 f9 03 c8 83 c6 10 03 f9 03 ca 03 f9 4d 0f 85 67 ff ff ff 8b c1 33 d2 b9 f1 ff 00 00 f7 f1 8b c7 bf f1 ff 00 00 8b ca 33 d2 f7 f7 ff 4c 24 18 8b fa 0f 85 38 ff ff ff 85 db 0f 84 da 00 00 00 83 fb 10 0f 82 a1 00 00 00 8b eb c1 ed 04 33 d2 33 c0 8a 16 8a 46 01 03 ca 33 d2 8a 56 02 03 f9 03 c8 33 c0 8a 46 03 03 f9 03 ca 33 d2 8a 56 04 03 f9 03 c8 33 c0 8a 46 05 03 f9 03 ca 33 d2 8a 56 06 03 f9 03 c8 33 c0 8a 46 07 03 f9 03 ca 33 d2 8a 56 08 03 f9 03 c8 33 c0 8a 46 09 03 f9 03 ca 33 d2 8a 56 0a 03 f9 03 c8 33 c0 8a 46 0b 03 f9 03 ca 33 d2 8a 56 0c 03 f9 03 c8 33 c0 8a 46 0d 03 f9 03 ca 33 d2 8a 56 0e 03 f9 03 c8 33 c0 8a 46 0f 03 f9 03 ca 83 eb 10 03 f9 03 c8 03 f9 83 c6 10 }
            $s3 = { 55 8b ec 6a ff 68 [2] 40 00 68 [2] 40 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 5f 57 ff 15 [2] 40 00 59 83 0d [2] 41 00 ff 83 0d [2] 41 00 ff ff 15 [2] 40 00 8b 0d [2] 41 00 89 08 ff 15 [2] 40 00 8b 0d [2] 41 00 89 08 a1 [2] 40 00 8b 00 a3 [2] 41 00 e8 ?? 01 00 00 39 1d [3] 00 75 0c 68 [2] 40 00 ff 15 [2] 40 00 59 e8 ?? 01 00 00 68 [3] 00 68 [3] 00 e8 ?? 01 00 00 a1 [2] 41 00 89 45 94 8d 45 94 50 ff 35 [2] 41 00 8d 45 9c 50 8d 45 90 50 8d 45 a0 50 ff 15 [2] 40 00 68 [3] 00 68 00 [2] 00 e8 ?? 01 00 00 83 c4 24 a1 [2] 40 00 8b 30 3b }
    condition:
            uint16(0) == 0x5a4d and filesize > 150KB and all of ($s*) 
}
